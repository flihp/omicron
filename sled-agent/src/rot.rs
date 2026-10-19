// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Mechanisms for interacting with the sled's RoTs.

use crate::config::HeliosRotConfig;
use dropshot::HttpError;
use helios_rot::{
    DynHeliosRot, DynHeliosRotError, HeliosOsRot, HeliosRotMock,
    HeliosRotMockError,
};
use oxide_rot::{Attest, AttestError, ipcc, mock};
use sled_agent_types::rot as SaRotTypes;
use slog::Logger;
use slog_error_chain::InlineErrorChain;
use sprockets_tls::keys::AttestConfig;
use thiserror::Error;
use tokio::sync::{Mutex, MutexGuard, Semaphore, SemaphorePermit};
use x509_cert::der::{EncodePem, pem::LineEnding};

pub struct MeasurementLog(oxide_rot::Log);

impl From<oxide_rot::Log> for MeasurementLog {
    fn from(log: oxide_rot::Log) -> Self {
        MeasurementLog(log)
    }
}

impl From<MeasurementLog> for SaRotTypes::MeasurementLog {
    fn from(log: MeasurementLog) -> Self {
        let measurements = log
            .0
            .iter()
            .copied()
            .map(|m| match m {
                oxide_rot::Measurement::Sha3_256(d) => {
                    SaRotTypes::Measurement::Sha3_256(
                        SaRotTypes::Sha3_256Digest(d.0),
                    )
                }
            })
            .collect();
        SaRotTypes::MeasurementLog(measurements)
    }
}

pub struct CertificateChain(Vec<String>);

impl TryFrom<x509_cert::PkiPath> for CertificateChain {
    type Error = x509_cert::der::Error;

    fn try_from(chain: x509_cert::PkiPath) -> Result<Self, Self::Error> {
        let certs: Result<Vec<_>, _> =
            chain.into_iter().map(|cert| cert.to_pem(LineEnding::LF)).collect();
        Ok(CertificateChain(certs?))
    }
}

impl From<CertificateChain> for SaRotTypes::CertificateChain {
    fn from(chain: CertificateChain) -> Self {
        SaRotTypes::CertificateChain(chain.0)
    }
}

/// A nonce from the API. Each RoT accepts only nonces of a particular length,
/// so the conversion to the RoT's nonce type happens once the target RoT is
/// known.
pub struct Nonce(SaRotTypes::Nonce);

impl From<SaRotTypes::Nonce> for Nonce {
    fn from(nonce: SaRotTypes::Nonce) -> Self {
        Nonce(nonce)
    }
}

impl Nonce {
    fn len(&self) -> usize {
        match &self.0 {
            SaRotTypes::Nonce::N32(n) => n.len(),
            SaRotTypes::Nonce::N48(n) => n.len(),
        }
    }

    fn into_oxide(self) -> Result<oxide_rot::Nonce, RotError> {
        match self.0 {
            SaRotTypes::Nonce::N32(n32) => {
                Ok(oxide_rot::Nonce::N32(n32.into()))
            }
            SaRotTypes::Nonce::N48(_) => Err(RotError::NonceLength {
                rot: "Oxide",
                expected: 32,
                actual: self.len(),
            }),
        }
    }

    fn into_helios(self) -> Result<helios_rot::Nonce, RotError> {
        match self.0 {
            SaRotTypes::Nonce::N48(n48) => {
                Ok(helios_rot::Nonce::N48(helios_rot::Array(n48)))
            }
            SaRotTypes::Nonce::N32(_) => Err(RotError::NonceLength {
                rot: "Helios",
                expected: helios_rot::Nonce48::LENGTH,
                actual: self.len(),
            }),
        }
    }
}

pub enum Attestation {
    Oxide(oxide_rot::Attestation),
    Helios(helios_rot::Attestation),
}

impl From<Attestation> for SaRotTypes::Attestation {
    fn from(att: Attestation) -> Self {
        match att {
            Attestation::Oxide(oxide_rot::Attestation::Ed25519(sig)) => {
                SaRotTypes::Attestation::Ed25519(SaRotTypes::Ed25519Signature(
                    sig.0,
                ))
            }
            Attestation::Helios(helios_rot::Attestation::P384(sig)) => {
                SaRotTypes::Attestation::P384(SaRotTypes::P384Signature(sig.0))
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum RotError {
    #[error("failed to create mock attestor: {0}")]
    AttestMock(#[from] mock::AttestMockError),

    #[error("attestation request failed: {0}")]
    Attest(#[from] AttestError),

    #[error("failed to create mock Helios RoT: {0}")]
    HeliosRotMock(#[from] HeliosRotMockError),

    #[error("Helios RoT request failed: {0}")]
    HeliosRot(#[from] DynHeliosRotError),

    #[error("failed to encode certificate chain as PEM: {0}")]
    CertificateEncoding(#[source] x509_cert::der::Error),

    #[error("the Helios RoT does not provide a measurement log")]
    NoMeasurementLog,

    #[error("the {rot} RoT requires a {expected}-byte nonce, got {actual}")]
    NonceLength { rot: &'static str, expected: usize, actual: usize },

    #[error("RoT attestation queue full")]
    Busy,
}

impl From<RotError> for HttpError {
    fn from(e: RotError) -> Self {
        match e {
            RotError::Busy => HttpError::for_unavail(
                None,
                InlineErrorChain::new(&e).to_string(),
            ),
            RotError::NoMeasurementLog | RotError::NonceLength { .. } => {
                HttpError::for_bad_request(
                    None,
                    InlineErrorChain::new(&e).to_string(),
                )
            }
            _ => HttpError::for_internal_error(
                InlineErrorChain::new(&e).to_string(),
            ),
        }
    }
}

/// Maximum number of outstanding (in-flight or waiting) RoT requests.
const QUEUE_SIZE: usize = 256;

/// The RoT implementation backing a [`RotAttestor`].
enum RotImpl {
    Oxide(Box<dyn Attest + Send + Sync>),
    Helios(Box<dyn DynHeliosRot>),
}

/// Mediates access to an RoT on the current sled.
///
/// Attestation requests to the Oxide RoT (on a real sled) are proxied through
/// a few layers: Sled Agent ([`RotAttestor`]) <--(via IPCC)--> SP <-> RoT.
/// Requests to the Helios RoT go through the os_rot driver to the host CPU's
/// DICE Protection Environment, opening the os_rot device for each request. Each RoT services a single attestation
/// request at a time, so we serialize requests here rather than having
/// concurrent callers contend for the underlying interface.
///
/// At most [`QUEUE_SIZE`] requests may be outstanding at once. Requests made
/// beyond that limit fail immediately with [`RotError::Busy`] rather than
/// waiting indefinitely.
pub struct RotAttestor {
    log: Logger,
    queue: Semaphore,
    rot: Mutex<RotImpl>,
}

impl RotAttestor {
    /// Creates a new Oxide RoT attestor with the given config.
    pub fn new_oxide(
        log: &Logger,
        attest_config: &AttestConfig,
    ) -> Result<Self, RotError> {
        let log = log.new(o!(
            "component" => "RotAttestor",
            "rot" => "oxide",
            "interface" => match attest_config {
                AttestConfig::Ipcc => "ipcc",
                AttestConfig::Local { .. } => "mock",
            }
        ));

        let attest: Box<dyn Attest + Send + Sync> = match attest_config {
            AttestConfig::Ipcc => Box::new(ipcc::AttestIpcc::new()),
            AttestConfig::Local {
                priv_key,
                cert_chain,
                log,
                test_corpus: _,
            } => Box::new(mock::AttestMock::load(cert_chain, log, priv_key)?),
        };

        Ok(Self::new(log, RotImpl::Oxide(attest)))
    }

    /// Creates a new Helios RoT attestor with the given config.
    pub fn new_helios(
        log: &Logger,
        config: &HeliosRotConfig,
    ) -> Result<Self, RotError> {
        let log = log.new(o!(
            "component" => "RotAttestor",
            "rot" => "helios",
            "interface" => match config {
                HeliosRotConfig::OsRot => "os_rot",
                HeliosRotConfig::Local { .. } => "mock",
            }
        ));

        let attest: Box<dyn DynHeliosRot> = match config {
            HeliosRotConfig::OsRot => Box::new(HeliosOsRot::default()),
            HeliosRotConfig::Local { priv_key, cert_chain } => {
                Box::new(HeliosRotMock::load(cert_chain, priv_key)?)
            }
        };

        Ok(Self::new(log, RotImpl::Helios(attest)))
    }

    fn new(log: Logger, rot: RotImpl) -> Self {
        RotAttestor {
            log,
            queue: Semaphore::new(QUEUE_SIZE),
            rot: Mutex::new(rot),
        }
    }

    /// Wait for exclusive access to the RoT, reserving a queue slot for the
    /// duration of the request. Fails with [`RotError::Busy`] if the queue is
    /// full.
    async fn acquire(&self) -> Result<RotGuard<'_>, RotError> {
        let _permit = self.queue.try_acquire().map_err(|_| RotError::Busy)?;
        let rot = self.rot.lock().await;
        Ok(RotGuard { _permit, rot })
    }

    pub async fn get_measurement_log(
        &self,
    ) -> Result<MeasurementLog, RotError> {
        let guard = self.acquire().await?;
        debug!(self.log, "getting measurement log");
        match &*guard.rot {
            RotImpl::Oxide(attest) => {
                Ok(attest.get_measurement_log().await?.into())
            }
            RotImpl::Helios(_) => Err(RotError::NoMeasurementLog),
        }
    }

    pub async fn get_certificate_chain(
        &self,
    ) -> Result<CertificateChain, RotError> {
        let guard = self.acquire().await?;
        debug!(self.log, "getting certificate chain");
        let chain = match &*guard.rot {
            RotImpl::Oxide(attest) => attest.get_certificates().await?,
            RotImpl::Helios(helios) => helios.get_certificates().await?,
        };
        CertificateChain::try_from(chain).map_err(RotError::CertificateEncoding)
    }

    pub async fn attest(&self, nonce: Nonce) -> Result<Attestation, RotError> {
        let guard = self.acquire().await?;
        debug!(self.log, "getting attestation");
        match &*guard.rot {
            RotImpl::Oxide(attest) => {
                let nonce = nonce.into_oxide()?;
                Ok(Attestation::Oxide(attest.attest(&nonce).await?))
            }
            RotImpl::Helios(helios) => {
                let nonce = nonce.into_helios()?;
                Ok(Attestation::Helios(helios.attest(&nonce).await?))
            }
        }
    }
}

/// Exclusive access to the RoT, along with the queue slot reserved for the
/// request. Both are released when dropped.
struct RotGuard<'a> {
    _permit: SemaphorePermit<'a>,
    rot: MutexGuard<'a, RotImpl>,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use attest_mock::MockData;
    use camino::Utf8Path;
    use camino_tempfile::Utf8TempDir;
    use dice_verifier::oxide_rot::verify_attestation;
    use omicron_test_utils::dev::test_setup_log;
    use sprockets_tls_test_utils::{
        OutputFileExistsBehavior, alias_prefix, certlist_path, private_key_path,
    };
    use x509_cert::{Certificate, der::DecodePem};

    // An arbitrary digest for the single measurement in the mock log.
    pub(crate) const DIGEST: &str =
        "be4df4e085175f3de0c8ac4837e1c2c9a34e8983209dac6b549e94154f7cdd9c";

    /// Write the keys, certs, and measurement log for the mock RoT to `dir`
    fn write_mock_data(dir: &Utf8Path) {
        let behavior = OutputFileExistsBehavior::Overwrite;

        let doc = sprockets_tls_test_utils::generate_config(1);
        doc.write_key_pairs(dir.to_owned(), behavior).unwrap();
        doc.write_certificates(dir.to_owned(), behavior).unwrap();
        doc.write_certificate_lists(dir.to_owned(), behavior).unwrap();

        let log_kdl = format!(
            r#"
            measurement {{
                algorithm "sha3-256"
                digest "{DIGEST}"
            }}
            "#
        );

        let log = attest_mock::MockLog::parse("log.kdl", &log_kdl)
            .unwrap()
            .to_bytes()
            .unwrap();
        std::fs::write(dir.join("log.bin"), &log).unwrap();
    }

    /// Write the mock RoT's data to `dir` and return a config that uses it.
    pub(crate) fn mock_config(dir: &Utf8Path) -> AttestConfig {
        write_mock_data(dir);

        let alias = alias_prefix(1);
        AttestConfig::Local {
            priv_key: private_key_path(dir.to_owned(), &alias),
            cert_chain: certlist_path(dir.to_owned(), &alias),
            log: dir.join("log.bin"),
            test_corpus: vec![],
        }
    }

    /// Write a self-signed P-384 alias cert and its key to `dir` and return a
    /// config for the mock Helios RoT that uses them
    fn helios_mock_config(dir: &Utf8Path) -> HeliosRotConfig {
        let mut params = rcgen::CertificateParams::new(vec![]);
        params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;
        let cert = rcgen::Certificate::from_params(params).unwrap();

        let cert_chain = dir.join("helios-alias.certlist.pem");
        let priv_key = dir.join("helios-alias.key.pem");
        std::fs::write(&cert_chain, cert.serialize_pem().unwrap()).unwrap();
        std::fs::write(&priv_key, cert.serialize_private_key_pem()).unwrap();

        HeliosRotConfig::Local { priv_key, cert_chain }
    }

    /// Drive "normal" operation of the `RotAttestor` backed by the mock Oxide
    /// RoT to get and appraise an attestation
    #[tokio::test]
    async fn rot_attestor_verify_attestation() {
        let logctx = test_setup_log("rot_attestor_verify_attestation");
        let tmp = Utf8TempDir::new().unwrap();
        let cfg = mock_config(tmp.path());

        // Get artifacts required to verify the attestation
        let attestor = RotAttestor::new_oxide(&logctx.log, &cfg).unwrap();

        let log = attestor.get_measurement_log().await.unwrap();
        let chain = attestor.get_certificate_chain().await.unwrap();
        let nonce = [7u8; 32];
        let attestation = attestor
            .attest(SaRotTypes::Nonce::N32(nonce).into())
            .await
            .unwrap();

        // The first cert in the chain is the leaf. This cert holds the public
        // part of the key used to sign the attestation.
        let alias = Certificate::from_pem(&chain.0[0]).unwrap();
        let Attestation::Oxide(oxide_attestation) = &attestation else {
            panic!("expected an Oxide RoT attestation");
        };
        verify_attestation(
            &alias,
            oxide_attestation,
            &log.0,
            &oxide_rot::Nonce::N32(nonce.into()),
        )
        .expect("attestation should verify against the alias cert");

        let log: SaRotTypes::MeasurementLog = log.into();
        assert_eq!(log.0.len(), 1);

        let SaRotTypes::Measurement::Sha3_256(digest) = &log.0[0];
        assert_eq!(hex::encode(digest.0), DIGEST);

        let chain: SaRotTypes::CertificateChain = chain.into();
        assert!(!chain.0.is_empty());
        assert!(
            chain
                .0
                .iter()
                .all(|c| c.starts_with("-----BEGIN CERTIFICATE-----"))
        );

        let SaRotTypes::Attestation::Ed25519(sig) = attestation.into() else {
            panic!("expected an Ed25519 attestation");
        };
        assert_eq!(sig.0.len(), 64);

        logctx.cleanup_successful();
    }

    /// Ensure new requests are rejected when the request queue is full
    #[tokio::test]
    async fn rot_attestor_queue_full() {
        let logctx = test_setup_log("rot_attestor_queue_full");
        let tmp = Utf8TempDir::new().unwrap();
        let cfg = mock_config(tmp.path());
        let attestor = RotAttestor::new_oxide(&logctx.log, &cfg).unwrap();

        // fill request queue
        attestor.queue.try_acquire_many(QUEUE_SIZE as u32).unwrap().forget();

        // Request queue is full, additional requests are rejected
        assert!(matches!(
            attestor.get_measurement_log().await,
            Err(RotError::Busy)
        ));
        assert!(matches!(
            attestor.get_certificate_chain().await,
            Err(RotError::Busy)
        ));
        let nonce: Nonce = SaRotTypes::Nonce::N32([7u8; 32]).into();
        assert!(matches!(attestor.attest(nonce).await, Err(RotError::Busy)));

        // RotError::Busy is reported to clients as 503 / Service Unavailable
        let err: HttpError = RotError::Busy.into();
        assert_eq!(
            err.status_code.as_status(),
            http::StatusCode::SERVICE_UNAVAILABLE
        );

        // Once the outstanding requests complete, new ones succeed.
        attestor.queue.add_permits(QUEUE_SIZE);
        assert!(attestor.get_measurement_log().await.is_ok());

        logctx.cleanup_successful();
    }

    /// The Oxide RoT only accepts 32-byte nonces
    #[tokio::test]
    async fn rot_attestor_oxide_rejects_n48() {
        let logctx = test_setup_log("rot_attestor_oxide_rejects_n48");
        let tmp = Utf8TempDir::new().unwrap();
        let cfg = mock_config(tmp.path());
        let attestor = RotAttestor::new_oxide(&logctx.log, &cfg).unwrap();

        let nonce: Nonce = SaRotTypes::Nonce::N48([7u8; 48]).into();
        let err = attestor.attest(nonce).await.err().unwrap();
        assert!(matches!(
            err,
            RotError::NonceLength { expected: 32, actual: 48, .. }
        ));
        let err: HttpError = err.into();
        assert_eq!(err.status_code.as_status(), http::StatusCode::BAD_REQUEST);

        logctx.cleanup_successful();
    }

    /// Drive "normal" operation of the `RotAttestor` backed by the mock Helios
    /// RoT to get and appraise an attestation
    #[tokio::test]
    async fn rot_attestor_helios_verify_attestation() {
        let logctx = test_setup_log("rot_attestor_helios_verify_attestation");
        let tmp = Utf8TempDir::new().unwrap();
        let cfg = helios_mock_config(tmp.path());
        let attestor = RotAttestor::new_helios(&logctx.log, &cfg).unwrap();

        let chain = attestor.get_certificate_chain().await.unwrap();
        let nonce = [7u8; 48];
        let attestation = attestor
            .attest(SaRotTypes::Nonce::N48(nonce).into())
            .await
            .unwrap();

        let alias = Certificate::from_pem(&chain.0[0]).unwrap();
        let Attestation::Helios(helios_attestation) = &attestation else {
            panic!("expected a Helios RoT attestation");
        };

        // `dice_verifier` depends on a different revision of the `helios-rot`
        // crate than we do, so its `Attestation` type is distinct from ours.
        // The serialized forms are identical, so we convert between them with
        // a serde round trip.
        let verifier_attestation: dice_verifier::helios_rot::Attestation =
            serde_json::from_value(
                serde_json::to_value(helios_attestation).unwrap(),
            )
            .unwrap();
        dice_verifier::helios_rot::verify_attestation(
            &alias,
            &verifier_attestation,
            &dice_verifier::helios_rot::Nonce::try_from(&nonce[..]).unwrap(),
        )
        .expect("attestation should verify against the alias cert");

        let chain: SaRotTypes::CertificateChain = chain.into();
        assert_eq!(chain.0.len(), 1);
        assert!(chain.0[0].starts_with("-----BEGIN CERTIFICATE-----"));

        let SaRotTypes::Attestation::P384(sig) = attestation.into() else {
            panic!("expected a P-384 attestation");
        };
        assert_eq!(sig.0.len(), 96);

        logctx.cleanup_successful();
    }

    /// The Helios RoT has no measurement log and only accepts 48-byte nonces
    #[tokio::test]
    async fn rot_attestor_helios_bad_requests() {
        let logctx = test_setup_log("rot_attestor_helios_bad_requests");
        let tmp = Utf8TempDir::new().unwrap();
        let cfg = helios_mock_config(tmp.path());
        let attestor = RotAttestor::new_helios(&logctx.log, &cfg).unwrap();

        let err = attestor.get_measurement_log().await.err().unwrap();
        assert!(matches!(err, RotError::NoMeasurementLog));
        let err: HttpError = err.into();
        assert_eq!(err.status_code.as_status(), http::StatusCode::BAD_REQUEST);

        let nonce: Nonce = SaRotTypes::Nonce::N32([7u8; 32]).into();
        let err = attestor.attest(nonce).await.err().unwrap();
        assert!(matches!(
            err,
            RotError::NonceLength { expected: 48, actual: 32, .. }
        ));
        let err: HttpError = err.into();
        assert_eq!(err.status_code.as_status(), http::StatusCode::BAD_REQUEST);

        logctx.cleanup_successful();
    }

    /// Creating a `RotAttestor` for the Helios OS RoT doesn't require the
    /// os_rot device, but requests that need it fail
    #[tokio::test]
    async fn rot_attestor_helios_os_rot_no_device() {
        // This test needs a machine without the os_rot driver.
        if Utf8Path::new("/dev/os_rot").exists() {
            return;
        }

        let logctx = test_setup_log("rot_attestor_helios_os_rot_no_device");
        let attestor =
            RotAttestor::new_helios(&logctx.log, &HeliosRotConfig::OsRot)
                .unwrap();

        let err = attestor.get_certificate_chain().await.err().unwrap();
        assert!(matches!(err, RotError::HeliosRot(_)));
        let err: HttpError = err.into();
        assert_eq!(
            err.status_code.as_status(),
            http::StatusCode::INTERNAL_SERVER_ERROR
        );

        logctx.cleanup_successful();
    }
}
