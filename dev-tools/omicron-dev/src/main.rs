// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, anyhow};
use attest_mock::MockData;
use camino::{Utf8Path, Utf8PathBuf};
use camino_tempfile::Utf8TempDir;
use clap::{Args, Parser, Subcommand};
use futures::StreamExt;
use gateway_client::ClientInfo as _;
use gateway_test_utils::setup::DEFAULT_SP_SIM_CONFIG;
use libc::SIGINT;
use nexus_config::NexusConfig;
use nexus_test_interface::NexusServer;
use nexus_test_utils::resource_helpers::DiskTest;
use nexus_test_utils::{SimHeliosRotConfig, SimRotConfig};
use signal_hook_tokio::Signals;
use sprockets_tls_test_utils::{
    OutputFileExistsBehavior, alias_prefix, certlist_path, private_key_path,
};
use std::fs;

const DEFAULT_NEXUS_CONFIG: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../nexus/examples/config.toml");

fn main() -> anyhow::Result<()> {
    oxide_tokio_rt::run(async {
        let args = OmicronDevApp::parse();
        args.exec().await
    })
}

/// Tools for working with a local Omicron deployment.
#[derive(Clone, Debug, Parser)]
#[clap(version)]
struct OmicronDevApp {
    #[clap(subcommand)]
    command: OmicronDevCmd,
}

impl OmicronDevApp {
    async fn exec(&self) -> Result<(), anyhow::Error> {
        match &self.command {
            OmicronDevCmd::RunAll(args) => args.exec().await,
        }
    }
}

#[derive(Clone, Debug, Subcommand)]
enum OmicronDevCmd {
    /// Run a full simulated control plane
    RunAll(RunAllArgs),
}

#[derive(Clone, Debug, Args)]
struct RunAllArgs {
    /// Nexus external API listen port.  Use `0` to request any available port.
    #[clap(long, action)]
    nexus_listen_port: Option<u16>,
    /// Override the gateway server configuration file.
    #[clap(long, default_value = DEFAULT_SP_SIM_CONFIG)]
    gateway_config: Utf8PathBuf,
    /// Override the nexus configuration file.
    #[clap(long, default_value = DEFAULT_NEXUS_CONFIG)]
    nexus_config: Utf8PathBuf,
}

impl RunAllArgs {
    async fn exec(&self) -> Result<(), anyhow::Error> {
        // Start a stream listening for SIGINT
        let signals =
            Signals::new(&[SIGINT]).expect("failed to wait for SIGINT");
        let mut signal_stream = signals.fuse();

        // Read configuration.
        let config_str = fs::read_to_string(&self.nexus_config)?;
        let mut config: NexusConfig = toml::from_str(&config_str).context(
            format!("parsing config: {}", self.nexus_config.as_str()),
        )?;
        config.pkg.log = dropshot::ConfigLogging::File {
            // See LogContext::new(),
            path: "UNUSED".to_string().into(),
            level: dropshot::ConfigLoggingLevel::Trace,
            if_exists: dropshot::ConfigLoggingIfExists::Fail,
        };

        if let Some(p) = self.nexus_listen_port {
            config
                .deployment
                .dropshot_external
                .dropshot
                .bind_address
                .set_port(p);
        }

        // Generate the artifacts used by the simulated sled agents' mock RoTs.
        // These must outlive the control plane, so `rot_dir` is held until
        // the end of this function.
        let rot_dir = Utf8TempDir::with_prefix("omicron-dev-rot-")
            .context("creating directory for mock RoT artifacts")?;
        let sim_rot = write_mock_rot_artifacts(rot_dir.path())
            .context("generating mock RoT artifacts")?;
        let sim_helios_rot = write_mock_helios_rot_artifacts(rot_dir.path())
            .context("generating mock Helios RoT artifacts")?;

        println!("omicron-dev: setting up all services ... ");
        let cptestctx = nexus_test_utils::omicron_dev_setup_with_config::<
            omicron_nexus::Server,
        >(
            &mut config,
            0,
            self.gateway_config.clone(),
            Some(sim_rot),
            Some(sim_helios_rot),
        )
        .await
        .context("error setting up services")?;

        println!("omicron-dev: Adding disks to first sled agent");

        // This is how our integration tests are identifying that "disks exist"
        // within the database.
        //
        // This inserts:
        // - DEFAULT_ZPOOL_COUNT zpools, each of which contains:
        //   - A crucible dataset
        //   - A debug dataset
        DiskTest::new(&cptestctx).await;

        println!("omicron-dev: services are running.");

        // Print out basic information about what was started.
        // NOTE: The stdout strings here are not intended to be stable, but they
        // are used by the test suite.
        println!(
            "omicron-dev: debug dropbox:          {}",
            cptestctx.debug_dropbox_path()
        );

        let addr = cptestctx.external_client.bind_address;
        println!("omicron-dev: nexus external API:     {:?}", addr);
        println!(
            "omicron-dev: nexus internal API:     {:?}",
            cptestctx.server.get_http_server_internal_address(),
        );
        println!(
            "omicron-dev: nexus lockstep API:     {:?}",
            cptestctx.server.get_http_server_lockstep_address(),
        );
        println!(
            "omicron-dev: sled agent API:         http://{:?}",
            cptestctx.sled_agents[0].local_addr(),
        );
        println!("omicron-dev: mock RoT artifacts:     {}", rot_dir.path(),);
        println!(
            "omicron-dev: cockroachdb pid:        {}",
            cptestctx.database.pid(),
        );
        println!(
            "omicron-dev: cockroachdb URL:        {}",
            cptestctx.database.pg_config()
        );
        println!(
            "omicron-dev: cockroachdb directory:  {}",
            cptestctx.database.temp_dir()
        );
        println!(
            "omicron-dev: clickhouse native addr: {}",
            cptestctx.clickhouse.native_address(),
        );
        println!(
            "omicron-dev: clickhouse http addr:   {}",
            cptestctx.clickhouse.http_address(),
        );
        println!(
            "omicron-dev: internal DNS HTTP:      http://{}",
            cptestctx.internal_dns.dropshot_server.local_addr()
        );
        println!(
            "omicron-dev: internal DNS:           {}",
            cptestctx
                .internal_dns
                .dns_server
                .sole_local_address()
                .context("Expected exactly 1 internal DNS address")?,
        );
        println!(
            "omicron-dev: external DNS name:      {}",
            cptestctx.external_dns_zone_name,
        );
        println!(
            "omicron-dev: external DNS HTTP:      http://{}",
            cptestctx.external_dns.dropshot_server.local_addr()
        );
        for addr in cptestctx.external_dns.dns_server.local_addresses() {
            println!("omicron-dev: external DNS:           {}", addr,);
            println!(
                "omicron-dev:   e.g. `dig @{} -p {} {}.sys.{}`",
                addr.ip(),
                addr.port(),
                cptestctx.silo_name,
                cptestctx.external_dns_zone_name,
            );
        }
        for (switch_slot, gateway) in &cptestctx.gateway {
            println!(
                "omicron-dev: management gateway:     {} ({:?})",
                gateway.client.baseurl(),
                switch_slot,
            );
        }
        println!(
            "omicron-dev: silo name:              {}",
            cptestctx.silo_name,
        );
        println!(
            "omicron-dev: privileged user name:   {}",
            cptestctx.user_name.as_ref(),
        );
        println!("omicron-dev: privileged password:    {}", cptestctx.password);

        // Wait for a signal.
        let caught_signal = signal_stream.next().await;
        assert_eq!(caught_signal.unwrap(), SIGINT);
        eprintln!(
            "omicron-dev: caught signal, shutting down and removing \
            temporary directory"
        );

        cptestctx.teardown().await;
        Ok(())
    }
}

/// An arbitrary digest for the single measurement in the mock RoT's
/// measurement log.
const MOCK_ROT_DIGEST: &str =
    "be4df4e085175f3de0c8ac4837e1c2c9a34e8983209dac6b549e94154f7cdd9c";

/// Write the keys, certificates, and measurement log needed by the simulated
/// sled agents' mock RoT to `dir`, returning a config that refers to them.
fn write_mock_rot_artifacts(dir: &Utf8Path) -> anyhow::Result<SimRotConfig> {
    let behavior = OutputFileExistsBehavior::Overwrite;
    let doc = sprockets_tls_test_utils::generate_config(1);
    doc.write_key_pairs(dir.to_owned(), behavior)
        .map_err(|e| anyhow!("writing mock RoT key pairs: {e:?}"))?;
    doc.write_certificates(dir.to_owned(), behavior)
        .map_err(|e| anyhow!("writing mock RoT certificates: {e:?}"))?;
    doc.write_certificate_lists(dir.to_owned(), behavior)
        .map_err(|e| anyhow!("writing mock RoT certificate chains: {e:?}"))?;

    let log_kdl = format!(
        r#"
        measurement {{
            algorithm "sha3-256"
            digest "{MOCK_ROT_DIGEST}"
        }}
        "#
    );
    let log = attest_mock::MockLog::parse("log.kdl", &log_kdl)
        .context("parsing mock RoT measurement log")?
        .to_bytes()
        .context("encoding mock RoT measurement log")?;
    let log_path = dir.join("log.bin");
    fs::write(&log_path, &log)
        .with_context(|| format!("writing {log_path}"))?;

    let alias = alias_prefix(1);
    Ok(SimRotConfig {
        priv_key: private_key_path(dir.to_owned(), &alias),
        cert_chain: certlist_path(dir.to_owned(), &alias),
        log: log_path,
    })
}

/// Write a self-signed P-384 certificate and its private key for the
/// simulated sled agents' mock Helios RoT to `dir`, returning a config that
/// refers to them.
fn write_mock_helios_rot_artifacts(
    dir: &Utf8Path,
) -> anyhow::Result<SimHeliosRotConfig> {
    let mut params =
        rcgen::CertificateParams::new(vec![String::from("helios-rot-mock")]);
    params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;
    let cert = rcgen::Certificate::from_params(params)
        .context("generating mock Helios RoT certificate")?;

    let cert_chain = dir.join("helios-rot.certlist.pem");
    let cert_pem =
        cert.serialize_pem().context("encoding mock Helios RoT certificate")?;
    fs::write(&cert_chain, cert_pem)
        .with_context(|| format!("writing {cert_chain}"))?;

    let priv_key = dir.join("helios-rot.key.pem");
    fs::write(&priv_key, cert.serialize_private_key_pem())
        .with_context(|| format!("writing {priv_key}"))?;

    Ok(SimHeliosRotConfig { priv_key, cert_chain })
}
