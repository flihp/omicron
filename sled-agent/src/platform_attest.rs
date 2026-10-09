// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Platform attestation.

use dropshot::{ErrorStatusCode, HttpError};
use sled_agent_types::platform_attest as SaPlatformAttestTypes;
use slog_error_chain::InlineErrorChain;
use thiserror::Error;

pub struct QualifyingData(vm_attest::QualifyingData);

impl From<SaPlatformAttestTypes::QualifyingData> for QualifyingData {
    fn from(qdata: SaPlatformAttestTypes::QualifyingData) -> Self {
        QualifyingData(vm_attest::QualifyingData::from(<[u8; 32]>::from(
            qdata.0,
        )))
    }
}

impl From<QualifyingData> for vm_attest::QualifyingData {
    fn from(qdata: QualifyingData) -> Self {
        qdata.0
    }
}

#[derive(Debug, Error)]
pub enum PlatformAttestError {
    #[error("platform attestation is not implemented")]
    Unimplemented,
}

impl From<PlatformAttestError> for HttpError {
    fn from(e: PlatformAttestError) -> Self {
        let message = InlineErrorChain::new(&e).to_string();
        match e {
            PlatformAttestError::Unimplemented => HttpError {
                status_code: ErrorStatusCode::NOT_IMPLEMENTED,
                error_code: None,
                external_message: message.clone(),
                internal_message: message,
                headers: None,
            },
        }
    }
}

pub fn attest(
    _qdata: vm_attest::QualifyingData,
) -> Result<(), PlatformAttestError> {
    Err(PlatformAttestError::Unimplemented)
}
