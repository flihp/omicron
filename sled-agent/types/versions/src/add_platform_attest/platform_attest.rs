// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Platform attestation types for the Sled Agent API.

use byte_wrapper::HexArray;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

const QUALIFYING_DATA_LEN: usize = 32;

/// Caller chosen data used to qualify a platform attestation. This is
/// typically a random nonce provided as part of an attestation challenge to
/// guarantee freshness thereby preventing replay attacks. It must not be
/// reused.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema)]
pub struct QualifyingData(pub HexArray<QUALIFYING_DATA_LEN>);
