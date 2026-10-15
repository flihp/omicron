// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Version `ADD_HELIOS_ROT` of the Sled Agent API.
//!
//! This version adds the Helios OS RoT as a target for the RoT attestation
//! endpoints, along with the 48-byte nonces and P-384 signatures it uses.

pub mod attestation;
