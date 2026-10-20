// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! RoT attestation types for the Sled Agent API.

use std::fmt;

use omicron_common::BytesToHexDebug;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v19;
use crate::v19::attestation::Ed25519Signature;
#[cfg(doc)]
use crate::v19::attestation::{CertificateChain, MeasurementLog};

/// A Root of Trust (RoT) which provides measurments and signed attestations.
#[derive(Deserialize, Serialize, JsonSchema, strum::Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum Rot {
    /// The per-sled RoT in an Oxide rack.
    Oxide,
    /// The RoT implemented by the Helios OS using the host CPU's DICE
    /// Protection Environment (DPE).
    Helios,
}

impl From<v19::attestation::Rot> for Rot {
    fn from(old: v19::attestation::Rot) -> Self {
        match old {
            v19::attestation::Rot::Oxide => Rot::Oxide,
        }
    }
}

/// Path parameters for RoT attestation requests.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RotPathParams {
    /// Which RoT to use
    pub rot: Rot,
}

impl From<v19::attestation::RotPathParams> for RotPathParams {
    fn from(old: v19::attestation::RotPathParams) -> Self {
        RotPathParams { rot: old.rot.into() }
    }
}

/// A random nonce provided as part of an attestation challenge to guarantee
/// freshness thereby preventing replay attacks.
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum Nonce {
    /// A 32-byte nonce.
    #[serde(with = "byte_wrapper::HexArray::<32>")]
    N32([u8; 32]),
    /// A 48-byte nonce.
    #[serde(with = "byte_wrapper::HexArray::<48>")]
    N48([u8; 48]),
}

impl From<v19::attestation::Nonce> for Nonce {
    fn from(old: v19::attestation::Nonce) -> Self {
        match old {
            v19::attestation::Nonce::N32(n) => Nonce::N32(n),
        }
    }
}

const P384_SIG_LEN: usize = 96;

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct P384Signature(
    #[serde(with = "byte_wrapper::HexArray::<P384_SIG_LEN>")]
    pub  [u8; P384_SIG_LEN],
);

impl fmt::Debug for P384Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("P384Signature").field(&BytesToHexDebug(&self.0)).finish()
    }
}

/// An RoT produced attestation that represents a signature over the provided
/// [`Nonce`] combined with the [`MeasurementLog`] (if the RoT provides one)
/// and signed by a key certified by the [`CertificateChain`].
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Attestation {
    /// An Ed25519 signature.
    Ed25519(Ed25519Signature),
    /// A P-384 ECDSA signature.
    P384(P384Signature),
}

/// Error returned when converting an [`Attestation`] that cannot be
/// represented in a prior API version.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
#[error("P-384 attestation is unrepresentable in this API version")]
pub struct P384AttestationError;

impl TryFrom<Attestation> for v19::attestation::Attestation {
    type Error = P384AttestationError;

    fn try_from(new: Attestation) -> Result<Self, Self::Error> {
        match new {
            Attestation::Ed25519(sig) => Ok(Self::Ed25519(sig)),
            Attestation::P384(_) => Err(P384AttestationError),
        }
    }
}
