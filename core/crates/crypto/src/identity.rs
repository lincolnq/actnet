//! Long-term identity key pairs.
//!
//! Every actnet account has a single [`IdentityKeyPair`] generated at account
//! creation and never replaced. The public half ([`IdentityKey`]) is published
//! to the homeserver so other users can initiate encrypted sessions without the
//! owner being online (X3DH). The private half never leaves the device.
//!
//! Both types are thin wrappers around their libsignal equivalents. The
//! wrapping exists to keep libsignal types out of the public API surface of
//! this crate — callers deal with our types and serialized bytes, not
//! `libsignal_protocol` imports.

use libsignal_protocol as signal;

use crate::error::CryptoError;

// See session.rs for explanation of the `TryRngCore::unwrap_err()` pattern.
use rand::TryRngCore as _;

/// A local identity — the long-term key pair that identifies a user.
/// Generated once at account creation; the public half is published to the server.
pub struct IdentityKeyPair(pub(crate) signal::IdentityKeyPair);

impl IdentityKeyPair {
    pub fn generate() -> Self {
        Self(signal::IdentityKeyPair::generate(
            &mut rand::rngs::OsRng.unwrap_err(),
        ))
    }

    pub fn public_key(&self) -> IdentityKey {
        IdentityKey(*self.0.identity_key())
    }

    pub fn private_key(&self) -> &signal::PrivateKey {
        self.0.private_key()
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.0.serialize().to_vec()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, CryptoError> {
        signal::IdentityKeyPair::try_from(bytes)
            .map(Self)
            .map_err(CryptoError::Signal)
    }
}

/// The public identity key — what other users see and what the server stores.
#[derive(Clone, Copy)]
pub struct IdentityKey(pub(crate) signal::IdentityKey);

impl IdentityKey {
    pub fn serialize(&self) -> Vec<u8> {
        self.0.serialize().to_vec()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, CryptoError> {
        signal::IdentityKey::decode(bytes)
            .map(Self)
            .map_err(CryptoError::Signal)
    }
}
