//! Error type for the `crypto` crate.
//!
//! [`CryptoError`] is the single error type returned by all public functions in
//! this crate. Most variants wrap a [`libsignal_protocol::SignalProtocolError`];
//! the remainder cover cases that arise in our own conversion code (bad key
//! bytes, out-of-range device IDs) before libsignal is even reached.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("libsignal error: {0}")]
    Signal(#[from] libsignal_protocol::SignalProtocolError),

    #[error("invalid key material")]
    InvalidKey,

    #[error("no session established with {0}")]
    NoSession(String),

    #[error("unexpected ciphertext type")]
    InvalidCiphertext,
}
