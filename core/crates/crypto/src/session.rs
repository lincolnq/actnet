//! Session establishment and message encryption/decryption.
//!
//! This module is the heart of the `crypto` crate. It exposes three async
//! functions that cover the entire Double Ratchet message lifecycle:
//!
//! - [`initiate_session`] — process a recipient's prekey bundle (X3DH) to
//!   establish an outbound session before the first message is sent.
//! - [`encrypt`] — encrypt a plaintext for a recipient with an established
//!   session, advancing the sending ratchet.
//! - [`decrypt`] — decrypt an incoming message, advancing the receiving ratchet.
//!
//! # The `Store` trait
//!
//! libsignal's ratchet is stateful: every encrypt or decrypt call advances key
//! material that must be persisted so the next call can pick up where the last
//! left off. This module defines [`Store`], a supertrait that composes all five
//! libsignal store sub-traits. Callers must supply a `&mut impl Store`; the
//! `store` crate provides the production SQLCipher-backed implementation.
//!
//! The `Clone` bound on `Store` is load-bearing: libsignal's session functions
//! take separate `&mut dyn SessionStore` and `&mut dyn IdentityKeyStore`
//! parameters. Since both must point to the same underlying state, we clone the
//! Arc-backed store handle to produce two independent `&mut` bindings that
//! share data through the Arc.
//!
//! # Message kinds
//!
//! The first message sent after [`initiate_session`] is a [`MessageKind::PreKey`]
//! message — it carries the X3DH key-agreement material so the recipient can
//! establish their end of the session on receipt. All subsequent messages are
//! [`MessageKind::Whisper`] messages. The session remains "unacknowledged" (and
//! Alice continues sending PreKey messages) until Alice receives a reply from
//! Bob.

use libsignal_protocol as signal;
use std::time::SystemTime;
use types::{AccountId, DeviceId};

// rand 0.9 split RNG traits: `OsRng` implements `TryRngCore` (fallible), but
// libsignal expects `CryptoRng` (infallible). `TryRngCore::unwrap_err()`
// adapts a fallible RNG into an infallible one that panics on OS-level RNG
// failure — which is the correct behaviour (if the OS can't provide entropy,
// nothing safe can happen). The name is confusing but it's the official API.
use rand::TryRngCore as _;

use crate::{error::CryptoError, prekeys::RecipientKeyBundle};

// ── Store trait ───────────────────────────────────────────────────────────────

/// Combined store trait required for all session operations.
///
/// `crypto` defines this; `store` implements it. The `Clone` bound is required
/// because libsignal's session functions take separate mutable references for
/// each store sub-trait. Since all sub-traits must point to the same underlying
/// state, callers clone the store handle (which is `Arc`-backed) to satisfy
/// multiple `&mut dyn Trait` parameters without aliasing.
pub trait Store:
    signal::SessionStore
    + signal::IdentityKeyStore
    + signal::PreKeyStore
    + signal::SignedPreKeyStore
    + signal::KyberPreKeyStore
    + Clone
    + Send
{
}

// ── Message types ─────────────────────────────────────────────────────────────

/// An encrypted message ready to hand to the homeserver for delivery.
#[derive(Debug, Clone)]
pub struct EncryptedMessage {
    pub ciphertext: Vec<u8>,
    pub kind: MessageKind,
}

/// Distinguishes the two ciphertext types the Double Ratchet produces.
///
/// A `PreKey` message is the first one sent to a recipient — it carries the
/// X3DH key-agreement material alongside the ciphertext. Subsequent messages
/// use `Whisper`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    PreKey,
    Whisper,
}

impl EncryptedMessage {
    fn from_signal(msg: signal::CiphertextMessage) -> Self {
        use signal::CiphertextMessageType;
        let kind = match msg.message_type() {
            CiphertextMessageType::PreKey => MessageKind::PreKey,
            _ => MessageKind::Whisper,
        };
        EncryptedMessage {
            ciphertext: msg.serialize().to_vec(),
            kind,
        }
    }
}

// ── Address ───────────────────────────────────────────────────────────────────

/// The address of a device: (account_id, device_id).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceAddress {
    pub account_id: AccountId,
    pub device_id: DeviceId,
}

impl DeviceAddress {
    pub fn new(account_id: AccountId, device_id: DeviceId) -> Self {
        Self { account_id, device_id }
    }

    pub(crate) fn to_protocol_address(&self) -> Result<signal::ProtocolAddress, CryptoError> {
        let device_id = signal::DeviceId::try_from(self.device_id.0)
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(signal::ProtocolAddress::new(
            self.account_id.0.clone(),
            device_id,
        ))
    }
}

impl std::fmt::Display for DeviceAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.account_id, self.device_id.0)
    }
}

// ── Session operations ────────────────────────────────────────────────────────

/// Process a recipient's key bundle and establish an outbound session.
///
/// Must be called once before the first `encrypt` to a given recipient.
pub async fn initiate_session<S: Store>(
    store: &mut S,
    local: &DeviceAddress,
    recipient: &DeviceAddress,
    bundle: &RecipientKeyBundle,
) -> Result<(), CryptoError> {
    let local_addr = local.to_protocol_address()?;
    let remote_addr = recipient.to_protocol_address()?;
    let signal_bundle = bundle.to_signal_bundle()?;

    let mut identity_store = store.clone();

    signal::process_prekey_bundle(
        &remote_addr,
        &local_addr,
        store,
        &mut identity_store,
        &signal_bundle,
        SystemTime::now(),
        &mut rand::rngs::OsRng.unwrap_err(),
    )
    .await
    .map_err(CryptoError::Signal)
}

/// Encrypt a plaintext for a recipient with an established session.
///
/// Advances the sending ratchet; the updated session state is persisted to
/// the store automatically by libsignal.
pub async fn encrypt<S: Store>(
    store: &mut S,
    local: &DeviceAddress,
    recipient: &DeviceAddress,
    plaintext: &[u8],
) -> Result<EncryptedMessage, CryptoError> {
    let local_addr = local.to_protocol_address()?;
    let remote_addr = recipient.to_protocol_address()?;
    let mut identity_store = store.clone();

    let ciphertext = signal::message_encrypt(
        plaintext,
        &remote_addr,
        &local_addr,
        store,
        &mut identity_store,
        SystemTime::now(),
        &mut rand::rngs::OsRng.unwrap_err(),
    )
    .await
    .map_err(CryptoError::Signal)?;

    Ok(EncryptedMessage::from_signal(ciphertext))
}

/// Decrypt a message from a sender, advancing the receiving ratchet.
///
/// The updated session state is persisted to the store automatically.
pub async fn decrypt<S: Store>(
    store: &mut S,
    local: &DeviceAddress,
    sender: &DeviceAddress,
    message: &EncryptedMessage,
) -> Result<Vec<u8>, CryptoError> {
    let local_addr = local.to_protocol_address()?;
    let remote_addr = sender.to_protocol_address()?;
    let mut identity_store = store.clone();
    let mut prekey_store = store.clone();
    let signed_prekey_store = store.clone();
    let mut kyber_store = store.clone();

    match message.kind {
        MessageKind::PreKey => {
            let prekey_msg =
                signal::PreKeySignalMessage::try_from(message.ciphertext.as_slice())
                    .map_err(CryptoError::Signal)?;

            signal::message_decrypt_prekey(
                &prekey_msg,
                &remote_addr,
                &local_addr,
                store,
                &mut identity_store,
                &mut prekey_store,
                &signed_prekey_store,
                &mut kyber_store,
                &mut rand::rngs::OsRng.unwrap_err(),
            )
            .await
            .map_err(CryptoError::Signal)
        }
        MessageKind::Whisper => {
            let signal_msg =
                signal::SignalMessage::try_from(message.ciphertext.as_slice())
                    .map_err(CryptoError::Signal)?;

            signal::message_decrypt_signal(
                &signal_msg,
                &remote_addr,
                &local_addr,
                store,
                &mut identity_store,
                &mut rand::rngs::OsRng.unwrap_err(),
            )
            .await
            .map_err(CryptoError::Signal)
        }
    }
}
