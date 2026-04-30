//! Shared primitive types used across every crate in the workspace.
//!
//! This crate is a leaf — it has no internal dependencies and only lightweight
//! external ones (serde, uuid). Every other crate that needs to pass identifiers
//! or timestamps across a boundary imports from here rather than defining its own
//! versions. Keeping it dependency-free means it can be imported anywhere without
//! pulling in libsignal, Tokio, or SQLite.
//!
//! Types defined here are intentionally thin newtypes. They carry no behaviour
//! beyond serialization and display; all logic lives in the crates that use them.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The decentralized identifier for a user account.
/// In production this is a `did:plc:...` string. Treated as opaque here.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccountId(pub String);

impl AccountId {
    pub fn new(did: impl Into<String>) -> Self {
        Self(did.into())
    }
}

impl std::fmt::Display for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A device within an account. A user may register multiple devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub u32);

impl DeviceId {
    pub fn new(id: u32) -> Self {
        Self(id)
    }
}

impl From<DeviceId> for u32 {
    fn from(d: DeviceId) -> u32 {
        d.0
    }
}

/// A unique identifier for a message in the outbound queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub Uuid);

impl MessageId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for MessageId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Unix timestamp in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Timestamp(pub i64);

impl Timestamp {
    pub fn now() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before Unix epoch")
            .as_millis() as i64;
        Self(ms)
    }

    pub fn as_millis(self) -> i64 {
        self.0
    }
}
