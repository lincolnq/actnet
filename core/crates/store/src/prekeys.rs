//! Prekey pool management.
//!
//! This module exposes the higher-level prekey operations that `app-core` uses
//! to manage the pools. The low-level single-record get/save/remove operations
//! required by libsignal's store traits live in [`crate::session`]; this module
//! sits above them and deals with batches and pool health.
//!
//! `app-core` is responsible for the refill policy: it calls
//! [`Store::remaining_one_time_prekey_count`] and
//! [`Store::remaining_kyber_prekey_count`] after each session initiation and
//! tops up the pools when either drops below a threshold (typically 10 keys).
//! The threshold is a policy decision, not enforced here.

use crate::{db::Store, error::StoreError};

impl Store {
    /// Save a batch of generated one-time prekey records to the pool.
    pub async fn save_one_time_prekeys(
        &self,
        records: &[(u32, Vec<u8>)],
    ) -> Result<(), StoreError> {
        let records = records.to_vec();
        self.conn
            .call(move |conn| {
                let tx = conn.transaction()?;
                for (id, record) in &records {
                    tx.execute(
                        "INSERT OR REPLACE INTO prekeys (id, record) VALUES (?1, ?2)",
                        rusqlite::params![id, record],
                    )?;
                }
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(StoreError::Db)
    }

    /// Number of one-time prekeys remaining in the pool.
    /// The app should refill when this drops below a threshold (typically 10).
    pub async fn remaining_one_time_prekey_count(&self) -> Result<usize, StoreError> {
        let count: i64 = self
            .conn
            .call(|conn| {
                conn.query_row("SELECT COUNT(*) FROM prekeys", [], |row| row.get(0))
                    .map_err(Into::into)
            })
            .await
            .map_err(StoreError::Db)?;
        Ok(count as usize)
    }

    /// Save the active signed prekey record.
    pub async fn save_signed_prekey(
        &self,
        id: u32,
        record: &[u8],
    ) -> Result<(), StoreError> {
        let record = record.to_vec();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO signed_prekeys (id, record) VALUES (?1, ?2)",
                    rusqlite::params![id, record],
                )?;
                Ok(())
            })
            .await
            .map_err(StoreError::Db)
    }

    /// Save a batch of generated Kyber prekey records to the pool.
    pub async fn save_kyber_prekeys(
        &self,
        records: &[(u32, Vec<u8>)],
    ) -> Result<(), StoreError> {
        let records = records.to_vec();
        self.conn
            .call(move |conn| {
                let tx = conn.transaction()?;
                for (id, record) in &records {
                    tx.execute(
                        "INSERT OR REPLACE INTO kyber_prekeys (id, record) VALUES (?1, ?2)",
                        rusqlite::params![id, record],
                    )?;
                }
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(StoreError::Db)
    }

    /// Number of Kyber prekeys remaining in the pool.
    pub async fn remaining_kyber_prekey_count(&self) -> Result<usize, StoreError> {
        let count: i64 = self
            .conn
            .call(|conn| {
                conn.query_row("SELECT COUNT(*) FROM kyber_prekeys", [], |row| row.get(0))
                    .map_err(Into::into)
            })
            .await
            .map_err(StoreError::Db)?;
        Ok(count as usize)
    }
}
