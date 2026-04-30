//! Outbound message queue.
//!
//! When `app-core` encrypts a message it hands the ciphertext to this queue
//! before attempting delivery. If the homeserver is unreachable, the message
//! stays here until the next successful connection, at which point `app-core`
//! calls [`Store::drain`] and retries all pending messages in order. Once the
//! server acknowledges delivery, [`Store::mark_delivered`] removes the message.
//!
//! The queue holds ciphertext only — plaintext never touches the database.
//! Message ordering is preserved: [`Store::drain`] returns rows sorted by
//! `enqueued_at` ascending.

use types::{MessageId, Timestamp};

use crate::{db::Store, error::StoreError};

/// An encrypted message held in the outbound queue pending delivery.
#[derive(Debug, Clone)]
pub struct QueuedMessage {
    pub id: MessageId,
    pub recipient_name: String,
    pub recipient_device_id: u32,
    pub ciphertext: Vec<u8>,
    /// 0 = PreKey, 1 = Whisper
    pub message_kind: u8,
    pub enqueued_at: Timestamp,
}

impl Store {
    /// Add a message to the outbound queue.
    pub async fn enqueue(&self, msg: &QueuedMessage) -> Result<(), StoreError> {
        let id = msg.id.to_string();
        let recipient_name = msg.recipient_name.clone();
        let recipient_device_id = msg.recipient_device_id;
        let ciphertext = msg.ciphertext.clone();
        let message_kind = msg.message_kind as i64;
        let enqueued_at = msg.enqueued_at.as_millis();

        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO message_queue
                     (id, recipient_name, recipient_device_id, ciphertext, message_kind, enqueued_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![
                        id,
                        recipient_name,
                        recipient_device_id,
                        ciphertext,
                        message_kind,
                        enqueued_at
                    ],
                )?;
                Ok(())
            })
            .await
            .map_err(StoreError::Db)
    }

    /// Return all queued messages, oldest first.
    pub async fn drain(&self) -> Result<Vec<QueuedMessage>, StoreError> {
        self.conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, recipient_name, recipient_device_id, ciphertext,
                            message_kind, enqueued_at
                     FROM message_queue
                     ORDER BY enqueued_at ASC",
                )?;

                let rows = stmt.query_map([], |row| {
                    Ok(QueuedMessage {
                        id: MessageId(
                            uuid::Uuid::parse_str(&row.get::<_, String>(0)?)
                                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                                    0,
                                    rusqlite::types::Type::Text,
                                    Box::new(e),
                                ))?,
                        ),
                        recipient_name: row.get(1)?,
                        recipient_device_id: row.get(2)?,
                        ciphertext: row.get(3)?,
                        message_kind: row.get::<_, i64>(4)? as u8,
                        enqueued_at: Timestamp(row.get(5)?),
                    })
                })?;

                rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
            })
            .await
            .map_err(StoreError::Db)
    }

    /// Remove a delivered message from the queue.
    pub async fn mark_delivered(&self, id: MessageId) -> Result<(), StoreError> {
        let id_str = id.to_string();
        self.conn
            .call(move |conn| {
                conn.execute("DELETE FROM message_queue WHERE id = ?1", [&id_str])?;
                Ok(())
            })
            .await
            .map_err(StoreError::Db)
    }
}
