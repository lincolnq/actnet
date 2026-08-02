//! Directory entries: the client-facing "Network tab" project directory
//! (docs/20, docs/22).
//!
//! `GET /v1/projects` reads [`list`]; adminbot's `/install-project` manifest
//! drives per-Project entries via [`replace_for_project`]. Every entry is created
//! through a manifest install.
//!
//! An entry's `project_id` references the installed Project it belongs to and is
//! dropped by `ON DELETE CASCADE` when that Project is uninstalled. (The column
//! is nullable for historical unowned rows, but new rows always set it.)
//!
//! This table has NO did/account_id column — it is directory metadata only, so
//! the membership-opacity discipline (docs/03 §3.9) does not apply.

use sqlx::{Acquire, PgConnection, Row};

/// A directory row as served to clients (the `GET /v1/projects` shape).
pub struct DirectoryEntry {
    pub name: String,
    pub url: String,
    pub description: String,
    pub client_id: Option<String>,
    pub official: bool,
}

/// A manifest-driven entry to (re)write for a Project. Officialness and OAuth
/// client id are not accepted from this path (always non-official, no client
/// id) — see the module docs.
pub struct ProjectEntry {
    pub name: String,
    pub url: String,
    pub description: String,
}

/// Every directory entry, in display order. The OAuth `client_id` is *inherited*
/// from the owning Project (`projects.oauth_client_id`) via a join — the
/// authoritative registration lives on the Project entity (docs/25), not copied
/// onto each directory row. Unowned/seeded rows (`project_id IS NULL`) have none.
pub async fn list(conn: &mut PgConnection) -> Result<Vec<DirectoryEntry>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT d.name, d.url, d.description, p.oauth_client_id AS client_id, d.official
         FROM directory_entries d
         LEFT JOIN projects p ON p.id = d.project_id
         ORDER BY d.position, d.id",
    )
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| DirectoryEntry {
            name: r.get("name"),
            url: r.get("url"),
            description: r.get("description"),
            client_id: r.get("client_id"),
            official: r.get("official"),
        })
        .collect())
}

/// Replace the full set of directory entries for one Project (delete-then-insert
/// in a transaction). Entries are stored non-official with no client id and in
/// the given order.
pub async fn replace_for_project(
    conn: &mut PgConnection,
    project_id: i64,
    entries: &[ProjectEntry],
) -> Result<(), sqlx::Error> {
    let mut tx = conn.begin().await?;
    sqlx::query("DELETE FROM directory_entries WHERE project_id = $1")
        .bind(project_id)
        .execute(&mut *tx)
        .await?;
    for (i, e) in entries.iter().enumerate() {
        sqlx::query(
            "INSERT INTO directory_entries (project_id, name, url, description, position)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(project_id)
        .bind(&e.name)
        .bind(&e.url)
        .bind(&e.description)
        .bind(i as i32)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}
