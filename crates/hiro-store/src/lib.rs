//! SQLite-backed template store.
//!
//! The store persists *encrypted* embedding blobs only: encryption and
//! decryption are the caller's responsibility (see `hiro-tpm`). Nothing
//! sensitive is ever written in plaintext.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("database path has no parent directory: {0}")]
    NoParent(String),
    #[error("user not found: {0}")]
    UserNotFound(String),
    #[error("template not found: {0}")]
    TemplateNotFound(i64),
}

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug, Clone)]
pub struct UserRecord {
    pub name: String,
    pub uid: Option<i64>,
    pub camera_fingerprint: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct TemplateRecord {
    pub id: i64,
    pub user_name: String,
    pub model: String,
    pub dim: usize,
    /// Ciphertext: nonce (12 bytes) || AES-GCM ciphertext.
    pub ciphertext: Vec<u8>,
    pub quality: Option<f32>,
    pub created_at: i64,
}

pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (creating if needed) the store at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                StoreError::NoParent(format!("cannot create {}: {e}", parent.display()))
            })?;
        }
        let conn = Connection::open(path)?;
        let store = Self { conn };
        store.init()?;
        Ok(store)
    }

    /// In-memory store, for tests and ephemeral daemons.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.init()?;
        Ok(store)
    }

    fn init(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS users (
                name               TEXT PRIMARY KEY,
                uid                INTEGER,
                camera_fingerprint TEXT,
                created_at         INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS templates (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_name  TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,
                model      TEXT NOT NULL,
                dim        INTEGER NOT NULL,
                ciphertext BLOB NOT NULL,
                quality    REAL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS events (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        INTEGER NOT NULL,
                user_name TEXT,
                action    TEXT NOT NULL,
                detail    TEXT
            );
            "#,
        )?;
        Ok(())
    }

    pub fn upsert_user(&self, name: &str, uid: Option<i64>) -> Result<()> {
        self.conn.execute(
            r#"INSERT INTO users (name, uid, created_at)
               VALUES (?1, ?2, unixepoch())
               ON CONFLICT(name) DO UPDATE SET uid = excluded.uid"#,
            params![name, uid],
        )?;
        Ok(())
    }

    pub fn get_user(&self, name: &str) -> Result<Option<UserRecord>> {
        Ok(self
            .conn
            .query_row(
                "SELECT name, uid, camera_fingerprint, created_at FROM users WHERE name = ?1",
                params![name],
                |row| {
                    Ok(UserRecord {
                        name: row.get(0)?,
                        uid: row.get(1)?,
                        camera_fingerprint: row.get(2)?,
                        created_at: row.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn list_users(&self) -> Result<Vec<UserRecord>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, uid, camera_fingerprint, created_at FROM users ORDER BY name")?;
        let rows = stmt.query_map([], |row| {
            Ok(UserRecord {
                name: row.get(0)?,
                uid: row.get(1)?,
                camera_fingerprint: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn add_template(
        &self,
        user_name: &str,
        model: &str,
        dim: usize,
        ciphertext: &[u8],
        quality: Option<f32>,
    ) -> Result<i64> {
        let id = self.conn.query_row(
            r#"INSERT INTO templates (user_name, model, dim, ciphertext, quality, created_at)
               VALUES (?1, ?2, ?3, ?4, ?5, unixepoch())
               RETURNING id"#,
            params![user_name, model, dim as i64, ciphertext, quality],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(id)
    }

    pub fn list_templates(&self, user_name: &str) -> Result<Vec<TemplateRecord>> {
        let mut stmt = self.conn.prepare(
            r#"SELECT id, user_name, model, dim, ciphertext, quality, created_at
               FROM templates WHERE user_name = ?1 ORDER BY id"#,
        )?;
        let rows = stmt.query_map(params![user_name], |row| {
            Ok(TemplateRecord {
                id: row.get(0)?,
                user_name: row.get(1)?,
                model: row.get(2)?,
                dim: row.get::<_, i64>(3)? as usize,
                ciphertext: row.get(4)?,
                quality: row.get(5)?,
                created_at: row.get(6)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn remove_template(&self, user_name: &str, id: i64) -> Result<bool> {
        let changed = self.conn.execute(
            "DELETE FROM templates WHERE id = ?1 AND user_name = ?2",
            params![id, user_name],
        )?;
        if changed == 0 {
            return Err(StoreError::TemplateNotFound(id));
        }
        Ok(true)
    }

    pub fn clear_templates(&self, user_name: &str) -> Result<usize> {
        let changed = self.conn.execute(
            "DELETE FROM templates WHERE user_name = ?1",
            params![user_name],
        )?;
        Ok(changed)
    }

    pub fn count_templates(&self, user_name: &str) -> Result<usize> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM templates WHERE user_name = ?1",
            params![user_name],
            |row| row.get::<_, i64>(0),
        )? as usize)
    }

    pub fn total_templates(&self) -> Result<usize> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM templates", [], |row| {
                row.get::<_, i64>(0)
            })? as usize)
    }

    pub fn set_camera_fingerprint(&self, user_name: &str, fingerprint: &str) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE users SET camera_fingerprint = ?1 WHERE name = ?2",
            params![fingerprint, user_name],
        )?;
        if changed == 0 {
            return Err(StoreError::UserNotFound(user_name.into()));
        }
        Ok(())
    }

    pub fn camera_fingerprint(&self, user_name: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT camera_fingerprint FROM users WHERE name = ?1",
                params![user_name],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten())
    }

    pub fn record_event(&self, user_name: Option<&str>, action: &str, detail: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO events (ts, user_name, action, detail) VALUES (unixepoch(), ?1, ?2, ?3)",
            params![user_name, action, detail],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        Store::open_in_memory().unwrap()
    }

    #[test]
    fn user_upsert_and_get() {
        let s = store();
        s.upsert_user("alice", Some(1000)).unwrap();
        let u = s.get_user("alice").unwrap().unwrap();
        assert_eq!(u.uid, Some(1000));
        s.upsert_user("alice", Some(1001)).unwrap();
        let u = s.get_user("alice").unwrap().unwrap();
        assert_eq!(u.uid, Some(1001));
        assert!(s.get_user("bob").unwrap().is_none());
    }

    #[test]
    fn template_lifecycle() {
        let s = store();
        s.upsert_user("alice", Some(1000)).unwrap();
        let id = s
            .add_template("alice", "auraface", 512, b"cipher-bytes", Some(0.9))
            .unwrap();
        assert_eq!(s.count_templates("alice").unwrap(), 1);

        let tpls = s.list_templates("alice").unwrap();
        assert_eq!(tpls.len(), 1);
        assert_eq!(tpls[0].id, id);
        assert_eq!(tpls[0].dim, 512);
        assert_eq!(tpls[0].ciphertext, b"cipher-bytes");
        assert!((tpls[0].quality.unwrap() - 0.9).abs() < 1e-6);

        assert!(s.remove_template("alice", id).unwrap());
        assert!(matches!(
            s.remove_template("alice", id),
            Err(StoreError::TemplateNotFound(_))
        ));
        assert_eq!(s.count_templates("alice").unwrap(), 0);
    }

    #[test]
    fn clear_removes_only_target_user() {
        let s = store();
        s.upsert_user("alice", None).unwrap();
        s.upsert_user("bob", None).unwrap();
        s.add_template("alice", "m", 4, b"a1", None).unwrap();
        s.add_template("alice", "m", 4, b"a2", None).unwrap();
        s.add_template("bob", "m", 4, b"b1", None).unwrap();

        assert_eq!(s.clear_templates("alice").unwrap(), 2);
        assert_eq!(s.count_templates("bob").unwrap(), 1);
        assert_eq!(s.total_templates().unwrap(), 1);
    }

    #[test]
    fn camera_fingerprint_roundtrip() {
        let s = store();
        s.upsert_user("alice", None).unwrap();
        assert!(s.camera_fingerprint("alice").unwrap().is_none());
        s.set_camera_fingerprint("alice", "13d3:56ea:usb-x:?")
            .unwrap();
        assert_eq!(
            s.camera_fingerprint("alice").unwrap().unwrap(),
            "13d3:56ea:usb-x:?"
        );
    }

    #[test]
    fn events_are_recorded() {
        let s = store();
        s.record_event(Some("alice"), "verify", "matched").unwrap();
        s.record_event(None, "startup", "").unwrap();
    }

    #[test]
    fn foreign_key_enforcement() {
        let s = store();
        assert!(s.add_template("ghost", "m", 4, b"x", None).is_err());
    }
}
