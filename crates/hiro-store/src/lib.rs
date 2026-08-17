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
    /// Last refinement timestamp (`None` when never refined).
    pub refined_at: Option<i64>,
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
        // The database contains encrypted templates, audit events, and the
        // sealed keyring password. The parent directory is expected to be
        // root-only, but lock the file to 0600 as defence in depth so a
        // stray copy or a lax directory never exposes it.
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
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
                login_secret       BLOB,
                match_threshold    REAL,
                created_at         INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS templates (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_name  TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,
                model      TEXT NOT NULL,
                dim        INTEGER NOT NULL,
                ciphertext BLOB NOT NULL,
                quality    REAL,
                created_at INTEGER NOT NULL,
                refined_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS events (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        INTEGER NOT NULL,
                user_name TEXT,
                action    TEXT NOT NULL,
                detail    TEXT
            );

            CREATE TABLE IF NOT EXISTS boot_auth (
                boot_id      TEXT NOT NULL,
                user_name    TEXT NOT NULL,
                logged_in_at INTEGER NOT NULL,
                PRIMARY KEY (boot_id, user_name)
            );
            "#,
        )?;
        self.migrate()?;
        // Bounded audit retention: the events mirror is the daemon's
        // journal backup, and journald rotates the primary copy. Without a
        // prune, the table grows forever — a slow local disk-fill vector.
        // (The journal keeps the authoritative, longer-lived trail.)
        const AUDIT_RETENTION_DAYS: i64 = 365;
        let _ = self.conn.execute(
            "DELETE FROM events WHERE ts < unixepoch() - ?1",
            params![AUDIT_RETENTION_DAYS * 86_400],
        )?;
        Ok(())
    }

    /// Column-level migrations for stores created before a schema change.
    /// Kept additive and idempotent: each step only runs when the target
    /// column/table is missing.
    fn migrate(&self) -> Result<()> {
        let mut stmt = self
            .conn
            .prepare("PRAGMA table_info(users)")
            .map_err(StoreError::Db)?;
        let cols: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(StoreError::Db)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(StoreError::Db)?;
        if !cols.iter().any(|c| c == "login_secret") {
            self.conn
                .execute_batch("ALTER TABLE users ADD COLUMN login_secret BLOB")
                .map_err(StoreError::Db)?;
        }
        if !cols.iter().any(|c| c == "match_threshold") {
            self.conn
                .execute_batch("ALTER TABLE users ADD COLUMN match_threshold REAL")
                .map_err(StoreError::Db)?;
        }
        if !cols.iter().any(|c| c == "camera_secret") {
            self.conn
                .execute_batch("ALTER TABLE users ADD COLUMN camera_secret BLOB")
                .map_err(StoreError::Db)?;
        }
        let mut tstmt = self
            .conn
            .prepare("PRAGMA table_info(templates)")
            .map_err(StoreError::Db)?;
        let tcols: Vec<String> = tstmt
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(StoreError::Db)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(StoreError::Db)?;
        if !tcols.iter().any(|c| c == "refined_at") {
            self.conn
                .execute_batch("ALTER TABLE templates ADD COLUMN refined_at INTEGER")
                .map_err(StoreError::Db)?;
        }
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
            r#"SELECT id, user_name, model, dim, ciphertext, quality, created_at, refined_at
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
                refined_at: row.get(7)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Replace a template's ciphertext (adaptive template refinement) and
    /// stamp `refined_at`. The ciphertext must already be sealed for
    /// `user_name`. Returns `false` when the template no longer exists
    /// (e.g. removed mid-request).
    pub fn update_template(&self, user_name: &str, id: i64, ciphertext: &[u8]) -> Result<bool> {
        let changed = self.conn.execute(
            "UPDATE templates SET ciphertext = ?3, refined_at = unixepoch()
             WHERE id = ?1 AND user_name = ?2",
            params![id, user_name, ciphertext],
        )?;
        Ok(changed > 0)
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

    /// Persist the user's auto-calibrated per-user match threshold.
    pub fn set_match_threshold(&self, user_name: &str, threshold: f32) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE users SET match_threshold = ?1 WHERE name = ?2",
            params![threshold, user_name],
        )?;
        if changed == 0 {
            return Err(StoreError::UserNotFound(user_name.into()));
        }
        Ok(())
    }

    /// The user's auto-calibrated per-user match threshold, if one exists.
    pub fn match_threshold(&self, user_name: &str) -> Result<Option<f32>> {
        Ok(self
            .conn
            .query_row(
                "SELECT match_threshold FROM users WHERE name = ?1",
                params![user_name],
                |row| row.get::<_, Option<f32>>(0),
            )
            .optional()?
            .flatten())
    }

    /// Persist the per-user camera-pinning secret generated at enrollment
    /// (`None` removes it). Together with `camera_fingerprint` this marks
    /// the pinning record as genuine; verification fails closed unless both
    /// are present.
    pub fn set_camera_secret(&self, user_name: &str, secret: Option<&[u8]>) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE users SET camera_secret = ?1 WHERE name = ?2",
            params![secret, user_name],
        )?;
        if changed == 0 {
            return Err(StoreError::UserNotFound(user_name.into()));
        }
        Ok(())
    }

    /// Drop the per-user camera-pinning record (binding + secret). Used by
    /// `hiro clear` so removing all templates also clears the pin and
    /// re-enrollment starts fresh. A no-op for unknown users.
    pub fn clear_camera_binding(&self, user_name: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE users SET camera_fingerprint = NULL, camera_secret = NULL WHERE name = ?1",
            params![user_name],
        )?;
        Ok(())
    }

    /// The per-user camera-pinning secret, if one was recorded.
    pub fn camera_secret(&self, user_name: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn
            .query_row(
                "SELECT camera_secret FROM users WHERE name = ?1",
                params![user_name],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?
            .flatten())
    }

    /// Store the sealed login password for a user (`None` removes it).
    /// The value is always the AES-256-GCM ciphertext from a `KeyManager`,
    /// never a plaintext secret.
    pub fn set_login_secret(&self, user_name: &str, ciphertext: Option<&[u8]>) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE users SET login_secret = ?1 WHERE name = ?2",
            params![ciphertext, user_name],
        )?;
        if changed == 0 {
            return Err(StoreError::UserNotFound(user_name.into()));
        }
        Ok(())
    }

    /// Fetch the sealed login password ciphertext for a user.
    pub fn login_secret(&self, user_name: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn
            .query_row(
                "SELECT login_secret FROM users WHERE name = ?1",
                params![user_name],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?
            .flatten())
    }

    /// Drop the sealed login password for a user. Returns whether a stored
    /// secret was actually removed (false for users with no record).
    pub fn clear_login_secret(&self, user_name: &str) -> Result<bool> {
        let changed = self.conn.execute(
            "UPDATE users SET login_secret = NULL WHERE name = ?1",
            params![user_name],
        )?;
        Ok(changed > 0)
    }

    pub fn record_event(&self, user_name: Option<&str>, action: &str, detail: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO events (ts, user_name, action, detail) VALUES (unixepoch(), ?1, ?2, ?3)",
            params![user_name, action, detail],
        )?;
        Ok(())
    }

    /// Record that `user_name` logged in during the boot identified by
    /// `boot_id`, arming face authentication for them until the next boot.
    /// Idempotent: a second login in the same boot is a no-op.
    pub fn mark_boot_auth_user(&self, boot_id: &str, user_name: &str) -> Result<()> {
        self.conn.execute(
            r#"INSERT INTO boot_auth (boot_id, user_name, logged_in_at)
               VALUES (?1, ?2, unixepoch())
               ON CONFLICT(boot_id, user_name) DO NOTHING"#,
            params![boot_id, user_name],
        )?;
        Ok(())
    }

    /// Login names of the users who have logged in during `boot_id`.
    pub fn boot_auth_users(&self, boot_id: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT user_name FROM boot_auth WHERE boot_id = ?1 ORDER BY user_name")?;
        let rows = stmt.query_map(params![boot_id], |row| row.get::<_, String>(0))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Drop boot-auth records for every boot other than `boot_id`. Returns
    /// the number of stale rows removed.
    pub fn prune_boot_auth(&self, boot_id: &str) -> Result<usize> {
        let changed = self.conn.execute(
            "DELETE FROM boot_auth WHERE boot_id <> ?1",
            params![boot_id],
        )?;
        Ok(changed)
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
    fn camera_pin_secret_roundtrip_and_clear() {
        let s = store();
        s.upsert_user("alice", Some(1000)).unwrap();
        assert!(s.camera_secret("alice").unwrap().is_none());
        s.set_camera_fingerprint("alice", "13d3:56ea:uvcvideo:/sys/x").unwrap();
        s.set_camera_secret("alice", Some(&[7u8; 32])).unwrap();
        assert_eq!(s.camera_secret("alice").unwrap().unwrap(), vec![7u8; 32]);
        s.clear_camera_binding("alice").unwrap();
        assert!(s.camera_fingerprint("alice").unwrap().is_none());
        assert!(s.camera_secret("alice").unwrap().is_none());
        // Unknown users are a no-op.
        s.clear_camera_binding("nobody").unwrap();
    }

    #[test]
    fn match_threshold_lifecycle() {
        let s = store();
        s.upsert_user("alice", None).unwrap();
        assert!(s.match_threshold("alice").unwrap().is_none());
        s.set_match_threshold("alice", 0.62).unwrap();
        assert_eq!(s.match_threshold("alice").unwrap().unwrap(), 0.62);
        // Unknown user: setter errors, getter returns None.
        assert!(s.set_match_threshold("ghost", 0.5).is_err());
        assert!(s.match_threshold("ghost").unwrap().is_none());
    }

    #[test]
    fn login_secret_lifecycle() {
        let s = store();
        s.upsert_user("alice", Some(1000)).unwrap();
        assert!(s.login_secret("alice").unwrap().is_none());

        s.set_login_secret("alice", Some(b"nonce+ct".as_slice()))
            .unwrap();
        assert_eq!(s.login_secret("alice").unwrap().unwrap(), b"nonce+ct");

        s.clear_login_secret("alice").unwrap();
        assert!(s.login_secret("alice").unwrap().is_none());
        // Clearing again for an existing user still reports true (the row
        // matched); an unknown user reports false rather than erroring.
        assert!(s.clear_login_secret("alice").unwrap());
        assert!(!s.clear_login_secret("nobody").unwrap());
        assert!(matches!(
            s.set_login_secret("nobody", Some(b"x".as_slice())),
            Err(StoreError::UserNotFound(_))
        ));
    }

    #[test]
    fn migration_adds_login_secret_to_legacy_db() {
        // Simulate a pre-keyring store: create the schema without the
        // column, then reopen through the normal open path.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.db");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                r#"
                PRAGMA journal_mode = WAL;
                CREATE TABLE users (
                    name               TEXT PRIMARY KEY,
                    uid                INTEGER,
                    camera_fingerprint TEXT,
                    created_at         INTEGER NOT NULL
                );
                CREATE TABLE templates (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_name  TEXT NOT NULL,
                    model      TEXT NOT NULL,
                    dim        INTEGER NOT NULL,
                    ciphertext BLOB NOT NULL,
                    quality    REAL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE events (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts        INTEGER NOT NULL,
                    user_name TEXT,
                    action    TEXT NOT NULL,
                    detail    TEXT
                );
                "#,
            )
            .unwrap();
        }
        let s = Store::open(&path).unwrap();
        s.upsert_user("alice", None).unwrap();
        s.set_login_secret("alice", Some(b"ct".as_slice())).unwrap();
        assert_eq!(s.login_secret("alice").unwrap().unwrap(), b"ct");

        // The refined_at column migration must land on legacy schemas too.
        let id = s.add_template("alice", "m", 4, b"old", None).unwrap();
        assert!(s.list_templates("alice").unwrap()[0].refined_at.is_none());
        assert!(s.update_template("alice", id, b"new").unwrap());
        let row = &s.list_templates("alice").unwrap()[0];
        assert_eq!(row.ciphertext, b"new");
        assert!(row.refined_at.is_some());
    }

    #[test]
    fn update_template_stamps_refined_at() {
        let s = store();
        s.upsert_user("alice", Some(1000)).unwrap();
        let id = s
            .add_template("alice", "auraface", 512, b"cipher-bytes", Some(0.9))
            .unwrap();
        assert!(
            s.list_templates("alice").unwrap()[0].refined_at.is_none(),
            "a fresh template is never refined"
        );

        assert!(s.update_template("alice", id, b"refined").unwrap());
        let row = &s.list_templates("alice").unwrap()[0];
        assert_eq!(row.ciphertext, b"refined");
        assert!(row.refined_at.is_some(), "refinement stamps refined_at");

        // Wrong id or wrong user: no-op, and the stored blob is untouched.
        assert!(!s.update_template("alice", id + 1, b"x").unwrap());
        s.upsert_user("bob", None).unwrap();
        assert!(!s.update_template("bob", id, b"x").unwrap());
        assert_eq!(s.list_templates("alice").unwrap()[0].ciphertext, b"refined");
    }

    #[test]
    fn events_are_recorded() {
        let s = store();
        s.record_event(Some("alice"), "verify", "matched").unwrap();
        s.record_event(None, "startup", "").unwrap();
    }

    #[test]
    fn boot_auth_tracks_logins_per_boot() {
        let s = store();
        s.mark_boot_auth_user("boot-1", "alice").unwrap();
        s.mark_boot_auth_user("boot-1", "bob").unwrap();
        // Idempotent within a boot.
        s.mark_boot_auth_user("boot-1", "alice").unwrap();
        // A different boot is separate state.
        s.mark_boot_auth_user("boot-2", "carol").unwrap();

        let mut boot1 = s.boot_auth_users("boot-1").unwrap();
        boot1.sort();
        assert_eq!(boot1, vec!["alice", "bob"]);
        assert_eq!(s.boot_auth_users("boot-2").unwrap(), vec!["carol"]);
        assert!(s.boot_auth_users("boot-3").unwrap().is_empty());
    }

    #[test]
    fn prune_boot_auth_keeps_only_current_boot() {
        let s = store();
        s.mark_boot_auth_user("boot-old", "alice").unwrap();
        s.mark_boot_auth_user("boot-old", "bob").unwrap();
        s.mark_boot_auth_user("boot-now", "alice").unwrap();

        let removed = s.prune_boot_auth("boot-now").unwrap();
        assert_eq!(removed, 2);
        assert_eq!(s.boot_auth_users("boot-now").unwrap(), vec!["alice"]);
        assert!(s.boot_auth_users("boot-old").unwrap().is_empty());
    }

    #[test]
    fn boot_auth_is_isolated_from_users_table() {
        // Recording a login does not require a users row.
        let s = store();
        s.mark_boot_auth_user("boot-1", "ghost").unwrap();
        assert_eq!(s.boot_auth_users("boot-1").unwrap(), vec!["ghost"]);
    }

    #[test]
    fn foreign_key_enforcement() {
        let s = store();
        assert!(s.add_template("ghost", "m", 4, b"x", None).is_err());
    }
}
