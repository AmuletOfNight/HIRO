//! Shared daemon state.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::ops::{Deref, DerefMut};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use hiro_core::Config;
use hiro_face::FacePipeline;
use hiro_hw::quirks::QuirkDb;
use hiro_store::Store;
use hiro_tpm::KeyManager;

use crate::auth::{AuthError, AuthResult};
use crate::camera::CameraSession;
use crate::policy::{Caller, Policy};

/// Checks whether a plaintext password is the current login password for a
/// user. The production implementation consults `/etc/shadow` via
/// [`crate::passwd`]; tests inject a stub so the keyring release path can
/// be exercised without touching the real account database.
pub trait PasswordChecker: Send + Sync {
    fn check(&self, user: &str, password: &str) -> bool;
}

/// The real checker: `crypt(3)` against the shadow entry.
pub struct ShadowPasswordChecker;

impl PasswordChecker for ShadowPasswordChecker {
    fn check(&self, user: &str, password: &str) -> bool {
        crate::passwd::verify_password(user, password)
    }
}

/// Which users may use face auth since the current boot.
///
/// Mirrors `security.require_password_after_boot`: a user is only allowed
/// to authenticate (or enroll) once they have logged in during the current
/// boot. State is persisted in the store keyed by the kernel boot id, so
/// daemon restarts mid-boot keep the armed set.
pub struct BootAuth {
    pub boot_id: String,
    pub logged_in: HashSet<String>,
}

/// A request awaiting an explicit Allow/Disallow decision after a confident
/// face match (the action-approval gate).
pub struct PendingApproval {
    pub id: u64,
    pub user: String,
    pub service: String,
    /// Best match score observed before the prompt appeared.
    pub score: f32,
    /// `None` until the user (or their status indicator) decides via
    /// `Op::Approve`; then `Some(allow)`.
    pub decided: Option<bool>,
    /// Per-approval secret for secure-desktop (root-rendered) approvals.
    /// `Some` only when `approval.secure_desktop` is enabled: the daemon
    /// passes it to the root-owned `hiro-approve` dialog, and `Op::Approve`
    /// is only honoured when the caller is root *and* presents the secret.
    /// In-session approvals leave this `None` (the prompt itself lives in
    /// the user's session, so the decision is made by the session).
    pub secret: Option<String>,
    pub created: Instant,
}

/// Everything a request handler needs. Cheap to clone: the heavy pieces
/// live behind locks.
pub struct Daemon {
    pub cfg: RwLock<Config>,
    pub store: Mutex<Store>,
    pub km: Box<dyn KeyManager>,
    pub pipeline: RwLock<Box<dyn FacePipeline>>,
    pub camera: Arc<Mutex<CameraSession>>,
    pub policy: Mutex<Policy>,
    /// Verifies a candidate login password against the account (used for
    /// keyring unlock release).
    pub password_checker: Box<dyn PasswordChecker>,
    /// Subscribers to authentication state events (`Op::Watch`). Each
    /// watcher carries its SO_PEERCRED caller so broadcasts can be filtered
    /// to the caller's own user (privacy), and uses a bounded channel so a
    /// stalled watcher is dropped instead of growing the daemon's memory.
    pub watchers: Mutex<Vec<Watcher>>,
    /// Users who have logged in since the last reboot (after-reboot gate).
    pub boot_auth: Mutex<BootAuth>,
    /// Pending action approvals awaiting an Allow/Disallow decision, keyed
    /// by approval id (`Op::Approve`).
    pub approvals: Mutex<HashMap<u64, PendingApproval>>,
    pub config_path: Option<std::path::PathBuf>,
    pub started_at: std::time::Instant,
}

pub type SharedDaemon = Arc<Daemon>;

/// One `Op::Watch` subscriber: the caller identity (for per-user event
/// filtering) and its bounded event channel.
pub struct Watcher {
    pub caller: Caller,
    pub tx: SyncSender<String>,
}

/// A held camera session with automatic release on drop and per-user
/// budget accounting, so a single local user cannot monopolise the camera
/// (blocking every other user's face auth) by chaining long verify/enroll
/// requests.
///
/// Acquired via [`Daemon::camera_acquire`]; dropping the guard releases the
/// camera *and* records the hold duration against the caller's rolling
/// budget. `user` is `None` for the approval phase, which follows a real
/// face match and is exempt from the quota (denying a matched request
/// because a quota was already spent would be hostile to legitimate users).
pub struct CameraGuard<'a> {
    camera: std::sync::MutexGuard<'a, CameraSession>,
    daemon: &'a Daemon,
    user: Option<String>,
    started: Instant,
}

impl Deref for CameraGuard<'_> {
    type Target = CameraSession;
    fn deref(&self) -> &CameraSession {
        &self.camera
    }
}

impl DerefMut for CameraGuard<'_> {
    fn deref_mut(&mut self) -> &mut CameraSession {
        &mut self.camera
    }
}

impl Drop for CameraGuard<'_> {
    fn drop(&mut self) {
        self.camera.release();
        if let Some(user) = &self.user {
            if let Ok(mut policy) = self.daemon.policy.lock() {
                policy.record_camera_time(user, self.started.elapsed());
            }
        }
    }
}

/// How many pending events a watcher may buffer before it is considered
/// too slow and dropped. Scanning/enrollment broadcast a few events per
/// second; 64 comfortably covers the burst while bounding memory.
pub const WATCH_BUFFER: usize = 64;

/// Fill `buf` from the kernel CSPRNG. `/dev/urandom` is always available on
/// Linux; a failure is a system-level fault, and proceeding with zeros
/// would silently produce guessable approval ids, pin secrets, and
/// approval secrets — so it is a hard error (consistent with `hiro-tpm`).
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    let mut f = std::fs::File::open("/dev/urandom").expect("cannot open /dev/urandom");
    f.read_exact(&mut buf)
        .expect("cannot read from /dev/urandom");
    buf
}

/// A random 64-bit value (not guessable from a counter).
pub fn random_u64() -> u64 {
    u64::from_ne_bytes(random_bytes()).max(1)
}

/// A random approval id in `[1, 2^32)`.
///
/// The daemon broadcasts `approval_id` to the GNOME Shell indicator, which
/// parses JSON numbers as IEEE doubles — only integers below 2^53 are
/// exact there. A full 64-bit random id would be rounded by the extension
/// and echoed back wrong, breaking the approve round-trip. 32 random bits
/// are still unpredictable (no counter-based guessing) while remaining
/// exactly representable in JS.
pub fn random_approval_id() -> u64 {
    u64::from(u32::from_ne_bytes(random_bytes::<4>())).max(1)
}

/// A random per-approval secret for secure-console dialogs (32 hex chars).
pub fn random_secret() -> String {
    let mut s = String::with_capacity(32);
    for b in random_bytes::<16>() {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Broadcast a state event to all `Op::Watch` subscribers.
pub fn broadcast_state(daemon: &SharedDaemon, event: &hiro_core::proto::StateEvent) {
    let line = match serde_json::to_string(event) {
        Ok(mut l) => {
            l.push('\n');
            l
        }
        Err(e) => {
            log::error!("cannot serialize state event: {e}");
            return;
        }
    };
    let mut watchers = match daemon.watchers.lock() {
        Ok(w) => w,
        Err(_) => return,
    };
    watchers.retain(|w| {
        // Root watchers see every event; non-root watchers only see events
        // for their own user (plus user-less "idle" broadcasts). This stops
        // any local process from monitoring other users' auth activity.
        if !w.caller.is_root() {
            if let Some(user) = &event.user {
                if crate::lookup::uid_of(user) != Some(w.caller.uid) {
                    return true; // keep the watcher, skip this event
                }
            }
        }
        // Bounded channel: a watcher that stops reading is dropped rather
        // than growing the daemon's memory without bound.
        w.tx.try_send(line.clone()).is_ok()
    });
}

/// Overrides used by tests (mock camera, stub pipeline, temp storage).
pub struct DaemonOptions {
    pub camera_source: Option<Box<dyn hiro_hw::capture::VideoSource>>,
    pub pipeline: Option<Box<dyn FacePipeline>>,
    pub key_manager: Option<Box<dyn KeyManager>>,
    pub store: Option<Store>,
    pub config_path: Option<std::path::PathBuf>,
    pub password_checker: Option<Box<dyn PasswordChecker>>,
}

impl Daemon {
    pub fn build(cfg: Config, opts: DaemonOptions) -> Result<SharedDaemon, String> {
        let quirks = QuirkDb::load(None);
        let store = match opts.store {
            Some(s) => s,
            None => Store::open(&cfg.storage.db_path).map_err(|e| e.to_string())?,
        };
        let km = match opts.key_manager {
            Some(k) => k,
            None => hiro_tpm::load(&cfg.storage.key_path).map_err(|e| e.to_string())?,
        };
        let pipeline = match opts.pipeline {
            Some(p) => p,
            None => hiro_face::create(&cfg.recognition).map_err(|e| e.to_string())?,
        };
        let password_checker = opts
            .password_checker
            .unwrap_or_else(|| Box::new(ShadowPasswordChecker) as Box<dyn PasswordChecker>);
        let camera = Arc::new(Mutex::new(CameraSession::new(
            &cfg,
            quirks.clone(),
            opts.camera_source,
        )));
        let policy = Policy::new(cfg.security.clone());

        // Seed the after-reboot gate from the store: a fresh boot id prunes
        // every stale record (no user is armed), while a daemon restart
        // within the same boot keeps the users who already logged in.
        let boot_id = crate::boot::current_boot_id();
        store
            .prune_boot_auth(&boot_id)
            .map_err(|e| format!("cannot prune stale boot-auth records: {e}"))?;
        let logged_in = store
            .boot_auth_users(&boot_id)
            .map_err(|e| format!("cannot load boot-auth state: {e}"))?
            .into_iter()
            .collect::<HashSet<_>>();

        Ok(Arc::new(Daemon {
            cfg: RwLock::new(cfg),
            store: Mutex::new(store),
            km,
            pipeline: RwLock::new(pipeline),
            camera,
            policy: Mutex::new(policy),
            password_checker,
            watchers: Mutex::new(Vec::new()),
            boot_auth: Mutex::new(BootAuth { boot_id, logged_in }),
            approvals: Mutex::new(HashMap::new()),
            config_path: opts.config_path,
            started_at: std::time::Instant::now(),
        }))
    }

    /// Acquire the camera on behalf of `user`, enforcing the per-user
    /// rolling camera-time budget so a single account cannot hold the
    /// camera indefinitely and starve every other user's face auth.
    ///
    /// The returned [`CameraGuard`] releases the camera and records the
    /// hold duration on drop (including panic paths). Pass `user = None`
    /// to skip the budget (used by the action-approval phase, which runs
    /// only after a real face match for an authorized request).
    pub fn camera_acquire(&self, user: Option<&str>) -> AuthResult<CameraGuard<'_>> {
        if let Some(u) = user {
            let mut policy = self
                .policy
                .lock()
                .map_err(|_| AuthError::Internal("policy lock poisoned".into()))?;
            if !policy.camera_budget_check(u) {
                return Err(AuthError::RateLimited);
            }
        }
        let mut camera = self
            .camera
            .lock()
            .map_err(|_| AuthError::Internal("camera lock poisoned".into()))?;
        camera
            .acquire()
            .map_err(|e| AuthError::Camera(e.to_string()))?;
        Ok(CameraGuard {
            camera,
            daemon: self,
            user: user.map(str::to_string),
            started: Instant::now(),
        })
    }

    /// Reload the configuration file. Rebuilds the pipeline when the
    /// recognition section changed and updates policy parameters.
    pub fn reload(&self, path: &std::path::Path) -> Result<(), String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let new_cfg = Config::from_toml(&text).map_err(|e| e.to_string())?;

        {
            let mut cfg = self.cfg.write().map_err(|_| "cfg lock poisoned")?;
            let recognition_changed = cfg.recognition.model_dir != new_cfg.recognition.model_dir
                || cfg.recognition.detector != new_cfg.recognition.detector
                || cfg.recognition.embedder != new_cfg.recognition.embedder;
            if recognition_changed {
                let pipeline =
                    hiro_face::create(&new_cfg.recognition).map_err(|e| e.to_string())?;
                let mut slot = self
                    .pipeline
                    .write()
                    .map_err(|_| "pipeline lock poisoned")?;
                *slot = pipeline;
                log::info!("recognition pipeline rebuilt");
            }
            *cfg = new_cfg.clone();
        }
        self.policy
            .lock()
            .map_err(|_| "policy lock poisoned")?
            .update_cfg(new_cfg.security);
        log::info!("configuration reloaded");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_ids_are_js_safe() {
        // The GNOME Shell indicator parses approval_id as an IEEE double:
        // values at or above 2^53 are rounded and break the approve
        // round-trip. Approval ids must stay below that and never be 0.
        for _ in 0..1000 {
            let id = random_approval_id();
            assert!(id >= 1, "approval id must be positive: {id}");
            assert!(
                id < 1u64 << 53,
                "approval id must be exactly representable in JS: {id}"
            );
            assert!(id <= u64::from(u32::MAX), "approval id out of range: {id}");
        }
    }

    #[test]
    fn approval_ids_are_not_predictable() {
        // Two consecutive approvals should not share an id (overwhelmingly
        // likely for 32 random bits; flaky odds are ~1/2^32).
        let a = random_approval_id();
        let b = random_approval_id();
        assert_ne!(a, b);
    }
}
