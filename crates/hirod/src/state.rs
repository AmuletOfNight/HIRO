//! Shared daemon state.

use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, RwLock};

use hiro_core::Config;
use hiro_face::FacePipeline;
use hiro_hw::quirks::QuirkDb;
use hiro_store::Store;
use hiro_tpm::KeyManager;

use crate::camera::CameraSession;
use crate::policy::Policy;

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
    /// Subscribers to authentication state events (`Op::Watch`).
    pub watchers: Mutex<Vec<Sender<String>>>,
    pub config_path: Option<std::path::PathBuf>,
    pub started_at: std::time::Instant,
}

pub type SharedDaemon = Arc<Daemon>;

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
    watchers.retain(|tx| tx.send(line.clone()).is_ok());
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
        Ok(Arc::new(Daemon {
            cfg: RwLock::new(cfg),
            store: Mutex::new(store),
            km,
            pipeline: RwLock::new(pipeline),
            camera,
            policy: Mutex::new(policy),
            password_checker,
            watchers: Mutex::new(Vec::new()),
            config_path: opts.config_path,
            started_at: std::time::Instant::now(),
        }))
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
