use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{CoreError, Result};

/// How the IR emitter is activated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum EmitterMode {
    /// Try in-process UVC extension-unit control, fall back to
    /// `linux-enable-ir-emitter` if present.
    #[default]
    Auto,
    /// Only use the external `linux-enable-ir-emitter` tool.
    External,
    /// Never touch the emitter.
    Off,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DeviceConfig {
    /// Explicit device path, e.g. `/dev/video2`. Auto-detected when unset.
    pub path: Option<String>,
    /// Refuse to authenticate unless the selected device is IR-capable.
    pub require_ir: bool,
    pub emitter: EmitterMode,
    /// Keep the V4L2 stream open this many seconds after the last use,
    /// to serve rapid successive requests (lock, sudo, polkit) quickly.
    pub warm_stream_seconds: u64,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            path: None,
            require_ir: true,
            emitter: EmitterMode::Auto,
            warm_stream_seconds: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CameraConfig {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    /// FourCC as a 4-character string, e.g. "YUYV" or "GRAY8".
    pub pixel_format: String,
    /// Maximum frames captured per auth attempt before giving up. Bounded
    /// by `daemon.max_request_timeout_ms` too; this mainly sets how long a
    /// user has to satisfy the liveness gate (move slightly) before the
    /// attempt is judged.
    pub max_frames: u32,
}

impl Default for CameraConfig {
    fn default() -> Self {
        Self {
            width: 640,
            height: 480,
            fps: 30,
            pixel_format: "YUYV".into(),
            max_frames: 120,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RecognitionConfig {
    pub model_dir: PathBuf,
    pub detector: String,
    pub embedder: String,
    /// Cosine-similarity threshold; a frame scores a hit at or above this.
    pub match_threshold: f32,
    /// Number of independent frame hits required for a positive verdict.
    pub quorum_frames: u32,
    /// Give up a single auth attempt after this many milliseconds.
    pub frame_timeout_ms: u64,
    /// Anti-spoof gate: require temporal frame variance and landmark
    /// micro-motion before accepting a match.
    pub enable_liveness: bool,
    /// Minimum mean-abs-diff between consecutive frames (liveness).
    pub liveness_min_variance: f32,
    /// Minimum mean landmark displacement between consecutive detections,
    /// in normalized [0,1] coordinates (liveness).
    pub liveness_min_motion: f32,
    /// Minimum fraction of the frame a face must cover (enrollment).
    pub min_face_area: f32,
    /// Minimum Laplacian-variance sharpness (enrollment).
    pub min_sharpness: f32,
    /// Maximum cosine similarity for a new enrollment frame to count as
    /// distinct from already-stored templates.
    pub dedupe_threshold: f32,
}

impl Default for RecognitionConfig {
    fn default() -> Self {
        Self {
            model_dir: PathBuf::from("/usr/share/hiro/models"),
            detector: "scrfd".into(),
            embedder: "auraface".into(),
            match_threshold: 0.60,
            quorum_frames: 3,
            frame_timeout_ms: 3_000,
            enable_liveness: true,
            liveness_min_variance: 3.0,
            liveness_min_motion: 0.002,
            min_face_area: 0.02,
            min_sharpness: 5.0,
            dedupe_threshold: 0.55,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    pub rate_limit_attempts: u32,
    pub rate_limit_window_secs: u64,
    /// Cool-off period after too many consecutive failures.
    pub lockout_secs: u64,
    pub max_templates_per_user: usize,
    /// If false (default), verification refuses a camera whose identity
    /// differs from the one recorded at enrollment.
    pub allow_camera_change: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            rate_limit_attempts: 5,
            rate_limit_window_secs: 60,
            lockout_secs: 30,
            max_templates_per_user: 16,
            allow_camera_change: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    pub db_path: PathBuf,
    pub key_path: PathBuf,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            db_path: PathBuf::from("/var/lib/hiro/templates.db"),
            key_path: PathBuf::from("/var/lib/hiro/hiro.key"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DaemonConfig {
    pub socket_path: PathBuf,
    pub log_level: String,
    pub audit: bool,
    /// Daemon-side cap on per-request timeouts supplied by clients (ms),
    /// so PAM callers can never be blocked longer than this.
    pub max_request_timeout_ms: u64,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/run/hirod/hirod.sock"),
            log_level: "info".into(),
            audit: true,
            max_request_timeout_ms: 10_000,
        }
    }
}

/// Automatic login-keyring unlock on face authentication.
///
/// When enabled, the login password the user enrolled with `hiro keyring
/// set` is stored sealed (AES-256-GCM under the TPM-sealed data key) and,
/// on a verified face match, handed back to `pam_hiro.so` so it can be fed
/// to `pam_gnome_keyring.so` / `pam_kwallet.so` via `PAM_AUTHTK`. The
/// password is re-verified against the account before every release, so a
/// changed password can never break face login — it just leaves the keyring
/// locked until the user re-enrolls.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct KeyringConfig {
    /// Master switch. Defaults to off; this feature stores a credential
    /// that unlocks the user's keyring, so it must be opted into.
    pub enabled: bool,
    /// PAM services whose auth stacks end with a keyring module and should
    /// receive the injected authtok. Graphical greeters and session logins
    /// are the meaningful cases; `sudo`/`su`/polkit are not.
    pub services: Vec<String>,
}

impl Default for KeyringConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            services: vec![
                "gdm-password".into(),
                "sddm".into(),
                "lightdm".into(),
                "lightdm-greeter".into(),
                "login".into(),
                "tty".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub device: DeviceConfig,
    pub camera: CameraConfig,
    pub recognition: RecognitionConfig,
    pub security: SecurityConfig,
    pub storage: StorageConfig,
    pub daemon: DaemonConfig,
    pub keyring: KeyringConfig,
}

impl Config {
    /// Load configuration from a TOML string, filling in defaults for
    /// missing sections and validating values.
    pub fn from_toml(toml_text: &str) -> Result<Self> {
        let cfg: Config = toml::from_str(toml_text)
            .map_err(|e| CoreError::config(format!("failed to parse configuration: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.camera.width == 0 || self.camera.height == 0 {
            return Err(CoreError::config(
                "camera.width and camera.height must be non-zero",
            ));
        }
        if self.camera.fps == 0 {
            return Err(CoreError::config("camera.fps must be non-zero"));
        }
        if !(0.0..=1.0).contains(&self.recognition.match_threshold) {
            return Err(CoreError::config(
                "recognition.match_threshold must be within [0, 1]",
            ));
        }
        if self.recognition.quorum_frames == 0 {
            return Err(CoreError::config(
                "recognition.quorum_frames must be at least 1",
            ));
        }
        if self.security.rate_limit_attempts == 0 {
            return Err(CoreError::config(
                "security.rate_limit_attempts must be at least 1",
            ));
        }
        if !(0.0..=1.0).contains(&self.recognition.min_face_area) {
            return Err(CoreError::config(
                "recognition.min_face_area must be within [0, 1]",
            ));
        }
        if !(0.0..=1.0).contains(&self.recognition.dedupe_threshold) {
            return Err(CoreError::config(
                "recognition.dedupe_threshold must be within [0, 1]",
            ));
        }
        if self.camera.pixel_format.len() != 4 || !self.camera.pixel_format.is_ascii() {
            return Err(CoreError::config(
                "camera.pixel_format must be a 4-character FourCC such as YUYV or GRAY8",
            ));
        }
        if self.keyring.enabled && self.keyring.services.is_empty() {
            return Err(CoreError::config(
                "keyring.services must list at least one PAM service when keyring is enabled",
            ));
        }
        for svc in &self.keyring.services {
            if svc.trim().is_empty() {
                return Err(CoreError::config(
                    "keyring.services entries must not be empty",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn empty_toml_yields_defaults() {
        let cfg = Config::from_toml("").unwrap();
        assert_eq!(cfg.camera.width, 640);
        assert!(cfg.device.require_ir);
    }

    #[test]
    fn partial_toml_fills_defaults() {
        let cfg = Config::from_toml(
            r#"
            [camera]
            width = 320
            height = 240

            [recognition]
            model_dir = "/srv/hiro/models"
            match_threshold = 0.75
            "#,
        )
        .unwrap();
        assert_eq!(cfg.camera.width, 320);
        assert_eq!(cfg.camera.height, 240);
        assert_eq!(cfg.camera.fps, 30);
        assert_eq!(cfg.recognition.match_threshold, 0.75);
        assert_eq!(cfg.recognition.embedder, "auraface");
        assert_eq!(
            cfg.storage.db_path,
            PathBuf::from("/var/lib/hiro/templates.db")
        );
    }

    #[test]
    fn rejects_bad_threshold() {
        let err = Config::from_toml(
            r#"
            [recognition]
            match_threshold = 1.5
            "#,
        )
        .unwrap_err();
        assert!(err.message.contains("match_threshold"));
    }

    #[test]
    fn rejects_bad_fourcc() {
        let err = Config::from_toml(
            r#"
            [camera]
            pixel_format = "YUV"
            "#,
        )
        .unwrap_err();
        assert!(err.message.contains("FourCC"));
    }

    #[test]
    fn keyring_defaults_to_disabled() {
        let cfg = Config::default();
        assert!(!cfg.keyring.enabled);
        assert!(cfg.keyring.services.contains(&"gdm-password".to_string()));
        Config::default().validate().unwrap();
    }

    #[test]
    fn keyring_toml_roundtrip() {
        let cfg = Config::from_toml(
            r#"
            [keyring]
            enabled = true
            services = ["gdm-password", "sddm"]
            "#,
        )
        .unwrap();
        assert!(cfg.keyring.enabled);
        assert_eq!(cfg.keyring.services, vec!["gdm-password", "sddm"]);
    }

    #[test]
    fn keyring_enabled_requires_services() {
        let err = Config::from_toml(
            r#"
            [keyring]
            enabled = true
            services = []
            "#,
        )
        .unwrap_err();
        assert!(err.message.contains("keyring.services"), "{err}");
    }
}
