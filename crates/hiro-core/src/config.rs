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
    /// distinct from already-stored templates. Only frames *more* similar
    /// than this are rejected as duplicate poses, so this must be lenient:
    /// the same face at different angles typically scores 0.7–0.9
    /// similarity (even more on IR, where RGB-trained models see a domain
    /// gap). A low value like 0.55 rejects almost every frame unless the
    /// user makes extreme pose changes, making a full enrollment very slow.
    pub dedupe_threshold: f32,
    /// Minimum temporal frame variance an enrollment frame must show before
    /// it is accepted. Unlike `liveness_min_variance`, this is a quality
    /// gate for the enrollment path only: the default of `0.0` disables it
    /// so the user can hold a pose for a sharp capture instead of having to
    /// keep moving. The anti-spoof liveness gate still applies to
    /// verification, which is the surface that defends against photo/video
    /// replay. When set above zero, static frames are rejected before the
    /// face pipeline runs at all.
    pub enroll_min_variance: f32,
    /// Automatic per-user match-threshold calibration. When enabled,
    /// `hiro enroll` measures the user's genuine match scores in a short
    /// calibration pass and stores a per-user threshold; verification uses
    /// that threshold (falling back to `match_threshold` for users without
    /// a calibration), and each successful match slowly adapts it toward
    /// the observed score.
    pub auto_threshold: bool,
    /// How far below the measured genuine scores the calibrated per-user
    /// threshold sits.
    pub auto_threshold_margin: f32,
    /// Security floor for calibrated/adapted thresholds: never require less
    /// than this, no matter how low the measured scores are.
    pub auto_threshold_min: f32,
    /// Ceiling for calibrated/adapted thresholds: never require more than
    /// this, even if the user scores very high.
    pub auto_threshold_max: f32,
    /// Exponential-moving-average rate applied to the per-user threshold
    /// after each successful match (`0.0` disables adaptive tracking).
    /// Adaptation only ever happens on success, never on failure.
    pub auto_threshold_adapt: f32,
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
            dedupe_threshold: 0.85,
            enroll_min_variance: 0.0,
            auto_threshold: true,
            auto_threshold_margin: 0.05,
            auto_threshold_min: 0.50,
            auto_threshold_max: 0.90,
            auto_threshold_adapt: 0.02,
        }
    }
}

/// Action-approval gate: after a confident face match for a *non-login*
/// service (sudo, su, polkit, lock screen, ...), pause for an explicit
/// Allow/Disallow decision before the request is granted. Login-screen
/// services (the greeter / session logins) and the `hiro test` self-check
/// bypass the prompt because the user is triggering those themselves.
///
/// The prompt is shown by the in-session status indicator (GNOME Shell
/// extension) unless `secure_desktop` is enabled, in which case the
/// `hiro-approve` helper renders it on a dedicated VT ("secure console").
///
/// On by default: an app asking for sudo should not silently run just
/// because the camera recognized the user's face — the user must confirm.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ApprovalConfig {
    /// Master switch for the approval gate (on by default).
    pub enabled: bool,
    /// PAM services that skip the approval prompt because the user is
    /// initiating the request themselves: graphical greeters / session
    /// logins, and the `hiro test` self-check. Every other service requires
    /// approval after a confident match.
    pub bypass_services: Vec<String>,
    /// How long the user has to press Allow after the face meets the match
    /// threshold. The prompt — and the ability to approve — disappears when
    /// this expires. (It also hides while the user is detected as absent,
    /// but reappears if they step back into the frame; see
    /// `absent_score_margin` / `absent_frames`.)
    pub timeout_ms: u64,
    /// How far below the effective match threshold the live score must fall
    /// (for `absent_frames` consecutive frames) before the user is treated
    /// as absent: the Allow/Deny buttons disappear, but the request keeps
    /// waiting until `timeout_ms` before it is denied, so the user can
    /// step back into the frame and still decide.
    pub absent_score_margin: f32,
    /// Consecutive frames with no convincing face (no detection, or a score
    /// below `absent_score_margin` under the match threshold) before the
    /// prompt is hidden. Roughly one second at 30 fps with the default.
    /// Unlike the timeout this never fails the request on its own.
    pub absent_frames: u32,
    /// Show the Allow/Disallow prompt on a dedicated VT ("secure desktop")
    /// via `hiro-approve` instead of the in-session status indicator. Off
    /// by default. Requires the daemon to run as root (VT/console ioctls).
    pub secure_desktop: bool,
    /// VT number the secure-desktop dialog switches to when
    /// `secure_desktop` is enabled.
    pub secure_vt: u32,
    /// Path to the secure-desktop dialog helper (`hiro-approve`).
    pub secure_dialog: PathBuf,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bypass_services: vec![
                "gdm-password".into(),
                "sddm".into(),
                "lightdm".into(),
                "lightdm-greeter".into(),
                "login".into(),
                "tty".into(),
                "hiro-test".into(),
            ],
            timeout_ms: 5_000,
            absent_score_margin: 0.10,
            absent_frames: 30,
            secure_desktop: false,
            secure_vt: 8,
            secure_dialog: PathBuf::from("/usr/lib/hiro/hiro-approve"),
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
    /// Require a successful login after every reboot before face
    /// authentication is allowed for a user. Until the user logs in
    /// (password or equivalent) during a boot, `hirod` refuses to verify or
    /// enroll them, mirroring Windows Hello / macOS Touch ID behaviour. The
    /// login is recorded by `pam_hiro.so`'s session hook; state is
    /// persisted keyed by kernel boot id so daemon restarts (suspend/
    /// resume, crashes) do not reset it mid-boot.
    pub require_password_after_boot: bool,
    /// Rolling per-user camera-time budget (seconds). The daemon enforces
    /// that a single user holds the camera for at most this much time per
    /// `camera_budget_window_secs`, so one account cannot monopolise the
    /// global camera and block every other user's face auth. Zero disables
    /// the budget.
    pub camera_budget_secs: u64,
    /// The rolling window over which `camera_budget_secs` is enforced.
    /// Zero disables the budget.
    pub camera_budget_window_secs: u64,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            rate_limit_attempts: 5,
            rate_limit_window_secs: 60,
            lockout_secs: 30,
            max_templates_per_user: 16,
            allow_camera_change: false,
            require_password_after_boot: true,
            // 15 camera-seconds per minute per user: generous for genuine
            // use (a normal verify is a few seconds), tight enough that a
            // single attacker cannot hold the camera most of the time.
            camera_budget_secs: 15,
            camera_budget_window_secs: 60,
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

/// How the desktop-agnostic fallback UI (`hiro-ui`) decides whether to
/// render the in-session indicator / approval prompts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UiMode {
    /// Render unless running on GNOME with the `hiro-status@hiro` Shell
    /// extension enabled (which owns the UI there).
    #[default]
    Auto,
    /// Always render, ignoring desktop/extension detection.
    On,
    /// Never render (rely on the GNOME extension, the secure console, or
    /// no UI at all).
    Off,
}

/// Session UI configuration for the desktop-agnostic `hiro-ui` fallback.
///
/// The GNOME Shell extension remains the first-class UI; `hiro-ui` covers
/// every other desktop (and GNOME sessions without the extension enabled).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UiConfig {
    pub active: UiMode,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            active: UiMode::Auto,
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
    pub approval: ApprovalConfig,
    pub ui: UiConfig,
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
        if !(0.0..=255.0).contains(&self.recognition.enroll_min_variance) {
            return Err(CoreError::config(
                "recognition.enroll_min_variance must be within [0, 255]",
            ));
        }
        if !(0.0..=1.0).contains(&self.recognition.auto_threshold_margin) {
            return Err(CoreError::config(
                "recognition.auto_threshold_margin must be within [0, 1]",
            ));
        }
        if !(0.0..=1.0).contains(&self.recognition.auto_threshold_min) {
            return Err(CoreError::config(
                "recognition.auto_threshold_min must be within [0, 1]",
            ));
        }
        if !(0.0..=1.0).contains(&self.recognition.auto_threshold_max) {
            return Err(CoreError::config(
                "recognition.auto_threshold_max must be within [0, 1]",
            ));
        }
        if self.recognition.auto_threshold_min > self.recognition.auto_threshold_max {
            return Err(CoreError::config(
                "recognition.auto_threshold_min must not exceed auto_threshold_max",
            ));
        }
        if !(0.0..=1.0).contains(&self.recognition.auto_threshold_adapt) {
            return Err(CoreError::config(
                "recognition.auto_threshold_adapt must be within [0, 1]",
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
        for svc in &self.approval.bypass_services {
            if svc.trim().is_empty() {
                return Err(CoreError::config(
                    "approval.bypass_services entries must not be empty",
                ));
            }
        }
        if self.approval.timeout_ms == 0 {
            return Err(CoreError::config("approval.timeout_ms must be at least 1"));
        }
        if !(0.0..=1.0).contains(&self.approval.absent_score_margin) {
            return Err(CoreError::config(
                "approval.absent_score_margin must be within [0, 1]",
            ));
        }
        if self.approval.absent_frames == 0 {
            return Err(CoreError::config(
                "approval.absent_frames must be at least 1",
            ));
        }
        if self.approval.secure_vt == 0 {
            return Err(CoreError::config("approval.secure_vt must be at least 1"));
        }
        if self.approval.secure_dialog.as_os_str().is_empty() {
            return Err(CoreError::config(
                "approval.secure_dialog must not be empty",
            ));
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
    fn enrollment_dedupe_default_is_lenient() {
        // The dedupe gate only rejects frames *more* similar than this, so
        // the default must sit above the 0.6–0.9 similarity a real face
        // shows across modest pose changes; otherwise every frame is a
        // "duplicate pose" and enrollment never completes.
        assert!(
            Config::default().recognition.dedupe_threshold >= 0.8,
            "dedupe_threshold must be lenient enough for small head turns"
        );
        assert!(Config::default().recognition.dedupe_threshold <= 1.0);
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
    fn after_reboot_password_gate_defaults_to_on() {
        assert!(Config::default().security.require_password_after_boot);
        let cfg = Config::from_toml("[security]\nrequire_password_after_boot = false").unwrap();
        assert!(!cfg.security.require_password_after_boot);
    }

    #[test]
    fn auto_threshold_defaults() {
        let cfg = Config::default();
        assert!(cfg.recognition.auto_threshold);
        assert_eq!(cfg.recognition.auto_threshold_margin, 0.05);
        assert_eq!(cfg.recognition.auto_threshold_min, 0.50);
        assert_eq!(cfg.recognition.auto_threshold_max, 0.90);
        assert_eq!(cfg.recognition.auto_threshold_adapt, 0.02);
        Config::default().validate().unwrap();
    }

    #[test]
    fn auto_threshold_bounds_must_allow_a_range() {
        let err = Config::from_toml(
            "[recognition]\nauto_threshold_min = 0.95\nauto_threshold_max = 0.50",
        )
        .unwrap_err();
        assert!(err.message.contains("auto_threshold_min"), "{err}");
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

    #[test]
    fn approval_defaults() {
        let cfg = Config::default();
        assert!(cfg.approval.enabled, "approval gate must be on by default");
        assert!(
            cfg.approval
                .bypass_services
                .contains(&"gdm-password".to_string()),
            "login screens must bypass approval by default"
        );
        assert!(
            cfg.approval
                .bypass_services
                .contains(&"hiro-test".to_string()),
            "`hiro test` must bypass approval by default (no status UI)"
        );
        assert!(!cfg.approval.secure_desktop, "secure desktop is opt-in");
        assert_eq!(cfg.approval.secure_vt, 8);
        assert_eq!(
            cfg.approval.absent_frames, 30,
            "walk-away detection must be debounced (~1s at 30fps), not 4 frames"
        );
        assert_eq!(cfg.approval.absent_score_margin, 0.10);
        Config::default().validate().unwrap();
    }

    #[test]
    fn approval_absent_fields_roundtrip() {
        let cfg = Config::from_toml(
            r#"
            [approval]
            absent_frames = 60
            absent_score_margin = 0.05
            "#,
        )
        .unwrap();
        assert_eq!(cfg.approval.absent_frames, 60);
        assert_eq!(cfg.approval.absent_score_margin, 0.05);
    }

    #[test]
    fn approval_rejects_zero_absent_frames() {
        let err = Config::from_toml("[approval]\nabsent_frames = 0").unwrap_err();
        assert!(err.message.contains("approval.absent_frames"), "{err}");
    }

    #[test]
    fn approval_secure_desktop_toml_roundtrip() {
        let cfg = Config::from_toml(
            r#"
            [approval]
            secure_desktop = true
            secure_vt = 9
            "#,
        )
        .unwrap();
        assert!(cfg.approval.secure_desktop);
        assert_eq!(cfg.approval.secure_vt, 9);
        assert!(cfg.approval.enabled, "master switch stays on");
    }

    #[test]
    fn approval_rejects_zero_timeout() {
        let err = Config::from_toml("[approval]\ntimeout_ms = 0").unwrap_err();
        assert!(err.message.contains("approval.timeout_ms"), "{err}");
    }

    #[test]
    fn ui_defaults_to_auto() {
        let cfg = Config::default();
        assert_eq!(cfg.ui.active, UiMode::Auto);
        let cfg = Config::from_toml("").unwrap();
        assert_eq!(cfg.ui.active, UiMode::Auto);
    }

    #[test]
    fn ui_mode_roundtrip() {
        let cfg = Config::from_toml("[ui]\nactive = \"off\"").unwrap();
        assert_eq!(cfg.ui.active, UiMode::Off);
        let cfg = Config::from_toml("[ui]\nactive = \"on\"").unwrap();
        assert_eq!(cfg.ui.active, UiMode::On);
    }

    #[test]
    fn ui_rejects_unknown_mode() {
        let err = Config::from_toml("[ui]\nactive = \"sometimes\"").unwrap_err();
        assert!(err.message.contains("active"), "{err}");
    }
}
