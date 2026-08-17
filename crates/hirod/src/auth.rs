//! Authentication and enrollment flows.

use std::path::Path;
use std::time::{Duration, Instant};

use hiro_core::proto::{EnrollResult, QualityReport, StateEvent, VerifyResult};
use hiro_core::{constant_time_match, Config, Embedding};
use hiro_face::FacePipeline;
use hiro_hw::frame as hwframe;
use zeroize::Zeroizing;

use crate::audit::audit;
use crate::camera::CameraSession;
use crate::liveness::{MotionTracker, VarianceTracker};
use crate::policy::{authorize, Caller, PolicyVerdict};
use crate::state::SharedDaemon;

#[derive(Debug, Clone)]
pub enum AuthError {
    NoSuchUser(String),
    Denied(String),
    RateLimited,
    LockedOut,
    Camera(String),
    Internal(String),
}

impl AuthError {
    /// Stable, machine-readable reason code for this error. Used for
    /// verdicts and state-event broadcasts so client-influenced strings
    /// (usernames, service names) can never alter the reported reason.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::NoSuchUser(_) => "no_such_user",
            Self::Denied(_) => "denied",
            Self::RateLimited => "rate_limited",
            Self::LockedOut => "locked_out",
            Self::Camera(_) => "camera_unavailable",
            Self::Internal(_) => "error",
        }
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSuchUser(u) => write!(f, "no such user: {u}"),
            Self::Denied(m) => write!(f, "denied: {m}"),
            Self::RateLimited => write!(f, "rate limited"),
            Self::LockedOut => write!(f, "locked out after repeated failures"),
            Self::Camera(m) => write!(f, "camera: {m}"),
            Self::Internal(m) => write!(f, "internal error: {m}"),
        }
    }
}

pub type AuthResult<T> = std::result::Result<T, AuthError>;

/// Monotonic sequence for `hiro-approve` transient unit names, so a
/// re-spawned dialog (the user stepped away and came back) never collides
/// with a still-shutting-down instance.
static DIALOG_SPAWN_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn target_uid(user: &str) -> AuthResult<u32> {
    crate::lookup::uid_of(user).ok_or_else(|| AuthError::NoSuchUser(user.into()))
}

/// The camera-pinning binding recorded at enrollment and re-checked at
/// verification: USB identity fingerprint, kernel driver, and the canonical
/// sysfs device path.
///
/// `vid:pid:bus:serial` alone is spoofable in USB descriptors, and most UVC
/// cameras report no serial. Binding to the kernel's device node path and
/// driver (which USB descriptors cannot influence) plus a per-user random
/// secret stored at enrollment makes a swapped-in camera fail verification
/// unless it lands on the exact same node topology *and* the stored pinning
/// record (with its secret) is present and untouched.
fn camera_binding(camera: &CameraSession) -> String {
    let fp = camera
        .identity()
        .map(|i| i.fingerprint())
        .unwrap_or_else(|| "unknown".into());
    let driver = camera.driver().unwrap_or_else(|| "?".into());
    let sysfs = camera
        .camera_path()
        .and_then(|p| hiro_hw::discover::sysfs_device_path(Path::new(&p)))
        .unwrap_or_else(|| "?".into());
    format!("{fp}|{driver}|{sysfs}")
}

struct LoadedTemplate {
    id: i64,
    embedding: Embedding,
}

fn load_templates(daemon: &SharedDaemon, user: &str) -> AuthResult<Vec<LoadedTemplate>> {
    let store = daemon
        .store
        .lock()
        .map_err(|_| AuthError::Internal("store lock poisoned".into()))?;
    let rows = store
        .list_templates(user)
        .map_err(|e| AuthError::Internal(format!("template lookup failed: {e}")))?;
    let mut out = Vec::new();
    for row in rows {
        // Decrypt bound to the owning user so a ciphertext copied from
        // another account's row (template substitution) fails to unseal.
        let plain = daemon
            .km
            .unseal(user.as_bytes(), &row.ciphertext)
            .map_err(|e| AuthError::Internal(format!("template decryption failed: {e}")))?;
        match Embedding::from_bytes(&row.model, row.dim, &plain) {
            Some(emb) => out.push(LoadedTemplate {
                id: row.id,
                embedding: emb,
            }),
            None => log::warn!("template {} for {user} has bad shape; skipped", row.id),
        }
    }
    Ok(out)
}

/// Consult policy before announcing a scan. Rate limiting and lockout are
/// handled here so the UI can show the reason immediately instead of
/// pretending a scan is about to happen.
fn policy_gate(daemon: &SharedDaemon, user: &str) -> AuthResult<()> {
    let mut policy = daemon
        .policy
        .lock()
        .map_err(|_| AuthError::Internal("policy lock poisoned".into()))?;
    match policy.check(user) {
        PolicyVerdict::Allow => Ok(()),
        PolicyVerdict::RateLimited => Err(AuthError::RateLimited),
        PolicyVerdict::LockedOut => Err(AuthError::LockedOut),
    }
}

/// Whether the after-reboot password gate currently refuses `user`: true
/// when `security.require_password_after_boot` is on and no login has been
/// recorded for `user` during the current boot.
fn boot_gate_blocks(daemon: &SharedDaemon, user: &str) -> AuthResult<bool> {
    let requires = {
        let cfg = daemon
            .cfg
            .read()
            .map_err(|_| AuthError::Internal("cfg lock poisoned".into()))?;
        cfg.security.require_password_after_boot
    };
    if !requires {
        return Ok(false);
    }
    let boot = daemon
        .boot_auth
        .lock()
        .map_err(|_| AuthError::Internal("boot auth lock poisoned".into()))?;
    Ok(!boot.logged_in.contains(user))
}

/// Record that `user` logged in during the current boot, arming face auth
/// for them until the next reboot.
///
/// Called by `pam_hiro.so`'s session hook (via `Op::Login`) after the PAM
/// auth stack succeeded — i.e. the user authenticated to the account, which
/// for the first login of a boot is necessarily not face auth. Idempotent;
/// the state is persisted keyed by the kernel boot id so daemon restarts
/// mid-boot keep it.
pub fn record_login(
    daemon: &SharedDaemon,
    caller: Caller,
    user: &str,
    service: &str,
) -> AuthResult<()> {
    // The account must exist (unknown users are rejected even by root).
    let _uid = target_uid(user)?;
    // Root-only: greeter/login PAM session stacks run as root, and arming
    // face auth for a boot must be tied to an actual PAM session open —
    // not to any same-uid process claiming a login. Before this gate, any
    // process running as the user could arm their own face auth without a
    // password, silently defeating the after-reboot password gate.
    if !caller.is_root() {
        return Err(AuthError::Denied(format!(
            "caller uid {} may not record a login for {user}: \
             only root (the PAM session hook) may arm face auth",
            caller.uid
        )));
    }
    let mut boot = daemon
        .boot_auth
        .lock()
        .map_err(|_| AuthError::Internal("boot auth lock poisoned".into()))?;
    if boot.logged_in.insert(user.to_string()) {
        let store = daemon
            .store
            .lock()
            .map_err(|_| AuthError::Internal("store lock poisoned".into()))?;
        store
            .mark_boot_auth_user(&boot.boot_id, user)
            .map_err(|e| AuthError::Internal(format!("cannot persist login state: {e}")))?;
        audit(
            &store,
            Some(user),
            "login",
            &format!("service={service} boot={} caller_uid={}", boot.boot_id, caller.uid),
        );
    }
    Ok(())
}

/// The match threshold applied to `user`'s verifications: the user's
/// auto-calibrated per-user value when automatic calibration is enabled and
/// one exists, otherwise the global `recognition.match_threshold`.
fn effective_threshold(daemon: &SharedDaemon, user: &str) -> AuthResult<f32> {
    let cfg = daemon
        .cfg
        .read()
        .map_err(|_| AuthError::Internal("cfg lock poisoned".into()))?
        .clone();
    if !cfg.recognition.auto_threshold {
        return Ok(cfg.recognition.match_threshold);
    }
    let store = daemon
        .store
        .lock()
        .map_err(|_| AuthError::Internal("store lock poisoned".into()))?;
    Ok(store
        .match_threshold(user)
        .map_err(|e| AuthError::Internal(format!("cannot read calibrated threshold: {e}")))?
        .unwrap_or(cfg.recognition.match_threshold))
}

/// Slowly nudge a user's calibrated threshold toward the observed score of a
/// successful match (exponential moving average). Only ever called on
/// success — never on failure — so an attacker probing for a weak threshold
/// cannot lower it. Clamped to the configured `[min, max]` bounds.
fn adapt_threshold(daemon: &SharedDaemon, user: &str, observed: f32) -> AuthResult<()> {
    let cfg = daemon
        .cfg
        .read()
        .map_err(|_| AuthError::Internal("cfg lock poisoned".into()))?
        .clone();
    if !cfg.recognition.auto_threshold || cfg.recognition.auto_threshold_adapt <= 0.0 {
        return Ok(());
    }
    let rate = cfg.recognition.auto_threshold_adapt;
    let store = daemon
        .store
        .lock()
        .map_err(|_| AuthError::Internal("store lock poisoned".into()))?;
    let current = store
        .match_threshold(user)
        .map_err(|e| AuthError::Internal(format!("cannot read calibrated threshold: {e}")))?
        .unwrap_or(cfg.recognition.match_threshold);
    let next = (current + (observed - current) * rate)
        .max(cfg.recognition.auto_threshold_min)
        .min(cfg.recognition.auto_threshold_max);
    if (next - current).abs() > 0.001 {
        store.set_match_threshold(user, next).map_err(|e| {
            AuthError::Internal(format!("cannot persist calibrated threshold: {e}"))
        })?;
    }
    Ok(())
}

/// Measure the user's genuine match scores against their template set and
/// derive a per-user match threshold.
///
/// Runs a short pass over live frames (the camera is already held open by
/// enrollment), embedding every frame with a detected face and recording its
/// best similarity against the templates. The threshold is set at the 25th
/// percentile of those scores minus the configured margin, clamped to
/// `[auto_threshold_min, auto_threshold_max]`. Returns `Ok(None)` when not
/// enough usable frames arrive (the caller keeps the global threshold).
fn calibrate_threshold(
    daemon: &SharedDaemon,
    user: &str,
    cfg: &Config,
    camera: &mut CameraSession,
    pipeline: &dyn FacePipeline,
    templates: &[Embedding],
    budget_cap: Option<Duration>,
) -> AuthResult<Option<f32>> {
    const TARGET_SAMPLES: usize = 12;
    const MIN_SAMPLES: usize = 3;
    const DEADLINE: Duration = Duration::from_secs(6);
    // Calibration runs while enrollment already holds the camera; never let
    // it extend the total hold past the user's remaining camera budget.
    let deadline = DEADLINE.min(budget_cap.unwrap_or(DEADLINE));

    crate::state::broadcast_state(
        daemon,
        &StateEvent {
            state: "scanning".into(),
            op: "enroll".into(),
            user: Some(user.into()),
            score: None,
            reason: Some("calibrating".into()),
            variance: None,
            motion: None,
            min_variance: None,
            min_motion: None,
            accepted: None,
            target: None,
            rejected: None,
            service: None,
            approval_id: None,
            approval_timeout_ms: None,
            secure: None,
            user_present: None,
        },
    );

    let mut scores: Vec<f32> = Vec::with_capacity(TARGET_SAMPLES);
    let start = Instant::now();
    while scores.len() < TARGET_SAMPLES && start.elapsed() < deadline {
        let frame = match camera.next_frame(Duration::from_millis(250)) {
            Ok(Some(f)) => f,
            Ok(None) => continue,
            Err(_) => break,
        };
        let Some(gray) = frame.to_gray() else {
            continue;
        };
        let det = match pipeline.detect(&gray, frame.width, frame.height) {
            Ok(Some(d)) => d,
            _ => continue,
        };
        let emb = match pipeline.embed_crop(&gray, frame.width, frame.height, det.landmarks) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let mut best = 0.0f32;
        for tpl in templates {
            if let Some(sim) = emb.cosine(tpl) {
                if sim > best {
                    best = sim;
                }
            }
        }
        if best > 0.0 {
            scores.push(best);
        }
    }
    if scores.len() < MIN_SAMPLES {
        return Ok(None);
    }
    scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = (scores.len() * 25) / 100;
    let p25 = scores[idx.min(scores.len() - 1)];
    let threshold = (p25 - cfg.recognition.auto_threshold_margin)
        .max(cfg.recognition.auto_threshold_min)
        .min(cfg.recognition.auto_threshold_max);
    let store = daemon
        .store
        .lock()
        .map_err(|_| AuthError::Internal("store lock poisoned".into()))?;
    store
        .set_match_threshold(user, threshold)
        .map_err(|e| AuthError::Internal(format!("cannot persist calibrated threshold: {e}")))?;
    log::info!(
        "calibrated per-user match threshold for {user}: {threshold:.3} ({} samples, p25={p25:.3})",
        scores.len()
    );
    Ok(Some(threshold))
}

/// Run a face-verification attempt for `user`.
///
/// Returns the verdict (with `matched` and a stable `reason`) or a typed
/// error; never an unstructured string, so caller-supplied strings cannot
/// influence the reason reported to PAM or the status indicator.
pub fn verify(
    daemon: &SharedDaemon,
    caller: Caller,
    user: &str,
    service: &str,
    timeout_ms: u64,
    want_keyring: bool,
) -> AuthResult<VerifyResult> {
    let started = Instant::now();
    // Resolve and authorize up front so the after-reboot gate reports the
    // same "no such user" / "denied" reasons as a normal attempt (and does
    // not leak armed state to unauthorized callers).
    let uid = target_uid(user)?;
    if !authorize(caller, Some(uid)) {
        return Err(AuthError::Denied(format!(
            "caller uid {} may not verify for {user}",
            caller.uid
        )));
    }

    if boot_gate_blocks(daemon, user)? {
        // The user has not logged in since the last reboot: refuse without
        // touching the camera. This is a clean non-match (password
        // fallback), never an error.
        {
            let store = daemon
                .store
                .lock()
                .map_err(|_| AuthError::Internal("store lock poisoned".into()))?;
            audit(
                &store,
                Some(user),
                "verify",
                &format!("service={service} reason=password_required"),
            );
        }
        crate::state::broadcast_state(
            daemon,
            &StateEvent {
                state: "failure".into(),
                op: "verify".into(),
                user: Some(user.into()),
                score: None,
                reason: Some("password_required".into()),
                variance: None,
                motion: None,
                min_variance: None,
                min_motion: None,
                accepted: None,
                target: None,
                rejected: None,
                service: None,
                approval_id: None,
                approval_timeout_ms: None,
                secure: None,
                user_present: None,
            },
        );
        return Ok(VerifyResult {
            matched: false,
            user: user.into(),
            score: None,
            template_id: None,
            frames_analyzed: 0,
            liveness_ok: false,
            camera_ok: true,
            elapsed_ms: started.elapsed().as_millis() as u64,
            variance: None,
            motion: None,
            keyring_password: None,
            reason: "password_required".into(),
            threshold_used: effective_threshold(daemon, user)?,
        });
    }

    if let Err(err) = policy_gate(daemon, user) {
        // Rejected before any scanning happens; tell watchers right away.
        let reason = err.reason_code();
        crate::state::broadcast_state(
            daemon,
            &StateEvent {
                state: "failure".into(),
                op: "verify".into(),
                user: Some(user.into()),
                score: None,
                reason: Some(reason.into()),
                variance: None,
                motion: None,
                min_variance: None,
                min_motion: None,
                accepted: None,
                target: None,
                rejected: None,
                service: None,
                approval_id: None,
                approval_timeout_ms: None,
                secure: None,
                user_present: None,
            },
        );
        return Err(err);
    }
    crate::state::broadcast_state(daemon, &StateEvent::scanning(user));
    match verify_inner(daemon, caller, user, service, timeout_ms) {
        Ok(mut result) => {
            // Action-approval gate: for non-login services (sudo, lock,
            // polkit, ...), a confident face match pauses for an explicit
            // Allow/Disallow decision before the action is granted. Login
            // screens bypass the prompt because the user triggers them
            // themselves.
            if result.matched && approval_required(daemon, service, caller) {
                let cfg = daemon
                    .cfg
                    .read()
                    .map_err(|_| AuthError::Internal("cfg lock poisoned".into()))?
                    .clone();
                // Cap the decision window by the remaining request budget
                // so the PAM caller is never kept waiting past its timeout.
                let budget =
                    Duration::from_millis(timeout_ms.min(cfg.daemon.max_request_timeout_ms));
                let window = cfg
                    .approval
                    .timeout_ms
                    .min(budget.saturating_sub(started.elapsed()).as_millis() as u64);
                match run_approval_phase(
                    daemon,
                    user,
                    service,
                    Duration::from_millis(window),
                    &result,
                ) {
                    ApprovalVerdict::Granted => result.reason = "approved".into(),
                    ApprovalVerdict::Denied => {
                        result.matched = false;
                        result.reason = "approval_denied".into();
                    }
                    ApprovalVerdict::Timeout => {
                        result.matched = false;
                        result.reason = "approval_timeout".into();
                    }
                    ApprovalVerdict::CameraError => {
                        result.matched = false;
                        result.camera_ok = false;
                        result.reason = "camera_unavailable".into();
                    }
                }
            }
            if want_keyring {
                attach_keyring_password(daemon, caller, user, service, &mut result);
            }
            result.elapsed_ms = started.elapsed().as_millis() as u64;
            {
                let mut policy = daemon
                    .policy
                    .lock()
                    .map_err(|_| AuthError::Internal("policy lock poisoned".into()))?;
                if result.matched {
                    policy.record_success(user);
                } else if failure_counts_toward_lockout(&result.reason) {
                    // Only genuine failed attempts (no match, denied
                    // approval, liveness failure) accumulate towards the
                    // lockout; environmental verdicts (no templates,
                    // camera mismatch/unavailable) are not user failures.
                    policy.record_failure(user);
                }
            }
            // Slow adaptive tightening: nudge the per-user threshold toward
            // this match's observed score. Success-only, so failed probes can
            // never weaken it.
            if result.matched {
                if let Some(score) = result.score {
                    if let Err(e) = adapt_threshold(daemon, user, score) {
                        log::warn!("threshold adaptation skipped: {e}");
                    }
                }
            }
            {
                let store = daemon
                    .store
                    .lock()
                    .map_err(|_| AuthError::Internal("store lock poisoned".into()))?;
                audit(
                    &store,
                    Some(user),
                    "verify",
                    &format!(
                        "service={service} matched={} reason={} score={:?} caller_uid={} caller_pid={}",
                        result.matched, result.reason, result.score, caller.uid, caller.pid
                    ),
                );
            }
            crate::state::broadcast_state(
                daemon,
                &hiro_core::proto::StateEvent {
                    state: if result.matched { "success" } else { "failure" }.into(),
                    op: "verify".into(),
                    user: Some(user.into()),
                    score: result.score,
                    reason: Some(result.reason.clone()),
                    variance: result.variance,
                    motion: result.motion,
                    min_variance: None,
                    min_motion: None,
                    accepted: None,
                    target: None,
                    rejected: None,
                    service: None,
                    approval_id: None,
                    approval_timeout_ms: None,
                    secure: None,
                    user_present: None,
                },
            );
            Ok(result)
        }
        Err(e) => {
            let store = daemon
                .store
                .lock()
                .map_err(|_| AuthError::Internal("store lock poisoned".into()))?;
            audit(
                &store,
                Some(user),
                "verify",
                &format!("service={service} error={e}"),
            );
            crate::state::broadcast_state(
                daemon,
                &hiro_core::proto::StateEvent {
                    state: "failure".into(),
                    op: "verify".into(),
                    user: Some(user.into()),
                    score: None,
                    reason: Some(e.reason_code().into()),
                    variance: None,
                    motion: None,
                    min_variance: None,
                    min_motion: None,
                    accepted: None,
                    target: None,
                    rejected: None,
                    service: None,
                    approval_id: None,
                    approval_timeout_ms: None,
                    secure: None,
                    user_present: None,
                },
            );
            Err(e)
        }
    }
}

/// Verdict reasons that represent a real failed authentication attempt and
/// should accumulate towards the per-user lockout counter. Environmental
/// verdicts (`no_templates`, `camera_mismatch`, `camera_unavailable`,
/// `password_required`) are not user failures and must not let a stuck
/// camera state lock a user out of face auth.
fn failure_counts_toward_lockout(reason: &str) -> bool {
    matches!(
        reason,
        "no_match" | "no_face" | "liveness_failed" | "approval_denied" | "approval_timeout"
    )
}

fn verify_inner(
    daemon: &SharedDaemon,
    caller: Caller,
    user: &str,
    _service: &str,
    timeout_ms: u64,
) -> AuthResult<VerifyResult> {
    let uid = target_uid(user)?;
    if !authorize(caller, Some(uid)) {
        return Err(AuthError::Denied(format!(
            "caller uid {} may not verify for {user}",
            caller.uid
        )));
    }

    let cfg = daemon
        .cfg
        .read()
        .map_err(|_| AuthError::Internal("cfg lock poisoned".into()))?
        .clone();
    let threshold = effective_threshold(daemon, user)?;
    let quorum = cfg.recognition.quorum_frames;
    let max_frames = cfg.camera.max_frames;
    let deadline = Duration::from_millis(timeout_ms.min(cfg.daemon.max_request_timeout_ms));
    let liveness_enabled = cfg.recognition.enable_liveness;
    let min_variance = cfg.recognition.liveness_min_variance;
    let min_motion = cfg.recognition.liveness_min_motion;
    let allow_camera_change = cfg.security.allow_camera_change;

    let templates = load_templates(daemon, user)?;
    if templates.is_empty() {
        return Ok(VerifyResult {
            matched: false,
            user: user.into(),
            score: None,
            template_id: None,
            frames_analyzed: 0,
            liveness_ok: false,
            camera_ok: true,
            elapsed_ms: 0,
            variance: None,
            motion: None,
            keyring_password: None,
            reason: "no_templates".into(),
            threshold_used: threshold,
        });
    }

    let mut camera = daemon.camera_acquire(Some(user), deadline)?;
    // The per-user camera budget caps how long this request may hold the
    // shared camera, even below the request's own deadline (a queued
    // concurrent request may have reserved most of the budget already).
    let deadline = camera.budget_cap().map_or(deadline, |cap| deadline.min(cap));

    if !allow_camera_change {
        let current = camera_binding(&camera);
        let (stored_binding, stored_secret) = {
            let store = daemon
                .store
                .lock()
                .map_err(|_| AuthError::Internal("store lock poisoned".into()))?;
            (
                store.camera_fingerprint(user).map_err(|e| {
                    AuthError::Internal(format!("cannot read camera binding: {e}"))
                })?,
                store
                    .camera_secret(user)
                    .map_err(|e| AuthError::Internal(format!("cannot read camera pin: {e}")))?,
            )
        };
        // Fail closed: an enrollment that did not record both a binding and
        // a per-user pin secret is not pinned and cannot verify. A rogue
        // camera must not be accepted just because the DB record is empty.
        let pinned = match (stored_binding, stored_secret) {
            (Some(binding), Some(secret)) if !binding.is_empty() && !secret.is_empty() => binding,
            _ => {
                camera.release();
                return Ok(VerifyResult {
                    matched: false,
                    user: user.into(),
                    score: None,
                    template_id: None,
                    frames_analyzed: 0,
                    liveness_ok: false,
                    camera_ok: false,
                    elapsed_ms: 0,
                    variance: None,
                    motion: None,
                    keyring_password: None,
                    reason: "camera_mismatch".into(),
                    threshold_used: threshold,
                });
            }
        };
        if pinned != current {
            camera.release();
            return Ok(VerifyResult {
                matched: false,
                user: user.into(),
                score: None,
                template_id: None,
                frames_analyzed: 0,
                liveness_ok: false,
                camera_ok: false,
                elapsed_ms: 0,
                variance: None,
                motion: None,
                keyring_password: None,
                reason: "camera_mismatch".into(),
                threshold_used: threshold,
            });
        }
    }

    let pipeline = daemon
        .pipeline
        .read()
        .map_err(|_| AuthError::Internal("pipeline lock poisoned".into()))?;

    let mut variance = VarianceTracker::new();
    let mut motion = MotionTracker::new();
    let mut hits: std::collections::HashMap<i64, u32> = std::collections::HashMap::new();
    let mut best_score: Option<f32> = None;
    let mut best_template: Option<i64> = None;
    let mut frames_analyzed = 0u32;
    let mut saw_face = false;
    let mut liveness_satisfied = false;

    let loop_start = Instant::now();
    while frames_analyzed < max_frames && loop_start.elapsed() < deadline {
        let frame = match camera.next_frame(Duration::from_millis(250)) {
            Ok(Some(f)) => f,
            Ok(None) => continue,
            Err(e) => {
                camera.release();
                return Err(AuthError::Camera(e.to_string()));
            }
        };
        frames_analyzed += 1;
        let Some(gray) = frame.to_gray() else {
            continue;
        };
        variance.update(&gray);

        // Stream live liveness progress to `Op::Watch` subscribers (the
        // shell extension) so the user gets real-time "keep moving" cues.
        // Throttled to every few frames, plus an immediate nudge the moment
        // both signals cross their thresholds.
        if liveness_enabled {
            let satisfied = variance.max_diff >= min_variance && motion.max_motion >= min_motion;
            if frames_analyzed.is_multiple_of(3) || (satisfied && !liveness_satisfied) {
                liveness_satisfied = satisfied;
                crate::state::broadcast_state(
                    daemon,
                    &StateEvent {
                        state: "scanning".into(),
                        op: "verify".into(),
                        user: Some(user.into()),
                        score: None,
                        reason: None,
                        variance: Some(variance.max_diff),
                        motion: Some(motion.max_motion),
                        min_variance: Some(min_variance),
                        min_motion: Some(min_motion),
                        accepted: None,
                        target: None,
                        rejected: None,
                        service: None,
                        approval_id: None,
                        approval_timeout_ms: None,
                        secure: None,
                        user_present: None,
                    },
                );
            }
        }

        let hit = match pipeline.process(&gray, frame.width, frame.height) {
            Ok(Some(hit)) => hit,
            Ok(None) => continue,
            Err(e) => {
                camera.release();
                return Err(AuthError::Internal(format!("pipeline failed: {e}")));
            }
        };
        saw_face = true;
        motion.update(&hit.landmarks);

        if hit.embedding.model != templates[0].embedding.model {
            camera.release();
            return Err(AuthError::Internal(format!(
                "pipeline model {} does not match stored templates {}",
                hit.embedding.model, templates[0].embedding.model
            )));
        }
        for tpl in &templates {
            if let Some(sim) = hit.embedding.cosine(&tpl.embedding) {
                if sim > best_score.unwrap_or(-2.0) {
                    best_score = Some(sim);
                    best_template = Some(tpl.id);
                }
                if constant_time_match(sim, threshold) {
                    let count = hits.entry(tpl.id).or_insert(0);
                    *count += 1;
                    if *count >= quorum {
                        let liveness_ok = !liveness_enabled
                            || (variance.max_diff >= min_variance
                                && motion.max_motion >= min_motion);
                        if liveness_ok {
                            // The face matched and (when enabled) the
                            // liveness gate is satisfied: accept now.
                            camera.release();
                            return Ok(VerifyResult {
                                matched: true,
                                user: user.into(),
                                score: best_score,
                                template_id: best_template,
                                frames_analyzed,
                                liveness_ok: true,
                                camera_ok: true,
                                elapsed_ms: 0,
                                variance: Some(variance.max_diff),
                                motion: Some(motion.max_motion),
                                keyring_password: None,
                                reason: "match".into(),
                                threshold_used: threshold,
                            });
                        }
                        // Quorum met but liveness is not satisfied yet. Do
                        // NOT fail the user for holding still: keep scanning
                        // so they have the rest of the window to move. If
                        // they never do, the loop below reports
                        // `liveness_failed` instead of matching.
                    }
                }
            }
        }
    }

    camera.release();
    let liveness_ok =
        !liveness_enabled || (variance.max_diff >= min_variance && motion.max_motion >= min_motion);
    let quorum_met = hits.values().any(|&c| c >= quorum);
    let reason = if !saw_face {
        "no_face"
    } else if quorum_met && !liveness_ok {
        "liveness_failed"
    } else {
        "no_match"
    };
    Ok(VerifyResult {
        matched: false,
        user: user.into(),
        score: best_score,
        template_id: best_template,
        frames_analyzed,
        liveness_ok,
        camera_ok: true,
        elapsed_ms: 0,
        variance: Some(variance.max_diff),
        motion: Some(motion.max_motion),
        keyring_password: None,
        reason: reason.into(),
        threshold_used: threshold,
    })
}

/// Whether an authentication request must pause for an explicit
/// Allow/Disallow decision after the face scan: enabled and the service is
/// not one the user triggered themselves (login screens, `hiro test`).
///
/// The service name is caller-supplied, so a bypass-listed service is only
/// trusted to skip the prompt when the caller is root — the real PAM login
/// stacks run as root. A same-uid process claiming "gdm-password" must not
/// get to choose the security behaviour; the one exemption is the
/// designated self-test service `hiro test`, whose verdict grants nothing.
fn approval_required(daemon: &SharedDaemon, service: &str, caller: Caller) -> bool {
    let cfg = match daemon.cfg.read() {
        Ok(c) => c.clone(),
        Err(_) => return false,
    };
    if !cfg.approval.enabled {
        return false;
    }
    if cfg
        .approval
        .bypass_services
        .iter()
        .any(|s| s == service)
        && (caller.is_root() || service == "hiro-test")
    {
        return false;
    }
    true
}

enum ApprovalVerdict {
    /// The user explicitly allowed the action.
    Granted,
    /// The user explicitly denied the action.
    Denied,
    /// The decision window expired without a choice.
    Timeout,
    /// The camera (or template loading) failed during the decision window.
    CameraError,
}

fn remove_approval(daemon: &SharedDaemon, id: u64) {
    if let Ok(mut approvals) = daemon.approvals.lock() {
        approvals.remove(&id);
    }
    // Best-effort: drop any leftover secret file for this approval (the
    // dialog normally unlinks it after reading).
    if let Ok(cfg) = daemon.cfg.read() {
        if let Some(dir) = cfg.daemon.socket_path.parent() {
            let _ = std::fs::remove_file(dir.join(format!("approve-{id}.secret")));
        }
    }
}

/// (Re-)broadcast the approval prompt so the status indicator can show (or
/// hide) the Allow/Deny buttons. `user_present` flips between `Some(true)`
/// and `Some(false)` as the user steps in and out of the frame; the request
/// itself keeps waiting until `approval.timeout_ms` regardless.
#[allow(clippy::too_many_arguments)]
fn broadcast_approval(
    daemon: &SharedDaemon,
    id: u64,
    user: &str,
    service: &str,
    score: f32,
    timeout_ms: u64,
    secure: bool,
    user_present: Option<bool>,
) {
    crate::state::broadcast_state(
        daemon,
        &StateEvent {
            state: "approval_pending".into(),
            op: "verify".into(),
            user: Some(user.into()),
            score: Some(score),
            reason: None,
            variance: None,
            motion: None,
            min_variance: None,
            min_motion: None,
            accepted: None,
            target: None,
            rejected: None,
            service: Some(service.into()),
            approval_id: Some(id),
            approval_timeout_ms: Some(timeout_ms),
            secure: Some(secure),
            user_present,
        },
    );
}

/// Pause a matched verification for an explicit user decision.
///
/// Broadcasts `state: "approval_pending"` so the status indicator can show
/// Allow/Disallow (or, with `approval.secure_desktop`, hands the decision
/// to the `hiro-approve` dialog on a dedicated VT). Keeps watching the
/// camera for the whole window:
///
/// * a decision (`Op::Approve`) ends the wait — Granted or Denied;
/// * the window (`approval.timeout_ms`) expiring denies the request;
/// * if the user leaves the frame (or their score collapses) for
///   `approval.absent_frames` consecutive frames, the buttons disappear but
///   the request *keeps waiting* — the prompt returns if they step back
///   into the frame, and the request still only fails when the window
///   actually times out.
fn run_approval_phase(
    daemon: &SharedDaemon,
    user: &str,
    service: &str,
    window: Duration,
    result: &VerifyResult,
) -> ApprovalVerdict {
    let cfg = match daemon.cfg.read() {
        Ok(c) => c.clone(),
        Err(_) => return ApprovalVerdict::CameraError,
    };
    let absent_score = (result.threshold_used - cfg.approval.absent_score_margin).max(0.0);
    let max_absent_frames = cfg.approval.absent_frames.max(1);
    let score = result.score.unwrap_or(result.threshold_used);

    let id = crate::state::random_approval_id();
    // Secure-console approvals carry a per-approval secret that only the
    // root-owned `hiro-approve` dialog (which receives it on its command
    // line) knows; `Op::Approve` must present it together with root.
    let secret = if cfg.approval.secure_desktop {
        Some(crate::state::random_secret())
    } else {
        None
    };
    // The dialog needs the secret too; keep a copy since the original is
    // moved into the pending-approval record below.
    let dialog_secret = secret.clone();

    // Register the pending approval so `Op::Approve` can find it, pruning
    // any entries a panicked handler may have left behind.
    {
        let mut approvals = match daemon.approvals.lock() {
            Ok(a) => a,
            Err(_) => return ApprovalVerdict::CameraError,
        };
        approvals.retain(|_, p| p.created.elapsed() < Duration::from_secs(300));
        approvals.insert(
            id,
            crate::state::PendingApproval {
                id,
                user: user.into(),
                service: service.into(),
                score,
                decided: None,
                secret,
                created: Instant::now(),
            },
        );
    }

    let timeout_ms = window.as_millis() as u64;
    let secure = cfg.approval.secure_desktop;

    // Tell the status indicator to show the Allow/Disallow prompt.
    broadcast_approval(
        daemon,
        id,
        user,
        service,
        score,
        timeout_ms,
        secure,
        Some(true),
    );

    // With the secure console enabled, the decision happens on a dedicated
    // VT (spawned outside the hardened daemon unit via systemd-run, with a
    // direct fallback when systemd is absent). Only this root-owned dialog
    // can decide: `Op::Approve` is gated on root + the secret below.
    if secure {
        spawn_secure_dialog(
            daemon,
            id,
            user,
            service,
            timeout_ms,
            dialog_secret.as_deref(),
        );
    }

    // Keep watching the user for the rest of the window. This phase runs
    // only after a real face match for the caller's own authorized request,
    // so it is exempt from the per-user camera budget.
    let mut camera = match daemon.camera_acquire(None, window) {
        Ok(c) => c,
        Err(_) => {
            remove_approval(daemon, id);
            return ApprovalVerdict::CameraError;
        }
    };
    let templates = match load_templates(daemon, user) {
        Ok(t) => t,
        Err(_) => {
            camera.release();
            remove_approval(daemon, id);
            return ApprovalVerdict::CameraError;
        }
    };
    let pipeline = match daemon.pipeline.read() {
        Ok(p) => p,
        Err(_) => {
            camera.release();
            remove_approval(daemon, id);
            return ApprovalVerdict::CameraError;
        }
    };

    let start = Instant::now();
    let mut absent_frames = 0u32;
    let mut user_present = true;
    let verdict = loop {
        // A decision arrived through `Op::Approve`?
        {
            let approvals = match daemon.approvals.lock() {
                Ok(a) => a,
                Err(_) => break ApprovalVerdict::CameraError,
            };
            if let Some(p) = approvals.get(&id) {
                if let Some(decided) = p.decided {
                    break if decided {
                        ApprovalVerdict::Granted
                    } else {
                        ApprovalVerdict::Denied
                    };
                }
            }
        }
        // The decision window expired? The request is denied — this is the
        // normal "the user never decided" (or walked away and never came
        // back) outcome.
        if start.elapsed() >= window {
            break ApprovalVerdict::Timeout;
        }
        // Watch one frame to track whether the user is still there.
        let frame = match camera.next_frame(Duration::from_millis(100)) {
            Ok(Some(f)) => f,
            Ok(None) => continue,
            Err(_) => break ApprovalVerdict::CameraError,
        };
        let Some(gray) = frame.to_gray() else {
            continue;
        };
        let present_now = match pipeline.process(&gray, frame.width, frame.height) {
            Ok(Some(hit)) => {
                let mut best = 0.0f32;
                for tpl in &templates {
                    if let Some(sim) = hit.embedding.cosine(&tpl.embedding) {
                        if sim > best {
                            best = sim;
                        }
                    }
                }
                // A convincing face: the user is in front of the camera.
                best >= absent_score
            }
            Ok(None) => false,
            Err(_) => break ApprovalVerdict::CameraError,
        };

        if present_now {
            absent_frames = 0;
            if !user_present {
                // The user stepped back into the frame: re-show the prompt.
                user_present = true;
                broadcast_approval(
                    daemon,
                    id,
                    user,
                    service,
                    score,
                    timeout_ms,
                    secure,
                    Some(true),
                );
                // Re-open the secure console dialog, which dismissed itself
                // when the user stepped away.
                if secure {
                    spawn_secure_dialog(
                        daemon,
                        id,
                        user,
                        service,
                        timeout_ms,
                        dialog_secret.as_deref(),
                    );
                }
            }
        } else {
            absent_frames += 1;
            if user_present && absent_frames >= max_absent_frames {
                // The user stepped away: hide the buttons, but keep the
                // window open — they can still decide if they come back,
                // and the request only fails when the window times out.
                user_present = false;
                broadcast_approval(
                    daemon,
                    id,
                    user,
                    service,
                    score,
                    timeout_ms,
                    secure,
                    Some(false),
                );
            }
        }
    };

    camera.release();
    remove_approval(daemon, id);
    verdict
}

/// Write the per-approval secret to a root-only file (0600), truncating any
/// previous copy for the same approval (the dialog re-spawns with the same
/// secret when the user steps back into the frame). Keeps the secret out of
/// the dialog's argv, which is world-readable on default Linux
/// (`/proc/<pid>/cmdline`, mode 0444, without hidepid) and is recorded by
/// systemd in the transient unit's ExecStart line.
fn write_secret_file(path: &std::path::Path, secret: &str) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true).mode(0o600);
    match opts.open(path) {
        Ok(mut f) => {
            if let Err(e) = f.write_all(secret.as_bytes()) {
                log::warn!("cannot write approval secret file {}: {e}", path.display());
            }
        }
        Err(e) => log::warn!("cannot create approval secret file {}: {e}", path.display()),
    }
}

/// Launch the secure-console approval dialog (`hiro-approve`) on a
/// dedicated VT. Runs outside the hardened daemon unit via `systemd-run`
/// (needed for VT/console ioctls and `/dev/tty` access), falling back to a
/// direct spawn when systemd is not available (e.g. hirod started from a
/// terminal). Best-effort: if the dialog cannot be shown, the approval
/// simply waits out its window as if no one were watching.
///
/// The per-approval `secret` is handed to the dialog through a root-only
/// file (see [`write_secret_file`]) so its decision can be authenticated
/// (`Op::Approve` requires root + this secret for secure approvals), while
/// never appearing on the dialog's command line.
fn spawn_secure_dialog(
    daemon: &SharedDaemon,
    id: u64,
    user: &str,
    service: &str,
    timeout_ms: u64,
    secret: Option<&str>,
) {
    let (dialog, vt, socket) = {
        let cfg = match daemon.cfg.read() {
            Ok(c) => c.clone(),
            Err(_) => return,
        };
        (
            cfg.approval.secure_dialog.clone(),
            cfg.approval.secure_vt,
            cfg.daemon.socket_path.clone(),
        )
    };
    // The dialog can be re-spawned when the user steps back into the
    // frame; a monotonically increasing sequence keeps the transient
    // unit name unique so a re-spawn never collides with a dialog that
    // is still shutting down.
    let seq = DIALOG_SPAWN_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut args = vec![
        format!("--vt={vt}"),
        format!("--socket={}", socket.display()),
        format!("--user={user}"),
        format!("--approval-id={id}"),
        format!("--service={service}"),
        format!("--timeout-ms={timeout_ms}"),
    ];
    let secret_path = if let Some(s) = secret {
        let dir = socket
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| std::path::PathBuf::from("/run"));
        let file = dir.join(format!("approve-{id}.secret"));
        write_secret_file(&file, s);
        args.push(format!("--secret-file={}", file.display()));
        Some(file)
    } else {
        None
    };
    let dialog_str = dialog.display().to_string();

    std::thread::spawn(move || {
        let unit = format!("hiro-approve-{id}-{seq}");
        let mut cmd = std::process::Command::new("systemd-run");
        cmd.args(["--quiet", "--collect", "--no-ask-password"])
            .arg(format!("--unit={unit}"))
            .arg(&dialog_str)
            .args(&args);
        match cmd.status() {
            // systemd-run returns as soon as the unit is started; the
            // dialog itself reads and unlinks the secret file.
            Ok(st) if st.success() => return,
            Ok(st) => log::warn!("systemd-run exited {st}; spawning secure dialog directly"),
            Err(e) => log::warn!("systemd-run unavailable ({e}); spawning secure dialog directly"),
        }
        match std::process::Command::new(&dialog_str).args(&args).spawn() {
            Ok(mut child) => {
                let _ = child.wait();
                // The dialog unlinks the secret file after reading it; if
                // it never did (crash), clean up the stale copy.
                if let Some(p) = &secret_path {
                    let _ = std::fs::remove_file(p);
                }
            }
            Err(e) => {
                log::warn!("cannot launch secure dialog {dialog_str}: {e}");
                if let Some(p) = &secret_path {
                    let _ = std::fs::remove_file(p);
                }
            }
        }
    });
}

/// After a verified face match, release the sealed login password so the
/// PAM stack can unlock the login keyring (`pam_gnome_keyring` / KWallet).
///
/// All of these must hold or the password stays sealed:
///
/// * the request explicitly asked for it (`want_keyring`),
/// * the caller is **root** — greeter and login stacks run as root, and
///   restricting release to root closes the silent-harvesting hole where a
///   process running as the user could ask for their own login password
///   and receive it the moment the user's face was in front of the camera,
/// * the match is real,
/// * the feature is enabled and the PAM service is listed in
///   `keyring.services`,
/// * a sealed secret exists and unseals cleanly,
/// * the password still matches the account in `/etc/shadow`.
///
/// The account re-check is what keeps face login working after a password
/// change: a stale or mistyped secret is simply never released, so the
/// stack keeps its normal short-circuit behaviour (keyring stays locked)
/// instead of failing authentication.
fn attach_keyring_password(
    daemon: &SharedDaemon,
    caller: Caller,
    user: &str,
    service: &str,
    result: &mut VerifyResult,
) {
    if !result.matched {
        return;
    }
    // Root-only release. Greeter/login PAM stacks run as root; a
    // same-uid process asking for the password must never get it, even on
    // a listed "bypass" service — the daemon cannot tell a real greeter
    // from malware with the same uid. (A root caller could obtain the
    // password anyway, e.g. from /etc/shadow, so root is the trusted
    // boundary.)
    if !caller.is_root() {
        return;
    }
    let cfg = match daemon.cfg.read() {
        Ok(c) => c.clone(),
        Err(_) => return,
    };
    if !cfg.keyring.enabled || !cfg.keyring.services.iter().any(|s| s == service) {
        return;
    }

    let secret = {
        let store = match daemon.store.lock() {
            Ok(s) => s,
            Err(_) => return,
        };
        match store.login_secret(user) {
            Ok(Some(ct)) => ct,
            _ => return,
        }
    };

    let plain = match daemon.km.unseal(user.as_bytes(), &secret) {
        Ok(p) => p,
        Err(e) => {
            log::error!("hiro: cannot unseal keyring password for {user}: {e}");
            return;
        }
    };
    // Zeroize the plaintext on the invalid-UTF-8 path: `into_bytes` hands
    // the buffer back so it can be wiped before the Vec is freed.
    let password = match String::from_utf8(plain) {
        Ok(s) => s,
        Err(e) => {
            let mut bytes = e.into_bytes();
            bytes.fill(0);
            log::error!("hiro: sealed keyring password for {user} is not valid UTF-8");
            return;
        }
    };
    // Zeroize the password buffer when it goes out of scope at the end of
    // this function (the copy put into the response is zeroized after the
    // connection writes it; see server.rs).
    let password = Zeroizing::new(password);

    if !daemon.password_checker.check(user, &password) {
        log::warn!(
            "hiro: sealed keyring password for {user} no longer matches the account; \
             re-run `hiro keyring set` to update it"
        );
        {
            let store = match daemon.store.lock() {
                Ok(s) => s,
                Err(_) => return,
            };
            audit(
                &store,
                Some(user),
                "keyring_unlock",
                "skipped: password no longer matches account",
            );
        }
        return;
    }

    // Zeroizing<String> zeroizes the password buffer on drop; the copy in
    // the response is dropped as soon as the connection writes it.
    result.keyring_password = Some(password.to_string());
    {
        let store = match daemon.store.lock() {
            Ok(s) => s,
            Err(_) => return,
        };
        audit(&store, Some(user), "keyring_unlock", "armed");
    }
}

/// Capture and store new face templates for `user`.
///
/// Broadcasts `op: "enroll"` events to `Op::Watch` subscribers so the
/// status indicator can show a distinct "enrolling" status, live progress,
/// and the final result (templates added / rejected). Early failures also
/// produce a terminal `failure` event so the indicator is never left stuck
/// on a scanning status.
pub fn enroll(
    daemon: &SharedDaemon,
    caller: Caller,
    user: &str,
    max_models: usize,
) -> Result<EnrollResult, String> {
    let started = Instant::now();
    let uid = target_uid(user).map_err(|e| e.to_string())?;
    if !authorize(caller, Some(uid)) {
        return Err(AuthError::Denied(format!(
            "caller uid {} may not enroll for {user}",
            caller.uid
        ))
        .to_string());
    }
    if boot_gate_blocks(daemon, user).map_err(|e| e.to_string())? {
        {
            let store = daemon
                .store
                .lock()
                .map_err(|_| "store lock poisoned".to_string())?;
            audit(&store, Some(user), "enroll", "reason=password_required");
        }
        crate::state::broadcast_state(
            daemon,
            &StateEvent {
                state: "failure".into(),
                op: "enroll".into(),
                user: Some(user.into()),
                score: None,
                reason: Some("password_required".into()),
                variance: None,
                motion: None,
                min_variance: None,
                min_motion: None,
                accepted: None,
                target: None,
                rejected: None,
                service: None,
                approval_id: None,
                approval_timeout_ms: None,
                secure: None,
                user_present: None,
            },
        );
        return Err(
            "password login required after reboot; log in once before enrolling a face".to_string(),
        );
    }
    // Enrollment holds the camera for up to tens of seconds and streams
    // per-frame progress events; like verify it must be rate-limited, or a
    // local user could monopolise the camera indefinitely (blocking every
    // other user's face auth) and drive watcher memory growth.
    if let Err(err) = policy_gate(daemon, user) {
        return Err(err.to_string());
    }
    crate::state::broadcast_state(daemon, &StateEvent::enrolling(user));

    match enroll_inner(daemon, caller, user, max_models) {
        Ok(outcome) => {
            let added = outcome.result.added;
            let rejected = outcome.result.rejected;
            {
                let store = daemon
                    .store
                    .lock()
                    .map_err(|_| "store lock poisoned".to_string())?;
                audit(
                    &store,
                    Some(user),
                    "enroll",
                    &format!(
                        "added={added} rejected={rejected} frames={} elapsed_ms={}",
                        outcome.frames,
                        started.elapsed().as_millis()
                    ),
                );
            }
            crate::state::broadcast_state(
                daemon,
                &StateEvent {
                    state: if added > 0 { "success" } else { "failure" }.into(),
                    op: "enroll".into(),
                    user: Some(user.into()),
                    score: None,
                    reason: if added > 0 {
                        None
                    } else {
                        Some(outcome.failure_reason.clone())
                    },
                    variance: None,
                    motion: None,
                    min_variance: None,
                    min_motion: None,
                    accepted: Some(added),
                    target: Some(outcome.target),
                    rejected: Some(rejected),
                    service: None,
                    approval_id: None,
                    approval_timeout_ms: None,
                    secure: None,
                    user_present: None,
                },
            );
            Ok(outcome.result)
        }
        Err(e) => {
            {
                let store = daemon
                    .store
                    .lock()
                    .map_err(|_| "store lock poisoned".to_string())?;
                audit(
                    &store,
                    Some(user),
                    "enroll",
                    &format!("error={e} elapsed_ms={}", started.elapsed().as_millis()),
                );
            }
            crate::state::broadcast_state(
                daemon,
                &StateEvent {
                    state: "failure".into(),
                    op: "enroll".into(),
                    user: Some(user.into()),
                    score: None,
                    reason: Some(enroll_error_reason(&e).into()),
                    variance: None,
                    motion: None,
                    min_variance: None,
                    min_motion: None,
                    accepted: None,
                    target: None,
                    rejected: None,
                    service: None,
                    approval_id: None,
                    approval_timeout_ms: None,
                    secure: None,
                    user_present: None,
                },
            );
            Err(e)
        }
    }
}

struct EnrollOutcome {
    result: EnrollResult,
    target: usize,
    frames: u32,
    /// Machine-readable reason when no templates were captured
    /// (`no_face`, `face_too_small`, `blurry`, `static_scene`,
    /// `duplicate_pose`, or `no_face` as the default).
    failure_reason: String,
}

/// Record the first rejection reason seen; later reasons do not overwrite
/// it so the user gets the most likely fixable cause.
fn note_rejection(reason: &mut Option<&'static str>, what: &'static str) {
    if reason.is_none() {
        *reason = Some(what);
    }
}

/// Map an early enrollment error to a stable, user-displayable reason code.
fn enroll_error_reason(e: &str) -> &'static str {
    if e.contains("no such user") {
        "no_such_user"
    } else if e.contains("denied") {
        "denied"
    } else if e.contains("template limit") {
        "template_limit"
    } else if e.contains("camera changed") {
        "camera_mismatch"
    } else if e.contains("camera") {
        "camera_unavailable"
    } else {
        "error"
    }
}

/// Broadcast live enrollment progress to `Op::Watch` subscribers so the
/// status indicator can show the accepted/target count and, on rejections,
/// a stable reason code that tells the user what to change (move closer,
/// hold still, turn the head, etc.). Called for every accepted frame and
/// every rejected frame; the event is small and the loop is human-paced.
fn broadcast_enroll_progress(
    daemon: &SharedDaemon,
    user: &str,
    accepted: usize,
    target: usize,
    rejected: usize,
    reason: Option<&str>,
) {
    crate::state::broadcast_state(
        daemon,
        &StateEvent {
            state: "scanning".into(),
            op: "enroll".into(),
            user: Some(user.into()),
            score: None,
            reason: reason.map(str::to_string),
            variance: None,
            motion: None,
            min_variance: None,
            min_motion: None,
            accepted: Some(accepted),
            target: Some(target),
            rejected: Some(rejected),
            service: None,
            approval_id: None,
            approval_timeout_ms: None,
            secure: None,
            user_present: None,
        },
    );
}

/// Capture, quality-gate, and store face templates. Owns the camera for the
/// duration; always releases it before returning.
fn enroll_inner(
    daemon: &SharedDaemon,
    caller: Caller,
    user: &str,
    max_models: usize,
) -> Result<EnrollOutcome, String> {
    let uid = target_uid(user).map_err(|e| e.to_string())?;
    if !authorize(caller, Some(uid)) {
        return Err(format!(
            "caller uid {} may not enroll for {user}",
            caller.uid
        ));
    }

    let cfg = daemon
        .cfg
        .read()
        .map_err(|_| "cfg lock poisoned".to_string())?
        .clone();
    let max_per_user = cfg.security.max_templates_per_user;
    let min_area = cfg.recognition.min_face_area;
    let min_sharpness = cfg.recognition.min_sharpness;
    // Enrollment uses its own frame-variance gate, not the verification
    // anti-spoof threshold: it defaults to 0.0 (disabled) so a user can hold
    // a pose for a sharp capture instead of having to keep moving.
    let min_variance = cfg.recognition.enroll_min_variance;
    let dedupe_threshold = cfg.recognition.dedupe_threshold;
    let max_frames = cfg.camera.max_frames * 4;

    {
        let store = daemon
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        store
            .upsert_user(user, Some(i64::from(uid)))
            .map_err(|e| e.to_string())?;
        let existing = store.count_templates(user).map_err(|e| e.to_string())?;
        if existing >= max_per_user {
            return Err(format!(
                "template limit reached ({existing}/{max_per_user}); remove templates first"
            ));
        }
    }

    let mut camera = daemon
        .camera_acquire(Some(user), Duration::from_secs(60))
        .map_err(|e| e.to_string())?;

    // Record the camera-pinning binding (USB identity + driver + sysfs
    // node path) and a fresh per-user random secret. The secret marks the
    // pinning record as genuine: verification fails closed unless both a
    // binding and a secret are present, so a downgraded/empty record can
    // never make a rogue camera acceptable.
    let current = camera_binding(&camera);
    let pin_secret = crate::state::random_bytes::<32>();
    {
        let store = daemon
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        // Only a genuinely pinned record (one carrying a pin secret) is
        // compared against the current camera. Records written before the
        // binding+secret format carry no secret and therefore pinned
        // nothing — treat them as unpinned so the first enrollment after an
        // upgrade simply re-pins instead of locking the user out.
        let pinned = store
            .camera_secret(user)
            .map_err(|e| e.to_string())?
            .is_some_and(|s| !s.is_empty());
        if pinned {
            if let Some(stored) = store.camera_fingerprint(user).map_err(|e| e.to_string())? {
                if stored != current {
                    camera.release();
                    return Err(format!(
                        "camera changed since previous enrollment ({stored} vs {current}); \
                         run `hiro clear` first or set security.allow_camera_change"
                    ));
                }
            }
        }
        store
            .set_camera_fingerprint(user, &current)
            .map_err(|e| e.to_string())?;
        store
            .set_camera_secret(user, Some(&pin_secret))
            .map_err(|e| e.to_string())?;
    }

    let pipeline = daemon
        .pipeline
        .read()
        .map_err(|_| "pipeline lock poisoned".to_string())?;

    let existing_templates = load_templates(daemon, user).map_err(|e| e.to_string())?;
    let target = max_models.min(max_per_user.saturating_sub(existing_templates.len()));

    let mut candidates: Vec<(Embedding, QualityReport)> = Vec::new();
    let mut variance = VarianceTracker::new();
    let mut frames_analyzed = 0u32;
    let mut rejected = 0usize;
    let mut primary_reject: Option<&'static str> = None;
    let deadline = Duration::from_secs(60);
    // The per-user camera budget caps how long enrollment may hold the
    // shared camera: even a request that would run the full 60 s window is
    // cut at the user's remaining allowance, so one account cannot pin the
    // camera and starve every other user's face auth.
    let deadline = camera.budget_cap().map_or(deadline, |cap| deadline.min(cap));
    // If no face is ever detected, do not hold the camera for the full
    // window: fail fast so an absent/stale enrollment cannot monopolise the
    // camera (which would block every other user's face auth).
    const NO_FACE_BUDGET: Duration = Duration::from_secs(15);
    let mut saw_face = false;

    let loop_start = Instant::now();
    while candidates.len() < target
        && frames_analyzed < max_frames
        && loop_start.elapsed() < deadline
        && (saw_face || loop_start.elapsed() < NO_FACE_BUDGET)
    {
        let frame = match camera.next_frame(Duration::from_millis(250)) {
            Ok(Some(f)) => f,
            Ok(None) => continue,
            Err(e) => {
                camera.release();
                return Err(e.to_string());
            }
        };
        frames_analyzed += 1;
        let Some(gray) = frame.to_gray() else {
            rejected += 1;
            note_rejection(&mut primary_reject, "no_luma");
            log::debug!(
                "enroll frame rejected: no luma extraction for {:?} ({} bytes, {}x{})",
                frame.format,
                frame.data.len(),
                frame.width,
                frame.height
            );
            broadcast_enroll_progress(
                daemon,
                user,
                candidates.len(),
                target,
                rejected,
                Some("no_luma"),
            );
            continue;
        };
        let diff = variance.update(&gray);

        // Cheap anti-stall gate first: when the operator requires motion
        // (`enroll_min_variance > 0`), reject static frames *before* the
        // expensive face pipeline runs. The default of 0 disables this so
        // the user can hold still for a sharp capture.
        if min_variance > 0.0 && diff < min_variance {
            log::debug!("enroll frame rejected: static scene ({diff:.1})");
            rejected += 1;
            note_rejection(&mut primary_reject, "static_scene");
            broadcast_enroll_progress(
                daemon,
                user,
                candidates.len(),
                target,
                rejected,
                Some("static_scene"),
            );
            continue;
        }

        // Run the detector only, then apply the cheap face-size and
        // sharpness gates before paying for the embedder.
        let det = match pipeline.detect(&gray, frame.width, frame.height) {
            Ok(Some(d)) => {
                saw_face = true;
                d
            }
            Ok(None) => {
                rejected += 1;
                note_rejection(&mut primary_reject, "no_face");
                log::debug!(
                    "enroll frame rejected: face not found (mean={:.1})",
                    gray.iter().map(|&v| f64::from(v)).sum::<f64>() / gray.len() as f64
                );
                broadcast_enroll_progress(
                    daemon,
                    user,
                    candidates.len(),
                    target,
                    rejected,
                    Some("no_face"),
                );
                continue;
            }
            Err(e) => {
                camera.release();
                return Err(format!("pipeline failed: {e}"));
            }
        };

        let bbox = det.bbox;
        let size_ratio = (bbox[2] - bbox[0]).max(0.0) * (bbox[3] - bbox[1]).max(0.0);
        if size_ratio < min_area {
            log::debug!("enroll frame rejected: face too small ({size_ratio:.3})");
            rejected += 1;
            note_rejection(&mut primary_reject, "face_too_small");
            broadcast_enroll_progress(
                daemon,
                user,
                candidates.len(),
                target,
                rejected,
                Some("face_too_small"),
            );
            continue;
        }
        let sharpness = hwframe::sharpness(&gray, frame.width, frame.height).unwrap_or(0.0);
        if sharpness < min_sharpness {
            log::debug!("enroll frame rejected: blurry ({sharpness:.1})");
            rejected += 1;
            note_rejection(&mut primary_reject, "blurry");
            broadcast_enroll_progress(
                daemon,
                user,
                candidates.len(),
                target,
                rejected,
                Some("blurry"),
            );
            continue;
        }

        let embedding = match pipeline.embed_crop(&gray, frame.width, frame.height, det.landmarks) {
            Ok(e) => e,
            Err(e) => {
                camera.release();
                return Err(format!("pipeline failed: {e}"));
            }
        };

        let too_similar = existing_templates.iter().any(|t| {
            embedding
                .cosine(&t.embedding)
                .is_some_and(|s| s > dedupe_threshold)
        }) || candidates
            .iter()
            .any(|(e, _)| embedding.cosine(e).is_some_and(|s| s > dedupe_threshold));
        if too_similar {
            log::debug!("enroll frame rejected: duplicate pose");
            rejected += 1;
            note_rejection(&mut primary_reject, "duplicate_pose");
            broadcast_enroll_progress(
                daemon,
                user,
                candidates.len(),
                target,
                rejected,
                Some("duplicate_pose"),
            );
            continue;
        }
        candidates.push((
            embedding,
            QualityReport {
                face_found: true,
                sharpness,
                variance: diff,
                size_ratio,
            },
        ));
        log::info!(
            "enroll frame accepted ({}/{}): sharpness={:.1} size={:.3}",
            candidates.len(),
            target,
            sharpness,
            size_ratio
        );
        broadcast_enroll_progress(daemon, user, candidates.len(), target, rejected, None);
    }

    let mut template_ids = Vec::new();
    let mut reports = Vec::new();
    let added = candidates.len();
    let store = daemon
        .store
        .lock()
        .map_err(|_| "store lock poisoned".to_string())?;
    for (embedding, report) in &candidates {
        // Bound the ciphertext to the owning user so it cannot be
        // substituted into another account's row.
        let ciphertext = daemon
            .km
            .seal(user.as_bytes(), &embedding.serialize())
            .map_err(|e| e.to_string())?;
        let id = store
            .add_template(
                user,
                &embedding.model,
                embedding.dim,
                &ciphertext,
                Some(report.sharpness),
            )
            .map_err(|e| e.to_string())?;
        template_ids.push(id);
        reports.push(report.clone());
    }
    drop(store);

    // Automatic per-user threshold calibration: measure the user's genuine
    // match scores against their (now stored) template set in a short live
    // pass. Best-effort — if calibration yields too few usable frames, the
    // global `match_threshold` stays in effect.
    let mut calibrated_threshold = None;
    if cfg.recognition.auto_threshold && added > 0 {
        let mut calibrate_templates: Vec<Embedding> = existing_templates
            .iter()
            .map(|t| t.embedding.clone())
            .collect();
        calibrate_templates.extend(candidates.iter().map(|(e, _)| e.clone()));
        let calib_cap = camera.budget_cap();
        match calibrate_threshold(
            daemon,
            user,
            &cfg,
            &mut camera,
            &**pipeline,
            &calibrate_templates,
            calib_cap,
        ) {
            Ok(Some(t)) => calibrated_threshold = Some(t),
            Ok(None) => log::debug!("threshold calibration skipped: not enough usable frames"),
            Err(e) => log::warn!("threshold calibration skipped: {e}"),
        }
    }

    camera.release();

    let failure_reason = if added > 0 {
        String::new()
    } else {
        primary_reject.unwrap_or("no_face").to_string()
    };

    Ok(EnrollOutcome {
        result: EnrollResult {
            added,
            rejected,
            template_ids,
            reports,
            match_threshold: calibrated_threshold,
        },
        target,
        frames: frames_analyzed,
        failure_reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hiro_core::config::Config;
    use hiro_face::stub::StubPipeline;
    use hiro_face::FacePipeline;
    use hiro_hw::mock::MockSource;
    use hiro_store::Store;
    use hiro_tpm::SoftwareKeyManager;
    use std::sync::{Arc, Mutex, RwLock};

    use crate::camera::CameraSession;
    use crate::policy::Policy;
    use crate::state::{BootAuth, Daemon, PasswordChecker};

    /// Test stand-in for the shadow-password checker.
    struct StubChecker {
        /// Whether the candidate password is accepted.
        ok: bool,
    }

    impl PasswordChecker for StubChecker {
        fn check(&self, _user: &str, _password: &str) -> bool {
            self.ok
        }
    }

    fn test_daemon() -> SharedDaemon {
        test_daemon_with_checker(false)
    }

    /// Simulate the PAM session hook: record a login so face auth is armed
    /// for the current boot.
    fn arm_login(daemon: &SharedDaemon, user: &str) {
        record_login(daemon, Caller { uid: 0, pid: 1 }, user, "test-login").unwrap();
    }

    fn test_daemon_with_checker(passwords_ok: bool) -> SharedDaemon {
        let mut cfg = Config::default();
        cfg.recognition.detector = "stub".into();
        cfg.recognition.match_threshold = 0.90;
        cfg.recognition.quorum_frames = 2;
        cfg.camera.max_frames = 20;
        cfg.camera.width = 64;
        cfg.camera.height = 48;
        cfg.device.require_ir = false;
        // The approval gate is on by default; unit tests that exercise the
        // existing instant-match flow disable it here and enable it
        // explicitly (see the approval tests below).
        cfg.approval.enabled = false;

        let km = SoftwareKeyManager::from_key([7u8; 32]);
        let store = Store::open_in_memory().unwrap();
        let camera = Arc::new(Mutex::new(CameraSession::new(
            &cfg,
            hiro_hw::quirks::QuirkDb::default(),
            Some(Box::new(MockSource::new(64, 48, vec![]))),
        )));
        let policy = Policy::new(cfg.security.clone());
        let pipeline: Box<dyn FacePipeline> = Box::new(StubPipeline::new());
        Arc::new(Daemon {
            cfg: RwLock::new(cfg),
            store: Mutex::new(store),
            km: Box::new(km),
            pipeline: RwLock::new(pipeline),
            camera,
            policy: Mutex::new(policy),
            password_checker: Box::new(StubChecker { ok: passwords_ok }),
            watchers: Mutex::new(Vec::new()),
            boot_auth: Mutex::new(BootAuth {
                boot_id: "test-boot".into(),
                logged_in: Default::default(),
            }),
            approvals: Mutex::new(std::collections::HashMap::new()),
            config_path: None,
            started_at: std::time::Instant::now(),
        })
    }

    #[test]
    fn enroll_then_verify_succeeds_with_mock() {
        let daemon = test_daemon();

        // Current user's login name, so non-root authz passes.
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let user = me.name.clone();
        arm_login(&daemon, &user);
        // Enroll as root caller with a face every 3rd frame.
        {
            let mut cam = daemon.camera.lock().unwrap();
            cam.set_mock_face_every(Some(3));
        }
        let caller = Caller { uid: 0, pid: 1 };
        let enroll_result = enroll(&daemon, caller, &user, 4).unwrap();
        assert!(
            enroll_result.added >= 1,
            "enroll failed: {:?}",
            enroll_result.reports
        );
        assert!(!enroll_result.template_ids.is_empty());

        // Verify with the same face schedule.
        let result = verify(&daemon, caller, &user, "test-service", 5000, false).unwrap();
        assert!(result.matched, "verify failed: {result:?}");
        assert!(result.liveness_ok, "liveness should pass: {result:?}");
        assert!(result.frames_analyzed >= 3);

        // A camera with no face must not match.
        {
            let mut cam = daemon.camera.lock().unwrap();
            cam.set_mock_face_every(None);
        }
        let result = verify(&daemon, caller, &user, "test-service", 2000, false).unwrap();
        assert!(
            !result.matched,
            "verify should fail without a face: {result:?}"
        );
        assert_eq!(result.reason, "no_face");
    }

    /// Enrollment must not require frame-to-frame motion: a user should be
    /// able to hold a pose for a sharp capture. The enrollment variance gate
    /// defaults to 0 (off); only when an operator sets
    /// `recognition.enroll_min_variance` is a motion requirement enforced.
    #[test]
    fn enroll_does_not_require_motion_by_default() {
        let daemon = test_daemon();
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        arm_login(&daemon, &me.name);
        // Every frame carries a face, so the only variance signal is the
        // mock's per-pixel noise — far below any liveness threshold. With the
        // gate off (default), enrollment still accepts.
        {
            let mut cam = daemon.camera.lock().unwrap();
            cam.set_mock_face_every(Some(1));
        }
        let caller = Caller { uid: 0, pid: 1 };
        let result = enroll(&daemon, caller, &me.name, 1).unwrap();
        assert!(
            result.added >= 1,
            "default enrollment should accept a still frame: {:?}",
            result.reports
        );
    }

    #[test]
    fn enroll_static_scene_gate_rejects_when_enabled() {
        let daemon = test_daemon();
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        arm_login(&daemon, &me.name);
        {
            let mut cfg = daemon.cfg.write().unwrap();
            // Impossible to satisfy (mean abs diff maxes at 255): every
            // frame is rejected as `static_scene`.
            cfg.recognition.enroll_min_variance = 1000.0;
        }
        {
            let mut cam = daemon.camera.lock().unwrap();
            cam.set_mock_face_every(Some(1));
        }
        let caller = Caller { uid: 0, pid: 1 };
        let result = enroll(&daemon, caller, &me.name, 1).unwrap();
        assert_eq!(result.added, 0, "static frames must be rejected");
        assert!(
            result.rejected > 0,
            "static frames should be counted as rejected"
        );
    }

    /// Migration path: a pre-pin enrollment (old bare fingerprint, no pin
    /// secret) pinned nothing, so the next enrollment must re-pin without
    /// tripping the "camera changed" error. Verification of such a record
    /// stays fail-closed (no secret = camera_mismatch), forcing a genuine
    /// re-enrollment.
    #[test]
    fn legacy_unpinned_record_re_pins_on_enrollment() {
        let daemon = test_daemon();
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let user = me.name.clone();
        arm_login(&daemon, &user);
        // Simulate a record written before the binding+secret format.
        {
            let store = daemon.store.lock().unwrap();
            store
                .upsert_user(&user, Some(i64::from(me.uid.as_raw())))
                .unwrap();
            store
                .set_camera_fingerprint(
                    &user,
                    "13d3:56ea:usb-0000:00:14.0-7.3:10126159",
                )
                .unwrap();
            assert!(store.camera_secret(&user).unwrap().is_none());
        }
        {
            let mut cam = daemon.camera.lock().unwrap();
            cam.set_mock_face_every(Some(3));
        }
        let caller = Caller { uid: 0, pid: 1 };
        let result = enroll(&daemon, caller, &user, 2).unwrap();
        assert!(
            result.added >= 1,
            "legacy record must allow re-enrollment: {:?}",
            result.reports
        );
        // The pin is now the new binding + secret.
        let store = daemon.store.lock().unwrap();
        let fp = store
            .camera_fingerprint(&user)
            .unwrap()
            .expect("binding written");
        assert!(fp.contains('|'), "expected new binding format, got {fp}");
        assert!(
            store
                .camera_secret(&user)
                .unwrap()
                .is_some_and(|s| !s.is_empty())
        );
    }

    /// A genuinely pinned record that does not match the current camera
    /// still refuses enrollment (the rogue-camera protection).
    #[test]
    fn genuinely_pinned_camera_mismatch_refuses_enrollment() {
        let daemon = test_daemon();
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let user = me.name.clone();
        arm_login(&daemon, &user);
        {
            let store = daemon.store.lock().unwrap();
            store
                .upsert_user(&user, Some(i64::from(me.uid.as_raw())))
                .unwrap();
            store
                .set_camera_fingerprint(
                    &user,
                    "13d3:56ea:usb-x:?|uvcvideo|/sys/devices/other",
                )
                .unwrap();
            store.set_camera_secret(&user, Some(&[1u8; 32])).unwrap();
        }
        {
            let mut cam = daemon.camera.lock().unwrap();
            cam.set_mock_face_every(Some(3));
        }
        let caller = Caller { uid: 0, pid: 1 };
        let err = enroll(&daemon, caller, &user, 2).unwrap_err();
        assert!(
            err.contains("camera changed"),
            "pinned mismatch must refuse: {err}"
        );
    }

    /// Automatic calibration must produce a per-user threshold that
    /// verification actually uses — even when the global `match_threshold`
    /// is far too strict to ever match (the 0.99 failure mode).
    #[test]
    fn enroll_calibrates_per_user_threshold_used_by_verify() {
        let daemon = test_daemon();
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let user = me.name.clone();
        arm_login(&daemon, &user);
        {
            let mut cfg = daemon.cfg.write().unwrap();
            // A global bar that no real score ever reaches.
            cfg.recognition.match_threshold = 0.99;
        }
        {
            let mut cam = daemon.camera.lock().unwrap();
            cam.set_mock_face_every(Some(3));
        }
        let caller = Caller { uid: 0, pid: 1 };

        let enrolled = enroll(&daemon, caller, &user, 4).unwrap();
        assert!(enrolled.added >= 1, "enroll failed: {:?}", enrolled.reports);
        let calibrated = enrolled
            .match_threshold
            .expect("calibration must store a per-user threshold");
        assert!(
            (0.50..0.99).contains(&calibrated),
            "calibrated threshold should sit inside the configured bounds, got {calibrated}"
        );

        // The per-user threshold — not the 0.99 global — governs verification.
        let result = verify(&daemon, caller, &user, "test-service", 5000, false).unwrap();
        assert!(result.matched, "verify failed: {result:?}");
        assert!(
            (result.threshold_used - calibrated).abs() < 0.001,
            "threshold_used should be the calibrated value, got {}",
            result.threshold_used
        );
    }

    /// A successful match slowly moves the per-user threshold toward the
    /// observed score (EMA), never overshooting the observed value.
    #[test]
    fn successful_verify_adapts_threshold_toward_score() {
        let daemon = test_daemon();
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let user = me.name.clone();
        arm_login(&daemon, &user);
        {
            let mut cam = daemon.camera.lock().unwrap();
            cam.set_mock_face_every(Some(3));
        }
        let caller = Caller { uid: 0, pid: 1 };
        enroll(&daemon, caller, &user, 4).unwrap();

        // Park the threshold below the configured ceiling so the EMA has
        // headroom to creep toward the observed score.
        let before = 0.70f32;
        daemon
            .store
            .lock()
            .unwrap()
            .set_match_threshold(&user, before)
            .unwrap();
        let result = verify(&daemon, caller, &user, "test-service", 5000, false).unwrap();
        assert!(result.matched, "verify failed: {result:?}");
        let observed = result.score.unwrap();

        let after = daemon
            .store
            .lock()
            .unwrap()
            .match_threshold(&user)
            .unwrap()
            .unwrap();
        assert!(
            after > before && after <= observed,
            "threshold should creep toward the observed score: before={before} after={after} observed={observed}"
        );
    }

    /// Failures must never move the threshold — an attacker cannot weaken
    /// it by forcing misses.
    #[test]
    fn failed_verify_does_not_weaken_threshold() {
        let daemon = test_daemon();
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let user = me.name.clone();
        arm_login(&daemon, &user);
        {
            let mut cam = daemon.camera.lock().unwrap();
            cam.set_mock_face_every(Some(3));
        }
        let caller = Caller { uid: 0, pid: 1 };
        enroll(&daemon, caller, &user, 4).unwrap();
        let before = daemon
            .store
            .lock()
            .unwrap()
            .match_threshold(&user)
            .unwrap()
            .unwrap();

        // No face on camera: a clean non-match.
        {
            let mut cam = daemon.camera.lock().unwrap();
            cam.set_mock_face_every(None);
        }
        let result = verify(&daemon, caller, &user, "test-service", 2000, false).unwrap();
        assert!(!result.matched);

        let after = daemon
            .store
            .lock()
            .unwrap()
            .match_threshold(&user)
            .unwrap()
            .unwrap();
        assert_eq!(
            before, after,
            "failed attempts must not change the threshold"
        );
    }

    #[test]
    fn camera_budget_exhaustion_rates_limits_verify() {
        let daemon = test_daemon();
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let user = me.name.clone();
        arm_login(&daemon, &user);
        {
            let mut cam = daemon.camera.lock().unwrap();
            cam.set_mock_face_every(Some(3));
        }
        let caller = Caller { uid: 0, pid: 1 };
        enroll(&daemon, caller, &user, 2).unwrap();

        // Exhaust the per-user camera budget (default 15s / 60s).
        {
            let mut policy = daemon.policy.lock().unwrap();
            for _ in 0..10 {
                policy.record_camera_time(&user, std::time::Duration::from_secs(2));
            }
        }
        let err = verify(&daemon, caller, &user, "test-service", 5000, false).unwrap_err();
        assert!(
            matches!(err, AuthError::RateLimited),
            "over-budget verify must be rate limited: {err:?}"
        );
    }

    /// Verify without templates is a fast fail.
    #[test]
    fn verify_without_templates_is_fast_fail() {
        let daemon = test_daemon();
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        arm_login(&daemon, &me.name);
        let caller = Caller { uid: 0, pid: 1 };
        let result = verify(&daemon, caller, &me.name, "test-service", 5000, false).unwrap();
        assert!(!result.matched);
        assert_eq!(result.reason, "no_templates");
    }

    #[test]
    fn verify_for_unknown_user_fails() {
        let daemon = test_daemon();
        let caller = Caller { uid: 0, pid: 1 };
        let err = verify(
            &daemon,
            caller,
            "definitely-not-a-user-xyz",
            "x",
            1000,
            false,
        )
        .unwrap_err();
        assert!(
            matches!(err, AuthError::NoSuchUser(_)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn non_root_cannot_act_for_others() {
        let daemon = test_daemon();
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let caller = Caller { uid: 65534, pid: 1 };
        let err = verify(&daemon, caller, &me.name, "x", 1000, false).unwrap_err();
        assert!(matches!(err, AuthError::Denied(_)));
    }

    #[test]
    fn face_auth_gated_until_password_login_after_boot() {
        let daemon = test_daemon();
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let user = me.name.clone();
        let caller = Caller { uid: 0, pid: 1 };

        // Not logged in since boot: face auth is a clean non-match
        // (password fallback), and enrollment is refused too.
        let result = verify(&daemon, caller, &user, "gdm-password", 1000, false).unwrap();
        assert!(!result.matched);
        assert!(result.camera_ok, "gate must not blame the camera");
        assert_eq!(result.reason, "password_required");
        let err = enroll(&daemon, caller, &user, 4).unwrap_err();
        assert!(err.contains("password"), "unexpected enroll error: {err}");

        // Recording a login arms face auth for the rest of the boot.
        arm_login(&daemon, &user);
        let result = verify(&daemon, caller, &user, "gdm-password", 1000, false).unwrap();
        assert!(!result.matched, "no templates yet: {result:?}");
        assert_eq!(result.reason, "no_templates");
        {
            let mut cam = daemon.camera.lock().unwrap();
            cam.set_mock_face_every(Some(3));
        }
        let enrolled = enroll(&daemon, caller, &user, 4).unwrap();
        assert!(enrolled.added >= 1, "enroll failed: {:?}", enrolled.reports);

        // A second login record is idempotent and does not error.
        record_login(&daemon, caller, &user, "gdm-password").unwrap();
    }

    #[test]
    fn after_reboot_gate_can_be_disabled() {
        let daemon = test_daemon();
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let user = me.name.clone();
        {
            let mut cfg = daemon.cfg.write().unwrap();
            cfg.security.require_password_after_boot = false;
        }
        // Without the gate, face auth proceeds even with no login recorded.
        let caller = Caller { uid: 0, pid: 1 };
        let result = verify(&daemon, caller, &user, "x", 1000, false).unwrap();
        assert!(!result.matched);
        assert_eq!(result.reason, "no_templates");
    }

    #[test]
    fn record_login_requires_authorization() {
        let daemon = test_daemon();
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        // A different-uid non-root caller is denied.
        let stranger = Caller { uid: 65534, pid: 1 };
        let err = record_login(&daemon, stranger, &me.name, "x")
            .unwrap_err()
            .to_string();
        assert!(err.contains("denied"), "unexpected: {err}");
        // A same-uid non-root caller is denied too: arming face auth for a
        // boot must come from the root PAM session hook, not from any
        // process running as the user (the after-reboot gate would be
        // meaningless if malware in the session could arm it).
        let same_uid = Caller {
            uid: me.uid.as_raw(),
            pid: 31_337,
        };
        let err = record_login(&daemon, same_uid, &me.name, "x")
            .unwrap_err()
            .to_string();
        assert!(err.contains("denied"), "unexpected: {err}");
        // Unknown users are rejected even by root.
        let err = record_login(&daemon, Caller { uid: 0, pid: 1 }, "nobody-xyz", "x")
            .unwrap_err()
            .to_string();
        assert!(err.contains("no such user"), "unexpected: {err}");
    }

    /// Enroll `user` with the mock face, arm a sealed login password, and
    /// enable keyring unlock for `gdm-password`. Liveness is disabled: the
    /// deterministic mock's landmark motion is marginal from one verify to
    /// the next, and these tests exercise the password-release path, not
    /// the anti-spoof gate.
    fn arm_keyring(daemon: &SharedDaemon, user: &str) {
        arm_login(daemon, user);
        {
            let mut cfg = daemon.cfg.write().unwrap();
            cfg.keyring.enabled = true;
            cfg.keyring.services = vec!["gdm-password".into()];
            cfg.recognition.enable_liveness = false;
        }
        {
            let mut cam = daemon.camera.lock().unwrap();
            cam.set_mock_face_every(Some(3));
        }
        enroll(daemon, Caller { uid: 0, pid: 1 }, user, 4).unwrap();
        let ciphertext = daemon.km.seal(user.as_bytes(), b"login-password").unwrap();
        let store = daemon.store.lock().unwrap();
        store.set_login_secret(user, Some(&ciphertext)).unwrap();
    }

    #[test]
    fn keyring_password_released_only_when_armed() {
        // The account check passes, so the sealed password can be released.
        let daemon = test_daemon_with_checker(true);
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let user = me.name.clone();
        arm_keyring(&daemon, &user);
        let caller = Caller { uid: 0, pid: 1 };

        // Listed service + want_keyring: the password is released.
        let result = verify(&daemon, caller, &user, "gdm-password", 5000, true).unwrap();
        assert!(result.matched);
        assert_eq!(result.keyring_password.as_deref(), Some("login-password"));

        // Not requested: stays sealed.
        let result = verify(&daemon, caller, &user, "gdm-password", 5000, false).unwrap();
        assert!(result.matched);
        assert!(result.keyring_password.is_none());

        // Service not listed: stays sealed.
        let result = verify(&daemon, caller, &user, "sudo", 5000, true).unwrap();
        assert!(result.matched);
        assert!(result.keyring_password.is_none());
    }

    #[test]
    fn keyring_password_never_released_when_stale_or_disabled() {
        // The account check fails (password changed since enrollment): face
        // login must still succeed, with the keyring password withheld.
        let daemon = test_daemon_with_checker(false);
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let user = me.name.clone();
        arm_keyring(&daemon, &user);
        let caller = Caller { uid: 0, pid: 1 };

        let result = verify(&daemon, caller, &user, "gdm-password", 5000, true).unwrap();
        assert!(result.matched, "face login must keep working: {result:?}");
        assert!(result.keyring_password.is_none());

        // Feature disabled daemon-side: not released either.
        {
            let mut cfg = daemon.cfg.write().unwrap();
            cfg.keyring.enabled = false;
        }
        let result = verify(&daemon, caller, &user, "gdm-password", 5000, true).unwrap();
        assert!(result.matched);
        assert!(result.keyring_password.is_none());
    }

    #[test]
    fn keyring_password_not_released_without_match() {
        let daemon = test_daemon_with_checker(true);
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let user = me.name.clone();
        arm_keyring(&daemon, &user);
        // No face after enrollment.
        {
            let mut cam = daemon.camera.lock().unwrap();
            cam.set_mock_face_every(None);
        }
        let caller = Caller { uid: 0, pid: 1 };
        let result = verify(&daemon, caller, &user, "gdm-password", 2000, true).unwrap();
        assert!(!result.matched);
        assert!(result.keyring_password.is_none());
    }

    /// H-2 regression: a process running as the user (same uid, not root)
    /// asking for the login password on a bypass-listed keyring service
    /// must never receive it — even with a matching face in front of the
    /// camera. Before the root-only-release fix, this returned the
    /// plaintext login password.
    #[test]
    fn non_root_caller_cannot_harvest_keyring_password() {
        let daemon = test_daemon_with_checker(true);
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let user = me.name.clone();
        arm_keyring(&daemon, &user);
        // The attacker runs as the user, not as root.
        let caller = Caller {
            uid: me.uid.as_raw(),
            pid: 31_337,
        };
        let result = verify(&daemon, caller, &user, "gdm-password", 5000, true).unwrap();
        assert!(result.matched, "face should match: {result:?}");
        assert!(
            result.keyring_password.is_none(),
            "same-uid callers must never receive the login password: {result:?}"
        );
    }

    /// Background thread that flips the pending approval for `user` to
    /// `decided` after `delay_ms` — simulating the user clicking
    /// Allow/Deny in the status indicator (possibly after stepping away
    /// and back).
    fn spawn_decider(
        daemon: &SharedDaemon,
        user: &str,
        allow: bool,
        delay_ms: u64,
    ) -> std::thread::JoinHandle<()> {
        let daemon = daemon.clone();
        let user = user.to_string();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while std::time::Instant::now() < deadline {
                {
                    let mut approvals = daemon.approvals.lock().unwrap();
                    for p in approvals.values_mut() {
                        if p.user == user {
                            p.decided = Some(allow);
                            return;
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        })
    }

    /// Non-login services must pause for an explicit decision after a
    /// confident match; login screens and `hiro test` stay instant. The
    /// bypass list is honoured only for root callers (the real PAM login
    /// stacks) — a same-uid process must not be able to claim a bypass
    /// service to skip the gate on its own request.
    #[test]
    fn approval_required_flags_non_login_services() {
        let daemon = test_daemon();
        {
            let mut cfg = daemon.cfg.write().unwrap();
            cfg.approval.enabled = true;
        }
        let root = Caller { uid: 0, pid: 1 };
        let user = Caller { uid: 1000, pid: 2 };
        assert!(approval_required(&daemon, "sudo", root));
        assert!(approval_required(&daemon, "su", root));
        assert!(!approval_required(&daemon, "gdm-password", root));
        assert!(!approval_required(&daemon, "lightdm", root));
        assert!(!approval_required(&daemon, "hiro-test", root));
        // Same-uid callers cannot claim a bypass-listed service...
        assert!(approval_required(&daemon, "gdm-password", user));
        // ...but the designated self-test service stays exempt.
        assert!(!approval_required(&daemon, "hiro-test", user));
        {
            let mut cfg = daemon.cfg.write().unwrap();
            cfg.approval.enabled = false;
        }
        assert!(!approval_required(&daemon, "sudo", root));
    }

    /// A sudo-style request parks after the match and completes only once
    /// the user allows it.
    #[test]
    fn approval_granted_when_user_allows() {
        let daemon = test_daemon();
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let user = me.name.clone();
        arm_login(&daemon, &user);
        {
            let mut cfg = daemon.cfg.write().unwrap();
            cfg.approval.enabled = true;
            cfg.recognition.enable_liveness = false;
        }
        {
            let mut cam = daemon.camera.lock().unwrap();
            cam.set_mock_face_every(Some(3));
        }
        let caller = Caller { uid: 0, pid: 1 };
        enroll(&daemon, caller, &user, 4).unwrap();

        let decider = spawn_decider(&daemon, &user, true, 0);
        let result = verify(&daemon, caller, &user, "sudo", 5000, false).unwrap();
        assert!(
            result.matched,
            "approval should have been granted: {result:?}"
        );
        assert_eq!(result.reason, "approved");
        decider.join().unwrap();
    }

    /// An explicit Deny turns the matched face into a clean non-match.
    #[test]
    fn approval_denied_when_user_denies() {
        let daemon = test_daemon();
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let user = me.name.clone();
        arm_login(&daemon, &user);
        {
            let mut cfg = daemon.cfg.write().unwrap();
            cfg.approval.enabled = true;
            cfg.recognition.enable_liveness = false;
        }
        {
            let mut cam = daemon.camera.lock().unwrap();
            cam.set_mock_face_every(Some(3));
        }
        let caller = Caller { uid: 0, pid: 1 };
        enroll(&daemon, caller, &user, 4).unwrap();

        let decider = spawn_decider(&daemon, &user, false, 0);
        let result = verify(&daemon, caller, &user, "sudo", 5000, false).unwrap();
        assert!(!result.matched, "denial must fail the request: {result:?}");
        assert_eq!(result.reason, "approval_denied");
        decider.join().unwrap();
    }

    /// If the user never decides, the window expires and the request fails.
    #[test]
    fn approval_times_out_without_decision() {
        let daemon = test_daemon();
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let user = me.name.clone();
        arm_login(&daemon, &user);
        {
            let mut cfg = daemon.cfg.write().unwrap();
            cfg.approval.enabled = true;
            cfg.approval.timeout_ms = 150;
            cfg.recognition.enable_liveness = false;
        }
        {
            let mut cam = daemon.camera.lock().unwrap();
            cam.set_mock_face_every(Some(3));
        }
        let caller = Caller { uid: 0, pid: 1 };
        enroll(&daemon, caller, &user, 4).unwrap();

        let result = verify(&daemon, caller, &user, "sudo", 5000, false).unwrap();
        assert!(
            !result.matched,
            "undecided approval must time out: {result:?}"
        );
        assert_eq!(result.reason, "approval_timeout");
    }

    /// Walk-away is not an automatic failure: the prompt hides, but the
    /// request keeps waiting and is only denied when the window actually
    /// times out. The mock emits a face every 3rd frame, so right after
    /// the match (which lands on a face frame) two noise frames follow:
    /// with `absent_frames = 2` the daemon detects the user stepping away
    /// almost immediately, yet the request must still run out its window
    /// instead of failing at once.
    #[test]
    fn approval_keeps_waiting_when_user_steps_away() {
        let daemon = test_daemon();
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let user = me.name.clone();
        arm_login(&daemon, &user);
        {
            let mut cfg = daemon.cfg.write().unwrap();
            cfg.approval.enabled = true;
            cfg.approval.absent_frames = 2;
            cfg.approval.timeout_ms = 400;
            cfg.recognition.enable_liveness = false;
        }
        {
            let mut cam = daemon.camera.lock().unwrap();
            cam.set_mock_face_every(Some(3));
        }
        let caller = Caller { uid: 0, pid: 1 };
        enroll(&daemon, caller, &user, 4).unwrap();

        let result = verify(&daemon, caller, &user, "sudo", 5000, false).unwrap();
        assert!(!result.matched, "the window must run out: {result:?}");
        assert_eq!(result.reason, "approval_timeout");
        assert!(
            result.elapsed_ms >= 300,
            "walk-away must not fail instantly (elapsed_ms={})",
            result.elapsed_ms
        );
    }

    /// If the user steps away and comes back, the prompt returns and they
    /// can still allow the request — the decision only fails at the window
    /// timeout, never at a walk-away.
    #[test]
    fn approval_resumes_after_user_returns() {
        let daemon = test_daemon();
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let user = me.name.clone();
        arm_login(&daemon, &user);
        {
            let mut cfg = daemon.cfg.write().unwrap();
            cfg.approval.enabled = true;
            cfg.approval.absent_frames = 2;
            cfg.recognition.enable_liveness = false;
        }
        {
            let mut cam = daemon.camera.lock().unwrap();
            cam.set_mock_face_every(Some(3));
        }
        let caller = Caller { uid: 0, pid: 1 };
        enroll(&daemon, caller, &user, 4).unwrap();

        // Decide only after the absence→return cycle has happened (the
        // mock flips to noise, then back to a face, within a few frames).
        let decider = spawn_decider(&daemon, &user, true, 150);
        let result = verify(&daemon, caller, &user, "sudo", 5000, false).unwrap();
        assert!(
            result.matched,
            "returning user must still be able to allow: {result:?}"
        );
        assert_eq!(result.reason, "approved");
        decider.join().unwrap();
    }

    /// Login-screen services skip the approval gate entirely: the match
    /// completes instantly with the normal `match` reason.
    #[test]
    fn login_service_bypasses_approval() {
        let daemon = test_daemon();
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let user = me.name.clone();
        arm_login(&daemon, &user);
        {
            let mut cfg = daemon.cfg.write().unwrap();
            cfg.approval.enabled = true;
            cfg.recognition.enable_liveness = false;
        }
        {
            let mut cam = daemon.camera.lock().unwrap();
            cam.set_mock_face_every(Some(3));
        }
        let caller = Caller { uid: 0, pid: 1 };
        enroll(&daemon, caller, &user, 4).unwrap();

        let result = verify(&daemon, caller, &user, "gdm-password", 5000, false).unwrap();
        assert!(result.matched, "login must stay instant: {result:?}");
        assert_eq!(result.reason, "match");
    }
}
