//! Authentication and enrollment flows.

use std::time::{Duration, Instant};

use hiro_core::proto::{EnrollResult, QualityReport, StateEvent, VerifyResult};
use hiro_core::{constant_time_match, Embedding};
use hiro_hw::frame as hwframe;

use crate::audit::audit;
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

fn target_uid(user: &str) -> AuthResult<u32> {
    crate::lookup::uid_of(user).ok_or_else(|| AuthError::NoSuchUser(user.into()))
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
        let plain = daemon
            .km
            .unseal(&row.ciphertext)
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

/// Run a face-verification attempt for `user`.
pub fn verify(
    daemon: &SharedDaemon,
    caller: Caller,
    user: &str,
    service: &str,
    timeout_ms: u64,
    want_keyring: bool,
) -> Result<VerifyResult, String> {
    let started = Instant::now();
    if let Err(err) = policy_gate(daemon, user) {
        // Rejected before any scanning happens; tell watchers right away.
        let reason = match &err {
            AuthError::RateLimited => "rate_limited",
            AuthError::LockedOut => "locked_out",
            _ => "error",
        };
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
            },
        );
        return Err(err.to_string());
    }
    crate::state::broadcast_state(daemon, &StateEvent::scanning(user));
    match verify_inner(daemon, caller, user, service, timeout_ms) {
        Ok(mut result) => {
            if want_keyring {
                attach_keyring_password(daemon, user, service, &mut result);
            }
            result.elapsed_ms = started.elapsed().as_millis() as u64;
            {
                let mut policy = daemon
                    .policy
                    .lock()
                    .map_err(|_| "policy lock poisoned".to_string())?;
                if result.matched {
                    policy.record_success(user);
                } else {
                    policy.record_failure(user);
                }
            }
            {
                let store = daemon
                    .store
                    .lock()
                    .map_err(|_| "store lock poisoned".to_string())?;
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
                },
            );
            Ok(result)
        }
        Err(e) => {
            let store = daemon
                .store
                .lock()
                .map_err(|_| "store lock poisoned".to_string())?;
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
                    reason: Some(e.to_string()),
                    variance: None,
                    motion: None,
                    min_variance: None,
                    min_motion: None,
                    accepted: None,
                    target: None,
                    rejected: None,
                },
            );
            Err(e.to_string())
        }
    }
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
    let threshold = cfg.recognition.match_threshold;
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
        });
    }

    let mut camera = daemon
        .camera
        .lock()
        .map_err(|_| AuthError::Internal("camera lock poisoned".into()))?;
    camera
        .acquire()
        .map_err(|e| AuthError::Camera(e.to_string()))?;

    if !allow_camera_change {
        let current = camera
            .identity()
            .map(|i| i.fingerprint())
            .unwrap_or_else(|| "unknown".into());
        let stored = daemon
            .store
            .lock()
            .map_err(|_| AuthError::Internal("store lock poisoned".into()))?
            .camera_fingerprint(user)
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        if let Some(stored) = stored {
            if stored != current {
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
                });
            }
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
            let satisfied = variance.max_diff >= min_variance
                && motion.max_motion >= min_motion;
            if frames_analyzed % 3 == 0 || (satisfied && !liveness_satisfied) {
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
    let liveness_ok = !liveness_enabled
        || (variance.max_diff >= min_variance && motion.max_motion >= min_motion);
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
    })
}

/// After a verified face match, release the sealed login password so the
/// PAM stack can unlock the login keyring (`pam_gnome_keyring` / KWallet).
///
/// All of these must hold or the password stays sealed:
///
/// * the request explicitly asked for it (`want_keyring`),
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
    user: &str,
    service: &str,
    result: &mut VerifyResult,
) {
    if !result.matched {
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

    let plain = match daemon.km.unseal(&secret) {
        Ok(p) => p,
        Err(e) => {
            log::error!("hiro: cannot unseal keyring password for {user}: {e}");
            return;
        }
    };
    let Ok(password) = String::from_utf8(plain) else {
        log::error!("hiro: sealed keyring password for {user} is not valid UTF-8");
        return;
    };

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

    result.keyring_password = Some(password);
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
    let min_variance = cfg.recognition.liveness_min_variance;
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
        .camera
        .lock()
        .map_err(|_| "camera lock poisoned".to_string())?;
    camera.acquire().map_err(|e| e.to_string())?;

    let current = camera
        .identity()
        .map(|i| i.fingerprint())
        .unwrap_or_else(|| "unknown".into());
    {
        let store = daemon
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        if let Some(stored) = store.camera_fingerprint(user).map_err(|e| e.to_string())? {
            if stored != current {
                camera.release();
                return Err(format!(
                    "camera changed since previous enrollment ({stored} vs {current}); \
                     run `hiro clear` first or set security.allow_camera_change"
                ));
            }
        }
        store
            .set_camera_fingerprint(user, &current)
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

    let loop_start = Instant::now();
    while candidates.len() < target
        && frames_analyzed < max_frames
        && loop_start.elapsed() < deadline
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
            continue;
        };
        let diff = variance.update(&gray);

        let hit = match pipeline.process(&gray, frame.width, frame.height) {
            Ok(Some(h)) => h,
            Ok(None) => {
                rejected += 1;
                note_rejection(&mut primary_reject, "no_face");
                log::debug!(
                    "enroll frame rejected: face not found (mean={:.1})",
                    gray.iter().map(|&v| f64::from(v)).sum::<f64>() / gray.len() as f64
                );
                continue;
            }
            Err(e) => {
                camera.release();
                return Err(format!("pipeline failed: {e}"));
            }
        };

        let bbox = hit.bbox;
        let size_ratio = (bbox[2] - bbox[0]).max(0.0) * (bbox[3] - bbox[1]).max(0.0);
        let sharpness = hwframe::sharpness(&gray, frame.width, frame.height).unwrap_or(0.0);
        let report = QualityReport {
            face_found: true,
            sharpness,
            variance: diff,
            size_ratio,
        };

        if size_ratio < min_area {
            log::debug!("enroll frame rejected: face too small ({size_ratio:.3})");
            rejected += 1;
            note_rejection(&mut primary_reject, "face_too_small");
            continue;
        }
        if sharpness < min_sharpness {
            log::debug!("enroll frame rejected: blurry ({sharpness:.1})");
            rejected += 1;
            note_rejection(&mut primary_reject, "blurry");
            continue;
        }
        if diff < min_variance {
            log::debug!("enroll frame rejected: static scene ({diff:.1})");
            rejected += 1;
            note_rejection(&mut primary_reject, "static_scene");
            continue;
        }
        let too_similar = existing_templates.iter().any(|t| {
            hit.embedding
                .cosine(&t.embedding)
                .is_some_and(|s| s > dedupe_threshold)
        }) || candidates.iter().any(|(e, _)| {
            hit.embedding
                .cosine(e)
                .is_some_and(|s| s > dedupe_threshold)
        });
        if too_similar {
            log::debug!("enroll frame rejected: duplicate pose");
            rejected += 1;
            note_rejection(&mut primary_reject, "duplicate_pose");
            continue;
        }
        candidates.push((hit.embedding, report));
        log::info!(
            "enroll frame accepted ({}/{}): sharpness={:.1} size={:.3}",
            candidates.len(),
            target,
            sharpness,
            size_ratio
        );
        crate::state::broadcast_state(
            daemon,
            &StateEvent {
                state: "scanning".into(),
                op: "enroll".into(),
                user: Some(user.into()),
                score: None,
                reason: None,
                variance: None,
                motion: None,
                min_variance: None,
                min_motion: None,
                accepted: Some(candidates.len()),
                target: Some(target),
                rejected: None,
            },
        );
    }

    let mut template_ids = Vec::new();
    let mut reports = Vec::new();
    let added = candidates.len();
    let store = daemon
        .store
        .lock()
        .map_err(|_| "store lock poisoned".to_string())?;
    for (embedding, report) in &candidates {
        let ciphertext = daemon
            .km
            .seal(&embedding.serialize())
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
    use crate::state::{Daemon, PasswordChecker};

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

    fn test_daemon_with_checker(passwords_ok: bool) -> SharedDaemon {
        let mut cfg = Config::default();
        cfg.recognition.detector = "stub".into();
        cfg.recognition.match_threshold = 0.90;
        cfg.recognition.quorum_frames = 2;
        cfg.camera.max_frames = 20;
        cfg.camera.width = 64;
        cfg.camera.height = 48;
        cfg.device.require_ir = false;

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

    #[test]
    fn verify_without_templates_is_fast_fail() {
        let daemon = test_daemon();
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
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
        assert!(err.contains("no such user"), "unexpected error: {err}");
    }

    #[test]
    fn non_root_cannot_act_for_others() {
        let daemon = test_daemon();
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let caller = Caller { uid: 65534, pid: 1 };
        let err = verify(&daemon, caller, &me.name, "x", 1000, false).unwrap_err();
        assert!(err.contains("denied"));
    }

    /// Enroll `user` with the mock face, arm a sealed login password, and
    /// enable keyring unlock for `gdm-password`. Liveness is disabled: the
    /// deterministic mock's landmark motion is marginal from one verify to
    /// the next, and these tests exercise the password-release path, not
    /// the anti-spoof gate.
    fn arm_keyring(daemon: &SharedDaemon, user: &str) {
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
        let ciphertext = daemon.km.seal(b"login-password").unwrap();
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
}
