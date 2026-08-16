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

/// Run a face-verification attempt for `user`.
pub fn verify(
    daemon: &SharedDaemon,
    caller: Caller,
    user: &str,
    service: &str,
    timeout_ms: u64,
) -> Result<VerifyResult, String> {
    let started = Instant::now();
    crate::state::broadcast_state(daemon, &StateEvent::scanning(user));
    match verify_inner(daemon, caller, user, service, timeout_ms) {
        Ok(mut result) => {
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
                    user: Some(user.into()),
                    score: result.score,
                    reason: Some(result.reason.clone()),
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
                    user: Some(user.into()),
                    score: None,
                    reason: Some(e.to_string()),
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

    {
        let mut policy = daemon
            .policy
            .lock()
            .map_err(|_| AuthError::Internal("policy lock poisoned".into()))?;
        match policy.check(user) {
            PolicyVerdict::Allow => {}
            PolicyVerdict::RateLimited => return Err(AuthError::RateLimited),
            PolicyVerdict::LockedOut => return Err(AuthError::LockedOut),
        }
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
                        camera.release();
                        let liveness_ok = !liveness_enabled
                            || (variance.max_diff >= min_variance
                                && motion.max_motion >= min_motion);
                        if !liveness_ok {
                            return Ok(VerifyResult {
                                matched: false,
                                user: user.into(),
                                score: None,
                                template_id: None,
                                frames_analyzed,
                                liveness_ok: false,
                                camera_ok: true,
                                elapsed_ms: 0,
                                reason: "liveness_failed".into(),
                            });
                        }
                        return Ok(VerifyResult {
                            matched: true,
                            user: user.into(),
                            score: best_score,
                            template_id: best_template,
                            frames_analyzed,
                            liveness_ok: true,
                            camera_ok: true,
                            elapsed_ms: 0,
                            reason: "match".into(),
                        });
                    }
                }
            }
        }
    }

    camera.release();
    let reason = if !saw_face { "no_face" } else { "no_match" };
    Ok(VerifyResult {
        matched: false,
        user: user.into(),
        score: best_score,
        template_id: best_template,
        frames_analyzed,
        liveness_ok: variance.max_diff >= min_variance && motion.max_motion >= min_motion,
        camera_ok: true,
        elapsed_ms: 0,
        reason: reason.into(),
    })
}

/// Capture and store new face templates for `user`.
pub fn enroll(
    daemon: &SharedDaemon,
    caller: Caller,
    user: &str,
    max_models: usize,
) -> Result<EnrollResult, String> {
    let started = Instant::now();
    crate::state::broadcast_state(daemon, &StateEvent::scanning(user));
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
    let deadline = Duration::from_secs(60);

    let loop_start = Instant::now();
    while candidates.len() < target
        && frames_analyzed < max_frames
        && loop_start.elapsed() < deadline
    {
        let frame = match camera.next_frame(Duration::from_millis(250)) {
            Ok(Some(f)) => f,
            Ok(None) => continue,
            Err(e) => return Err(e.to_string()),
        };
        frames_analyzed += 1;
        let Some(gray) = frame.to_gray() else {
            rejected += 1;
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
                log::debug!(
                    "enroll frame rejected: face not found (mean={:.1})",
                    gray.iter().map(|&v| f64::from(v)).sum::<f64>() / gray.len() as f64
                );
                continue;
            }
            Err(e) => return Err(format!("pipeline failed: {e}")),
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
            continue;
        }
        if sharpness < min_sharpness {
            log::debug!("enroll frame rejected: blurry ({sharpness:.1})");
            rejected += 1;
            continue;
        }
        if diff < min_variance {
            log::debug!("enroll frame rejected: static scene ({diff:.1})");
            rejected += 1;
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
                "added={added} rejected={rejected} frames={frames_analyzed} elapsed_ms={}",
                started.elapsed().as_millis()
            ),
        );
    }
    crate::state::broadcast_state(
        daemon,
        &StateEvent {
            state: if added > 0 { "success" } else { "failure" }.into(),
            user: Some(user.into()),
            score: None,
            reason: Some(format!("added={added}")),
        },
    );

    Ok(EnrollResult {
        added,
        rejected,
        template_ids,
        reports,
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
    use crate::state::Daemon;

    fn test_daemon() -> SharedDaemon {
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
        let result = verify(&daemon, caller, &user, "test-service", 5000).unwrap();
        assert!(result.matched, "verify failed: {result:?}");
        assert!(result.liveness_ok, "liveness should pass: {result:?}");
        assert!(result.frames_analyzed >= 3);

        // A camera with no face must not match.
        {
            let mut cam = daemon.camera.lock().unwrap();
            cam.set_mock_face_every(None);
        }
        let result = verify(&daemon, caller, &user, "test-service", 2000).unwrap();
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
        let result = verify(&daemon, caller, &me.name, "test-service", 5000).unwrap();
        assert!(!result.matched);
        assert_eq!(result.reason, "no_templates");
    }

    #[test]
    fn verify_for_unknown_user_fails() {
        let daemon = test_daemon();
        let caller = Caller { uid: 0, pid: 1 };
        let err = verify(&daemon, caller, "definitely-not-a-user-xyz", "x", 1000).unwrap_err();
        assert!(err.contains("no such user"), "unexpected error: {err}");
    }

    #[test]
    fn non_root_cannot_act_for_others() {
        let daemon = test_daemon();
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let caller = Caller { uid: 65534, pid: 1 };
        let err = verify(&daemon, caller, &me.name, "x", 1000).unwrap_err();
        assert!(err.contains("denied"));
    }
}
