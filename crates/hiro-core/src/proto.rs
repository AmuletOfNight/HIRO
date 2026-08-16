//! Versioned IPC protocol between clients (`pam_hiro.so`, `hiro` CLI) and
//! the `hirod` daemon. Framing is newline-delimited JSON over a Unix
//! stream socket; authorization happens out-of-band via SO_PEERCRED.

use serde::{Deserialize, Serialize};

use crate::{CameraIdentity, Embedding};

/// A request from a client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// Wire-protocol version (`crate::PROTOCOL_VERSION`).
    pub v: u8,
    /// Client-chosen correlation id, echoed in the response.
    pub id: u64,
    /// Flattened so the operation tag sits at the top level:
    /// `{"v":1,"id":0,"op":"watch", ...}`.
    #[serde(flatten)]
    pub op: Op,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    Ping,
    Verify {
        /// Login name of the user whose face should be checked.
        user: String,
        /// PAM service making the request, for audit purposes.
        service: String,
        /// Per-attempt cap in milliseconds; clamped daemon-side.
        timeout_ms: u64,
    },
    Enroll {
        user: String,
        /// Maximum number of new templates to store.
        max_models: usize,
    },
    Status,
    List {
        user: String,
    },
    Remove {
        user: String,
        template_id: i64,
    },
    Clear {
        user: String,
    },
    /// Capture one frame and write it (PNG) to the given path. Debug aid.
    Snapshot {
        path: String,
    },
    Reload,
    Prewarm,
    /// Subscribe to authentication state events. The daemon keeps the
    /// connection open and streams newline-delimited [`StateEvent`] JSON.
    Watch,
}

/// A response from the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub v: u8,
    pub id: u64,
    #[serde(flatten)]
    pub outcome: Outcome,
}

impl Response {
    pub fn ok(id: u64, result: ResultValue) -> Self {
        Self {
            v: crate::PROTOCOL_VERSION,
            id,
            outcome: Outcome::Ok { result },
        }
    }

    pub fn err(id: u64, error: impl Into<String>) -> Self {
        Self {
            v: crate::PROTOCOL_VERSION,
            id,
            outcome: Outcome::Err {
                error: error.into(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "ok", rename_all = "snake_case")]
pub enum Outcome {
    Ok { result: ResultValue },
    Err { error: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResultValue {
    Pong { daemon: String },
    Verify(VerifyResult),
    Enroll(EnrollResult),
    Status(StatusResult),
    List { templates: Vec<TemplateInfo> },
    Removed { id: i64 },
    Cleared { count: usize },
    Snapshot { path: String },
    Reloaded,
    Prewarmed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    pub matched: bool,
    pub user: String,
    /// Best cosine similarity observed; `None` when no face was seen.
    pub score: Option<f32>,
    pub template_id: Option<i64>,
    pub frames_analyzed: u32,
    pub liveness_ok: bool,
    pub camera_ok: bool,
    pub elapsed_ms: u64,
    /// Human-readable explanation of the verdict.
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResult {
    pub added: usize,
    pub rejected: usize,
    pub template_ids: Vec<i64>,
    pub reports: Vec<QualityReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityReport {
    pub face_found: bool,
    /// Laplacian-variance sharpness estimate of the captured frame.
    pub sharpness: f32,
    /// Temporal pixel variance across the capture window (liveness input).
    pub variance: f32,
    /// Fraction of frame area occupied by the face bounding box.
    pub size_ratio: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResult {
    pub version: String,
    pub camera: Option<String>,
    pub driver: Option<String>,
    pub ir_detected: Option<bool>,
    pub emitter_active: Option<bool>,
    pub models_loaded: bool,
    pub pipeline: String,
    pub templates: usize,
    pub tpm_available: Option<bool>,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateInfo {
    pub id: i64,
    pub created_at: i64,
    pub quality: Option<f32>,
    pub device: Option<String>,
}

/// Payload carried daemon-side with a captured, processed frame.
#[derive(Debug, Clone)]
pub struct FrameArtifacts {
    pub embedding: Option<Embedding>,
    /// Detection landmarks, when the detector produced a face.
    pub landmarks: Option<[[f32; 2]; 5]>,
    pub face_rect: Option<[f32; 4]>,
    pub sharpness: f32,
    pub variance: f32,
}

impl Default for FrameArtifacts {
    fn default() -> Self {
        Self {
            embedding: None,
            landmarks: None,
            face_rect: None,
            sharpness: 0.0,
            variance: 0.0,
        }
    }
}

/// Camera identity probe result, used by discovery and `hiro doctor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CameraProbe {
    pub path: String,
    pub driver: Option<String>,
    pub card: Option<String>,
    pub bus_info: Option<String>,
    pub identity: CameraIdentity,
    pub is_ir_candidate: bool,
    pub why_ir: String,
    pub captures_video: bool,
    pub formats: Vec<String>,
}

/// Authentication state broadcast to `Op::Watch` subscribers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateEvent {
    /// `idle`, `scanning`, `success`, or `failure`.
    pub state: String,
    pub user: Option<String>,
    pub score: Option<f32>,
    pub reason: Option<String>,
}

impl StateEvent {
    pub fn idle() -> Self {
        Self {
            state: "idle".into(),
            user: None,
            score: None,
            reason: None,
        }
    }

    pub fn scanning(user: &str) -> Self {
        Self {
            state: "scanning".into(),
            user: Some(user.into()),
            score: None,
            reason: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_roundtrip() {
        let req = Request {
            v: 1,
            id: 42,
            op: Op::Verify {
                user: "alice".into(),
                service: "sudo".into(),
                timeout_ms: 3000,
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: Request = serde_json::from_str(&json).unwrap();
        match back.op {
            Op::Verify {
                user,
                service,
                timeout_ms,
            } => {
                assert_eq!(user, "alice");
                assert_eq!(service, "sudo");
                assert_eq!(timeout_ms, 3000);
            }
            _ => panic!("wrong op"),
        }
    }

    #[test]
    fn response_error_roundtrip() {
        let resp = Response::err(7, "no camera");
        let json = serde_json::to_string(&resp).unwrap();
        let back: Response = serde_json::from_str(&json).unwrap();
        assert!(matches!(back.outcome, Outcome::Err { error } if error == "no camera"));
    }

    #[test]
    fn op_tags_are_snake_case() {
        let json = serde_json::to_string(&Request {
            v: 1,
            id: 1,
            op: Op::Snapshot {
                path: "/tmp/x.png".into(),
            },
        })
        .unwrap();
        assert!(json.contains("\"op\":\"snapshot\""), "unexpected: {json}");
    }
}
