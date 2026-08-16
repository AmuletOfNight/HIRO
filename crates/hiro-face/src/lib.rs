//! Face detection + embedding pipeline.
//!
//! [`FacePipeline`] is the abstraction the daemon matches against. Two
//! implementations are provided:
//!
//! * `OnnxPipeline` (feature `onnx`) — SCRFD detection + ArcFace-class
//!   embedding via ONNX Runtime.
//! * [`StubPipeline`] — deterministic synthetic pipeline used by the test
//!   suite and for smoke-testing a fresh installation without model files.

pub mod align;
pub mod models;
pub mod preprocess;
pub mod stub;

#[cfg(feature = "onnx")]
pub mod onnx;

use hiro_core::{config::RecognitionConfig, CoreError, Embedding};

pub type FaceResult<T> = std::result::Result<T, FaceError>;

#[derive(Debug, thiserror::Error)]
pub enum FaceError {
    #[error("pipeline unavailable: {0}")]
    Unavailable(String),
    #[error("pipeline failed: {0}")]
    Pipeline(String),
    #[error("model integrity failed: {0}")]
    Integrity(String),
    #[error("config error: {0}")]
    Config(String),
}

impl From<FaceError> for CoreError {
    fn from(e: FaceError) -> Self {
        match e {
            FaceError::Config(m) => CoreError::config(m),
            FaceError::Integrity(m) => CoreError::config(m),
            other => CoreError::internal(other.to_string()),
        }
    }
}

/// One detected face in a frame, with its embedding.
#[derive(Debug, Clone)]
pub struct FaceHit {
    pub embedding: Embedding,
    /// Five facial landmarks: right eye, left eye, nose, right mouth
    /// corner, left mouth corner (as in SCRFD). Normalized [0,1] in frame.
    pub landmarks: [[f32; 2]; 5],
    /// Bounding box [x0, y0, x1, y1], normalized [0,1] in frame.
    pub bbox: [f32; 4],
    /// Detector confidence.
    pub det_score: f32,
}

/// Runs detection + embedding on grayscale frames.
pub trait FacePipeline: Send + Sync {
    /// Analyze one frame. `luma` is a `width * height` grayscale buffer.
    /// Returns the best-scoring face hit, or `Ok(None)` when no face is
    /// present.
    fn process(&self, luma: &[u8], width: u32, height: u32) -> FaceResult<Option<FaceHit>>;

    fn name(&self) -> &str;

    fn loaded(&self) -> bool;
}

/// Build the pipeline for `config`.
///
/// * `detector == "stub"` (or the `onnx` feature is off) yields the
///   [`stub::StubPipeline`].
/// * Otherwise an ONNX pipeline is attempted; a missing or corrupted model
///   store is a hard error (fail closed) unless `stub` was requested.
pub fn create(config: &RecognitionConfig) -> FaceResult<Box<dyn FacePipeline>> {
    if config.detector == "stub" {
        return Ok(Box::new(stub::StubPipeline::new()));
    }
    #[cfg(feature = "onnx")]
    {
        let pipeline = onnx::OnnxPipeline::new(config)?;
        Ok(Box::new(pipeline))
    }
    #[cfg(not(feature = "onnx"))]
    {
        let _ = config;
        Err(FaceError::Unavailable(
            "ONNX inference was not compiled in (rebuild with --features onnx); \
             set recognition.detector = \"stub\" for smoke tests"
                .into(),
        ))
    }
}
