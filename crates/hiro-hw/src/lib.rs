//! Camera discovery, capture, and IR emitter control.
//!
//! HIRO targets the class of Windows Hello IR cameras that appear as
//! standard V4L2 capture nodes under the `uvcvideo` kernel driver. This
//! crate provides:
//!
//! * [`discover`] — enumeration of `/dev/video*` nodes with IR heuristics.
//! * [`capture`] — a [`VideoSource`] abstraction with a real V4L2 mmap
//!   implementation and a deterministic mock for tests.
//! * [`emitter`] — activation of the camera's 850 nm IR emitter via UVC
//!   extension-unit control (quirks DB) with a `linux-enable-ir-emitter`
//!   fallback.
//! * [`frame`] — frame representation and lightweight quality/liveness
//!   statistics shared with the daemon.

pub mod capture;
pub mod discover;
pub mod emitter;
pub mod frame;
pub mod mock;
pub mod quirks;

mod mock_util;

pub use capture::{V4lSource, VideoSource};
pub use emitter::Emitter;
pub use frame::Frame;

use hiro_core::CoreError;

pub type HwResult<T> = std::result::Result<T, HwError>;

#[derive(Debug, thiserror::Error)]
pub enum HwError {
    #[error("camera error: {0}")]
    Camera(String),
    #[error("no usable camera found")]
    NoCamera,
    #[error("camera busy: {0}")]
    Busy(String),
    #[error("unsupported format: {0}")]
    UnsupportedFormat(String),
    #[error("emitter error: {0}")]
    Emitter(String),
    #[error("invalid argument: {0}")]
    Invalid(String),
}

impl From<HwError> for CoreError {
    fn from(e: HwError) -> Self {
        CoreError::io(e.to_string())
    }
}
