//! HIRO shared core: configuration, IPC protocol, camera identity, embeddings.

pub mod camera;
pub mod config;
pub mod embed;
pub mod error;
pub mod proto;

pub use camera::CameraIdentity;
pub use config::Config;
pub use embed::{constant_time_match, Embedding};
pub use error::{CoreError, Result};

/// Protocol version. Bump on incompatible wire-format changes.
pub const PROTOCOL_VERSION: u8 = 1;

/// HIRO version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
