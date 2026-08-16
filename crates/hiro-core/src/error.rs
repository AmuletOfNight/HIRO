#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Config,
    Proto,
    InvalidInput,
    Io,
    Internal,
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config => write!(f, "config"),
            Self::Proto => write!(f, "protocol"),
            Self::InvalidInput => write!(f, "invalid-input"),
            Self::Io => write!(f, "io"),
            Self::Internal => write!(f, "internal"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{kind}: {message}")]
pub struct CoreError {
    pub kind: ErrorKind,
    pub message: String,
}

impl CoreError {
    pub fn config(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Config,
            message: message.into(),
        }
    }

    pub fn proto(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Proto,
            message: message.into(),
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::InvalidInput,
            message: message.into(),
        }
    }

    pub fn io(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Io,
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Internal,
            message: message.into(),
        }
    }
}

pub type Result<T> = std::result::Result<T, CoreError>;
