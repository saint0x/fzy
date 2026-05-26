//! Crate-wide error types.

use thiserror::Error;

pub type FozzyResult<T> = Result<T, FozzyError>;

#[derive(Debug, Error)]
pub enum FozzyError {
    #[error("config error: {0}")]
    Config(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("toml error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("scenario error: {0}")]
    Scenario(String),

    #[error("trace error: {0}")]
    Trace(String),

    #[error("report error: {0}")]
    Report(String),

    #[error("zip error: {0}")]
    Zip(String),
}

impl From<zip::result::ZipError> for FozzyError {
    fn from(value: zip::result::ZipError) -> Self {
        Self::Zip(value.to_string())
    }
}
