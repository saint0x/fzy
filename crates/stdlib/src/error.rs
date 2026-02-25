use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidInput,
    NotFound,
    Conflict,
    Timeout,
    Io,
    Internal,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::Timeout => "timeout",
            Self::Io => "io",
            Self::Internal => "internal",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreError {
    code: ErrorCode,
    message: String,
    contexts: Vec<String>,
}

impl CoreError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            contexts: Vec::new(),
        }
    }

    pub fn code(&self) -> ErrorCode {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn contexts(&self) -> &[String] {
        &self.contexts
    }

    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.contexts.push(context.into());
        self
    }

    pub fn push_context(&mut self, context: impl Into<String>) {
        self.contexts.push(context.into());
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)?;
        if !self.contexts.is_empty() {
            write!(f, " [{}]", self.contexts.join(" -> "))?;
        }
        Ok(())
    }
}

impl std::error::Error for CoreError {}

pub type CoreResult<T> = Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::{CoreError, ErrorCode};

    #[test]
    fn core_error_tracks_context_chain() {
        let err = CoreError::new(ErrorCode::NotFound, "record missing")
            .with_context("lookup user:42")
            .with_context("api GET /v1/user/42");
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert_eq!(err.contexts().len(), 2);
        assert!(err.to_string().contains("lookup user:42"));
    }
}
