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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    Transport,
    Parse,
    Timeout,
    Policy,
    Internal,
}

impl ErrorClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::Parse => "parse",
            Self::Timeout => "timeout",
            Self::Policy => "policy",
            Self::Internal => "internal",
        }
    }
}

pub fn classify(code: ErrorCode) -> ErrorClass {
    match code {
        ErrorCode::Io => ErrorClass::Transport,
        ErrorCode::InvalidInput => ErrorClass::Parse,
        ErrorCode::Timeout => ErrorClass::Timeout,
        ErrorCode::Conflict => ErrorClass::Policy,
        ErrorCode::NotFound | ErrorCode::Internal => ErrorClass::Internal,
    }
}

pub trait CoreResultExt<T> {
    fn context(self, context: impl Into<String>) -> CoreResult<T>;
    fn map_error_code(self, code: ErrorCode) -> CoreResult<T>;
}

impl<T> CoreResultExt<T> for CoreResult<T> {
    fn context(self, context: impl Into<String>) -> CoreResult<T> {
        self.map_err(|err| err.with_context(context))
    }

    fn map_error_code(self, code: ErrorCode) -> CoreResult<T> {
        self.map_err(|err| CoreError::new(code, err.to_string()))
    }
}

pub trait OptionExt<T> {
    fn or_error(self, code: ErrorCode, message: impl Into<String>) -> CoreResult<T>;
}

impl<T> OptionExt<T> for Option<T> {
    fn or_error(self, code: ErrorCode, message: impl Into<String>) -> CoreResult<T> {
        self.ok_or_else(|| CoreError::new(code, message))
    }
}

#[cfg(test)]
mod tests {
    use super::{classify, CoreError, CoreResultExt, ErrorClass, ErrorCode, OptionExt};

    #[test]
    fn core_error_tracks_context_chain() {
        let err = CoreError::new(ErrorCode::NotFound, "record missing")
            .with_context("lookup user:42")
            .with_context("api GET /v1/user/42");
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert_eq!(err.contexts().len(), 2);
        assert!(err.to_string().contains("lookup user:42"));
    }

    #[test]
    fn classify_error_codes() {
        assert_eq!(classify(ErrorCode::Io), ErrorClass::Transport);
        assert_eq!(classify(ErrorCode::Timeout), ErrorClass::Timeout);
    }

    #[test]
    fn result_context_and_option_helpers() {
        let err = Err::<(), _>(CoreError::new(ErrorCode::Internal, "boom"))
            .context("during startup")
            .expect_err("must fail");
        assert!(err.to_string().contains("during startup"));

        let missing: Option<i32> = None;
        let err = missing
            .or_error(ErrorCode::NotFound, "missing")
            .expect_err("must fail");
        assert_eq!(err.code(), ErrorCode::NotFound);
    }
}
