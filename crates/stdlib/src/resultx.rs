use crate::error::{CoreError, CoreResult, ErrorCode};

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
    use super::{classify, CoreResultExt, ErrorClass, OptionExt};
    use crate::error::{CoreError, ErrorCode};

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
