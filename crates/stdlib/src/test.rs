#[derive(Debug, Clone)]
pub struct TestCase {
    pub name: String,
    pub deterministic: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestHookError {
    AssertionFailed(String),
    EventuallyTimeout { attempts: usize, message: String },
    NeverViolated { attempt: usize, message: String },
}

pub fn assert_true(condition: bool, message: impl Into<String>) -> Result<(), TestHookError> {
    if condition {
        Ok(())
    } else {
        Err(TestHookError::AssertionFailed(message.into()))
    }
}

pub fn eventually<F>(
    max_attempts: usize,
    message: impl Into<String>,
    mut predicate: F,
) -> Result<(), TestHookError>
where
    F: FnMut(usize) -> bool,
{
    let message = message.into();
    for attempt in 0..max_attempts {
        if predicate(attempt) {
            return Ok(());
        }
    }
    Err(TestHookError::EventuallyTimeout {
        attempts: max_attempts,
        message,
    })
}

pub fn never<F>(
    attempts: usize,
    message: impl Into<String>,
    mut predicate: F,
) -> Result<(), TestHookError>
where
    F: FnMut(usize) -> bool,
{
    let message = message.into();
    for attempt in 0..attempts {
        if predicate(attempt) {
            return Err(TestHookError::NeverViolated { attempt, message });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{assert_true, eventually, never, TestHookError};

    #[test]
    fn assert_true_reports_failure() {
        assert_eq!(
            assert_true(false, "boom"),
            Err(TestHookError::AssertionFailed("boom".to_string()))
        );
    }

    #[test]
    fn eventually_succeeds_before_timeout() {
        assert!(eventually(5, "wait", |attempt| attempt >= 2).is_ok());
    }

    #[test]
    fn never_fails_when_predicate_happens() {
        assert_eq!(
            never(4, "must not happen", |attempt| attempt == 3),
            Err(TestHookError::NeverViolated {
                attempt: 3,
                message: "must not happen".to_string()
            })
        );
    }
}
