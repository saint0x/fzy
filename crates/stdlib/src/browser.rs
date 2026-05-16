use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserPriority {
    Render,
    Input,
    Background,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerCleanup {
    AutoOnDetach,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageScope {
    Local,
    Session,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserTimerPlan {
    pub delay_ms: u64,
    pub repeats: bool,
    pub priority: BrowserPriority,
    pub cancellation_key: String,
}

impl BrowserTimerPlan {
    pub fn timeout(delay_ms: u64, cancellation_key: impl Into<String>) -> Self {
        Self {
            delay_ms,
            repeats: false,
            priority: BrowserPriority::Input,
            cancellation_key: cancellation_key.into(),
        }
    }

    pub fn interval(delay_ms: u64, cancellation_key: impl Into<String>) -> Self {
        Self {
            delay_ms,
            repeats: true,
            priority: BrowserPriority::Background,
            cancellation_key: cancellation_key.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserListenerPlan {
    pub event_type: String,
    pub capture: bool,
    pub cleanup: ListenerCleanup,
}

impl BrowserListenerPlan {
    pub fn new(event_type: impl Into<String>) -> Self {
        Self {
            event_type: event_type.into(),
            capture: false,
            cleanup: ListenerCleanup::Manual,
        }
    }

    pub fn capture(mut self) -> Self {
        self.capture = true;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserStorageError {
    pub scope: StorageScope,
    pub key: String,
    pub diagnostic_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserRuntimeErrorRecord {
    pub hook: String,
    pub operation: String,
    pub diagnostic_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredConsoleLog {
    pub level: String,
    pub message: String,
    pub fields: BTreeMap<String, String>,
}

pub fn normalize_storage_key(key: &str) -> Result<&str, BrowserStorageError> {
    if key.trim().is_empty() {
        return Err(BrowserStorageError {
            scope: StorageScope::Local,
            key: key.to_string(),
            diagnostic_code: "browser.abi_contract_violation".to_string(),
        });
    }
    Ok(key)
}

pub fn structured_console_log(
    level: impl Into<String>,
    message: impl Into<String>,
    fields: BTreeMap<String, String>,
) -> StructuredConsoleLog {
    StructuredConsoleLog {
        level: level.into(),
        message: message.into(),
        fields,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_timer_and_listener_defaults_match_browser_abi_lane() {
        let timeout = BrowserTimerPlan::timeout(16, "raf:cancel");
        let interval = BrowserTimerPlan::interval(1000, "poll:cancel");
        let listener = BrowserListenerPlan::new("click").capture();
        assert!(!timeout.repeats);
        assert!(interval.repeats);
        assert_eq!(listener.cleanup, ListenerCleanup::Manual);
        assert!(listener.capture);
    }

    #[test]
    fn storage_keys_and_console_logs_are_structured() {
        let mut fields = BTreeMap::new();
        fields.insert("request_id".to_string(), "req-7".to_string());
        let event = structured_console_log("warn", "browser.storage.unavailable", fields);
        assert_eq!(normalize_storage_key("prefs.theme"), Ok("prefs.theme"));
        assert!(normalize_storage_key("").is_err());
        assert_eq!(event.level, "warn");
        assert_eq!(event.fields.get("request_id"), Some(&"req-7".to_string()));
    }
}
