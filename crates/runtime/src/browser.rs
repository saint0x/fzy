use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TimerHandle(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FrameHandle(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodeHandle(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ListenerHandle(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FetchHandle(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WebSocketHandle(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StreamHandle(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleOwnership {
    RuntimeOwned,
    CallerOwned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancellationPolicy {
    Idempotent,
    AbortSignalRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupPolicy {
    AutoOnDrop,
    ExplicitTeardownRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameCallbackPolicy {
    OneShot,
    RequeueFromCallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventPropagation {
    Bubble,
    Capture,
    TargetOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageArea {
    Local,
    Session,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleLevel {
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserErrorKind {
    Cancelled,
    Timeout,
    NotFound,
    PermissionDenied,
    StorageUnavailable,
    TransportClosed,
    AbiContractViolation,
}

impl BrowserErrorKind {
    pub fn diagnostic_code(self) -> &'static str {
        match self {
            Self::Cancelled => "browser.cancelled",
            Self::Timeout => "browser.timeout",
            Self::NotFound => "browser.not_found",
            Self::PermissionDenied => "browser.permission_denied",
            Self::StorageUnavailable => "browser.storage_unavailable",
            Self::TransportClosed => "browser.transport_closed",
            Self::AbiContractViolation => "browser.abi_contract_violation",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserError {
    pub kind: BrowserErrorKind,
    pub operation: String,
    pub detail: String,
}

impl BrowserError {
    pub fn new(
        kind: BrowserErrorKind,
        operation: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            operation: operation.into(),
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimerContract {
    pub ownership: HandleOwnership,
    pub cancellation: CancellationPolicy,
    pub cleanup: CleanupPolicy,
    pub repeat: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameContract {
    pub ownership: HandleOwnership,
    pub callback_policy: FrameCallbackPolicy,
    pub cleanup: CleanupPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventListenerContract {
    pub node: NodeHandle,
    pub event_type: String,
    pub propagation: EventPropagation,
    pub ownership: HandleOwnership,
    pub cleanup: CleanupPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchContract {
    pub ownership: HandleOwnership,
    pub cancellation: CancellationPolicy,
    pub cleanup: CleanupPolicy,
    pub abort_controller: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSocketContract {
    pub ownership: HandleOwnership,
    pub cancellation: CancellationPolicy,
    pub cleanup: CleanupPolicy,
    pub stream_bridge: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageErrorContract {
    pub area: StorageArea,
    pub key: String,
    pub error: BrowserError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleEvent {
    pub level: ConsoleLevel,
    pub message: String,
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeErrorEvent {
    pub hook: String,
    pub diagnostic_code: String,
    pub operation: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserAbiConformance {
    pub timers_are_idempotent: bool,
    pub listeners_require_cleanup: bool,
    pub fetch_uses_abort_controller: bool,
    pub websocket_supports_stream_bridge: bool,
    pub storage_maps_errors_to_diagnostics: bool,
    pub runtime_errors_surface_hooks: bool,
}

impl BrowserAbiConformance {
    pub fn is_complete(&self) -> bool {
        self.timers_are_idempotent
            && self.listeners_require_cleanup
            && self.fetch_uses_abort_controller
            && self.websocket_supports_stream_bridge
            && self.storage_maps_errors_to_diagnostics
            && self.runtime_errors_surface_hooks
    }
}

#[derive(Debug, Default)]
pub struct BrowserRuntimeAbi {
    next_handle: u64,
    timeouts: BTreeMap<TimerHandle, TimerContract>,
    intervals: BTreeMap<TimerHandle, TimerContract>,
    frames: BTreeMap<FrameHandle, FrameContract>,
    listeners: BTreeMap<ListenerHandle, EventListenerContract>,
    fetches: BTreeMap<FetchHandle, FetchContract>,
    websockets: BTreeMap<WebSocketHandle, WebSocketContract>,
    local_storage: BTreeMap<String, String>,
    session_storage: BTreeMap<String, String>,
    console_events: Vec<ConsoleEvent>,
    runtime_errors: Vec<RuntimeErrorEvent>,
}

impl BrowserRuntimeAbi {
    pub fn set_timeout(&mut self) -> TimerHandle {
        let handle = TimerHandle(self.next_handle());
        self.timeouts.insert(
            handle,
            TimerContract {
                ownership: HandleOwnership::RuntimeOwned,
                cancellation: CancellationPolicy::Idempotent,
                cleanup: CleanupPolicy::AutoOnDrop,
                repeat: false,
            },
        );
        handle
    }

    pub fn set_interval(&mut self) -> TimerHandle {
        let handle = TimerHandle(self.next_handle());
        self.intervals.insert(
            handle,
            TimerContract {
                ownership: HandleOwnership::RuntimeOwned,
                cancellation: CancellationPolicy::Idempotent,
                cleanup: CleanupPolicy::ExplicitTeardownRequired,
                repeat: true,
            },
        );
        handle
    }

    pub fn clear_timeout(&mut self, handle: TimerHandle) -> bool {
        self.timeouts.remove(&handle).is_some() || self.intervals.remove(&handle).is_some()
    }

    pub fn request_animation_frame(&mut self) -> FrameHandle {
        let handle = FrameHandle(self.next_handle());
        self.frames.insert(
            handle,
            FrameContract {
                ownership: HandleOwnership::RuntimeOwned,
                callback_policy: FrameCallbackPolicy::OneShot,
                cleanup: CleanupPolicy::AutoOnDrop,
            },
        );
        handle
    }

    pub fn raw_node_handle(&mut self) -> NodeHandle {
        NodeHandle(self.next_handle())
    }

    pub fn add_event_listener(
        &mut self,
        node: NodeHandle,
        event_type: impl Into<String>,
        propagation: EventPropagation,
    ) -> ListenerHandle {
        let handle = ListenerHandle(self.next_handle());
        self.listeners.insert(
            handle,
            EventListenerContract {
                node,
                event_type: event_type.into(),
                propagation,
                ownership: HandleOwnership::CallerOwned,
                cleanup: CleanupPolicy::ExplicitTeardownRequired,
            },
        );
        handle
    }

    pub fn remove_event_listener(&mut self, handle: ListenerHandle) -> bool {
        self.listeners.remove(&handle).is_some()
    }

    pub fn register_fetch(&mut self) -> FetchHandle {
        let handle = FetchHandle(self.next_handle());
        self.fetches.insert(
            handle,
            FetchContract {
                ownership: HandleOwnership::RuntimeOwned,
                cancellation: CancellationPolicy::AbortSignalRequired,
                cleanup: CleanupPolicy::AutoOnDrop,
                abort_controller: true,
            },
        );
        handle
    }

    pub fn abort_fetch(&mut self, handle: FetchHandle) -> bool {
        self.fetches.remove(&handle).is_some()
    }

    pub fn register_websocket(&mut self) -> WebSocketHandle {
        let handle = WebSocketHandle(self.next_handle());
        self.websockets.insert(
            handle,
            WebSocketContract {
                ownership: HandleOwnership::CallerOwned,
                cancellation: CancellationPolicy::Idempotent,
                cleanup: CleanupPolicy::ExplicitTeardownRequired,
                stream_bridge: true,
            },
        );
        handle
    }

    pub fn close_websocket(&mut self, handle: WebSocketHandle) -> bool {
        self.websockets.remove(&handle).is_some()
    }

    pub fn open_stream(&mut self) -> StreamHandle {
        StreamHandle(self.next_handle())
    }

    pub fn storage_set(
        &mut self,
        area: StorageArea,
        key: impl Into<String>,
        value: impl Into<String>,
    ) {
        let key = key.into();
        let value = value.into();
        match area {
            StorageArea::Local => {
                self.local_storage.insert(key, value);
            }
            StorageArea::Session => {
                self.session_storage.insert(key, value);
            }
        }
    }

    pub fn storage_get(
        &self,
        area: StorageArea,
        key: &str,
    ) -> Result<Option<&str>, StorageErrorContract> {
        if key.trim().is_empty() {
            return Err(StorageErrorContract {
                area,
                key: key.to_string(),
                error: BrowserError::new(
                    BrowserErrorKind::AbiContractViolation,
                    "storage.get",
                    "storage key must not be empty",
                ),
            });
        }
        let lookup = match area {
            StorageArea::Local => self.local_storage.get(key),
            StorageArea::Session => self.session_storage.get(key),
        };
        Ok(lookup.map(String::as_str))
    }

    pub fn console_log(
        &mut self,
        level: ConsoleLevel,
        message: impl Into<String>,
        fields: BTreeMap<String, String>,
    ) {
        self.console_events.push(ConsoleEvent {
            level,
            message: message.into(),
            fields,
        });
    }

    pub fn emit_runtime_error(&mut self, hook: impl Into<String>, error: BrowserError) {
        self.runtime_errors.push(RuntimeErrorEvent {
            hook: hook.into(),
            diagnostic_code: error.kind.diagnostic_code().to_string(),
            operation: error.operation,
            detail: error.detail,
        });
    }

    pub fn timeout_contract(&self, handle: TimerHandle) -> Option<&TimerContract> {
        self.timeouts
            .get(&handle)
            .or_else(|| self.intervals.get(&handle))
    }

    pub fn frame_contract(&self, handle: FrameHandle) -> Option<&FrameContract> {
        self.frames.get(&handle)
    }

    pub fn listener_contract(&self, handle: ListenerHandle) -> Option<&EventListenerContract> {
        self.listeners.get(&handle)
    }

    pub fn fetch_contract(&self, handle: FetchHandle) -> Option<&FetchContract> {
        self.fetches.get(&handle)
    }

    pub fn websocket_contract(&self, handle: WebSocketHandle) -> Option<&WebSocketContract> {
        self.websockets.get(&handle)
    }

    pub fn console_events(&self) -> &[ConsoleEvent] {
        &self.console_events
    }

    pub fn runtime_errors(&self) -> &[RuntimeErrorEvent] {
        &self.runtime_errors
    }

    pub fn conformance(&self) -> BrowserAbiConformance {
        BrowserAbiConformance {
            timers_are_idempotent: self
                .timeouts
                .values()
                .all(|contract| contract.cancellation == CancellationPolicy::Idempotent)
                && self
                    .intervals
                    .values()
                    .all(|contract| contract.cancellation == CancellationPolicy::Idempotent),
            listeners_require_cleanup: self
                .listeners
                .values()
                .all(|contract| contract.cleanup == CleanupPolicy::ExplicitTeardownRequired),
            fetch_uses_abort_controller: self.fetches.values().all(|contract| {
                contract.abort_controller
                    && contract.cancellation == CancellationPolicy::AbortSignalRequired
            }),
            websocket_supports_stream_bridge: self
                .websockets
                .values()
                .all(|contract| contract.stream_bridge),
            storage_maps_errors_to_diagnostics: self
                .storage_get(StorageArea::Local, "")
                .err()
                .is_some_and(|err| {
                    err.error.kind.diagnostic_code() == "browser.abi_contract_violation"
                }),
            runtime_errors_surface_hooks: !self.runtime_errors.is_empty(),
        }
    }

    fn next_handle(&mut self) -> u64 {
        self.next_handle += 1;
        self.next_handle
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timer_listener_fetch_and_storage_contracts_are_explicit() {
        let mut abi = BrowserRuntimeAbi::default();
        let timeout = abi.set_timeout();
        let interval = abi.set_interval();
        let frame = abi.request_animation_frame();
        let node = abi.raw_node_handle();
        let listener = abi.add_event_listener(node, "click", EventPropagation::Bubble);
        let fetch = abi.register_fetch();
        let websocket = abi.register_websocket();
        let _stream = abi.open_stream();
        abi.storage_set(StorageArea::Local, "theme", "sunrise");

        assert_eq!(
            abi.timeout_contract(timeout)
                .map(|contract| contract.cleanup),
            Some(CleanupPolicy::AutoOnDrop)
        );
        assert_eq!(
            abi.timeout_contract(interval)
                .map(|contract| contract.cleanup),
            Some(CleanupPolicy::ExplicitTeardownRequired)
        );
        assert_eq!(
            abi.frame_contract(frame)
                .map(|contract| contract.callback_policy),
            Some(FrameCallbackPolicy::OneShot)
        );
        assert_eq!(
            abi.listener_contract(listener)
                .map(|contract| contract.propagation),
            Some(EventPropagation::Bubble)
        );
        assert_eq!(
            abi.fetch_contract(fetch)
                .map(|contract| contract.cancellation),
            Some(CancellationPolicy::AbortSignalRequired)
        );
        assert_eq!(
            abi.websocket_contract(websocket)
                .map(|contract| contract.cleanup),
            Some(CleanupPolicy::ExplicitTeardownRequired)
        );
        assert_eq!(
            abi.storage_get(StorageArea::Local, "theme")
                .expect("storage lookup should succeed"),
            Some("sunrise")
        );
    }

    #[test]
    fn cleanup_and_error_hooks_are_idempotent_and_diagnostic_friendly() {
        let mut abi = BrowserRuntimeAbi::default();
        let timeout = abi.set_timeout();
        let node = abi.raw_node_handle();
        let listener = abi.add_event_listener(node, "submit", EventPropagation::Capture);
        let fetch = abi.register_fetch();
        let websocket = abi.register_websocket();
        let mut fields = BTreeMap::new();
        fields.insert("request_id".to_string(), "req-browser-1".to_string());
        abi.console_log(ConsoleLevel::Error, "browser.fetch.failed", fields);
        abi.emit_runtime_error(
            "overlay",
            BrowserError::new(
                BrowserErrorKind::Timeout,
                "fetch",
                "request exceeded deterministic timeout budget",
            ),
        );

        assert!(abi.clear_timeout(timeout));
        assert!(!abi.clear_timeout(timeout));
        assert!(abi.remove_event_listener(listener));
        assert!(!abi.remove_event_listener(listener));
        assert!(abi.abort_fetch(fetch));
        assert!(!abi.abort_fetch(fetch));
        assert!(abi.close_websocket(websocket));
        assert!(!abi.close_websocket(websocket));
        assert_eq!(abi.console_events().len(), 1);
        assert_eq!(abi.runtime_errors()[0].diagnostic_code, "browser.timeout");
        assert!(abi.conformance().is_complete());
    }
}
