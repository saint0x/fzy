use super::*;

pub struct HttpServerLimits {
    pub max_header_bytes: usize,
    pub max_body_bytes: usize,
    pub max_connections: usize,
    pub read_timeout_ms: u64,
    pub write_timeout_ms: u64,
    pub parse_timeout_ms: u64,
    pub keepalive_max_requests: usize,
}

impl Default for HttpServerLimits {
    fn default() -> Self {
        Self {
            max_header_bytes: 16 * 1024,
            max_body_bytes: 1024 * 1024,
            max_connections: 1024,
            read_timeout_ms: 5_000,
            write_timeout_ms: 5_000,
            parse_timeout_ms: 1_000,
            keepalive_max_requests: 100,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub keep_alive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub reason: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub keep_alive: bool,
    pub chunked: bool,
}

impl HttpResponse {
    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            reason: "OK".to_string(),
            headers: BTreeMap::new(),
            body: body.into(),
            keep_alive: true,
            chunked: false,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", self.status, self.reason).as_bytes());
        let mut has_connection = false;
        let mut has_len = false;
        let mut has_chunked = false;
        for (k, v) in &self.headers {
            let lower = k.to_ascii_lowercase();
            if lower == "connection" {
                has_connection = true;
            } else if lower == "content-length" {
                has_len = true;
            } else if lower == "transfer-encoding" {
                has_chunked = true;
            }
            out.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
        }
        if !has_connection {
            out.extend_from_slice(
                format!(
                    "Connection: {}\r\n",
                    if self.keep_alive {
                        "keep-alive"
                    } else {
                        "close"
                    }
                )
                .as_bytes(),
            );
        }
        if self.chunked {
            if !has_chunked {
                out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
            }
        } else if !has_len {
            out.extend_from_slice(format!("Content-Length: {}\r\n", self.body.len()).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        if self.chunked {
            out.extend_from_slice(encode_chunked(&self.body).as_slice());
        } else {
            out.extend_from_slice(&self.body);
        }
        out
    }
}

pub trait HttpRouter {
    fn route(&self, req: &HttpRequest) -> HttpResponse;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpConnectionMode {
    OneOff,
    Persistent { max_requests: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpServeOptions {
    pub accept_max_attempts: usize,
    pub accept_poll_max_events: usize,
    pub io_poll_max_events: usize,
    pub read_stall_limit: usize,
    pub write_stall_limit: usize,
}

impl Default for HttpServeOptions {
    fn default() -> Self {
        Self {
            accept_max_attempts: 32,
            accept_poll_max_events: 8,
            io_poll_max_events: 8,
            read_stall_limit: 64,
            write_stall_limit: 64,
        }
    }
}

pub fn parse_http_request(raw: &[u8], limits: &HttpServerLimits) -> Result<HttpRequest, NetError> {
    let headers_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| NetError::Parse("missing header terminator".to_string()))?;
    if headers_end > limits.max_header_bytes {
        return Err(NetError::LimitsExceeded(
            "header limit exceeded".to_string(),
        ));
    }

    let head = String::from_utf8(raw[..headers_end].to_vec())
        .map_err(|_| NetError::Parse("header bytes are not valid utf8".to_string()))?;
    let mut lines = head.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| NetError::Parse("missing request line".to_string()))?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() != 3 {
        return Err(NetError::Parse("invalid request line".to_string()));
    }

    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_string(), value.trim().to_string());
        }
    }

    let mut body = raw[(headers_end + 4)..].to_vec();
    if headers
        .get("Transfer-Encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        body = decode_chunked(&body)?;
    } else if let Some(content_length) = headers
        .get("Content-Length")
        .and_then(|value| value.parse::<usize>().ok())
    {
        if body.len() < content_length {
            return Err(NetError::Parse("incomplete request body".to_string()));
        }
        body.truncate(content_length);
    }
    if body.len() > limits.max_body_bytes {
        return Err(NetError::LimitsExceeded("body limit exceeded".to_string()));
    }

    let connection = headers
        .get("Connection")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| "keep-alive".to_string());

    Ok(HttpRequest {
        method: parts[0].to_string(),
        path: parts[1].to_string(),
        version: parts[2].to_string(),
        headers,
        body,
        keep_alive: connection != "close",
    })
}

pub fn serve_http_once<B: NetBackend, R: HttpRouter>(
    backend: &mut B,
    listener: SocketId,
    router: &R,
    limits: &HttpServerLimits,
) -> Result<usize, NetError> {
    serve_http_once_with_options(
        backend,
        listener,
        router,
        limits,
        HttpServeOptions::default(),
    )
}

pub fn serve_http_once_with_options<B: NetBackend, R: HttpRouter>(
    backend: &mut B,
    listener: SocketId,
    router: &R,
    limits: &HttpServerLimits,
    options: HttpServeOptions,
) -> Result<usize, NetError> {
    for _ in 0..options.accept_max_attempts.max(1) {
        backend.poll_register(listener, PollInterest::Acceptable, 128)?;
        let events = backend.poll_next(options.accept_poll_max_events.max(1))?;
        if !events
            .iter()
            .any(|event| matches!(event, PollerEvent::Acceptable(id) if *id == listener))
        {
            continue;
        }
        let Some(connection) = backend.accept(listener)? else {
            continue;
        };
        backend.request_started()?;
        let wrote = serve_http_connection_with_options(
            backend,
            connection,
            router,
            limits,
            HttpConnectionMode::OneOff,
            options,
        )?;
        backend.request_finished();
        return Ok(wrote);
    }
    Ok(0)
}

pub fn serve_http_persistent_once<B: NetBackend, R: HttpRouter>(
    backend: &mut B,
    listener: SocketId,
    router: &R,
    limits: &HttpServerLimits,
    max_requests_per_connection: usize,
) -> Result<usize, NetError> {
    let mode = HttpConnectionMode::Persistent {
        max_requests: max_requests_per_connection.max(1),
    };
    serve_http_persistent_once_with_options(
        backend,
        listener,
        router,
        limits,
        mode,
        HttpServeOptions::default(),
    )
}

pub fn serve_http_persistent_once_with_options<B: NetBackend, R: HttpRouter>(
    backend: &mut B,
    listener: SocketId,
    router: &R,
    limits: &HttpServerLimits,
    mode: HttpConnectionMode,
    options: HttpServeOptions,
) -> Result<usize, NetError> {
    for _ in 0..options.accept_max_attempts.max(1) {
        backend.poll_register(listener, PollInterest::Acceptable, 128)?;
        let events = backend.poll_next(options.accept_poll_max_events.max(1))?;
        if !events
            .iter()
            .any(|event| matches!(event, PollerEvent::Acceptable(id) if *id == listener))
        {
            continue;
        }
        let Some(connection) = backend.accept(listener)? else {
            continue;
        };
        backend.request_started()?;
        let wrote =
            serve_http_connection_with_options(backend, connection, router, limits, mode, options)?;
        backend.request_finished();
        return Ok(wrote);
    }
    Ok(0)
}

pub fn serve_http_connection<B: NetBackend, R: HttpRouter>(
    backend: &mut B,
    connection: SocketId,
    router: &R,
    limits: &HttpServerLimits,
    mode: HttpConnectionMode,
) -> Result<usize, NetError> {
    serve_http_connection_with_options(
        backend,
        connection,
        router,
        limits,
        mode,
        HttpServeOptions::default(),
    )
}

pub fn serve_http_connection_with_options<B: NetBackend, R: HttpRouter>(
    backend: &mut B,
    connection: SocketId,
    router: &R,
    limits: &HttpServerLimits,
    mode: HttpConnectionMode,
    options: HttpServeOptions,
) -> Result<usize, NetError> {
    let max_requests = match mode {
        HttpConnectionMode::OneOff => 1,
        HttpConnectionMode::Persistent { max_requests } => max_requests.max(1),
    };
    let persistent_mode = matches!(mode, HttpConnectionMode::Persistent { .. });

    let mut total_wrote = 0usize;
    let mut raw = Vec::with_capacity(limits.max_header_bytes.min(4096));
    for request_idx in 0..max_requests {
        if !(persistent_mode && request_idx > 0) {
            backend.poll_register(connection, PollInterest::Readable, 128)?;
            let _ = backend.poll_next(options.io_poll_max_events.max(1))?;
        }
        raw.clear();
        let max_total = limits.max_header_bytes + limits.max_body_bytes;
        let mut read_stalls = 0usize;
        let request = loop {
            let remaining = max_total.saturating_sub(raw.len());
            if remaining == 0 {
                backend.close(connection)?;
                return Err(NetError::LimitsExceeded(
                    "request exceeds configured size limits".to_string(),
                ));
            }
            let chunk = backend.read(connection, remaining.min(16 * 1024))?;
            if chunk.is_empty() {
                read_stalls += 1;
                if read_stalls > options.read_stall_limit.max(1) {
                    backend.close(connection)?;
                    return Err(NetError::DeadlineExceeded);
                }
                continue;
            }
            read_stalls = 0;
            raw.extend_from_slice(&chunk);
            if is_http_request_complete(&raw, limits)? {
                break parse_http_request(&raw, limits)?;
            }
        };

        if request
            .headers
            .get("Expect")
            .is_some_and(|value| value.eq_ignore_ascii_case("100-continue"))
        {
            let interim = b"HTTP/1.1 100 Continue\r\n\r\n";
            let _ = backend.write(connection, interim)?;
        }

        let mut response = router.route(&request);
        if !request.keep_alive || matches!(mode, HttpConnectionMode::OneOff) {
            response.keep_alive = false;
        }

        let serialized = response.to_bytes();
        if !(persistent_mode && request_idx > 0) {
            backend.poll_register(connection, PollInterest::Writable, 128)?;
            let _ = backend.poll_next(options.io_poll_max_events.max(1))?;
        }
        let mut wrote = 0usize;
        let mut write_stalls = 0usize;
        while wrote < serialized.len() {
            let n = backend.write(connection, &serialized[wrote..])?;
            if n == 0 {
                write_stalls += 1;
                if write_stalls > options.write_stall_limit.max(1) {
                    backend.close(connection)?;
                    return Err(NetError::DeadlineExceeded);
                }
                continue;
            }
            write_stalls = 0;
            wrote += n;
        }
        total_wrote += wrote;

        if !response.keep_alive {
            backend.close(connection)?;
            return Ok(total_wrote);
        }
    }

    backend.close(connection)?;
    Ok(total_wrote)
}

fn is_http_request_complete(raw: &[u8], limits: &HttpServerLimits) -> Result<bool, NetError> {
    let Some(headers_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Ok(false);
    };
    if headers_end > limits.max_header_bytes {
        return Err(NetError::LimitsExceeded(
            "header limit exceeded".to_string(),
        ));
    }
    let head = String::from_utf8_lossy(&raw[..headers_end]);
    let mut content_length = None::<usize>;
    let mut chunked = false;
    for line in head.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();
            if name == "content-length" {
                content_length = value.parse::<usize>().ok();
            } else if name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
        }
    }
    let body = &raw[(headers_end + 4)..];
    if chunked {
        Ok(body.windows(5).any(|w| w == b"0\r\n\r\n"))
    } else if let Some(len) = content_length {
        if len > limits.max_body_bytes {
            return Err(NetError::LimitsExceeded("body limit exceeded".to_string()));
        }
        Ok(body.len() >= len)
    } else {
        Ok(true)
    }
}

fn decode_chunked(raw: &[u8]) -> Result<Vec<u8>, NetError> {
    let mut index = 0usize;
    let mut out = Vec::new();
    while index < raw.len() {
        let Some(line_end) = raw[index..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|offset| index + offset)
        else {
            return Err(NetError::Parse("invalid chunked framing".to_string()));
        };
        let size_str = String::from_utf8(raw[index..line_end].to_vec())
            .map_err(|_| NetError::Parse("invalid chunk size".to_string()))?;
        let size = usize::from_str_radix(size_str.trim(), 16)
            .map_err(|_| NetError::Parse("invalid chunk size value".to_string()))?;
        index = line_end + 2;
        if size == 0 {
            break;
        }
        if index + size > raw.len() {
            return Err(NetError::Parse("chunk exceeds payload".to_string()));
        }
        out.extend_from_slice(&raw[index..index + size]);
        index += size;
        if index + 2 <= raw.len() {
            index += 2;
        }
    }
    Ok(out)
}

fn encode_chunked(raw: &[u8]) -> Vec<u8> {
    if raw.is_empty() {
        return b"0\r\n\r\n".to_vec();
    }
    let mut out = Vec::new();
    let mut index = 0usize;
    const CHUNK: usize = 16 * 1024;
    while index < raw.len() {
        let end = (index + CHUNK).min(raw.len());
        let chunk = &raw[index..end];
        out.extend_from_slice(format!("{:X}\r\n", chunk.len()).as_bytes());
        out.extend_from_slice(chunk);
        out.extend_from_slice(b"\r\n");
        index = end;
    }
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsPolicy {
    Disabled,
    ProxyTerminated {
        trusted_proxy_cidrs: Vec<String>,
    },
    NativeAdapter {
        provider: String,
        min_version: String,
        require_client_auth: bool,
    },
}

impl TlsPolicy {
    pub fn boundary_note(&self) -> &'static str {
        match self {
            Self::Disabled => "tls disabled: cleartext transport only",
            Self::ProxyTerminated { .. } => {
                "tls terminated at trusted proxy boundary; app enforces forwarded identity policy"
            }
            Self::NativeAdapter { .. } => {
                "tls handled by native adapter boundary before app protocol parsing"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderLimits {
    pub max_entries: usize,
    pub max_name_bytes: usize,
    pub max_value_bytes: usize,
}

impl Default for HeaderLimits {
    fn default() -> Self {
        Self {
            max_entries: 128,
            max_name_bytes: 256,
            max_value_bytes: 8 * 1024,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderMap {
    inner: BTreeMap<String, String>,
}

impl HeaderMap {
    pub fn insert(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
        limits: HeaderLimits,
    ) -> Result<(), NetError> {
        let canonical = canonicalize_header_name(name.into().as_str())?;
        let value = value.into().trim().to_string();
        if canonical.len() > limits.max_name_bytes || value.len() > limits.max_value_bytes {
            return Err(NetError::LimitsExceeded(
                "header entry exceeds configured limits".to_string(),
            ));
        }
        if !self.inner.contains_key(&canonical) && self.inner.len() >= limits.max_entries {
            return Err(NetError::LimitsExceeded(
                "header count exceeds configured limits".to_string(),
            ));
        }
        self.inner.insert(canonical, value);
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        let canonical = name.trim().to_ascii_lowercase();
        self.inner.get(&canonical).map(String::as_str)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.inner.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

pub fn canonicalize_header_name(name: &str) -> Result<String, NetError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(NetError::Parse("header name is empty".to_string()));
    }
    if trimmed.contains(':') || trimmed.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(NetError::Parse(
            "header name contains invalid bytes".to_string(),
        ));
    }
    Ok(trimmed.to_ascii_lowercase())
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct JsonPayload {
    fields: BTreeMap<String, Value>,
}

impl JsonPayload {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_str(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), NetError> {
        let key = validate_json_payload_key(key.into())?;
        self.fields.insert(key, Value::String(value.into()));
        Ok(())
    }

    pub fn set_raw(&mut self, key: impl Into<String>, value_json: &str) -> Result<(), NetError> {
        let key = validate_json_payload_key(key.into())?;
        let value = serde_json::from_str::<Value>(value_json)
            .map_err(|err| NetError::Parse(format!("payload.{key}: invalid JSON value: {err}")))?;
        self.fields.insert(key, value);
        Ok(())
    }

    pub fn set_value(&mut self, key: impl Into<String>, value: Value) -> Result<(), NetError> {
        let key = validate_json_payload_key(key.into())?;
        self.fields.insert(key, value);
        Ok(())
    }

    pub fn encode(&self) -> Result<String, NetError> {
        serde_json::to_string(&self.to_json_value())
            .map_err(|err| NetError::Parse(format!("payload: encode failed: {err}")))
    }

    pub fn to_json_value(&self) -> Value {
        let mut object = Map::new();
        for (key, value) in &self.fields {
            object.insert(key.clone(), value.clone());
        }
        Value::Object(object)
    }
}

pub fn json_payload_new() -> JsonPayload {
    JsonPayload::new()
}

pub fn json_payload_set_str(
    payload: &mut JsonPayload,
    key: impl Into<String>,
    value: impl Into<String>,
) -> Result<(), NetError> {
    payload.set_str(key, value)
}

pub fn json_payload_set_raw(
    payload: &mut JsonPayload,
    key: impl Into<String>,
    value_json: &str,
) -> Result<(), NetError> {
    payload.set_raw(key, value_json)
}

pub fn json_payload_encode(payload: &JsonPayload) -> Result<String, NetError> {
    payload.encode()
}

pub fn write_json_payload(
    status: u16,
    reason: impl Into<String>,
    payload: &JsonPayload,
    keep_alive: bool,
    limits: &HttpServerLimits,
) -> Result<HttpResponse, NetError> {
    let encoded = json_payload_encode(payload)?;
    HttpResponseBuilder::default()
        .status(status, reason)
        .header("Content-Type", "application/json", HeaderLimits::default())?
        .body(encoded.into_bytes())
        .keep_alive(keep_alive)
        .build(limits)
}

pub fn post_json_payload(
    path: impl Into<String>,
    payload: &JsonPayload,
    keep_alive: bool,
    limits: &HttpServerLimits,
) -> Result<HttpRequest, NetError> {
    let encoded = json_payload_encode(payload)?;
    HttpRequestBuilder::default()
        .method("POST")
        .path(path)
        .header("Content-Type", "application/json", HeaderLimits::default())?
        .body(encoded.into_bytes())
        .keep_alive(keep_alive)
        .build(limits)
}

fn validate_json_payload_key(key: String) -> Result<String, NetError> {
    if key.trim().is_empty() {
        return Err(NetError::Parse("payload key must not be empty".to_string()));
    }
    Ok(key)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequestBuilder {
    method: String,
    path: String,
    version: String,
    headers: HeaderMap,
    body: Vec<u8>,
    keep_alive: bool,
}

impl Default for HttpRequestBuilder {
    fn default() -> Self {
        Self {
            method: "GET".to_string(),
            path: "/".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: HeaderMap::default(),
            body: Vec::new(),
            keep_alive: true,
        }
    }
}

impl HttpRequestBuilder {
    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.method = method.into();
        self
    }

    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    pub fn header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
        limits: HeaderLimits,
    ) -> Result<Self, NetError> {
        self.headers.insert(name, value, limits)?;
        Ok(self)
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    pub fn keep_alive(mut self, keep_alive: bool) -> Self {
        self.keep_alive = keep_alive;
        self
    }

    pub fn build(self, limits: &HttpServerLimits) -> Result<HttpRequest, NetError> {
        if self.method.trim().is_empty() {
            return Err(NetError::Parse("request method is empty".to_string()));
        }
        if !self.path.starts_with('/') {
            return Err(NetError::Parse(
                "request path must be absolute and start with '/'".to_string(),
            ));
        }
        if self.body.len() > limits.max_body_bytes {
            return Err(NetError::LimitsExceeded(
                "request body exceeds configured limit".to_string(),
            ));
        }
        let mut headers = BTreeMap::new();
        for (k, v) in self.headers.iter() {
            headers.insert(k.to_string(), v.to_string());
        }
        Ok(HttpRequest {
            method: self.method,
            path: self.path,
            version: self.version,
            headers,
            body: self.body,
            keep_alive: self.keep_alive,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponseBuilder {
    status: u16,
    reason: String,
    headers: HeaderMap,
    body: Vec<u8>,
    keep_alive: bool,
    chunked: bool,
}

impl Default for HttpResponseBuilder {
    fn default() -> Self {
        Self {
            status: 200,
            reason: "OK".to_string(),
            headers: HeaderMap::default(),
            body: Vec::new(),
            keep_alive: true,
            chunked: false,
        }
    }
}

impl HttpResponseBuilder {
    pub fn status(mut self, status: u16, reason: impl Into<String>) -> Self {
        self.status = status;
        self.reason = reason.into();
        self
    }

    pub fn header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
        limits: HeaderLimits,
    ) -> Result<Self, NetError> {
        self.headers.insert(name, value, limits)?;
        Ok(self)
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    pub fn keep_alive(mut self, keep_alive: bool) -> Self {
        self.keep_alive = keep_alive;
        self
    }

    pub fn chunked(mut self, chunked: bool) -> Self {
        self.chunked = chunked;
        self
    }

    pub fn build(self, limits: &HttpServerLimits) -> Result<HttpResponse, NetError> {
        if self.body.len() > limits.max_body_bytes {
            return Err(NetError::LimitsExceeded(
                "response body exceeds configured limit".to_string(),
            ));
        }
        let mut headers = BTreeMap::new();
        for (k, v) in self.headers.iter() {
            headers.insert(k.to_string(), v.to_string());
        }
        Ok(HttpResponse {
            status: self.status,
            reason: self.reason,
            headers,
            body: self.body,
            keep_alive: self.keep_alive,
            chunked: self.chunked,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpTimeoutPolicy {
    pub connect_timeout_ms: u64,
    pub read_timeout_ms: u64,
    pub write_timeout_ms: u64,
}

impl Default for HttpTimeoutPolicy {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 3_000,
            read_timeout_ms: 5_000,
            write_timeout_ms: 5_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpRetryPolicy {
    pub max_attempts: usize,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub factor: u64,
}

impl Default for HttpRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff_ms: 50,
            max_backoff_ms: 1_000,
            factor: 2,
        }
    }
}

impl HttpRetryPolicy {
    pub fn validate(&self) -> Result<(), NetError> {
        if self.max_attempts == 0 || self.factor == 0 {
            return Err(NetError::Parse(
                "retry policy has invalid zero-valued fields".to_string(),
            ));
        }
        Ok(())
    }

    pub fn backoff_for_attempt(&self, attempt: usize) -> Option<u64> {
        if attempt == 0 || attempt > self.max_attempts {
            return None;
        }
        let mut delay = self.initial_backoff_ms.max(1);
        for _ in 1..attempt {
            delay = delay
                .saturating_mul(self.factor)
                .min(self.max_backoff_ms.max(1));
        }
        Some(delay)
    }
}
