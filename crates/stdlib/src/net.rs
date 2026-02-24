use capabilities::Capability;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};

pub fn required_capability_for_network() -> Capability {
    Capability::Network
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetMode {
    Host,
    Deterministic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SocketId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContextId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketOwnership {
    RuntimeOwned,
    ApplicationOwned,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetError {
    Io(String),
    NotFound,
    InvalidSocketKind,
    QueueFull,
    Cancelled,
    DeadlineExceeded,
    Parse(String),
    LimitsExceeded(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollInterest {
    Readable,
    Writable,
    Acceptable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollerEvent {
    Readable(SocketId),
    Writable(SocketId),
    Acceptable(SocketId),
    Closed(SocketId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetDecision {
    Bind {
        addr: String,
        listener: SocketId,
    },
    Listen {
        listener: SocketId,
        backlog: usize,
    },
    Accept {
        listener: SocketId,
        connection: SocketId,
    },
    Connect {
        addr: String,
        connection: SocketId,
    },
    Read {
        socket: SocketId,
        bytes: usize,
    },
    Write {
        socket: SocketId,
        bytes: usize,
    },
    Close {
        socket: SocketId,
    },
    Deadline {
        context: ContextId,
        deadline_ms: u64,
    },
    Cancel {
        context: ContextId,
    },
    Timeout {
        context: ContextId,
    },
    Reset {
        socket: SocketId,
    },
    ShutdownStart {
        timeout_ms: u64,
    },
}

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub id: ContextId,
    pub deadline_ms: Option<u64>,
    pub cancelled: bool,
    pub request_id: String,
}

impl RequestContext {
    pub fn new(id: ContextId, request_id: impl Into<String>) -> Self {
        Self {
            id,
            deadline_ms: None,
            cancelled: false,
            request_id: request_id.into(),
        }
    }

    pub fn with_deadline(mut self, deadline_ms: u64) -> Self {
        self.deadline_ms = Some(deadline_ms);
        self
    }

    pub fn check(&self, now_ms: u64) -> Result<(), NetError> {
        if self.cancelled {
            return Err(NetError::Cancelled);
        }
        if let Some(deadline) = self.deadline_ms {
            if now_ms > deadline {
                return Err(NetError::DeadlineExceeded);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct GracefulShutdown {
    pub draining: bool,
    pub in_flight: usize,
    pub timeout_ms: u64,
    pub started_at_ms: Option<u64>,
}

impl Default for GracefulShutdown {
    fn default() -> Self {
        Self {
            draining: false,
            in_flight: 0,
            timeout_ms: 0,
            started_at_ms: None,
        }
    }
}

impl GracefulShutdown {
    pub fn start(&mut self, timeout_ms: u64, now_ms: u64) {
        self.draining = true;
        self.timeout_ms = timeout_ms;
        self.started_at_ms = Some(now_ms);
    }

    pub fn request_started(&mut self) -> Result<(), NetError> {
        if self.draining {
            return Err(NetError::Cancelled);
        }
        self.in_flight += 1;
        Ok(())
    }

    pub fn request_finished(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
    }

    pub fn ready_to_exit(&self, now_ms: u64) -> bool {
        if !self.draining {
            return false;
        }
        if self.in_flight == 0 {
            return true;
        }
        match self.started_at_ms {
            Some(started) => now_ms.saturating_sub(started) >= self.timeout_ms,
            None => false,
        }
    }
}

pub trait NetBackend {
    fn register_context(&mut self, ctx: RequestContext);
    fn set_deadline(&mut self, context: ContextId, deadline_ms: u64) -> Result<(), NetError>;
    fn cancel(&mut self, context: ContextId) -> Result<(), NetError>;

    fn bind(&mut self, addr: &str) -> Result<SocketId, NetError>;
    fn listen(&mut self, listener: SocketId, backlog: usize) -> Result<(), NetError>;
    fn accept(&mut self, listener: SocketId) -> Result<Option<SocketId>, NetError>;
    fn connect(&mut self, addr: &str) -> Result<SocketId, NetError>;
    fn read(&mut self, socket: SocketId, max_bytes: usize) -> Result<Vec<u8>, NetError>;
    fn write(&mut self, socket: SocketId, payload: &[u8]) -> Result<usize, NetError>;
    fn close(&mut self, socket: SocketId) -> Result<(), NetError>;

    fn poll_register(
        &mut self,
        socket: SocketId,
        interest: PollInterest,
        max_queue_depth: usize,
    ) -> Result<(), NetError>;
    fn poll_next(&mut self, max_events: usize) -> Result<Vec<PollerEvent>, NetError>;

    fn begin_shutdown(&mut self, timeout_ms: u64, now_ms: u64);
    fn request_started(&mut self) -> Result<(), NetError>;
    fn request_finished(&mut self);
    fn shutdown_ready(&self, now_ms: u64) -> bool;

    fn decisions(&self) -> Vec<NetDecision>;
}

enum HostSocket {
    Listener(TcpListener),
    Stream(TcpStream),
}

pub struct HostNet {
    next_socket: u64,
    sockets: BTreeMap<SocketId, (HostSocket, SocketOwnership)>,
    poll_interests: BTreeMap<SocketId, PollInterest>,
    poll_queue: VecDeque<PollerEvent>,
    contexts: BTreeMap<ContextId, RequestContext>,
    decisions: Vec<NetDecision>,
    shutdown: GracefulShutdown,
}

impl Default for HostNet {
    fn default() -> Self {
        Self {
            next_socket: 1,
            sockets: BTreeMap::new(),
            poll_interests: BTreeMap::new(),
            poll_queue: VecDeque::new(),
            contexts: BTreeMap::new(),
            decisions: Vec::new(),
            shutdown: GracefulShutdown::default(),
        }
    }
}

impl HostNet {
    fn new_socket_id(&mut self) -> SocketId {
        let id = SocketId(self.next_socket);
        self.next_socket += 1;
        id
    }

    fn queue_event(&mut self, event: PollerEvent, max_depth: usize) -> Result<(), NetError> {
        if self.poll_queue.len() >= max_depth {
            return Err(NetError::QueueFull);
        }
        self.poll_queue.push_back(event);
        Ok(())
    }
}

impl NetBackend for HostNet {
    fn register_context(&mut self, ctx: RequestContext) {
        self.contexts.insert(ctx.id, ctx);
    }

    fn set_deadline(&mut self, context: ContextId, deadline_ms: u64) -> Result<(), NetError> {
        let ctx = self.contexts.get_mut(&context).ok_or(NetError::NotFound)?;
        ctx.deadline_ms = Some(deadline_ms);
        self.decisions.push(NetDecision::Deadline {
            context,
            deadline_ms,
        });
        Ok(())
    }

    fn cancel(&mut self, context: ContextId) -> Result<(), NetError> {
        let ctx = self.contexts.get_mut(&context).ok_or(NetError::NotFound)?;
        ctx.cancelled = true;
        self.decisions.push(NetDecision::Cancel { context });
        Ok(())
    }

    fn bind(&mut self, addr: &str) -> Result<SocketId, NetError> {
        let listener = TcpListener::bind(addr).map_err(|e| NetError::Io(e.to_string()))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| NetError::Io(e.to_string()))?;
        let id = self.new_socket_id();
        self.sockets.insert(
            id,
            (
                HostSocket::Listener(listener),
                SocketOwnership::RuntimeOwned,
            ),
        );
        self.decisions.push(NetDecision::Bind {
            addr: addr.to_string(),
            listener: id,
        });
        Ok(id)
    }

    fn listen(&mut self, listener: SocketId, backlog: usize) -> Result<(), NetError> {
        let Some((HostSocket::Listener(_), _)) = self.sockets.get(&listener) else {
            return Err(NetError::InvalidSocketKind);
        };
        self.decisions
            .push(NetDecision::Listen { listener, backlog });
        Ok(())
    }

    fn accept(&mut self, listener: SocketId) -> Result<Option<SocketId>, NetError> {
        let Some((HostSocket::Listener(sock), _)) = self.sockets.get_mut(&listener) else {
            return Err(NetError::InvalidSocketKind);
        };
        match sock.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(true)
                    .map_err(|e| NetError::Io(e.to_string()))?;
                let id = self.new_socket_id();
                self.sockets.insert(
                    id,
                    (
                        HostSocket::Stream(stream),
                        SocketOwnership::ApplicationOwned,
                    ),
                );
                self.decisions.push(NetDecision::Accept {
                    listener,
                    connection: id,
                });
                Ok(Some(id))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(NetError::Io(e.to_string())),
        }
    }

    fn connect(&mut self, addr: &str) -> Result<SocketId, NetError> {
        let stream = TcpStream::connect(addr).map_err(|e| NetError::Io(e.to_string()))?;
        stream
            .set_nonblocking(true)
            .map_err(|e| NetError::Io(e.to_string()))?;
        let id = self.new_socket_id();
        self.sockets.insert(
            id,
            (
                HostSocket::Stream(stream),
                SocketOwnership::ApplicationOwned,
            ),
        );
        self.decisions.push(NetDecision::Connect {
            addr: addr.to_string(),
            connection: id,
        });
        Ok(id)
    }

    fn read(&mut self, socket: SocketId, max_bytes: usize) -> Result<Vec<u8>, NetError> {
        let Some((HostSocket::Stream(stream), _)) = self.sockets.get_mut(&socket) else {
            return Err(NetError::InvalidSocketKind);
        };
        let mut buffer = vec![0_u8; max_bytes];
        match stream.read(&mut buffer) {
            Ok(n) => {
                buffer.truncate(n);
                self.decisions.push(NetDecision::Read { socket, bytes: n });
                Ok(buffer)
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(Vec::new()),
            Err(e) => Err(NetError::Io(e.to_string())),
        }
    }

    fn write(&mut self, socket: SocketId, payload: &[u8]) -> Result<usize, NetError> {
        let Some((HostSocket::Stream(stream), _)) = self.sockets.get_mut(&socket) else {
            return Err(NetError::InvalidSocketKind);
        };
        match stream.write(payload) {
            Ok(n) => {
                self.decisions.push(NetDecision::Write { socket, bytes: n });
                Ok(n)
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(NetError::Io(e.to_string())),
        }
    }

    fn close(&mut self, socket: SocketId) -> Result<(), NetError> {
        let Some((host_socket, _)) = self.sockets.remove(&socket) else {
            return Err(NetError::NotFound);
        };
        if let HostSocket::Stream(stream) = host_socket {
            let _ = stream.shutdown(Shutdown::Both);
        }
        self.decisions.push(NetDecision::Close { socket });
        self.poll_queue.push_back(PollerEvent::Closed(socket));
        Ok(())
    }

    fn poll_register(
        &mut self,
        socket: SocketId,
        interest: PollInterest,
        max_queue_depth: usize,
    ) -> Result<(), NetError> {
        if !self.sockets.contains_key(&socket) {
            return Err(NetError::NotFound);
        }
        self.poll_interests.insert(socket, interest);
        let event = match interest {
            PollInterest::Readable => PollerEvent::Readable(socket),
            PollInterest::Writable => PollerEvent::Writable(socket),
            PollInterest::Acceptable => PollerEvent::Acceptable(socket),
        };
        self.queue_event(event, max_queue_depth)
    }

    fn poll_next(&mut self, max_events: usize) -> Result<Vec<PollerEvent>, NetError> {
        let mut events = Vec::with_capacity(max_events);
        for _ in 0..max_events {
            if let Some(event) = self.poll_queue.pop_front() {
                events.push(event);
            } else {
                break;
            }
        }
        Ok(events)
    }

    fn begin_shutdown(&mut self, timeout_ms: u64, now_ms: u64) {
        self.shutdown.start(timeout_ms, now_ms);
        self.decisions
            .push(NetDecision::ShutdownStart { timeout_ms });
    }

    fn request_started(&mut self) -> Result<(), NetError> {
        self.shutdown.request_started()
    }

    fn request_finished(&mut self) {
        self.shutdown.request_finished();
    }

    fn shutdown_ready(&self, now_ms: u64) -> bool {
        self.shutdown.ready_to_exit(now_ms)
    }

    fn decisions(&self) -> Vec<NetDecision> {
        self.decisions.clone()
    }
}

pub struct DeterministicNet {
    next_socket: u64,
    open: BTreeSet<SocketId>,
    scripted_accepts: VecDeque<SocketId>,
    scripted_reads: BTreeMap<SocketId, VecDeque<Vec<u8>>>,
    poll_queue: VecDeque<PollerEvent>,
    contexts: BTreeMap<ContextId, RequestContext>,
    decisions: Vec<NetDecision>,
    shutdown: GracefulShutdown,
}

impl Default for DeterministicNet {
    fn default() -> Self {
        Self {
            next_socket: 1,
            open: BTreeSet::new(),
            scripted_accepts: VecDeque::new(),
            scripted_reads: BTreeMap::new(),
            poll_queue: VecDeque::new(),
            contexts: BTreeMap::new(),
            decisions: Vec::new(),
            shutdown: GracefulShutdown::default(),
        }
    }
}

impl DeterministicNet {
    pub fn with_scripted_accepts(accept_count: usize) -> Self {
        let mut runtime = Self::default();
        for _ in 0..accept_count {
            let id = SocketId(runtime.next_socket);
            runtime.next_socket += 1;
            runtime.scripted_accepts.push_back(id);
        }
        runtime
    }

    pub fn push_read_chunk(&mut self, socket: SocketId, chunk: impl Into<Vec<u8>>) {
        self.scripted_reads
            .entry(socket)
            .or_default()
            .push_back(chunk.into());
    }

    fn alloc_socket(&mut self) -> SocketId {
        let id = SocketId(self.next_socket);
        self.next_socket += 1;
        self.open.insert(id);
        id
    }
}

impl NetBackend for DeterministicNet {
    fn register_context(&mut self, ctx: RequestContext) {
        self.contexts.insert(ctx.id, ctx);
    }

    fn set_deadline(&mut self, context: ContextId, deadline_ms: u64) -> Result<(), NetError> {
        let Some(ctx) = self.contexts.get_mut(&context) else {
            return Err(NetError::NotFound);
        };
        ctx.deadline_ms = Some(deadline_ms);
        self.decisions.push(NetDecision::Deadline {
            context,
            deadline_ms,
        });
        Ok(())
    }

    fn cancel(&mut self, context: ContextId) -> Result<(), NetError> {
        let Some(ctx) = self.contexts.get_mut(&context) else {
            return Err(NetError::NotFound);
        };
        ctx.cancelled = true;
        self.decisions.push(NetDecision::Cancel { context });
        Ok(())
    }

    fn bind(&mut self, addr: &str) -> Result<SocketId, NetError> {
        let id = self.alloc_socket();
        self.decisions.push(NetDecision::Bind {
            addr: addr.to_string(),
            listener: id,
        });
        Ok(id)
    }

    fn listen(&mut self, listener: SocketId, backlog: usize) -> Result<(), NetError> {
        if !self.open.contains(&listener) {
            return Err(NetError::NotFound);
        }
        self.decisions
            .push(NetDecision::Listen { listener, backlog });
        Ok(())
    }

    fn accept(&mut self, listener: SocketId) -> Result<Option<SocketId>, NetError> {
        if !self.open.contains(&listener) {
            return Err(NetError::NotFound);
        }
        if let Some(connection) = self.scripted_accepts.pop_front() {
            self.open.insert(connection);
            self.decisions.push(NetDecision::Accept {
                listener,
                connection,
            });
            Ok(Some(connection))
        } else {
            Ok(None)
        }
    }

    fn connect(&mut self, addr: &str) -> Result<SocketId, NetError> {
        let id = self.alloc_socket();
        self.decisions.push(NetDecision::Connect {
            addr: addr.to_string(),
            connection: id,
        });
        Ok(id)
    }

    fn read(&mut self, socket: SocketId, max_bytes: usize) -> Result<Vec<u8>, NetError> {
        if !self.open.contains(&socket) {
            return Err(NetError::NotFound);
        }
        let chunk = self
            .scripted_reads
            .entry(socket)
            .or_default()
            .pop_front()
            .unwrap_or_default();
        let chunk = if chunk.len() > max_bytes {
            chunk[..max_bytes].to_vec()
        } else {
            chunk
        };
        self.decisions.push(NetDecision::Read {
            socket,
            bytes: chunk.len(),
        });
        Ok(chunk)
    }

    fn write(&mut self, socket: SocketId, payload: &[u8]) -> Result<usize, NetError> {
        if !self.open.contains(&socket) {
            return Err(NetError::NotFound);
        }
        self.decisions.push(NetDecision::Write {
            socket,
            bytes: payload.len(),
        });
        Ok(payload.len())
    }

    fn close(&mut self, socket: SocketId) -> Result<(), NetError> {
        if !self.open.remove(&socket) {
            return Err(NetError::NotFound);
        }
        self.decisions.push(NetDecision::Close { socket });
        self.poll_queue.push_back(PollerEvent::Closed(socket));
        Ok(())
    }

    fn poll_register(
        &mut self,
        socket: SocketId,
        interest: PollInterest,
        max_queue_depth: usize,
    ) -> Result<(), NetError> {
        if !self.open.contains(&socket) {
            return Err(NetError::NotFound);
        }
        if self.poll_queue.len() >= max_queue_depth {
            return Err(NetError::QueueFull);
        }
        self.poll_queue.push_back(match interest {
            PollInterest::Readable => PollerEvent::Readable(socket),
            PollInterest::Writable => PollerEvent::Writable(socket),
            PollInterest::Acceptable => PollerEvent::Acceptable(socket),
        });
        Ok(())
    }

    fn poll_next(&mut self, max_events: usize) -> Result<Vec<PollerEvent>, NetError> {
        let mut events = Vec::with_capacity(max_events);
        for _ in 0..max_events {
            if let Some(event) = self.poll_queue.pop_front() {
                events.push(event);
            } else {
                break;
            }
        }
        Ok(events)
    }

    fn begin_shutdown(&mut self, timeout_ms: u64, now_ms: u64) {
        self.shutdown.start(timeout_ms, now_ms);
        self.decisions
            .push(NetDecision::ShutdownStart { timeout_ms });
    }

    fn request_started(&mut self) -> Result<(), NetError> {
        self.shutdown.request_started()
    }

    fn request_finished(&mut self) {
        self.shutdown.request_finished();
    }

    fn shutdown_ready(&self, now_ms: u64) -> bool {
        self.shutdown.ready_to_exit(now_ms)
    }

    fn decisions(&self) -> Vec<NetDecision> {
        self.decisions.clone()
    }
}

pub enum NetRuntime {
    Host(HostNet),
    Deterministic(DeterministicNet),
}

impl NetRuntime {
    pub fn new(mode: NetMode) -> Self {
        match mode {
            NetMode::Host => Self::Host(HostNet::default()),
            NetMode::Deterministic => Self::Deterministic(DeterministicNet::default()),
        }
    }
}

impl NetBackend for NetRuntime {
    fn register_context(&mut self, ctx: RequestContext) {
        match self {
            Self::Host(backend) => backend.register_context(ctx),
            Self::Deterministic(backend) => backend.register_context(ctx),
        }
    }

    fn set_deadline(&mut self, context: ContextId, deadline_ms: u64) -> Result<(), NetError> {
        match self {
            Self::Host(backend) => backend.set_deadline(context, deadline_ms),
            Self::Deterministic(backend) => backend.set_deadline(context, deadline_ms),
        }
    }

    fn cancel(&mut self, context: ContextId) -> Result<(), NetError> {
        match self {
            Self::Host(backend) => backend.cancel(context),
            Self::Deterministic(backend) => backend.cancel(context),
        }
    }

    fn bind(&mut self, addr: &str) -> Result<SocketId, NetError> {
        match self {
            Self::Host(backend) => backend.bind(addr),
            Self::Deterministic(backend) => backend.bind(addr),
        }
    }

    fn listen(&mut self, listener: SocketId, backlog: usize) -> Result<(), NetError> {
        match self {
            Self::Host(backend) => backend.listen(listener, backlog),
            Self::Deterministic(backend) => backend.listen(listener, backlog),
        }
    }

    fn accept(&mut self, listener: SocketId) -> Result<Option<SocketId>, NetError> {
        match self {
            Self::Host(backend) => backend.accept(listener),
            Self::Deterministic(backend) => backend.accept(listener),
        }
    }

    fn connect(&mut self, addr: &str) -> Result<SocketId, NetError> {
        match self {
            Self::Host(backend) => backend.connect(addr),
            Self::Deterministic(backend) => backend.connect(addr),
        }
    }

    fn read(&mut self, socket: SocketId, max_bytes: usize) -> Result<Vec<u8>, NetError> {
        match self {
            Self::Host(backend) => backend.read(socket, max_bytes),
            Self::Deterministic(backend) => backend.read(socket, max_bytes),
        }
    }

    fn write(&mut self, socket: SocketId, payload: &[u8]) -> Result<usize, NetError> {
        match self {
            Self::Host(backend) => backend.write(socket, payload),
            Self::Deterministic(backend) => backend.write(socket, payload),
        }
    }

    fn close(&mut self, socket: SocketId) -> Result<(), NetError> {
        match self {
            Self::Host(backend) => backend.close(socket),
            Self::Deterministic(backend) => backend.close(socket),
        }
    }

    fn poll_register(
        &mut self,
        socket: SocketId,
        interest: PollInterest,
        max_queue_depth: usize,
    ) -> Result<(), NetError> {
        match self {
            Self::Host(backend) => backend.poll_register(socket, interest, max_queue_depth),
            Self::Deterministic(backend) => {
                backend.poll_register(socket, interest, max_queue_depth)
            }
        }
    }

    fn poll_next(&mut self, max_events: usize) -> Result<Vec<PollerEvent>, NetError> {
        match self {
            Self::Host(backend) => backend.poll_next(max_events),
            Self::Deterministic(backend) => backend.poll_next(max_events),
        }
    }

    fn begin_shutdown(&mut self, timeout_ms: u64, now_ms: u64) {
        match self {
            Self::Host(backend) => backend.begin_shutdown(timeout_ms, now_ms),
            Self::Deterministic(backend) => backend.begin_shutdown(timeout_ms, now_ms),
        }
    }

    fn request_started(&mut self) -> Result<(), NetError> {
        match self {
            Self::Host(backend) => backend.request_started(),
            Self::Deterministic(backend) => backend.request_started(),
        }
    }

    fn request_finished(&mut self) {
        match self {
            Self::Host(backend) => backend.request_finished(),
            Self::Deterministic(backend) => backend.request_finished(),
        }
    }

    fn shutdown_ready(&self, now_ms: u64) -> bool {
        match self {
            Self::Host(backend) => backend.shutdown_ready(now_ms),
            Self::Deterministic(backend) => backend.shutdown_ready(now_ms),
        }
    }

    fn decisions(&self) -> Vec<NetDecision> {
        match self {
            Self::Host(backend) => backend.decisions(),
            Self::Deterministic(backend) => backend.decisions(),
        }
    }
}

#[derive(Debug, Clone)]
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
            max_body_bytes: 1 * 1024 * 1024,
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
}

impl HttpResponse {
    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            reason: "OK".to_string(),
            headers: BTreeMap::new(),
            body: body.into(),
            keep_alive: true,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", self.status, self.reason).as_bytes());
        let mut headers = self.headers.clone();
        headers.insert("Content-Length".to_string(), self.body.len().to_string());
        headers.insert(
            "Connection".to_string(),
            if self.keep_alive {
                "keep-alive".to_string()
            } else {
                "close".to_string()
            },
        );
        for (k, v) in headers {
            out.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }
}

pub trait HttpRouter {
    fn route(&self, req: &HttpRequest) -> HttpResponse;
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

    let body = raw[(headers_end + 4)..].to_vec();
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
    let Some(connection) = backend.accept(listener)? else {
        return Ok(0);
    };
    backend.request_started()?;

    let raw = backend.read(connection, limits.max_header_bytes + limits.max_body_bytes)?;
    let request = parse_http_request(&raw, limits)?;
    let mut response = router.route(&request);
    if !request.keep_alive {
        response.keep_alive = false;
    }

    let serialized = response.to_bytes();
    let wrote = backend.write(connection, &serialized)?;
    if !response.keep_alive {
        backend.close(connection)?;
    }
    backend.request_finished();
    Ok(wrote)
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

#[cfg(test)]
mod tests {
    use super::{
        parse_http_request, DeterministicNet, HttpResponse, HttpRouter, HttpServerLimits,
        NetBackend, NetDecision, NetError, PollInterest, PollerEvent, RequestContext, SocketId,
    };

    struct TestRouter;

    impl HttpRouter for TestRouter {
        fn route(&self, req: &super::HttpRequest) -> HttpResponse {
            HttpResponse::ok(format!("{} {}", req.method, req.path))
        }
    }

    #[test]
    fn deterministic_net_records_replay_decisions() {
        let mut net = DeterministicNet::with_scripted_accepts(1);
        let listener = net.bind("127.0.0.1:8080").expect("bind should work");
        net.listen(listener, 128).expect("listen should work");
        let conn = net
            .accept(listener)
            .expect("accept call should work")
            .expect("one scripted connection should exist");
        net.push_read_chunk(conn, b"abc".to_vec());
        assert_eq!(net.read(conn, 16).expect("read should work"), b"abc");
        assert_eq!(net.write(conn, b"pong").expect("write should work"), 4);
        net.close(conn).expect("close should work");

        let decisions = net.decisions();
        assert!(matches!(decisions[0], NetDecision::Bind { .. }));
        assert!(matches!(
            decisions.last(),
            Some(NetDecision::Close { socket }) if *socket == conn
        ));
    }

    #[test]
    fn poller_queue_is_bounded() {
        let mut net = DeterministicNet::default();
        let listener = net.bind("listener").expect("bind should work");
        net.poll_register(listener, PollInterest::Acceptable, 1)
            .expect("first registration should fit in queue");
        assert_eq!(
            net.poll_register(listener, PollInterest::Readable, 1),
            Err(NetError::QueueFull)
        );
        assert_eq!(
            net.poll_next(8).expect("poll should work"),
            vec![PollerEvent::Acceptable(listener)]
        );
    }

    #[test]
    fn request_context_deadline_and_cancel_are_enforced() {
        let mut net = DeterministicNet::default();
        net.register_context(RequestContext::new(super::ContextId(7), "req-7"));
        net.set_deadline(super::ContextId(7), 20)
            .expect("deadline should work");
        net.cancel(super::ContextId(7)).expect("cancel should work");
        let ctx = net
            .contexts
            .get(&super::ContextId(7))
            .expect("context exists");
        assert_eq!(ctx.check(10), Err(NetError::Cancelled));
    }

    #[test]
    fn parse_http_request_parses_minimal_request() {
        let request = parse_http_request(
            b"GET /health HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n",
            &HttpServerLimits::default(),
        )
        .expect("request should parse");
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/health");
        assert!(!request.keep_alive);
    }

    #[test]
    fn http_serve_once_routes_request() {
        let mut net = DeterministicNet::with_scripted_accepts(1);
        let listener = net.bind("listener").expect("bind should work");
        let connection = SocketId(1);
        net.push_read_chunk(
            connection,
            b"GET /ping HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
        );

        let bytes = super::serve_http_once(
            &mut net,
            listener,
            &TestRouter,
            &HttpServerLimits::default(),
        )
        .expect("serve should work");
        assert!(bytes > 0);
        assert!(net
            .decisions()
            .iter()
            .any(|d| matches!(d, NetDecision::Write { socket, .. } if *socket == connection)));
    }

    #[test]
    fn graceful_shutdown_waits_for_inflight_or_timeout() {
        let mut net = DeterministicNet::default();
        net.request_started().expect("request should start");
        net.begin_shutdown(25, 10);
        assert!(!net.shutdown_ready(20));
        net.request_finished();
        assert!(net.shutdown_ready(21));
    }
}
