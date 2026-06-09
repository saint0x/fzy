use crate::core::{require_capability, CapabilityError};
use core::{Capability, CapabilityToken};
use serde_json::{Map, Value};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
#[cfg(unix)]
use std::os::unix::net::UnixDatagram;

pub fn required_capability_for_network() -> Capability {
    Capability::Http
}

pub fn connect_with_capability(
    backend: &mut dyn NetBackend,
    addr: &str,
    token: &CapabilityToken,
) -> Result<SocketId, CapabilityError> {
    require_capability(token, required_capability_for_network())?;
    backend
        .connect(addr)
        .map_err(|_| CapabilityError::Missing(required_capability_for_network()))
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketOptions {
    pub reuse_addr: bool,
    pub reuse_port: bool,
    pub tcp_nodelay: bool,
    pub keepalive: bool,
}

impl Default for SocketOptions {
    fn default() -> Self {
        Self {
            reuse_addr: true,
            reuse_port: true,
            tcp_nodelay: true,
            keepalive: true,
        }
    }
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
    InvalidAddress(String),
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
    BindUdp {
        addr: String,
        socket: SocketId,
    },
    ConnectUdp {
        addr: String,
        socket: SocketId,
    },
    BindUnix {
        path: String,
        socket: SocketId,
    },
    JoinMulticast {
        socket: SocketId,
        group: String,
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

#[derive(Debug, Clone, Default)]
pub struct GracefulShutdown {
    pub draining: bool,
    pub in_flight: usize,
    pub timeout_ms: u64,
    pub started_at_ms: Option<u64>,
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
        self.started_at_ms
            .map(|start| now_ms.saturating_sub(start) >= self.timeout_ms)
            .unwrap_or(false)
    }
}

pub trait NetBackend {
    fn register_context(&mut self, ctx: RequestContext);
    fn set_deadline(&mut self, context: ContextId, deadline_ms: u64) -> Result<(), NetError>;
    fn cancel(&mut self, context: ContextId) -> Result<(), NetError>;

    fn resolve_host(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, NetError>;

    fn bind(&mut self, addr: &str) -> Result<SocketId, NetError>;
    fn listen(&mut self, listener: SocketId, backlog: usize) -> Result<(), NetError>;
    fn accept(&mut self, listener: SocketId) -> Result<Option<SocketId>, NetError>;
    fn connect(&mut self, addr: &str) -> Result<SocketId, NetError>;

    fn bind_udp(&mut self, addr: &str) -> Result<SocketId, NetError>;
    fn connect_udp(&mut self, socket: SocketId, addr: &str) -> Result<(), NetError>;
    fn udp_send_to(
        &mut self,
        socket: SocketId,
        addr: &str,
        payload: &[u8],
    ) -> Result<usize, NetError>;
    fn udp_recv_from(
        &mut self,
        socket: SocketId,
        max_bytes: usize,
    ) -> Result<(Vec<u8>, Option<SocketAddr>), NetError>;

    fn bind_unix_datagram(&mut self, path: &str) -> Result<SocketId, NetError>;
    fn unix_send_to(
        &mut self,
        socket: SocketId,
        path: &str,
        payload: &[u8],
    ) -> Result<usize, NetError>;

    fn join_multicast_v4(&mut self, socket: SocketId, group: Ipv4Addr) -> Result<(), NetError>;

    fn set_socket_options(
        &mut self,
        socket: SocketId,
        options: SocketOptions,
    ) -> Result<(), NetError>;

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

    fn decisions(&self) -> &[NetDecision];
}

enum HostSocket {
    Listener(Socket),
    Listening(TcpListener, usize),
    Stream(TcpStream),
    Udp(UdpSocket),
    #[cfg(unix)]
    UnixDatagram(UnixDatagram),
}

pub struct HostNet {
    next_socket: u64,
    sockets: BTreeMap<SocketId, (HostSocket, SocketOwnership)>,
    poll_interests: BTreeMap<SocketId, PollInterest>,
    poll_slots: Vec<(SocketId, PollInterest)>,
    poll_scan_cursor: usize,
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
            poll_slots: Vec::new(),
            poll_scan_cursor: 0,
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

    fn resolve_one(addr: &str) -> Result<SocketAddr, NetError> {
        addr.to_socket_addrs()
            .map_err(|e| NetError::InvalidAddress(e.to_string()))?
            .next()
            .ok_or_else(|| NetError::InvalidAddress(addr.to_string()))
    }

    fn scan_poll_interests(&mut self, max_queue_depth: usize) -> Result<(), NetError> {
        if self.poll_slots.is_empty() {
            return Ok(());
        }
        let mut scanned = 0usize;
        while scanned < self.poll_slots.len() && self.poll_queue.len() < max_queue_depth {
            let idx = self.poll_scan_cursor % self.poll_slots.len();
            self.poll_scan_cursor = (idx + 1) % self.poll_slots.len();
            scanned += 1;
            let (socket, interest) = self.poll_slots[idx];
            if let Some(event) = self.poll_event_for(socket, interest) {
                self.queue_event(event, max_queue_depth)?;
            }
        }
        Ok(())
    }

    fn poll_event_for(&self, socket: SocketId, interest: PollInterest) -> Option<PollerEvent> {
        match (self.sockets.get(&socket).map(|(s, _)| s), interest) {
            (Some(HostSocket::Listening(_, _)), PollInterest::Acceptable) => {
                Some(PollerEvent::Acceptable(socket))
            }
            (Some(HostSocket::Stream(_)), PollInterest::Readable) => {
                Some(PollerEvent::Readable(socket))
            }
            (Some(HostSocket::Udp(_)), PollInterest::Readable) => {
                Some(PollerEvent::Readable(socket))
            }
            #[cfg(unix)]
            (Some(HostSocket::UnixDatagram(_)), PollInterest::Readable) => {
                Some(PollerEvent::Readable(socket))
            }
            (Some(HostSocket::Stream(_)), PollInterest::Writable) => {
                Some(PollerEvent::Writable(socket))
            }
            (Some(HostSocket::Udp(_)), PollInterest::Writable) => {
                Some(PollerEvent::Writable(socket))
            }
            #[cfg(unix)]
            (Some(HostSocket::UnixDatagram(_)), PollInterest::Writable) => {
                Some(PollerEvent::Writable(socket))
            }
            _ => None,
        }
    }

    fn remember_poll_interest(&mut self, socket: SocketId, interest: PollInterest) {
        if let Some(existing) = self
            .poll_slots
            .iter_mut()
            .find(|(existing_socket, _)| *existing_socket == socket)
        {
            *existing = (socket, interest);
        } else {
            self.poll_slots.push((socket, interest));
        }
    }

    fn forget_poll_interest(&mut self, socket: SocketId) {
        if let Some(idx) = self
            .poll_slots
            .iter()
            .position(|(existing_socket, _)| *existing_socket == socket)
        {
            self.poll_slots.swap_remove(idx);
            if self.poll_scan_cursor > idx {
                self.poll_scan_cursor = self.poll_scan_cursor.saturating_sub(1);
            }
            if self.poll_slots.is_empty() {
                self.poll_scan_cursor = 0;
            } else if self.poll_scan_cursor >= self.poll_slots.len() {
                self.poll_scan_cursor %= self.poll_slots.len();
            }
        }
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

    fn resolve_host(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, NetError> {
        (host, port)
            .to_socket_addrs()
            .map(|iter| iter.collect::<Vec<_>>())
            .map_err(|e| NetError::InvalidAddress(e.to_string()))
    }

    fn bind(&mut self, addr: &str) -> Result<SocketId, NetError> {
        let target = Self::resolve_one(addr)?;
        let domain = if target.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
            .map_err(|e| NetError::Io(e.to_string()))?;
        socket
            .set_reuse_address(true)
            .map_err(|e| NetError::Io(e.to_string()))?;
        socket
            .bind(&target.into())
            .map_err(|e| NetError::Io(e.to_string()))?;
        socket
            .set_nonblocking(true)
            .map_err(|e| NetError::Io(e.to_string()))?;
        socket
            .set_nonblocking(true)
            .map_err(|e| NetError::Io(e.to_string()))?;
        let id = self.new_socket_id();
        self.sockets.insert(
            id,
            (HostSocket::Listener(socket), SocketOwnership::RuntimeOwned),
        );
        self.decisions.push(NetDecision::Bind {
            addr: addr.to_string(),
            listener: id,
        });
        Ok(id)
    }

    fn listen(&mut self, listener: SocketId, backlog: usize) -> Result<(), NetError> {
        if backlog == 0 {
            return Err(NetError::LimitsExceeded("backlog must be > 0".to_string()));
        }
        let Some((socket, _)) = self.sockets.get_mut(&listener) else {
            return Err(NetError::InvalidSocketKind);
        };
        match socket {
            HostSocket::Listener(sock) => {
                sock.listen(backlog as i32)
                    .map_err(|e| NetError::Io(e.to_string()))?;
                sock.set_nonblocking(true)
                    .map_err(|e| NetError::Io(e.to_string()))?;
                let listener_sock: TcpListener = sock
                    .try_clone()
                    .map_err(|e| NetError::Io(e.to_string()))?
                    .into();
                *socket = HostSocket::Listening(listener_sock, backlog);
            }
            HostSocket::Listening(_, existing) => {
                if *existing != backlog {
                    return Err(NetError::LimitsExceeded(format!(
                        "listener already active with backlog {}",
                        existing
                    )));
                }
            }
            _ => return Err(NetError::InvalidSocketKind),
        }
        self.decisions
            .push(NetDecision::Listen { listener, backlog });
        Ok(())
    }

    fn accept(&mut self, listener: SocketId) -> Result<Option<SocketId>, NetError> {
        let Some((HostSocket::Listening(sock, _), _)) = self.sockets.get_mut(&listener) else {
            return Err(NetError::InvalidSocketKind);
        };
        match sock.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(true)
                    .map_err(|e| NetError::Io(e.to_string()))?;
                stream
                    .set_nodelay(true)
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
        let target = Self::resolve_one(addr)?;
        let stream = TcpStream::connect(target).map_err(|e| NetError::Io(e.to_string()))?;
        stream
            .set_nonblocking(true)
            .map_err(|e| NetError::Io(e.to_string()))?;
        stream
            .set_nodelay(true)
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

    fn bind_udp(&mut self, addr: &str) -> Result<SocketId, NetError> {
        let target = Self::resolve_one(addr)?;
        let socket = UdpSocket::bind(target).map_err(|e| NetError::Io(e.to_string()))?;
        socket
            .set_nonblocking(true)
            .map_err(|e| NetError::Io(e.to_string()))?;
        let id = self.new_socket_id();
        self.sockets.insert(
            id,
            (HostSocket::Udp(socket), SocketOwnership::ApplicationOwned),
        );
        self.decisions.push(NetDecision::BindUdp {
            addr: addr.to_string(),
            socket: id,
        });
        Ok(id)
    }

    fn connect_udp(&mut self, socket: SocketId, addr: &str) -> Result<(), NetError> {
        let target = Self::resolve_one(addr)?;
        let Some((HostSocket::Udp(sock), _)) = self.sockets.get_mut(&socket) else {
            return Err(NetError::InvalidSocketKind);
        };
        sock.connect(target)
            .map_err(|e| NetError::Io(e.to_string()))?;
        self.decisions.push(NetDecision::ConnectUdp {
            addr: addr.to_string(),
            socket,
        });
        Ok(())
    }

    fn udp_send_to(
        &mut self,
        socket: SocketId,
        addr: &str,
        payload: &[u8],
    ) -> Result<usize, NetError> {
        let target = Self::resolve_one(addr)?;
        let Some((HostSocket::Udp(sock), _)) = self.sockets.get_mut(&socket) else {
            return Err(NetError::InvalidSocketKind);
        };
        sock.send_to(payload, target)
            .map_err(|e| NetError::Io(e.to_string()))
    }

    fn udp_recv_from(
        &mut self,
        socket: SocketId,
        max_bytes: usize,
    ) -> Result<(Vec<u8>, Option<SocketAddr>), NetError> {
        let Some((HostSocket::Udp(sock), _)) = self.sockets.get_mut(&socket) else {
            return Err(NetError::InvalidSocketKind);
        };
        let mut buf = vec![0_u8; max_bytes];
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                buf.truncate(n);
                Ok((buf, Some(from)))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok((Vec::new(), None)),
            Err(e) => Err(NetError::Io(e.to_string())),
        }
    }

    fn bind_unix_datagram(&mut self, path: &str) -> Result<SocketId, NetError> {
        #[cfg(unix)]
        {
            let _ = std::fs::remove_file(path);
            let socket = UnixDatagram::bind(path).map_err(|e| NetError::Io(e.to_string()))?;
            socket
                .set_nonblocking(true)
                .map_err(|e| NetError::Io(e.to_string()))?;
            let id = self.new_socket_id();
            self.sockets.insert(
                id,
                (
                    HostSocket::UnixDatagram(socket),
                    SocketOwnership::ApplicationOwned,
                ),
            );
            self.decisions.push(NetDecision::BindUnix {
                path: path.to_string(),
                socket: id,
            });
            Ok(id)
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(NetError::Io(
                "unix datagram unsupported on this platform".to_string(),
            ))
        }
    }

    fn unix_send_to(
        &mut self,
        socket: SocketId,
        path: &str,
        payload: &[u8],
    ) -> Result<usize, NetError> {
        #[cfg(unix)]
        {
            let Some((HostSocket::UnixDatagram(sock), _)) = self.sockets.get_mut(&socket) else {
                return Err(NetError::InvalidSocketKind);
            };
            sock.send_to(payload, path)
                .map_err(|e| NetError::Io(e.to_string()))
        }
        #[cfg(not(unix))]
        {
            let _ = (socket, path, payload);
            Err(NetError::Io(
                "unix datagram unsupported on this platform".to_string(),
            ))
        }
    }

    fn join_multicast_v4(&mut self, socket: SocketId, group: Ipv4Addr) -> Result<(), NetError> {
        let Some((HostSocket::Udp(sock), _)) = self.sockets.get_mut(&socket) else {
            return Err(NetError::InvalidSocketKind);
        };
        sock.join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED)
            .map_err(|e| NetError::Io(e.to_string()))?;
        self.decisions.push(NetDecision::JoinMulticast {
            socket,
            group: group.to_string(),
        });
        Ok(())
    }

    fn set_socket_options(
        &mut self,
        socket: SocketId,
        options: SocketOptions,
    ) -> Result<(), NetError> {
        let Some((host_socket, _)) = self.sockets.get_mut(&socket) else {
            return Err(NetError::NotFound);
        };
        match host_socket {
            HostSocket::Listener(sock) => {
                sock.set_reuse_address(options.reuse_addr)
                    .map_err(|e| NetError::Io(e.to_string()))?;
                let _ = options.reuse_port;
            }
            HostSocket::Listening(listener, _) => {
                let sock = Socket::from(
                    listener
                        .try_clone()
                        .map_err(|e| NetError::Io(e.to_string()))?,
                );
                sock.set_reuse_address(options.reuse_addr)
                    .map_err(|e| NetError::Io(e.to_string()))?;
                let _ = options.reuse_port;
            }
            HostSocket::Stream(stream) => {
                stream
                    .set_nodelay(options.tcp_nodelay)
                    .map_err(|e| NetError::Io(e.to_string()))?;
                let _ = options.keepalive;
            }
            HostSocket::Udp(_) => {}
            #[cfg(unix)]
            HostSocket::UnixDatagram(_) => {}
        }
        Ok(())
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
        self.poll_interests.remove(&socket);
        self.forget_poll_interest(socket);
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
        _max_queue_depth: usize,
    ) -> Result<(), NetError> {
        let Some((host_socket, _)) = self.sockets.get(&socket) else {
            return Err(NetError::NotFound);
        };
        if matches!(interest, PollInterest::Acceptable)
            && !matches!(host_socket, HostSocket::Listening(_, _))
        {
            return Err(NetError::InvalidSocketKind);
        }
        self.poll_interests.insert(socket, interest);
        self.remember_poll_interest(socket, interest);
        Ok(())
    }

    fn poll_next(&mut self, max_events: usize) -> Result<Vec<PollerEvent>, NetError> {
        if self.poll_queue.is_empty() {
            self.scan_poll_interests(max_events.max(1))?;
        }
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

    fn decisions(&self) -> &[NetDecision] {
        &self.decisions
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
    listeners: BTreeMap<SocketId, String>,
    listening: BTreeSet<SocketId>,
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
            listeners: BTreeMap::new(),
            listening: BTreeSet::new(),
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

    fn validate_addr(addr: &str) -> Result<(), NetError> {
        if addr.starts_with("unix:") {
            return Ok(());
        }
        addr.to_socket_addrs()
            .map_err(|_| NetError::InvalidAddress(addr.to_string()))?
            .next()
            .ok_or_else(|| NetError::InvalidAddress(addr.to_string()))?;
        Ok(())
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

    fn resolve_host(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, NetError> {
        (host, port)
            .to_socket_addrs()
            .map(|iter| iter.collect())
            .map_err(|_| NetError::InvalidAddress(format!("{host}:{port}")))
    }

    fn bind(&mut self, addr: &str) -> Result<SocketId, NetError> {
        Self::validate_addr(addr)?;
        let id = self.alloc_socket();
        self.listeners.insert(id, addr.to_string());
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
        if !self.listeners.contains_key(&listener) {
            return Err(NetError::InvalidSocketKind);
        }
        if backlog == 0 {
            return Err(NetError::LimitsExceeded("backlog must be > 0".to_string()));
        }
        self.listening.insert(listener);
        self.decisions
            .push(NetDecision::Listen { listener, backlog });
        Ok(())
    }

    fn accept(&mut self, listener: SocketId) -> Result<Option<SocketId>, NetError> {
        if !self.listeners.contains_key(&listener) {
            return Err(NetError::InvalidSocketKind);
        }
        if !self.listening.contains(&listener) {
            return Ok(None);
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
        Self::validate_addr(addr)?;
        let id = self.alloc_socket();
        self.decisions.push(NetDecision::Connect {
            addr: addr.to_string(),
            connection: id,
        });
        Ok(id)
    }

    fn bind_udp(&mut self, addr: &str) -> Result<SocketId, NetError> {
        Self::validate_addr(addr)?;
        let id = self.alloc_socket();
        self.decisions.push(NetDecision::BindUdp {
            addr: addr.to_string(),
            socket: id,
        });
        Ok(id)
    }

    fn connect_udp(&mut self, socket: SocketId, addr: &str) -> Result<(), NetError> {
        if !self.open.contains(&socket) {
            return Err(NetError::NotFound);
        }
        Self::validate_addr(addr)?;
        self.decisions.push(NetDecision::ConnectUdp {
            addr: addr.to_string(),
            socket,
        });
        Ok(())
    }

    fn udp_send_to(
        &mut self,
        socket: SocketId,
        addr: &str,
        payload: &[u8],
    ) -> Result<usize, NetError> {
        if !self.open.contains(&socket) {
            return Err(NetError::NotFound);
        }
        Self::validate_addr(addr)?;
        self.decisions.push(NetDecision::Write {
            socket,
            bytes: payload.len(),
        });
        Ok(payload.len())
    }

    fn udp_recv_from(
        &mut self,
        socket: SocketId,
        max_bytes: usize,
    ) -> Result<(Vec<u8>, Option<SocketAddr>), NetError> {
        if !self.open.contains(&socket) {
            return Err(NetError::NotFound);
        }
        let chunk = self
            .scripted_reads
            .entry(socket)
            .or_default()
            .pop_front()
            .unwrap_or_default();
        let chunk = chunk.into_iter().take(max_bytes).collect::<Vec<_>>();
        Ok((chunk, None))
    }

    fn bind_unix_datagram(&mut self, path: &str) -> Result<SocketId, NetError> {
        if path.is_empty() {
            return Err(NetError::InvalidAddress("empty unix path".to_string()));
        }
        let id = self.alloc_socket();
        self.decisions.push(NetDecision::BindUnix {
            path: path.to_string(),
            socket: id,
        });
        Ok(id)
    }

    fn unix_send_to(
        &mut self,
        socket: SocketId,
        path: &str,
        payload: &[u8],
    ) -> Result<usize, NetError> {
        if !self.open.contains(&socket) {
            return Err(NetError::NotFound);
        }
        if path.is_empty() {
            return Err(NetError::InvalidAddress("empty unix path".to_string()));
        }
        self.decisions.push(NetDecision::Write {
            socket,
            bytes: payload.len(),
        });
        Ok(payload.len())
    }

    fn join_multicast_v4(&mut self, socket: SocketId, group: Ipv4Addr) -> Result<(), NetError> {
        if !self.open.contains(&socket) {
            return Err(NetError::NotFound);
        }
        self.decisions.push(NetDecision::JoinMulticast {
            socket,
            group: group.to_string(),
        });
        Ok(())
    }

    fn set_socket_options(
        &mut self,
        socket: SocketId,
        _options: SocketOptions,
    ) -> Result<(), NetError> {
        if !self.open.contains(&socket) {
            return Err(NetError::NotFound);
        }
        Ok(())
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
        self.listening.remove(&socket);
        self.listeners.remove(&socket);
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
        if matches!(interest, PollInterest::Acceptable) && !self.listening.contains(&socket) {
            return Err(NetError::InvalidSocketKind);
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

    fn decisions(&self) -> &[NetDecision] {
        &self.decisions
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

    fn resolve_host(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, NetError> {
        match self {
            Self::Host(backend) => backend.resolve_host(host, port),
            Self::Deterministic(backend) => backend.resolve_host(host, port),
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

    fn bind_udp(&mut self, addr: &str) -> Result<SocketId, NetError> {
        match self {
            Self::Host(backend) => backend.bind_udp(addr),
            Self::Deterministic(backend) => backend.bind_udp(addr),
        }
    }

    fn connect_udp(&mut self, socket: SocketId, addr: &str) -> Result<(), NetError> {
        match self {
            Self::Host(backend) => backend.connect_udp(socket, addr),
            Self::Deterministic(backend) => backend.connect_udp(socket, addr),
        }
    }

    fn udp_send_to(
        &mut self,
        socket: SocketId,
        addr: &str,
        payload: &[u8],
    ) -> Result<usize, NetError> {
        match self {
            Self::Host(backend) => backend.udp_send_to(socket, addr, payload),
            Self::Deterministic(backend) => backend.udp_send_to(socket, addr, payload),
        }
    }

    fn udp_recv_from(
        &mut self,
        socket: SocketId,
        max_bytes: usize,
    ) -> Result<(Vec<u8>, Option<SocketAddr>), NetError> {
        match self {
            Self::Host(backend) => backend.udp_recv_from(socket, max_bytes),
            Self::Deterministic(backend) => backend.udp_recv_from(socket, max_bytes),
        }
    }

    fn bind_unix_datagram(&mut self, path: &str) -> Result<SocketId, NetError> {
        match self {
            Self::Host(backend) => backend.bind_unix_datagram(path),
            Self::Deterministic(backend) => backend.bind_unix_datagram(path),
        }
    }

    fn unix_send_to(
        &mut self,
        socket: SocketId,
        path: &str,
        payload: &[u8],
    ) -> Result<usize, NetError> {
        match self {
            Self::Host(backend) => backend.unix_send_to(socket, path, payload),
            Self::Deterministic(backend) => backend.unix_send_to(socket, path, payload),
        }
    }

    fn join_multicast_v4(&mut self, socket: SocketId, group: Ipv4Addr) -> Result<(), NetError> {
        match self {
            Self::Host(backend) => backend.join_multicast_v4(socket, group),
            Self::Deterministic(backend) => backend.join_multicast_v4(socket, group),
        }
    }

    fn set_socket_options(
        &mut self,
        socket: SocketId,
        options: SocketOptions,
    ) -> Result<(), NetError> {
        match self {
            Self::Host(backend) => backend.set_socket_options(socket, options),
            Self::Deterministic(backend) => backend.set_socket_options(socket, options),
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

    fn decisions(&self) -> &[NetDecision] {
        match self {
            Self::Host(backend) => backend.decisions(),
            Self::Deterministic(backend) => backend.decisions(),
        }
    }
}

mod server;
pub use server::*;

#[cfg(test)]
mod tests;
