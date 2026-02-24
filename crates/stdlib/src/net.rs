use capabilities::Capability;
use std::collections::VecDeque;

pub fn required_capability_for_network() -> Capability {
    Capability::Network
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetMode {
    Host,
    Deterministic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetEvent {
    Send(String),
    Recv(String),
    Deadline(u64),
    Cancel,
}

pub trait NetBackend {
    fn send(&mut self, payload: &str);
    fn recv(&mut self) -> Option<String>;
    fn deadline(&mut self, millis: u64);
    fn cancel(&mut self);
    fn events(&self) -> Vec<NetEvent>;
}

#[derive(Default)]
pub struct HostNet {
    events: Vec<NetEvent>,
}

impl NetBackend for HostNet {
    fn send(&mut self, payload: &str) {
        self.events.push(NetEvent::Send(payload.to_string()));
    }

    fn recv(&mut self) -> Option<String> {
        let value = "host-recv".to_string();
        self.events.push(NetEvent::Recv(value.clone()));
        Some(value)
    }

    fn deadline(&mut self, millis: u64) {
        self.events.push(NetEvent::Deadline(millis));
    }

    fn cancel(&mut self) {
        self.events.push(NetEvent::Cancel);
    }

    fn events(&self) -> Vec<NetEvent> {
        self.events.clone()
    }
}

#[derive(Default)]
pub struct DeterministicNet {
    inbox: VecDeque<String>,
    events: Vec<NetEvent>,
}

impl DeterministicNet {
    pub fn with_inbox(messages: Vec<String>) -> Self {
        Self {
            inbox: VecDeque::from(messages),
            events: Vec::new(),
        }
    }
}

impl NetBackend for DeterministicNet {
    fn send(&mut self, payload: &str) {
        self.events.push(NetEvent::Send(payload.to_string()));
    }

    fn recv(&mut self) -> Option<String> {
        let value = self
            .inbox
            .pop_front()
            .unwrap_or_else(|| "det-recv".to_string());
        self.events.push(NetEvent::Recv(value.clone()));
        Some(value)
    }

    fn deadline(&mut self, millis: u64) {
        self.events.push(NetEvent::Deadline(millis));
    }

    fn cancel(&mut self) {
        self.events.push(NetEvent::Cancel);
    }

    fn events(&self) -> Vec<NetEvent> {
        self.events.clone()
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

    pub fn send(&mut self, payload: &str) {
        match self {
            Self::Host(net) => net.send(payload),
            Self::Deterministic(net) => net.send(payload),
        }
    }

    pub fn recv(&mut self) -> Option<String> {
        match self {
            Self::Host(net) => net.recv(),
            Self::Deterministic(net) => net.recv(),
        }
    }

    pub fn deadline(&mut self, millis: u64) {
        match self {
            Self::Host(net) => net.deadline(millis),
            Self::Deterministic(net) => net.deadline(millis),
        }
    }

    pub fn cancel(&mut self) {
        match self {
            Self::Host(net) => net.cancel(),
            Self::Deterministic(net) => net.cancel(),
        }
    }

    pub fn events(&self) -> Vec<NetEvent> {
        match self {
            Self::Host(net) => net.events(),
            Self::Deterministic(net) => net.events(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DeterministicNet, NetBackend, NetEvent};

    #[test]
    fn deterministic_net_records_deadline_and_cancel() {
        let mut net = DeterministicNet::with_inbox(vec!["ok".to_string()]);
        net.send("ping");
        assert_eq!(net.recv(), Some("ok".to_string()));
        net.deadline(12);
        net.cancel();
        assert_eq!(
            net.events(),
            vec![
                NetEvent::Send("ping".to_string()),
                NetEvent::Recv("ok".to_string()),
                NetEvent::Deadline(12),
                NetEvent::Cancel
            ]
        );
    }
}
