use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    Time,
    Random,
    FileSystem,
    Network,
    Process,
    Memory,
    Thread,
}

impl Capability {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "time" => Some(Self::Time),
            "rng" | "random" => Some(Self::Random),
            "fs" | "filesystem" => Some(Self::FileSystem),
            "net" | "network" => Some(Self::Network),
            "proc" | "process" => Some(Self::Process),
            "mem" | "memory" => Some(Self::Memory),
            "thread" | "threads" => Some(Self::Thread),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Time => "time",
            Self::Random => "rng",
            Self::FileSystem => "fs",
            Self::Network => "net",
            Self::Process => "proc",
            Self::Memory => "mem",
            Self::Thread => "thread",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CapabilitySet {
    values: BTreeSet<Capability>,
}

impl CapabilitySet {
    pub fn insert(&mut self, capability: Capability) {
        self.values.insert(capability);
    }

    pub fn contains(&self, capability: Capability) -> bool {
        self.values.contains(&capability)
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = Capability> + '_ {
        self.values.iter().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::{Capability, CapabilitySet};

    #[test]
    fn parse_aliases_work() {
        assert_eq!(Capability::parse("fs"), Some(Capability::FileSystem));
        assert_eq!(Capability::parse("network"), Some(Capability::Network));
        assert_eq!(Capability::parse("threads"), Some(Capability::Thread));
        assert_eq!(Capability::parse("unknown"), None);
    }

    #[test]
    fn capability_set_stores_values() {
        let mut set = CapabilitySet::default();
        set.insert(Capability::Time);
        assert!(set.contains(Capability::Time));
        assert_eq!(set.len(), 1);
    }
}
