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

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = Capability> + '_ {
        self.values.iter().copied()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityToken {
    values: BTreeSet<Capability>,
}

impl CapabilityToken {
    pub fn new(values: impl IntoIterator<Item = Capability>) -> Self {
        Self {
            values: values.into_iter().collect(),
        }
    }

    pub fn allows(&self, capability: Capability) -> bool {
        self.values.contains(&capability)
    }

    pub fn compose(&self, other: &Self) -> Self {
        let mut values = self.values.clone();
        values.extend(other.values.iter().copied());
        Self { values }
    }

    pub fn intersect(&self, other: &Self) -> Self {
        let values = self
            .values
            .intersection(&other.values)
            .copied()
            .collect::<BTreeSet<_>>();
        Self { values }
    }

    pub fn negate_from_universe(&self, universe: &Self) -> Self {
        let values = universe
            .values
            .difference(&self.values)
            .copied()
            .collect::<BTreeSet<_>>();
        Self { values }
    }

    pub fn revoke(&mut self, capability: Capability) {
        self.values.remove(&capability);
    }

    pub fn delegate_subset(&self, subset: impl IntoIterator<Item = Capability>) -> Self {
        let requested = subset.into_iter().collect::<BTreeSet<_>>();
        let values = requested
            .intersection(&self.values)
            .copied()
            .collect::<BTreeSet<_>>();
        Self { values }
    }

    pub fn iter(&self) -> impl Iterator<Item = Capability> + '_ {
        self.values.iter().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::{Capability, CapabilitySet, CapabilityToken};

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

    #[test]
    fn token_algebra_and_revocation_work() {
        let t1 = CapabilityToken::new([Capability::Network, Capability::FileSystem]);
        let t2 = CapabilityToken::new([Capability::Process, Capability::Network]);
        let composed = t1.compose(&t2);
        assert!(composed.allows(Capability::Network));
        assert!(composed.allows(Capability::Process));

        let intersection = t1.intersect(&t2);
        assert!(intersection.allows(Capability::Network));
        assert!(!intersection.allows(Capability::Process));

        let mut revocable = composed.clone();
        revocable.revoke(Capability::Network);
        assert!(!revocable.allows(Capability::Network));

        let delegated = composed.delegate_subset([Capability::Process, Capability::Memory]);
        assert!(delegated.allows(Capability::Process));
        assert!(!delegated.allows(Capability::Memory));
    }
}
