use std::collections::{BTreeMap, BTreeSet};

const SMALL_MAP_LIMIT: usize = 8;
const SMALL_SET_LIMIT: usize = 8;

#[derive(Debug, Clone, Default)]
pub struct DeterministicVec<T> {
    inner: Vec<T>,
}

impl<T> DeterministicVec<T> {
    pub fn new() -> Self {
        Self { inner: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Vec::with_capacity(capacity),
        }
    }

    pub fn push(&mut self, value: T) {
        self.inner.push(value);
    }

    pub fn pop(&mut self) -> Option<T> {
        self.inner.pop()
    }

    pub fn get(&self, index: usize) -> Option<&T> {
        self.inner.get(index)
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.inner.get_mut(index)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn clear(&mut self) {
        self.inner.clear();
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.inner.iter()
    }

    pub fn filter_clone(&self, mut predicate: impl FnMut(&T) -> bool) -> Vec<T>
    where
        T: Clone,
    {
        self.inner
            .iter()
            .filter(|value| predicate(value))
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct DeterministicMap<K, V>
where
    K: Ord,
{
    inner: DeterministicMapInner<K, V>,
}

#[derive(Debug, Clone)]
enum DeterministicMapInner<K, V> {
    Small(Vec<(K, V)>),
    Tree(BTreeMap<K, V>),
}

impl<K, V> Default for DeterministicMapInner<K, V> {
    fn default() -> Self {
        Self::Small(Vec::new())
    }
}

impl<K, V> DeterministicMap<K, V>
where
    K: Ord,
{
    pub fn new() -> Self {
        Self {
            inner: DeterministicMapInner::default(),
        }
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        match &mut self.inner {
            DeterministicMapInner::Small(values) => {
                match values.binary_search_by(|(existing, _)| existing.cmp(&key)) {
                    Ok(idx) => Some(std::mem::replace(&mut values[idx].1, value)),
                    Err(idx) => {
                        values.insert(idx, (key, value));
                        if values.len() > SMALL_MAP_LIMIT {
                            self.promote_map_to_tree();
                        }
                        None
                    }
                }
            }
            DeterministicMapInner::Tree(values) => values.insert(key, value),
        }
    }

    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        match &self.inner {
            DeterministicMapInner::Small(values) => values
                .binary_search_by(|(existing, _)| existing.borrow().cmp(key))
                .ok()
                .map(|idx| &values[idx].1),
            DeterministicMapInner::Tree(values) => values.get(key),
        }
    }

    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        match &mut self.inner {
            DeterministicMapInner::Small(values) => values
                .binary_search_by(|(existing, _)| existing.borrow().cmp(key))
                .ok()
                .map(|idx| values.remove(idx).1),
            DeterministicMapInner::Tree(values) => values.remove(key),
        }
    }

    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.get(key).is_some()
    }

    pub fn len(&self) -> usize {
        match &self.inner {
            DeterministicMapInner::Small(values) => values.len(),
            DeterministicMapInner::Tree(values) => values.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        MapIter::new(&self.inner)
    }

    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.iter().map(|(key, _)| key)
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.iter().map(|(_, value)| value)
    }

    pub fn get_or_insert_with(&mut self, key: K, value: impl FnOnce() -> V) -> &mut V {
        let should_promote = matches!(
            &self.inner,
            DeterministicMapInner::Small(values)
                if values.len() >= SMALL_MAP_LIMIT
                    && values
                        .binary_search_by(|(existing, _)| existing.cmp(&key))
                        .is_err()
        );
        if should_promote {
            self.promote_map_to_tree();
        }
        match &mut self.inner {
            DeterministicMapInner::Small(values) => {
                match values.binary_search_by(|(existing, _)| existing.cmp(&key)) {
                    Ok(idx) => &mut values[idx].1,
                    Err(idx) => {
                        values.insert(idx, (key, value()));
                        &mut values[idx].1
                    }
                }
            }
            DeterministicMapInner::Tree(values) => values.entry(key).or_insert_with(value),
        }
    }

    pub fn retain(&mut self, mut predicate: impl FnMut(&K, &mut V) -> bool) {
        match &mut self.inner {
            DeterministicMapInner::Small(values) => {
                values.retain_mut(|(key, value)| predicate(key, value))
            }
            DeterministicMapInner::Tree(values) => {
                values.retain(|key, value| predicate(key, value))
            }
        }
    }

    fn promote_map_to_tree(&mut self) {
        let DeterministicMapInner::Small(values) = &mut self.inner else {
            return;
        };
        let mut tree = BTreeMap::new();
        for (key, value) in std::mem::take(values) {
            tree.insert(key, value);
        }
        self.inner = DeterministicMapInner::Tree(tree);
    }
}

impl<K, V> Default for DeterministicMap<K, V>
where
    K: Ord,
{
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct DeterministicSet<T>
where
    T: Ord,
{
    inner: DeterministicSetInner<T>,
}

#[derive(Debug, Clone)]
enum DeterministicSetInner<T> {
    Small(Vec<T>),
    Tree(BTreeSet<T>),
}

impl<T> Default for DeterministicSetInner<T> {
    fn default() -> Self {
        Self::Small(Vec::new())
    }
}

impl<T> DeterministicSet<T>
where
    T: Ord,
{
    pub fn new() -> Self {
        Self {
            inner: DeterministicSetInner::default(),
        }
    }

    pub fn insert(&mut self, value: T) -> bool {
        match &mut self.inner {
            DeterministicSetInner::Small(values) => match values.binary_search(&value) {
                Ok(_) => false,
                Err(idx) => {
                    values.insert(idx, value);
                    if values.len() > SMALL_SET_LIMIT {
                        self.promote_set_to_tree();
                    }
                    true
                }
            },
            DeterministicSetInner::Tree(values) => values.insert(value),
        }
    }

    pub fn contains<Q>(&self, value: &Q) -> bool
    where
        T: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        match &self.inner {
            DeterministicSetInner::Small(values) => values
                .binary_search_by(|existing| existing.borrow().cmp(value))
                .is_ok(),
            DeterministicSetInner::Tree(values) => values.contains(value),
        }
    }

    pub fn remove<Q>(&mut self, value: &Q) -> bool
    where
        T: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        match &mut self.inner {
            DeterministicSetInner::Small(values) => values
                .binary_search_by(|existing| existing.borrow().cmp(value))
                .ok()
                .map(|idx| {
                    values.remove(idx);
                    true
                })
                .unwrap_or(false),
            DeterministicSetInner::Tree(values) => values.remove(value),
        }
    }

    pub fn len(&self) -> usize {
        match &self.inner {
            DeterministicSetInner::Small(values) => values.len(),
            DeterministicSetInner::Tree(values) => values.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        SetIter::new(&self.inner)
    }

    pub fn filter_clone(&self, mut predicate: impl FnMut(&T) -> bool) -> Vec<T>
    where
        T: Clone,
    {
        self.iter()
            .filter(|value| predicate(value))
            .cloned()
            .collect()
    }

    fn promote_set_to_tree(&mut self) {
        let DeterministicSetInner::Small(values) = &mut self.inner else {
            return;
        };
        let mut tree = BTreeSet::new();
        for value in std::mem::take(values) {
            tree.insert(value);
        }
        self.inner = DeterministicSetInner::Tree(tree);
    }
}

impl<T> Default for DeterministicSet<T>
where
    T: Ord,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> DeterministicMapInner<K, V> {
    fn is_empty(&self) -> bool {
        match self {
            Self::Small(values) => values.is_empty(),
            Self::Tree(values) => values.is_empty(),
        }
    }
}

impl<T> DeterministicSetInner<T> {
    fn is_empty(&self) -> bool {
        match self {
            Self::Small(values) => values.is_empty(),
            Self::Tree(values) => values.is_empty(),
        }
    }
}

enum MapIter<'a, K, V> {
    Small(std::slice::Iter<'a, (K, V)>),
    Tree(std::collections::btree_map::Iter<'a, K, V>),
}

impl<'a, K, V> MapIter<'a, K, V> {
    fn new(inner: &'a DeterministicMapInner<K, V>) -> Self {
        match inner {
            DeterministicMapInner::Small(values) => Self::Small(values.iter()),
            DeterministicMapInner::Tree(values) => Self::Tree(values.iter()),
        }
    }
}

impl<'a, K, V> Iterator for MapIter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Small(values) => values.next().map(|(key, value)| (key, value)),
            Self::Tree(values) => values.next(),
        }
    }
}

enum SetIter<'a, T> {
    Small(std::slice::Iter<'a, T>),
    Tree(std::collections::btree_set::Iter<'a, T>),
}

impl<'a, T> SetIter<'a, T> {
    fn new(inner: &'a DeterministicSetInner<T>) -> Self {
        match inner {
            DeterministicSetInner::Small(values) => Self::Small(values.iter()),
            DeterministicSetInner::Tree(values) => Self::Tree(values.iter()),
        }
    }
}

impl<'a, T> Iterator for SetIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Small(values) => values.next(),
            Self::Tree(values) => values.next(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DeterministicMap, DeterministicSet, DeterministicVec};

    #[test]
    fn deterministic_vec_is_index_stable() {
        let mut values = DeterministicVec::new();
        values.push("a");
        values.push("b");
        values.push("c");
        assert_eq!(values.get(1), Some(&"b"));
        assert_eq!(values.len(), 3);
    }

    #[test]
    fn deterministic_map_has_sorted_iteration() {
        let mut map = DeterministicMap::new();
        map.insert("k2", 2);
        map.insert("k1", 1);
        map.insert("k3", 3);
        let keys: Vec<&str> = map.keys().copied().collect();
        assert_eq!(keys, vec!["k1", "k2", "k3"]);
    }

    #[test]
    fn deterministic_set_is_stable() {
        let mut set = DeterministicSet::new();
        set.insert(3);
        set.insert(1);
        set.insert(2);
        let got: Vec<i32> = set.iter().copied().collect();
        assert_eq!(got, vec![1, 2, 3]);
    }

    #[test]
    fn map_get_or_insert_and_retain_are_stable() {
        let mut map = DeterministicMap::new();
        *map.get_or_insert_with("k2", || 2) += 1;
        map.insert("k1", 1);
        map.retain(|key, _| *key == "k2");
        let keys: Vec<&str> = map.keys().copied().collect();
        assert_eq!(keys, vec!["k2"]);
        assert_eq!(map.get("k2"), Some(&3));
    }

    #[test]
    fn vec_and_set_filter_clone_preserve_order() {
        let mut values = DeterministicVec::new();
        values.push(3);
        values.push(1);
        values.push(2);
        assert_eq!(values.filter_clone(|v| *v >= 2), vec![3, 2]);

        let mut set = DeterministicSet::new();
        set.insert(3);
        set.insert(1);
        set.insert(2);
        assert_eq!(set.filter_clone(|v| *v >= 2), vec![2, 3]);
    }

    #[test]
    fn small_map_and_set_promote_without_losing_order() {
        let mut map = DeterministicMap::new();
        for idx in (0..10).rev() {
            map.insert(idx, idx * 10);
        }
        let keys: Vec<i32> = map.keys().copied().collect();
        assert_eq!(keys, (0..10).collect::<Vec<_>>());
        assert_eq!(map.get(&4), Some(&40));

        let mut set = DeterministicSet::new();
        for idx in (0..10).rev() {
            assert!(set.insert(idx));
        }
        let values: Vec<i32> = set.iter().copied().collect();
        assert_eq!(values, (0..10).collect::<Vec<_>>());
        assert!(set.contains(&7));
    }
}
