use std::collections::{BTreeMap, BTreeSet};

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

#[derive(Debug, Clone, Default)]
pub struct DeterministicMap<K, V>
where
    K: Ord,
{
    inner: BTreeMap<K, V>,
}

impl<K, V> DeterministicMap<K, V>
where
    K: Ord,
{
    pub fn new() -> Self {
        Self {
            inner: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.inner.insert(key, value)
    }

    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.inner.get(key)
    }

    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.inner.remove(key)
    }

    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.inner.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.inner.iter()
    }

    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.inner.keys()
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.inner.values()
    }

    pub fn get_or_insert_with(&mut self, key: K, value: impl FnOnce() -> V) -> &mut V {
        self.inner.entry(key).or_insert_with(value)
    }

    pub fn retain(&mut self, mut predicate: impl FnMut(&K, &mut V) -> bool) {
        self.inner.retain(|key, value| predicate(key, value));
    }
}

#[derive(Debug, Clone, Default)]
pub struct DeterministicSet<T>
where
    T: Ord,
{
    inner: BTreeSet<T>,
}

impl<T> DeterministicSet<T>
where
    T: Ord,
{
    pub fn new() -> Self {
        Self {
            inner: BTreeSet::new(),
        }
    }

    pub fn insert(&mut self, value: T) -> bool {
        self.inner.insert(value)
    }

    pub fn contains<Q>(&self, value: &Q) -> bool
    where
        T: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.inner.contains(value)
    }

    pub fn remove<Q>(&mut self, value: &Q) -> bool
    where
        T: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.inner.remove(value)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
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
}
