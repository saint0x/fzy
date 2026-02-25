use std::fmt;
use std::sync::atomic::{fence, AtomicBool, AtomicI64, AtomicUsize, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicOrdering {
    Relaxed,
    Acquire,
    Release,
    AcqRel,
    SeqCst,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtomicOrderError {
    InvalidLoadOrdering(AtomicOrdering),
    InvalidStoreOrdering(AtomicOrdering),
}

impl fmt::Display for AtomicOrderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLoadOrdering(order) => {
                write!(f, "invalid ordering for atomic load: {:?}", order)
            }
            Self::InvalidStoreOrdering(order) => {
                write!(f, "invalid ordering for atomic store: {:?}", order)
            }
        }
    }
}

impl std::error::Error for AtomicOrderError {}

impl AtomicOrdering {
    fn as_std(self) -> Ordering {
        match self {
            Self::Relaxed => Ordering::Relaxed,
            Self::Acquire => Ordering::Acquire,
            Self::Release => Ordering::Release,
            Self::AcqRel => Ordering::AcqRel,
            Self::SeqCst => Ordering::SeqCst,
        }
    }

    fn validate_load(self) -> Result<Ordering, AtomicOrderError> {
        match self {
            Self::Release | Self::AcqRel => Err(AtomicOrderError::InvalidLoadOrdering(self)),
            _ => Ok(self.as_std()),
        }
    }

    fn validate_store(self) -> Result<Ordering, AtomicOrderError> {
        match self {
            Self::Acquire | Self::AcqRel => Err(AtomicOrderError::InvalidStoreOrdering(self)),
            _ => Ok(self.as_std()),
        }
    }
}

#[derive(Debug)]
pub struct AtomicI64Cell {
    inner: AtomicI64,
}

impl AtomicI64Cell {
    pub fn new(value: i64) -> Self {
        Self {
            inner: AtomicI64::new(value),
        }
    }

    pub fn load(&self, ordering: AtomicOrdering) -> Result<i64, AtomicOrderError> {
        Ok(self.inner.load(ordering.validate_load()?))
    }

    pub fn store(&self, value: i64, ordering: AtomicOrdering) -> Result<(), AtomicOrderError> {
        self.inner.store(value, ordering.validate_store()?);
        Ok(())
    }

    pub fn fetch_add(&self, value: i64, ordering: AtomicOrdering) -> i64 {
        self.inner.fetch_add(value, ordering.as_std())
    }
}

#[derive(Debug)]
pub struct AtomicBoolCell {
    inner: AtomicBool,
}

impl AtomicBoolCell {
    pub fn new(value: bool) -> Self {
        Self {
            inner: AtomicBool::new(value),
        }
    }

    pub fn load(&self, ordering: AtomicOrdering) -> Result<bool, AtomicOrderError> {
        Ok(self.inner.load(ordering.validate_load()?))
    }

    pub fn store(&self, value: bool, ordering: AtomicOrdering) -> Result<(), AtomicOrderError> {
        self.inner.store(value, ordering.validate_store()?);
        Ok(())
    }

    pub fn swap(&self, value: bool, ordering: AtomicOrdering) -> bool {
        self.inner.swap(value, ordering.as_std())
    }
}

#[derive(Debug)]
pub struct AtomicUsizeCell {
    inner: AtomicUsize,
}

impl AtomicUsizeCell {
    pub fn new(value: usize) -> Self {
        Self {
            inner: AtomicUsize::new(value),
        }
    }

    pub fn load(&self, ordering: AtomicOrdering) -> Result<usize, AtomicOrderError> {
        Ok(self.inner.load(ordering.validate_load()?))
    }

    pub fn store(&self, value: usize, ordering: AtomicOrdering) -> Result<(), AtomicOrderError> {
        self.inner.store(value, ordering.validate_store()?);
        Ok(())
    }

    pub fn fetch_add(&self, value: usize, ordering: AtomicOrdering) -> usize {
        self.inner.fetch_add(value, ordering.as_std())
    }
}

pub fn memory_fence(ordering: AtomicOrdering) {
    fence(ordering.as_std());
}

#[cfg(test)]
mod tests {
    use super::{memory_fence, AtomicBoolCell, AtomicI64Cell, AtomicOrderError, AtomicOrdering};

    #[test]
    fn atomic_i64_supports_explicit_ordering() {
        let cell = AtomicI64Cell::new(10);
        assert_eq!(cell.load(AtomicOrdering::Acquire).expect("load"), 10);
        cell.store(15, AtomicOrdering::Release).expect("store");
        assert_eq!(cell.fetch_add(5, AtomicOrdering::AcqRel), 15);
        assert_eq!(cell.load(AtomicOrdering::SeqCst).expect("load"), 20);
    }

    #[test]
    fn invalid_orderings_are_rejected() {
        let flag = AtomicBoolCell::new(true);
        let load_err = flag
            .load(AtomicOrdering::Release)
            .expect_err("release load should fail");
        assert!(matches!(load_err, AtomicOrderError::InvalidLoadOrdering(_)));

        let store_err = flag
            .store(false, AtomicOrdering::Acquire)
            .expect_err("acquire store should fail");
        assert!(matches!(
            store_err,
            AtomicOrderError::InvalidStoreOrdering(_)
        ));
    }

    #[test]
    fn fence_api_is_available() {
        memory_fence(AtomicOrdering::SeqCst);
    }
}
