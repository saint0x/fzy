use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocatorKind {
    System,
    Arena,
    Bump,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AllocationId(u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allocation {
    pub id: AllocationId,
    pub size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllocError {
    OutOfMemory,
    AllocationDisabled,
    InvalidAllocation,
}

pub trait Allocator {
    fn alloc(&mut self, size: usize) -> Result<Allocation, AllocError>;
    fn free(&mut self, id: AllocationId) -> Result<(), AllocError>;
    fn in_use_bytes(&self) -> usize;
}

#[derive(Default)]
pub struct SystemAllocator {
    next_id: u64,
    allocations: BTreeMap<AllocationId, Vec<u8>>,
}

impl Allocator for SystemAllocator {
    fn alloc(&mut self, size: usize) -> Result<Allocation, AllocError> {
        let id = AllocationId(self.next_id);
        self.next_id += 1;
        self.allocations.insert(id, vec![0; size]);
        Ok(Allocation { id, size })
    }

    fn free(&mut self, id: AllocationId) -> Result<(), AllocError> {
        self.allocations
            .remove(&id)
            .map(|_| ())
            .ok_or(AllocError::InvalidAllocation)
    }

    fn in_use_bytes(&self) -> usize {
        self.allocations.values().map(Vec::len).sum()
    }
}

pub struct ArenaAllocator {
    next_id: u64,
    capacity: usize,
    offset: usize,
    allocations: BTreeMap<AllocationId, (usize, usize)>,
}

impl ArenaAllocator {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            next_id: 0,
            capacity,
            offset: 0,
            allocations: BTreeMap::new(),
        }
    }

    pub fn reset(&mut self) {
        self.offset = 0;
        self.allocations.clear();
    }
}

impl Allocator for ArenaAllocator {
    fn alloc(&mut self, size: usize) -> Result<Allocation, AllocError> {
        if self.offset + size > self.capacity {
            return Err(AllocError::OutOfMemory);
        }
        let id = AllocationId(self.next_id);
        self.next_id += 1;
        self.allocations.insert(id, (self.offset, size));
        self.offset += size;
        Ok(Allocation { id, size })
    }

    fn free(&mut self, _id: AllocationId) -> Result<(), AllocError> {
        // Arena allocations are reclaimed on `reset`.
        Ok(())
    }

    fn in_use_bytes(&self) -> usize {
        self.allocations.values().map(|(_, size)| *size).sum()
    }
}

pub struct BumpAllocator {
    next_id: u64,
    capacity: usize,
    offset: usize,
    allocations: BTreeMap<AllocationId, usize>,
}

impl BumpAllocator {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            next_id: 0,
            capacity,
            offset: 0,
            allocations: BTreeMap::new(),
        }
    }
}

impl Allocator for BumpAllocator {
    fn alloc(&mut self, size: usize) -> Result<Allocation, AllocError> {
        if self.offset + size > self.capacity {
            return Err(AllocError::OutOfMemory);
        }
        let id = AllocationId(self.next_id);
        self.next_id += 1;
        self.offset += size;
        self.allocations.insert(id, size);
        Ok(Allocation { id, size })
    }

    fn free(&mut self, _id: AllocationId) -> Result<(), AllocError> {
        // Bump allocators intentionally do not support per-allocation free.
        Ok(())
    }

    fn in_use_bytes(&self) -> usize {
        self.offset
    }
}

#[derive(Default)]
pub struct FailAllocator;

impl Allocator for FailAllocator {
    fn alloc(&mut self, _size: usize) -> Result<Allocation, AllocError> {
        Err(AllocError::AllocationDisabled)
    }

    fn free(&mut self, _id: AllocationId) -> Result<(), AllocError> {
        Ok(())
    }

    fn in_use_bytes(&self) -> usize {
        0
    }
}

#[derive(Clone, Default)]
pub struct ThreadSafeSystemAllocator {
    inner: Arc<Mutex<SystemAllocator>>,
}

impl ThreadSafeSystemAllocator {
    pub fn alloc(&self, size: usize) -> Result<Allocation, AllocError> {
        self.inner
            .lock()
            .map_err(|_| AllocError::AllocationDisabled)?
            .alloc(size)
    }

    pub fn free(&self, id: AllocationId) -> Result<(), AllocError> {
        self.inner
            .lock()
            .map_err(|_| AllocError::AllocationDisabled)?
            .free(id)
    }

    pub fn in_use_bytes(&self) -> Result<usize, AllocError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| AllocError::AllocationDisabled)?
            .in_use_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AllocError, Allocator, ArenaAllocator, BumpAllocator, FailAllocator, SystemAllocator,
    };

    #[test]
    fn system_allocator_alloc_and_free() {
        let mut alloc = SystemAllocator::default();
        let block = alloc.alloc(32).expect("allocation should work");
        assert_eq!(alloc.in_use_bytes(), 32);
        alloc
            .free(block.id)
            .expect("freeing returned allocation should work");
        assert_eq!(alloc.in_use_bytes(), 0);
    }

    #[test]
    fn arena_allocator_is_resettable() {
        let mut arena = ArenaAllocator::with_capacity(16);
        arena.alloc(8).expect("first arena alloc should work");
        arena.alloc(8).expect("second arena alloc should work");
        assert_eq!(arena.in_use_bytes(), 16);
        assert_eq!(arena.alloc(1), Err(AllocError::OutOfMemory));
        arena.reset();
        assert_eq!(arena.in_use_bytes(), 0);
        assert!(arena.alloc(16).is_ok());
    }

    #[test]
    fn bump_allocator_monotonic_usage() {
        let mut bump = BumpAllocator::with_capacity(10);
        let block = bump.alloc(4).expect("bump alloc should work");
        assert_eq!(bump.in_use_bytes(), 4);
        bump.free(block.id).expect("free is a no-op but valid");
        assert_eq!(bump.in_use_bytes(), 4);
    }

    #[test]
    fn fail_allocator_always_errors() {
        let mut fail = FailAllocator;
        assert_eq!(fail.alloc(8), Err(AllocError::AllocationDisabled));
    }

    #[test]
    fn thread_safe_allocator_supports_parallel_ops() {
        use std::thread;

        let alloc = super::ThreadSafeSystemAllocator::default();
        let mut handles = Vec::new();
        for _ in 0..8 {
            let shared = alloc.clone();
            handles.push(thread::spawn(move || {
                let block = shared.alloc(16).expect("alloc should work");
                shared.free(block.id).expect("free should work");
            }));
        }
        for handle in handles {
            handle.join().expect("thread should finish");
        }
        assert_eq!(alloc.in_use_bytes().expect("bytes query should work"), 0);
    }
}
