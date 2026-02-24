use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverflowPolicy {
    Reject,
    DropOldest,
    DropNewest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelError {
    Full,
    Empty,
}

pub struct BoundedChannel<T> {
    queue: VecDeque<T>,
    capacity: usize,
    policy: OverflowPolicy,
}

impl<T> BoundedChannel<T> {
    pub fn new(capacity: usize, policy: OverflowPolicy) -> Self {
        Self {
            queue: VecDeque::new(),
            capacity,
            policy,
        }
    }

    pub fn send(&mut self, value: T) -> Result<(), ChannelError> {
        if self.queue.len() < self.capacity {
            self.queue.push_back(value);
            return Ok(());
        }

        match self.policy {
            OverflowPolicy::Reject => Err(ChannelError::Full),
            OverflowPolicy::DropOldest => {
                let _ = self.queue.pop_front();
                self.queue.push_back(value);
                Ok(())
            }
            OverflowPolicy::DropNewest => Ok(()),
        }
    }

    pub fn recv(&mut self) -> Result<T, ChannelError> {
        self.queue.pop_front().ok_or(ChannelError::Empty)
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }
}

#[derive(Default)]
pub struct DeterministicHooks {
    pub events: Vec<String>,
}

impl DeterministicHooks {
    pub fn record(&mut self, event: impl Into<String>) {
        self.events.push(event.into());
    }
}

pub struct SyncPrimitives<T: Clone> {
    pub mutex: Arc<Mutex<T>>,
    pub rwlock: Arc<RwLock<T>>,
    pub event: Arc<(Mutex<bool>, Condvar)>,
}

impl<T: Clone> SyncPrimitives<T> {
    pub fn new(value: T) -> Self {
        Self {
            mutex: Arc::new(Mutex::new(value.clone())),
            rwlock: Arc::new(RwLock::new(value)),
            event: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    pub fn signal(&self) {
        let (lock, cond) = &*self.event;
        let mut signaled = lock.lock().expect("signal mutex should lock");
        *signaled = true;
        cond.notify_all();
    }

    pub fn wait(&self) {
        let (lock, cond) = &*self.event;
        let mut signaled = lock.lock().expect("wait mutex should lock");
        while !*signaled {
            signaled = cond
                .wait(signaled)
                .expect("condvar wait should reacquire lock");
        }
    }
}

pub struct BufferPool {
    buffers: Vec<Vec<u8>>,
    buffer_size: usize,
}

impl BufferPool {
    pub fn new(pool_size: usize, buffer_size: usize) -> Self {
        let mut buffers = Vec::with_capacity(pool_size);
        for _ in 0..pool_size {
            buffers.push(vec![0_u8; buffer_size]);
        }
        Self {
            buffers,
            buffer_size,
        }
    }

    pub fn checkout(&mut self) -> Vec<u8> {
        self.buffers
            .pop()
            .unwrap_or_else(|| vec![0_u8; self.buffer_size])
    }

    pub fn checkin(&mut self, mut buffer: Vec<u8>) {
        buffer.fill(0);
        self.buffers.push(buffer);
    }
}

pub struct ObjectPool<T> {
    values: Vec<T>,
}

impl<T> ObjectPool<T> {
    pub fn new(values: Vec<T>) -> Self {
        Self { values }
    }

    pub fn checkout(&mut self) -> Option<T> {
        self.values.pop()
    }

    pub fn checkin(&mut self, value: T) {
        self.values.push(value);
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{BoundedChannel, BufferPool, ChannelError, ObjectPool, OverflowPolicy};

    #[test]
    fn bounded_channel_respects_overflow_policy() {
        let mut channel = BoundedChannel::new(1, OverflowPolicy::Reject);
        channel.send(1).expect("first send should work");
        assert_eq!(channel.send(2), Err(ChannelError::Full));
    }

    #[test]
    fn bounded_channel_drop_oldest() {
        let mut channel = BoundedChannel::new(2, OverflowPolicy::DropOldest);
        channel.send(1).expect("send should work");
        channel.send(2).expect("send should work");
        channel
            .send(3)
            .expect("drop oldest should keep send successful");
        assert_eq!(channel.recv().expect("recv should work"), 2);
        assert_eq!(channel.recv().expect("recv should work"), 3);
    }

    #[test]
    fn buffer_pool_reuses_and_zeroes_buffers() {
        let mut pool = BufferPool::new(1, 4);
        let mut buf = pool.checkout();
        buf.copy_from_slice(b"test");
        pool.checkin(buf);
        let reused = pool.checkout();
        assert_eq!(reused, vec![0, 0, 0, 0]);
    }

    #[test]
    fn object_pool_checkout_and_checkin() {
        let mut pool = ObjectPool::new(vec![1, 2]);
        let value = pool.checkout().expect("object expected");
        assert!(value == 1 || value == 2);
        pool.checkin(3);
        assert_eq!(pool.len(), 2);
    }
}
