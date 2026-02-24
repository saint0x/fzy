use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
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
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackpressureSignal {
    None,
    HighWatermark { depth: usize, capacity: usize },
    Saturated { depth: usize, capacity: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverflowEvent {
    DropOldest,
    DropNewest,
}

pub type OverflowCallback = Arc<dyn Fn(OverflowEvent) + Send + Sync + 'static>;

#[derive(Default, Clone)]
pub struct DeterministicHooks {
    pub events: Arc<Mutex<Vec<String>>>,
}

impl DeterministicHooks {
    pub fn record(&self, event: impl Into<String>) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event.into());
        }
    }

    pub fn snapshot(&self) -> Vec<String> {
        self.events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }
}

struct ChannelState<T> {
    queue: VecDeque<T>,
    closed: bool,
}

pub struct BoundedChannel<T> {
    state: Arc<(Mutex<ChannelState<T>>, Condvar, Condvar)>,
    capacity: usize,
    policy: OverflowPolicy,
    overflow_cb: Option<OverflowCallback>,
    high_watermark: usize,
    hooks: Option<DeterministicHooks>,
}

impl<T> Clone for BoundedChannel<T> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            capacity: self.capacity,
            policy: self.policy,
            overflow_cb: self.overflow_cb.clone(),
            high_watermark: self.high_watermark,
            hooks: self.hooks.clone(),
        }
    }
}

impl<T> BoundedChannel<T> {
    pub fn new(capacity: usize, policy: OverflowPolicy) -> Self {
        Self::with_options(capacity, policy, None, None)
    }

    pub fn with_options(
        capacity: usize,
        policy: OverflowPolicy,
        overflow_cb: Option<OverflowCallback>,
        hooks: Option<DeterministicHooks>,
    ) -> Self {
        let high_watermark = capacity.saturating_mul(3) / 4;
        Self {
            state: Arc::new((
                Mutex::new(ChannelState {
                    queue: VecDeque::new(),
                    closed: false,
                }),
                Condvar::new(),
                Condvar::new(),
            )),
            capacity: capacity.max(1),
            policy,
            overflow_cb,
            high_watermark,
            hooks,
        }
    }

    pub fn send(&self, value: T) -> Result<BackpressureSignal, ChannelError> {
        let (lock, not_empty, not_full) = &*self.state;
        let mut state = lock.lock().map_err(|_| ChannelError::Closed)?;
        if state.closed {
            return Err(ChannelError::Closed);
        }

        if state.queue.len() >= self.capacity {
            match self.policy {
                OverflowPolicy::Reject => {
                    self.record_hook("channel.send.reject_full");
                    return Err(ChannelError::Full);
                }
                OverflowPolicy::DropOldest => {
                    let _ = state.queue.pop_front();
                    self.fire_overflow(OverflowEvent::DropOldest);
                    self.record_hook("channel.send.drop_oldest");
                }
                OverflowPolicy::DropNewest => {
                    self.fire_overflow(OverflowEvent::DropNewest);
                    self.record_hook("channel.send.drop_newest");
                    return Ok(BackpressureSignal::Saturated {
                        depth: state.queue.len(),
                        capacity: self.capacity,
                    });
                }
            }
        }

        state.queue.push_back(value);
        let depth = state.queue.len();
        not_empty.notify_one();
        not_full.notify_one();
        self.record_hook(format!("channel.send.depth={depth}"));

        if depth >= self.capacity {
            Ok(BackpressureSignal::Saturated {
                depth,
                capacity: self.capacity,
            })
        } else if depth >= self.high_watermark {
            Ok(BackpressureSignal::HighWatermark {
                depth,
                capacity: self.capacity,
            })
        } else {
            Ok(BackpressureSignal::None)
        }
    }

    pub fn recv(&self) -> Result<T, ChannelError> {
        let (lock, not_empty, not_full) = &*self.state;
        let mut state = lock.lock().map_err(|_| ChannelError::Closed)?;
        loop {
            if let Some(value) = state.queue.pop_front() {
                not_full.notify_one();
                self.record_hook(format!("channel.recv.depth={}", state.queue.len()));
                return Ok(value);
            }
            if state.closed {
                return Err(ChannelError::Closed);
            }
            state = not_empty.wait(state).map_err(|_| ChannelError::Closed)?;
        }
    }

    pub fn try_recv(&self) -> Result<T, ChannelError> {
        let (lock, _, not_full) = &*self.state;
        let mut state = lock.lock().map_err(|_| ChannelError::Closed)?;
        if let Some(value) = state.queue.pop_front() {
            not_full.notify_one();
            return Ok(value);
        }
        if state.closed {
            return Err(ChannelError::Closed);
        }
        Err(ChannelError::Empty)
    }

    pub fn close(&self) {
        let (lock, not_empty, not_full) = &*self.state;
        if let Ok(mut state) = lock.lock() {
            state.closed = true;
            not_empty.notify_all();
            not_full.notify_all();
            self.record_hook("channel.close");
        }
    }

    pub fn len(&self) -> usize {
        let (lock, _, _) = &*self.state;
        lock.lock()
            .map(|state| state.queue.len())
            .unwrap_or_default()
    }

    fn fire_overflow(&self, event: OverflowEvent) {
        if let Some(cb) = &self.overflow_cb {
            cb(event);
        }
    }

    fn record_hook(&self, event: impl Into<String>) {
        if let Some(hooks) = &self.hooks {
            hooks.record(event);
        }
    }
}

pub struct SyncPrimitives<T: Clone> {
    pub mutex: Arc<Mutex<T>>,
    pub rwlock: Arc<RwLock<T>>,
    pub event: Arc<(Mutex<bool>, Condvar)>,
    hooks: Option<DeterministicHooks>,
}

impl<T: Clone> SyncPrimitives<T> {
    pub fn new(value: T) -> Self {
        Self {
            mutex: Arc::new(Mutex::new(value.clone())),
            rwlock: Arc::new(RwLock::new(value)),
            event: Arc::new((Mutex::new(false), Condvar::new())),
            hooks: None,
        }
    }

    pub fn with_hooks(value: T, hooks: DeterministicHooks) -> Self {
        let mut out = Self::new(value);
        out.hooks = Some(hooks);
        out
    }

    pub fn signal(&self) {
        let (lock, cond) = &*self.event;
        let mut signaled = lock.lock().expect("signal mutex should lock");
        *signaled = true;
        cond.notify_all();
        self.record_hook("sync.signal");
    }

    pub fn wait(&self) {
        let (lock, cond) = &*self.event;
        let mut signaled = lock.lock().expect("wait mutex should lock");
        while !*signaled {
            signaled = cond
                .wait(signaled)
                .expect("condvar wait should reacquire lock");
        }
        self.record_hook("sync.wait");
    }

    fn record_hook(&self, event: impl Into<String>) {
        if let Some(hooks) = &self.hooks {
            hooks.record(event);
        }
    }
}

#[derive(Clone)]
pub struct Semaphore {
    permits: Arc<(Mutex<usize>, Condvar)>,
    hooks: Option<DeterministicHooks>,
}

impl Semaphore {
    pub fn new(permits: usize) -> Self {
        Self {
            permits: Arc::new((Mutex::new(permits), Condvar::new())),
            hooks: None,
        }
    }

    pub fn with_hooks(permits: usize, hooks: DeterministicHooks) -> Self {
        Self {
            permits: Arc::new((Mutex::new(permits), Condvar::new())),
            hooks: Some(hooks),
        }
    }

    pub fn acquire(&self) {
        let (lock, cond) = &*self.permits;
        let mut count = lock.lock().expect("semaphore lock");
        while *count == 0 {
            count = cond.wait(count).expect("semaphore wait");
        }
        *count -= 1;
        if let Some(hooks) = &self.hooks {
            hooks.record(format!("semaphore.acquire.remaining={}", *count));
        }
    }

    pub fn release(&self) {
        let (lock, cond) = &*self.permits;
        let mut count = lock.lock().expect("semaphore lock");
        *count += 1;
        cond.notify_one();
        if let Some(hooks) = &self.hooks {
            hooks.record(format!("semaphore.release.available={}", *count));
        }
    }
}

#[derive(Clone)]
pub struct DeterministicBarrier {
    parties: usize,
    state: Arc<(Mutex<(usize, usize)>, Condvar)>,
    hooks: Option<DeterministicHooks>,
}

impl DeterministicBarrier {
    pub fn new(parties: usize) -> Self {
        Self {
            parties: parties.max(1),
            state: Arc::new((Mutex::new((0, 0)), Condvar::new())),
            hooks: None,
        }
    }

    pub fn with_hooks(parties: usize, hooks: DeterministicHooks) -> Self {
        let mut barrier = Self::new(parties);
        barrier.hooks = Some(hooks);
        barrier
    }

    pub fn wait(&self) {
        let (lock, cond) = &*self.state;
        let mut state = lock.lock().expect("barrier lock");
        let generation = state.1;
        state.0 += 1;
        if state.0 == self.parties {
            state.0 = 0;
            state.1 += 1;
            cond.notify_all();
            if let Some(hooks) = &self.hooks {
                hooks.record(format!("barrier.trip.gen={}", state.1));
            }
            return;
        }
        while generation == state.1 {
            state = cond.wait(state).expect("barrier wait");
        }
    }
}

pub struct OnceCell<T> {
    value: Arc<Mutex<Option<Arc<T>>>>,
}

impl<T> Default for OnceCell<T> {
    fn default() -> Self {
        Self {
            value: Arc::new(Mutex::new(None)),
        }
    }
}

impl<T> OnceCell<T> {
    pub fn set(&self, value: T) -> Result<(), Arc<T>> {
        let mut slot = self.value.lock().expect("once cell lock");
        if slot.is_some() {
            return Err(slot.as_ref().expect("already set").clone());
        }
        *slot = Some(Arc::new(value));
        Ok(())
    }

    pub fn get(&self) -> Option<Arc<T>> {
        self.value.lock().expect("once cell lock").as_ref().cloned()
    }

    pub fn get_or_init<F: FnOnce() -> T>(&self, init: F) -> Arc<T> {
        if let Some(existing) = self.get() {
            return existing;
        }
        let value = Arc::new(init());
        let mut slot = self.value.lock().expect("once cell lock");
        if slot.is_none() {
            *slot = Some(value.clone());
        }
        slot.as_ref().expect("once set").clone()
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
        let mut out = self
            .buffers
            .pop()
            .unwrap_or_else(|| vec![0_u8; self.buffer_size]);
        out.fill(0);
        out
    }

    pub fn checkin(&mut self, mut buffer: Vec<u8>) {
        buffer.fill(0);
        self.buffers.push(buffer);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionPolicy {
    Reject,
    DropOldest,
    DropNewest,
}

pub struct ObjectPool<T> {
    values: VecDeque<T>,
    max_size: usize,
    policy: EvictionPolicy,
    evicted: AtomicUsize,
}

impl<T> ObjectPool<T> {
    pub fn new(values: Vec<T>, max_size: usize, policy: EvictionPolicy) -> Self {
        let mut queue = VecDeque::from(values);
        while queue.len() > max_size {
            let _ = queue.pop_front();
        }
        Self {
            values: queue,
            max_size: max_size.max(1),
            policy,
            evicted: AtomicUsize::new(0),
        }
    }

    pub fn checkout(&mut self) -> Option<T> {
        self.values.pop_back()
    }

    pub fn checkin(&mut self, value: T) -> bool {
        if self.values.len() < self.max_size {
            self.values.push_back(value);
            return true;
        }
        match self.policy {
            EvictionPolicy::Reject => false,
            EvictionPolicy::DropOldest => {
                let _ = self.values.pop_front();
                self.evicted.fetch_add(1, Ordering::Relaxed);
                self.values.push_back(value);
                true
            }
            EvictionPolicy::DropNewest => {
                let _ = self.values.pop_back();
                self.evicted.fetch_add(1, Ordering::Relaxed);
                self.values.push_back(value);
                true
            }
        }
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn evictions(&self) -> usize {
        self.evicted.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::thread;

    use super::{
        BackpressureSignal, BoundedChannel, BufferPool, ChannelError, DeterministicBarrier,
        DeterministicHooks, EvictionPolicy, ObjectPool, OnceCell, OverflowPolicy, Semaphore,
    };

    #[test]
    fn bounded_channel_thread_safe_and_backpressure() {
        let hooks = DeterministicHooks::default();
        let channel = BoundedChannel::with_options(2, OverflowPolicy::Reject, None, Some(hooks));
        let producer = channel.clone();
        let consumer = channel.clone();

        let handle = thread::spawn(move || {
            producer.send(1).expect("send");
            producer.send(2).expect("send");
            assert_eq!(producer.send(3), Err(ChannelError::Full));
        });

        assert_eq!(consumer.recv().expect("recv"), 1);
        assert!(matches!(
            consumer.send(5).expect("send"),
            BackpressureSignal::HighWatermark { .. } | BackpressureSignal::Saturated { .. }
        ));
        handle.join().expect("join");
    }

    #[test]
    fn bounded_channel_overflow_callbacks_trigger() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&events);
        let cb = Arc::new(move |event| {
            sink.lock().expect("lock").push(format!("{event:?}"));
        });
        let channel = BoundedChannel::with_options(1, OverflowPolicy::DropOldest, Some(cb), None);
        channel.send(1).expect("send");
        channel.send(2).expect("send");
        assert_eq!(channel.recv().expect("recv"), 2);
        assert!(!events.lock().expect("lock").is_empty());
    }

    #[test]
    fn sync_primitives_hooks_capture_events() {
        let hooks = DeterministicHooks::default();
        let sync = super::SyncPrimitives::with_hooks(1_i32, hooks.clone());
        sync.signal();
        sync.wait();
        assert!(hooks.snapshot().iter().any(|event| event == "sync.signal"));
    }

    #[test]
    fn semaphore_barrier_and_oncecell_work() {
        let sem = Semaphore::new(1);
        sem.acquire();
        sem.release();

        let barrier = DeterministicBarrier::new(2);
        let other = barrier.clone();
        let handle = thread::spawn(move || other.wait());
        barrier.wait();
        handle.join().expect("barrier join");

        let cell = OnceCell::<usize>::default();
        assert_eq!(*cell.get_or_init(|| 7), 7);
        assert!(cell.set(8).is_err());
    }

    #[test]
    fn buffer_pool_zeroes_on_checkout() {
        let mut pool = BufferPool::new(1, 4);
        let mut buf = pool.checkout();
        buf.copy_from_slice(b"test");
        pool.checkin(buf);
        let reused = pool.checkout();
        assert_eq!(reused, vec![0, 0, 0, 0]);
    }

    #[test]
    fn object_pool_enforces_bounds_and_eviction() {
        let mut pool = ObjectPool::new(vec![1, 2], 2, EvictionPolicy::DropOldest);
        assert!(pool.checkin(3));
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.evictions(), 1);
    }
}
