//! Deterministic in-memory scheduler used by engine subsystems.

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore as _, SeedableRng as _};

use std::collections::VecDeque;

#[derive(Debug, Clone, Copy)]
pub enum SchedulerMode {
    Fifo,
    Random,
}

#[derive(Debug, Clone)]
pub struct ScheduledItem<T> {
    pub id: u64,
    pub label: String,
    pub payload: T,
}

#[derive(Debug)]
pub struct DeterministicScheduler<T> {
    mode: SchedulerMode,
    queue: VecDeque<ScheduledItem<T>>,
    next_id: u64,
    rng: ChaCha20Rng,
}

impl<T> DeterministicScheduler<T> {
    pub fn new(mode: SchedulerMode, seed: u64) -> Self {
        let seed_bytes = blake3::hash(&seed.to_le_bytes()).as_bytes().to_owned();
        let mut seed32 = [0u8; 32];
        seed32.copy_from_slice(&seed_bytes[..32]);
        Self {
            mode,
            queue: VecDeque::new(),
            next_id: 1,
            rng: ChaCha20Rng::from_seed(seed32),
        }
    }

    pub fn enqueue(&mut self, label: impl Into<String>, payload: T) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        self.queue.push_back(ScheduledItem {
            id,
            label: label.into(),
            payload,
        });
        id
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn pop_next(&mut self) -> Option<ScheduledItem<T>> {
        if self.queue.is_empty() {
            return None;
        }
        match self.mode {
            SchedulerMode::Fifo => self.queue.pop_front(),
            SchedulerMode::Random => {
                let idx = (self.rng.next_u64() as usize) % self.queue.len();
                self.queue.swap_remove_back(idx)
            }
        }
    }
}
