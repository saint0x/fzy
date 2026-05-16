use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::concurrency::DeterministicHooks;

static NEXT_RUNTIME_ID: AtomicUsize = AtomicUsize::new(1);

thread_local! {
    static ACTIVE_EFFECT: RefCell<Vec<ActiveEffect>> = const { RefCell::new(Vec::new()) };
}

type Cleanup = Box<dyn FnMut() + Send + 'static>;
type EffectRunner = Arc<Mutex<dyn FnMut() -> Option<Cleanup> + Send + 'static>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReactiveError {
    EffectDisposed,
    CycleDetected {
        effect: String,
        signal: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactiveCycleDiagnostic {
    pub effect: String,
    pub signal: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactiveSignalSnapshot {
    pub id: usize,
    pub label: String,
    pub subscriber_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactiveEffectSnapshot {
    pub id: usize,
    pub label: String,
    pub pending: bool,
    pub running: bool,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactiveSnapshot {
    pub signals: Vec<ReactiveSignalSnapshot>,
    pub effects: Vec<ReactiveEffectSnapshot>,
    pub pending_effects: Vec<String>,
    pub cycle_diagnostics: Vec<ReactiveCycleDiagnostic>,
}

#[derive(Clone)]
pub struct ReactiveRuntime {
    id: usize,
    state: Arc<Mutex<ReactiveState>>,
    hooks: Option<DeterministicHooks>,
}

impl Default for ReactiveRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl ReactiveRuntime {
    pub fn new() -> Self {
        Self {
            id: NEXT_RUNTIME_ID.fetch_add(1, Ordering::Relaxed),
            state: Arc::new(Mutex::new(ReactiveState::default())),
            hooks: None,
        }
    }

    pub fn with_hooks(hooks: DeterministicHooks) -> Self {
        let mut runtime = Self::new();
        runtime.hooks = Some(hooks);
        runtime
    }

    pub fn signal<T>(&self, value: T) -> Signal<T>
    where
        T: Clone + PartialEq + Send + 'static,
    {
        self.signal_named("signal", value)
    }

    pub fn signal_named<T>(&self, label: impl Into<String>, value: T) -> Signal<T>
    where
        T: Clone + PartialEq + Send + 'static,
    {
        let label = label.into();
        let id = {
            let mut state = self.state.lock().expect("reactive state lock");
            let id = state.next_signal_id;
            state.next_signal_id += 1;
            state.signal_labels.insert(id, label.clone());
            id
        };
        self.record_hook(format!("reactive.signal.create:{label}"));
        Signal {
            runtime: self.clone(),
            id,
            value: Arc::new(Mutex::new(value)),
        }
    }

    pub fn effect<F>(&self, label: impl Into<String>, run: F) -> Result<EffectHandle, ReactiveError>
    where
        F: FnMut() -> Option<Cleanup> + Send + 'static,
    {
        let label = label.into();
        let effect_id = {
            let mut state = self.state.lock().expect("reactive state lock");
            let effect_id = state.next_effect_id;
            state.next_effect_id += 1;
            state.effects.insert(
                effect_id,
                EffectSlot {
                    label: label.clone(),
                    runner: Arc::new(Mutex::new(run)),
                    cleanup: None,
                    running: false,
                    disposed: false,
                },
            );
            effect_id
        };
        self.record_hook(format!("reactive.effect.create:{label}"));
        self.run_effect(effect_id)?;
        Ok(EffectHandle {
            runtime: self.clone(),
            effect_id,
        })
    }

    pub fn batch<F>(&self, update: F) -> Result<(), ReactiveError>
    where
        F: FnOnce(),
    {
        {
            let mut state = self.state.lock().expect("reactive state lock");
            state.batch_depth += 1;
        }
        update();
        let should_flush = {
            let mut state = self.state.lock().expect("reactive state lock");
            state.batch_depth = state.batch_depth.saturating_sub(1);
            state.batch_depth == 0
        };
        if should_flush {
            self.flush()?;
        }
        Ok(())
    }

    pub fn snapshot(&self) -> ReactiveSnapshot {
        let state = self.state.lock().expect("reactive state lock");
        let mut signals = Vec::new();
        for (signal_id, label) in &state.signal_labels {
            let subscriber_count = state
                .signal_subscribers
                .get(signal_id)
                .map(|set| set.len())
                .unwrap_or_default();
            signals.push(ReactiveSignalSnapshot {
                id: *signal_id,
                label: label.clone(),
                subscriber_count,
            });
        }

        let mut effects = Vec::new();
        for (effect_id, slot) in &state.effects {
            let dependencies = state
                .effect_dependencies
                .get(effect_id)
                .map(|deps| {
                    deps.iter()
                        .map(|signal_id| state.label_for_signal(*signal_id))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            effects.push(ReactiveEffectSnapshot {
                id: *effect_id,
                label: slot.label.clone(),
                pending: state.pending_set.contains(effect_id),
                running: slot.running,
                dependencies,
            });
        }

        ReactiveSnapshot {
            signals,
            effects,
            pending_effects: state
                .pending
                .iter()
                .map(|effect_id| state.label_for_effect(*effect_id))
                .collect(),
            cycle_diagnostics: state.cycle_diagnostics.clone(),
        }
    }

    fn register_dependency(&self, signal_id: usize, effect_id: usize) {
        let mut state = self.state.lock().expect("reactive state lock");
        state
            .signal_subscribers
            .entry(signal_id)
            .or_default()
            .insert(effect_id);
        state
            .effect_dependencies
            .entry(effect_id)
            .or_default()
            .insert(signal_id);
    }

    fn schedule_signal(&self, signal_id: usize) -> Result<(), ReactiveError> {
        let should_flush = {
            let mut state = self.state.lock().expect("reactive state lock");
            let subscribers = state
                .signal_subscribers
                .get(&signal_id)
                .cloned()
                .unwrap_or_default();
            for effect_id in subscribers {
                if state.pending_set.insert(effect_id) {
                    state.pending.push_back(effect_id);
                }
            }
            state.batch_depth == 0
        };
        if should_flush {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&self) -> Result<(), ReactiveError> {
        loop {
            let next = {
                let mut state = self.state.lock().expect("reactive state lock");
                let next = state.pending.pop_front();
                if let Some(effect_id) = next {
                    state.pending_set.remove(&effect_id);
                }
                next
            };
            let Some(effect_id) = next else {
                return Ok(());
            };
            self.run_effect(effect_id)?;
        }
    }

    fn run_effect(&self, effect_id: usize) -> Result<(), ReactiveError> {
        let (label, runner, mut cleanup) = {
            let mut state = self.state.lock().expect("reactive state lock");
            state.detach_effect_dependencies(effect_id);
            let Some(slot) = state.effects.get_mut(&effect_id) else {
                return Err(ReactiveError::EffectDisposed);
            };
            if slot.disposed {
                return Err(ReactiveError::EffectDisposed);
            }
            if slot.running {
                let diagnostic = ReactiveCycleDiagnostic {
                    effect: slot.label.clone(),
                    signal: None,
                };
                state.cycle_diagnostics.push(diagnostic.clone());
                return Err(ReactiveError::CycleDetected {
                    effect: diagnostic.effect,
                    signal: diagnostic.signal,
                });
            }
            slot.running = true;
            (
                slot.label.clone(),
                Arc::clone(&slot.runner),
                slot.cleanup.take(),
            )
        };

        if let Some(cleanup_fn) = cleanup.as_mut() {
            cleanup_fn();
        }
        self.record_hook(format!("reactive.effect.run:{label}"));
        ACTIVE_EFFECT.with(|stack| {
            stack.borrow_mut().push(ActiveEffect {
                runtime_id: self.id,
                effect_id,
            });
        });
        let next_cleanup = {
            let mut runner = runner.lock().expect("reactive effect lock");
            runner()
        };
        ACTIVE_EFFECT.with(|stack| {
            stack.borrow_mut().pop();
        });

        let mut state = self.state.lock().expect("reactive state lock");
        if let Some(slot) = state.effects.get_mut(&effect_id) {
            slot.running = false;
            if !slot.disposed {
                slot.cleanup = next_cleanup;
            }
        }
        Ok(())
    }

    fn dispose_effect(&self, effect_id: usize) -> Result<(), ReactiveError> {
        let mut cleanup = {
            let mut state = self.state.lock().expect("reactive state lock");
            state.detach_effect_dependencies(effect_id);
            state.pending_set.remove(&effect_id);
            state.pending.retain(|pending| *pending != effect_id);
            let Some(mut slot) = state.effects.remove(&effect_id) else {
                return Err(ReactiveError::EffectDisposed);
            };
            slot.disposed = true;
            slot.cleanup
        };
        if let Some(cleanup_fn) = cleanup.as_mut() {
            cleanup_fn();
        }
        Ok(())
    }

    fn record_hook(&self, event: impl Into<String>) {
        if let Some(hooks) = &self.hooks {
            hooks.record(event);
        }
    }
}

#[derive(Clone)]
pub struct Signal<T>
where
    T: Clone + PartialEq + Send + 'static,
{
    runtime: ReactiveRuntime,
    id: usize,
    value: Arc<Mutex<T>>,
}

impl<T> Signal<T>
where
    T: Clone + PartialEq + Send + 'static,
{
    pub fn id(&self) -> usize {
        self.id
    }

    pub fn get(&self) -> T {
        ACTIVE_EFFECT.with(|stack| {
            if let Some(active) = stack
                .borrow()
                .last()
                .filter(|active| active.runtime_id == self.runtime.id)
                .cloned()
            {
                self.runtime.register_dependency(self.id, active.effect_id);
            }
        });
        self.peek()
    }

    pub fn peek(&self) -> T {
        self.value.lock().expect("reactive signal lock").clone()
    }

    pub fn set(&self, next: T) -> Result<bool, ReactiveError> {
        let changed = {
            let mut value = self.value.lock().expect("reactive signal lock");
            if *value == next {
                false
            } else {
                *value = next;
                true
            }
        };
        if changed {
            self.runtime
                .record_hook(format!("reactive.signal.set:{}", self.id));
            self.runtime.schedule_signal(self.id)?;
        }
        Ok(changed)
    }
}

pub struct EffectHandle {
    runtime: ReactiveRuntime,
    effect_id: usize,
}

impl EffectHandle {
    pub fn dispose(&self) -> Result<(), ReactiveError> {
        self.runtime.dispose_effect(self.effect_id)
    }
}

pub struct Computed<T>
where
    T: Clone + PartialEq + Send + 'static,
{
    signal: Signal<T>,
    _effect: EffectHandle,
}

impl<T> Computed<T>
where
    T: Clone + PartialEq + Send + 'static,
{
    pub fn get(&self) -> T {
        self.signal.get()
    }

    pub fn peek(&self) -> T {
        self.signal.peek()
    }

    pub fn signal(&self) -> Signal<T> {
        self.signal.clone()
    }
}

pub fn signal<T>(runtime: &ReactiveRuntime, value: T) -> Signal<T>
where
    T: Clone + PartialEq + Send + 'static,
{
    runtime.signal(value)
}

pub fn computed<T, F>(
    runtime: &ReactiveRuntime,
    label: impl Into<String>,
    mut compute: F,
) -> Result<Computed<T>, ReactiveError>
where
    T: Clone + PartialEq + Send + 'static,
    F: FnMut() -> T + Send + 'static,
{
    let label = label.into();
    let output = runtime.signal_named(format!("{label}:computed"), compute());
    let target = output.clone();
    let effect = runtime.effect(format!("{label}:effect"), move || {
        let next = compute();
        let _ = target.set(next);
        None
    })?;
    Ok(Computed {
        signal: output,
        _effect: effect,
    })
}

pub fn effect<F>(
    runtime: &ReactiveRuntime,
    label: impl Into<String>,
    run: F,
) -> Result<EffectHandle, ReactiveError>
where
    F: FnMut() -> Option<Cleanup> + Send + 'static,
{
    runtime.effect(label, run)
}

#[derive(Debug, Clone)]
struct ActiveEffect {
    runtime_id: usize,
    effect_id: usize,
}

#[derive(Default)]
struct ReactiveState {
    next_signal_id: usize,
    next_effect_id: usize,
    batch_depth: usize,
    signal_labels: BTreeMap<usize, String>,
    signal_subscribers: BTreeMap<usize, BTreeSet<usize>>,
    effect_dependencies: BTreeMap<usize, BTreeSet<usize>>,
    effects: BTreeMap<usize, EffectSlot>,
    pending: VecDeque<usize>,
    pending_set: BTreeSet<usize>,
    cycle_diagnostics: Vec<ReactiveCycleDiagnostic>,
}

impl ReactiveState {
    fn detach_effect_dependencies(&mut self, effect_id: usize) {
        let deps = self
            .effect_dependencies
            .remove(&effect_id)
            .unwrap_or_default();
        for signal_id in deps {
            if let Some(subscribers) = self.signal_subscribers.get_mut(&signal_id) {
                subscribers.remove(&effect_id);
                if subscribers.is_empty() {
                    self.signal_subscribers.remove(&signal_id);
                }
            }
        }
    }

    fn label_for_signal(&self, signal_id: usize) -> String {
        self.signal_labels
            .get(&signal_id)
            .cloned()
            .unwrap_or_else(|| format!("signal#{signal_id}"))
    }

    fn label_for_effect(&self, effect_id: usize) -> String {
        self.effects
            .get(&effect_id)
            .map(|slot| slot.label.clone())
            .unwrap_or_else(|| format!("effect#{effect_id}"))
    }
}

struct EffectSlot {
    label: String,
    runner: EffectRunner,
    cleanup: Option<Cleanup>,
    running: bool,
    disposed: bool,
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{computed, effect, signal, ReactiveRuntime};

    #[test]
    fn signal_effect_and_batching_propagate_once() {
        let runtime = ReactiveRuntime::new();
        let source = signal(&runtime, 1_i32);
        let runs = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&runs);
        let read = source.clone();
        let _effect = effect(&runtime, "watch-source", move || {
            sink.lock().expect("lock").push(read.get());
            None
        })
        .expect("effect should register");

        runtime
            .batch(|| {
                let _ = source.set(2);
                let _ = source.set(3);
            })
            .expect("batch should flush");

        assert_eq!(*runs.lock().expect("lock"), vec![1, 3]);
    }

    #[test]
    fn computed_tracks_dependencies_and_updates() {
        let runtime = ReactiveRuntime::new();
        let left = signal(&runtime, 4_i32);
        let right = signal(&runtime, 5_i32);
        let read_left = left.clone();
        let read_right = right.clone();
        let total = computed(&runtime, "sum", move || read_left.get() + read_right.get())
            .expect("computed should build");

        assert_eq!(total.get(), 9);
        left.set(9).expect("left should update");
        assert_eq!(total.peek(), 14);
    }

    #[test]
    fn effect_cleanup_runs_before_rerun_and_dispose() {
        let runtime = ReactiveRuntime::new();
        let source = signal(&runtime, 1_i32);
        let cleanups = Arc::new(Mutex::new(0_usize));
        let cleanups_sink = Arc::clone(&cleanups);
        let read = source.clone();
        let handle = effect(&runtime, "cleanup", move || {
            let _ = read.get();
            let cleanups_inner = Arc::clone(&cleanups_sink);
            Some(Box::new(move || {
                *cleanups_inner.lock().expect("lock") += 1;
            }))
        })
        .expect("effect should build");

        source.set(2).expect("update should rerun");
        handle.dispose().expect("dispose should work");

        assert_eq!(*cleanups.lock().expect("lock"), 2);
    }

    #[test]
    fn cycles_are_reported_when_effect_reenters_itself() {
        let runtime = ReactiveRuntime::new();
        let source = signal(&runtime, 0_i32);
        let read = source.clone();
        let write = source.clone();
        let handle = effect(&runtime, "self-cycle", move || {
            let next = read.get() + 1;
            let _ = write.set(next);
            None
        })
        .expect("effect registration should stay non-fatal");

        handle.dispose().expect("dispose should work");
        assert_eq!(runtime.snapshot().cycle_diagnostics.len(), 1);
    }
}
