pub(super) fn section() -> &'static str {
    r#"
static int32_t fz_interval_alloc(int32_t period_ms) {
  if (fz_interval_capacity == 0) {
    fz_intervals = (fz_interval_state*)calloc(
        (size_t)FZ_INITIAL_INTERVAL_CAPACITY, sizeof(fz_interval_state));
    if (fz_intervals == NULL) {
      return -1;
    }
    fz_interval_capacity = FZ_INITIAL_INTERVAL_CAPACITY;
  }
  for (int32_t i = 0; i < fz_interval_capacity; i++) {
    if (!fz_intervals[i].in_use) {
      fz_intervals[i].in_use = 1;
      fz_intervals[i].period_ms = period_ms;
      fz_intervals[i].next_ms = fz_now_ms() + period_ms;
      return i + 1;
    }
  }
  int32_t next_capacity = fz_interval_capacity;
  if (next_capacity < FZ_INITIAL_INTERVAL_CAPACITY) {
    next_capacity = FZ_INITIAL_INTERVAL_CAPACITY;
  }
  if (next_capacity > INT32_MAX / 2) {
    return -1;
  }
  next_capacity *= 2;
  size_t old_capacity = (size_t)fz_interval_capacity;
  size_t new_capacity = (size_t)next_capacity;
  fz_interval_state* next = (fz_interval_state*)realloc(
      fz_intervals, new_capacity * sizeof(fz_interval_state));
  if (next == NULL) {
    return -1;
  }
  memset(next + old_capacity, 0, (new_capacity - old_capacity) * sizeof(fz_interval_state));
  fz_intervals = next;
  fz_interval_capacity = next_capacity;
  fz_intervals[old_capacity].in_use = 1;
  fz_intervals[old_capacity].period_ms = period_ms;
  fz_intervals[old_capacity].next_ms = fz_now_ms() + period_ms;
  return (int32_t)old_capacity + 1;
}

static fz_interval_state* fz_interval_get(int32_t handle) {
  if (handle <= 0 || handle > fz_interval_capacity || fz_intervals == NULL) {
    return NULL;
  }
  fz_interval_state* interval = &fz_intervals[handle - 1];
  return interval->in_use ? interval : NULL;
}

int32_t fz_native_time_interval(int32_t period_ms) {
  if (period_ms <= 0) {
    return -1;
  }
  pthread_mutex_lock(&fz_time_lock);
  int32_t handle = fz_interval_alloc(period_ms);
  pthread_mutex_unlock(&fz_time_lock);
  return handle;
}

int32_t fz_native_time_tick(int32_t handle) {
  pthread_mutex_lock(&fz_time_lock);
  fz_interval_state* interval = fz_interval_get(handle);
  if (interval == NULL) {
    pthread_mutex_unlock(&fz_time_lock);
    return -1;
  }
  int64_t now = fz_now_ms();
  int64_t wait_ms = interval->next_ms - now;
  if (wait_ms > 0) {
    pthread_mutex_unlock(&fz_time_lock);
    usleep((useconds_t)wait_ms * 1000);
    pthread_mutex_lock(&fz_time_lock);
    interval = fz_interval_get(handle);
    if (interval == NULL) {
      pthread_mutex_unlock(&fz_time_lock);
      return -1;
    }
  }
  now = fz_now_ms();
  interval->next_ms = now + interval->period_ms;
  pthread_mutex_unlock(&fz_time_lock);
  return 0;
}

"#
}
