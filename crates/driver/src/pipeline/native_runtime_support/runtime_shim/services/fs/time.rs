pub(super) fn section() -> &'static str {
    r#"
int32_t fz_native_time_interval(int32_t period_ms) {
  if (period_ms <= 0) {
    return -1;
  }
  pthread_mutex_lock(&fz_time_lock);
  int32_t handle = -1;
  for (int i = 0; i < FZ_MAX_INTERVALS; i++) {
    if (!fz_intervals[i].in_use) {
      fz_intervals[i].in_use = 1;
      fz_intervals[i].period_ms = period_ms;
      fz_intervals[i].next_ms = fz_now_ms() + period_ms;
      handle = i + 1;
      break;
    }
  }
  pthread_mutex_unlock(&fz_time_lock);
  return handle;
}

int32_t fz_native_time_tick(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_INTERVALS) {
    return -1;
  }
  pthread_mutex_lock(&fz_time_lock);
  fz_interval_state* interval = &fz_intervals[handle - 1];
  if (!interval->in_use) {
    pthread_mutex_unlock(&fz_time_lock);
    return -1;
  }
  int64_t now = fz_now_ms();
  int64_t wait_ms = interval->next_ms - now;
  if (wait_ms > 0) {
    pthread_mutex_unlock(&fz_time_lock);
    usleep((useconds_t)wait_ms * 1000);
    pthread_mutex_lock(&fz_time_lock);
    interval = &fz_intervals[handle - 1];
  }
  now = fz_now_ms();
  interval->next_ms = now + interval->period_ms;
  pthread_mutex_unlock(&fz_time_lock);
  return 0;
}

"#
}
