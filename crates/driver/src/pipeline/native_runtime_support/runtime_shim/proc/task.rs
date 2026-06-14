pub(super) fn section() -> &'static str {
    r#"
int32_t fz_native_spawn(int32_t task_ref) {
  return fz_native_spawn_impl(task_ref, 0, 0);
}

int32_t fz_native_spawn_ctx(int32_t task_ref, int32_t context_id) {
  return fz_native_spawn_impl(task_ref, context_id, 0);
}

int32_t fz_native_join(int32_t handle) {
  pthread_t thread;
  pthread_mutex_lock(&fz_spawn_lock);
  fz_spawn_state* state = fz_spawn_state_by_handle_locked(handle);
  if (state == NULL || !state->in_use) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  if (state->detached) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -2;
  }
  if (state->joined && state->finished) {
    int32_t result = state->result;
    memset(state, 0, sizeof(*state));
    pthread_mutex_unlock(&fz_spawn_lock);
    return result;
  }
  state->joined = 1;
  thread = state->thread;
  pthread_mutex_unlock(&fz_spawn_lock);

  (void)pthread_join(thread, NULL);

  pthread_mutex_lock(&fz_spawn_lock);
  state = fz_spawn_state_by_handle_locked(handle);
  if (state == NULL || !state->in_use) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  int32_t result = state->result;
  memset(state, 0, sizeof(*state));
  pthread_mutex_unlock(&fz_spawn_lock);
  return result;
}

int32_t fz_native_detach(int32_t handle) {
  pthread_t thread;
  int should_detach = 0;
  pthread_mutex_lock(&fz_spawn_lock);
  fz_spawn_state* state = fz_spawn_state_by_handle_locked(handle);
  if (state == NULL || !state->in_use) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  if (state->detached) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return 0;
  }
  state->detached = 1;
  if (state->finished) {
    memset(state, 0, sizeof(*state));
    pthread_mutex_unlock(&fz_spawn_lock);
    return 0;
  }
  thread = state->thread;
  should_detach = 1;
  pthread_mutex_unlock(&fz_spawn_lock);
  if (should_detach) {
    (void)pthread_detach(thread);
  }
  return 0;
}

int32_t fz_native_cancel_task(int32_t handle) {
  pthread_t thread;
  int should_join = 0;
  pthread_mutex_lock(&fz_spawn_lock);
  fz_spawn_state* state = fz_spawn_state_by_handle_locked(handle);
  if (state == NULL || !state->in_use) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  state->cancelled = 1;
  if (!state->detached && !state->joined && !state->finished) {
    state->joined = 1;
    thread = state->thread;
    should_join = !pthread_equal(thread, pthread_self());
  } else if (!state->detached && !state->joined && state->finished) {
    state->joined = 1;
    thread = state->thread;
    should_join = !pthread_equal(thread, pthread_self());
  }
  pthread_mutex_unlock(&fz_spawn_lock);
  if (should_join) {
    (void)pthread_join(thread, NULL);
  }
  pthread_mutex_lock(&fz_spawn_lock);
  state = fz_spawn_state_by_handle_locked(handle);
  if (state != NULL && state->in_use && !state->detached) {
    memset(state, 0, sizeof(*state));
  }
  pthread_mutex_unlock(&fz_spawn_lock);
  return 0;
}

int32_t fz_native_task_result(int32_t handle) {
  pthread_mutex_lock(&fz_spawn_lock);
  fz_spawn_state* state = fz_spawn_state_by_handle_locked(handle);
  if (state == NULL || !state->in_use) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  int32_t result = state->finished ? state->result : -2;
  pthread_mutex_unlock(&fz_spawn_lock);
  return result;
}

int32_t fz_native_task_context_id(void) {
  return fz_tls_task_context;
}

int32_t fz_native_task_group_begin(void) {
  pthread_mutex_lock(&fz_spawn_lock);
  fz_task_group_state* group = fz_task_group_alloc_locked();
  if (group == NULL) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  memset(group, 0, sizeof(*group));
  group->in_use = 1;
  group->id = fz_next_task_group_id++;
  int32_t group_id = group->id;
  pthread_mutex_unlock(&fz_spawn_lock);
  return group_id;
}

int32_t fz_native_task_group_spawn(int32_t group_id, int32_t task_ref) {
  return fz_native_spawn_impl(task_ref, 0, group_id);
}

int32_t fz_native_task_group_spawn_n(int32_t group_id, int32_t task_ref, int32_t n) {
  if (n <= 0) {
    return 0;
  }
  for (int32_t i = 0; i < n; i++) {
    if (fz_native_task_group_spawn(group_id, task_ref) < 0) {
      return -1;
    }
  }
  return 0;
}

int32_t fz_native_task_group_join(int32_t group_id) {
  int32_t first_failure = 0;
  for (;;) {
    int32_t next_handle = 0;
    pthread_mutex_lock(&fz_spawn_lock);
    fz_task_group_state* group = fz_task_group_by_id_locked(group_id);
    if (group == NULL || !group->in_use) {
      pthread_mutex_unlock(&fz_spawn_lock);
      return -1;
    }
    for (int i = 0; i < FZ_MAX_SPAWN_THREADS; i++) {
      fz_spawn_state* state = &fz_spawn_states[i];
      if (state->in_use && state->group_id == group_id && !state->detached) {
        next_handle = state->handle;
        break;
      }
    }
    if (next_handle == 0) {
      group->in_use = 0;
      pthread_mutex_unlock(&fz_spawn_lock);
      return first_failure;
    }
    pthread_mutex_unlock(&fz_spawn_lock);
    int32_t joined = fz_native_join(next_handle);
    if (joined < 0) {
      return joined;
    }
    if (first_failure == 0 && joined != 0) {
      first_failure = joined;
    }
  }
}

int32_t fz_native_task_group_cancel(int32_t group_id) {
  pthread_t threads[FZ_MAX_SPAWN_THREADS];
  int thread_count = 0;
  pthread_mutex_lock(&fz_spawn_lock);
  fz_task_group_state* group = fz_task_group_by_id_locked(group_id);
  if (group == NULL || !group->in_use) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  for (int i = 0; i < FZ_MAX_SPAWN_THREADS; i++) {
    fz_spawn_state* state = &fz_spawn_states[i];
    if (state->in_use && state->group_id == group_id) {
      state->cancelled = 1;
      if (!state->detached && !state->joined) {
        state->joined = 1;
        threads[thread_count++] = state->thread;
      }
    }
  }
  pthread_mutex_unlock(&fz_spawn_lock);
  for (int i = 0; i < thread_count; i++) {
    if (!pthread_equal(threads[i], pthread_self())) {
      (void)pthread_join(threads[i], NULL);
    }
  }
  pthread_mutex_lock(&fz_spawn_lock);
  for (int i = 0; i < FZ_MAX_SPAWN_THREADS; i++) {
    fz_spawn_state* state = &fz_spawn_states[i];
    if (state->in_use && state->group_id == group_id && !state->detached) {
      memset(state, 0, sizeof(*state));
    }
  }
  group = fz_task_group_by_id_locked(group_id);
  if (group != NULL) {
    group->in_use = 0;
    group->active_count = 0;
  }
  pthread_mutex_unlock(&fz_spawn_lock);
  return 0;
}

int32_t fz_native_task_group_join_all(int32_t group_id) {
  return fz_native_task_group_join(group_id);
}

int32_t fz_native_task_parallel_map(int32_t list_handle, int32_t task_ref) {
  int32_t count = fz_runtime_list_len(list_handle);
  if (count < 0) {
    return -1;
  }
  int32_t group_id = fz_native_task_group_begin();
  if (group_id < 0) {
    return -1;
  }
  if (fz_native_task_group_spawn_n(group_id, task_ref, count) < 0) {
    (void)fz_native_task_group_cancel(group_id);
    return -1;
  }
  return fz_native_task_group_join_all(group_id);
}

int32_t fz_native_timeout(int32_t timeout_ms) {
  if (timeout_ms < 0) {
    return -1;
  }
  fz_tls_async_deadline_ms = fz_now_ms() + (int64_t)timeout_ms;
  return 0;
}

int32_t fz_native_deadline(int32_t deadline_ms) {
  fz_tls_async_deadline_ms = (int64_t)deadline_ms;
  return 0;
}

int32_t fz_native_cancel(void) {
  fz_tls_async_cancelled = 1;
  return 0;
}

int32_t fz_native_recv(void) {
  if (fz_async_current_task_cancelled()) {
    return -1;
  }
  if (fz_async_deadline_expired()) {
    return -1;
  }
  return 0;
}

int32_t fz_native_yield(void) {
  sched_yield();
  return 0;
}

int32_t fz_native_checkpoint(void) {
  sched_yield();
  return 0;
}

int32_t fz_native_assert_eq_i32(int32_t left, int32_t right) {
  if (left != right) {
    fprintf(stderr, "assert.eq_i32 failed: left=%d right=%d\n", left, right);
    return -1;
  }
  return 0;
}

int32_t fz_native_pulse(void) {
  sched_yield();
  return 0;
}

"#
}
