pub(super) fn section() -> &'static str {
    r#"
static void fz_proc_finalize(fz_proc_state* state, int exit_code) {
  if (state->stdout_fd >= 0) {
    (void)fz_drain_fd(state->stdout_fd, &state->stdout_buf);
    close(state->stdout_fd);
    state->stdout_fd = -1;
  }
  if (state->stderr_fd >= 0) {
    (void)fz_drain_fd(state->stderr_fd, &state->stderr_buf);
    close(state->stderr_fd);
    state->stderr_fd = -1;
  }
  state->stdout_id = fz_intern_slice(
      state->stdout_buf.data == NULL ? "" : state->stdout_buf.data,
      state->stdout_buf.data == NULL ? 0 : state->stdout_buf.len);
  state->stderr_id = fz_intern_slice(
      state->stderr_buf.data == NULL ? "" : state->stderr_buf.data,
      state->stderr_buf.data == NULL ? 0 : state->stderr_buf.len);
  state->exit_code = exit_code;
  state->done = 1;
}

static void fz_spawn_join_all(void) {
  for (int i = 0; i < FZ_MAX_SPAWN_THREADS; i++) {
    pthread_t thread;
    int should_join = 0;
    pthread_mutex_lock(&fz_spawn_lock);
    fz_spawn_state* state = &fz_spawn_states[i];
    if (state->in_use && !state->detached && !state->joined) {
      state->joined = 1;
      thread = state->thread;
      should_join = 1;
    }
    pthread_mutex_unlock(&fz_spawn_lock);
    if (should_join) {
      (void)pthread_join(thread, NULL);
    }
  }
}

static void fz_spawn_register_atexit(void) {
  const char* max_active = fz_env_get_bootstrapped("FZ_SPAWN_MAX_ACTIVE");
  if (max_active != NULL && max_active[0] != '\0') {
    int parsed = atoi(max_active);
    if (parsed > 0 && parsed <= FZ_MAX_SPAWN_THREADS) {
      fz_spawn_max_active = parsed;
    }
  }
  (void)atexit(fz_spawn_join_all);
}

static fz_spawn_state* fz_spawn_state_by_handle_locked(int32_t handle) {
  for (int i = 0; i < FZ_MAX_SPAWN_THREADS; i++) {
    if (fz_spawn_states[i].in_use && fz_spawn_states[i].handle == handle) {
      return &fz_spawn_states[i];
    }
  }
  return NULL;
}

static fz_spawn_state* fz_spawn_state_alloc_locked(void) {
  for (int i = 0; i < FZ_MAX_SPAWN_THREADS; i++) {
    if (!fz_spawn_states[i].in_use) {
      return &fz_spawn_states[i];
    }
  }
  return NULL;
}

static fz_task_group_state* fz_task_group_by_id_locked(int32_t group_id) {
  for (int i = 0; i < 256; i++) {
    if (fz_task_groups[i].in_use && fz_task_groups[i].id == group_id) {
      return &fz_task_groups[i];
    }
  }
  return NULL;
}

static fz_task_group_state* fz_task_group_alloc_locked(void) {
  for (int i = 0; i < 256; i++) {
    if (!fz_task_groups[i].in_use) {
      return &fz_task_groups[i];
    }
  }
  return NULL;
}

static void* fz_spawn_thread_main(void* arg) {
  fz_spawn_ctx* ctx = (fz_spawn_ctx*)arg;
  if (ctx == NULL) {
    return NULL;
  }
  int32_t handle = ctx->handle;
  free(ctx);

  fz_task_entry_fn entry = NULL;
  int32_t context_id = 0;
  int32_t group_id = 0;
  int cancelled = 0;
  pthread_mutex_lock(&fz_spawn_lock);
  fz_spawn_state* state = fz_spawn_state_by_handle_locked(handle);
  if (state != NULL) {
    state->started = 1;
    entry = fz_task_entries[state->task_ref - 1];
    context_id = state->context_id;
    group_id = state->group_id;
    cancelled = state->cancelled;
  }
  pthread_mutex_unlock(&fz_spawn_lock);

  int32_t result = -1;
  fz_tls_task_context = context_id;
  fz_tls_task_handle = handle;
  fz_tls_async_deadline_ms = 0;
  fz_tls_async_cancelled = cancelled ? 1 : 0;
  if (!cancelled && entry != NULL) {
    result = entry();
  } else if (cancelled) {
    result = -2;
  }
  fz_tls_task_handle = 0;
  fz_tls_async_deadline_ms = 0;
  fz_tls_async_cancelled = 0;
  fz_tls_task_context = 0;

  pthread_mutex_lock(&fz_spawn_lock);
  state = fz_spawn_state_by_handle_locked(handle);
  if (state != NULL) {
    state->finished = 1;
    state->result = result;
    if (fz_spawn_active_count > 0) {
      fz_spawn_active_count--;
    }
    if (group_id > 0) {
      fz_task_group_state* group = fz_task_group_by_id_locked(group_id);
      if (group != NULL && group->active_count > 0) {
        group->active_count--;
      }
    }
    if (state->detached) {
      memset(state, 0, sizeof(*state));
    }
  }
  pthread_mutex_unlock(&fz_spawn_lock);
  return NULL;
}

static int32_t fz_native_spawn_impl(int32_t task_ref, int32_t context_id, int32_t group_id) {
  if (task_ref <= 0 || task_ref > fz_task_entry_count) {
    return -1;
  }
  if (fz_task_entries[task_ref - 1] == NULL) {
    return -1;
  }

  pthread_once(&fz_spawn_atexit_once, fz_spawn_register_atexit);
  pthread_mutex_lock(&fz_spawn_lock);
  if (fz_spawn_active_count >= fz_spawn_max_active) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  if (group_id > 0 && fz_task_group_by_id_locked(group_id) == NULL) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  fz_spawn_state* state = fz_spawn_state_alloc_locked();
  if (state == NULL) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  memset(state, 0, sizeof(*state));
  state->in_use = 1;
  state->handle = fz_next_spawn_handle++;
  state->task_ref = task_ref;
  state->context_id = context_id;
  state->group_id = group_id;
  if (group_id > 0) {
    fz_task_group_state* group = fz_task_group_by_id_locked(group_id);
    if (group != NULL) {
      group->active_count++;
    }
  }
  fz_spawn_active_count++;
  int32_t handle = state->handle;
  pthread_mutex_unlock(&fz_spawn_lock);

  fz_spawn_ctx* ctx = (fz_spawn_ctx*)malloc(sizeof(fz_spawn_ctx));
  if (ctx == NULL) {
    pthread_mutex_lock(&fz_spawn_lock);
    state = fz_spawn_state_by_handle_locked(handle);
    if (state != NULL) {
      if (state->group_id > 0) {
        fz_task_group_state* group = fz_task_group_by_id_locked(state->group_id);
        if (group != NULL && group->active_count > 0) {
          group->active_count--;
        }
      }
      memset(state, 0, sizeof(*state));
    }
    if (fz_spawn_active_count > 0) {
      fz_spawn_active_count--;
    }
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  ctx->handle = handle;

  pthread_t thread;
  if (pthread_create(&thread, NULL, fz_spawn_thread_main, ctx) != 0) {
    free(ctx);
    pthread_mutex_lock(&fz_spawn_lock);
    state = fz_spawn_state_by_handle_locked(handle);
    if (state != NULL) {
      if (state->group_id > 0) {
        fz_task_group_state* group = fz_task_group_by_id_locked(state->group_id);
        if (group != NULL && group->active_count > 0) {
          group->active_count--;
        }
      }
      memset(state, 0, sizeof(*state));
    }
    if (fz_spawn_active_count > 0) {
      fz_spawn_active_count--;
    }
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }

  pthread_mutex_lock(&fz_spawn_lock);
  state = fz_spawn_state_by_handle_locked(handle);
  if (state != NULL) {
    state->thread = thread;
  }
  pthread_mutex_unlock(&fz_spawn_lock);
  return handle;
}

"#
}
