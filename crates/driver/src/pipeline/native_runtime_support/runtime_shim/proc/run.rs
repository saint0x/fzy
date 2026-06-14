pub(super) fn section() -> &'static str {
    r#"
int32_t fz_native_proc_wait(int32_t handle, int32_t timeout_ms) {
  pthread_mutex_lock(&fz_proc_lock);
  fz_proc_state* state = fz_proc_state_get(handle);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_proc_lock);
    fz_proc_set_last_error("proc_wait: invalid handle");
    return -1;
  }
  if (state->done) {
    pthread_mutex_unlock(&fz_proc_lock);
    return 0;
  }

  int64_t start = fz_now_ms();
  int status = 0;
  int timed_out = 0;
  for (;;) {
    if (fz_async_current_task_cancelled()) {
      kill(state->pid, SIGKILL);
      (void)waitpid(state->pid, &status, 0);
      timed_out = 1;
      break;
    }
    if (fz_async_deadline_expired()) {
      kill(state->pid, SIGKILL);
      (void)waitpid(state->pid, &status, 0);
      timed_out = 1;
      break;
    }
    if (fz_drain_fd(state->stdout_fd, &state->stdout_buf) < 0) {
      pthread_mutex_unlock(&fz_proc_lock);
      fz_proc_set_last_error("proc_wait: stdout drain failed");
      return -1;
    }
    if (fz_drain_fd(state->stderr_fd, &state->stderr_buf) < 0) {
      pthread_mutex_unlock(&fz_proc_lock);
      fz_proc_set_last_error("proc_wait: stderr drain failed");
      return -1;
    }

    pid_t waited = waitpid(state->pid, &status, WNOHANG);
    if (waited == state->pid) {
      break;
    }
    if (waited < 0) {
      pthread_mutex_unlock(&fz_proc_lock);
      fz_proc_set_last_error("proc_wait: waitpid failed");
      return -1;
    }
    if (timeout_ms == 0) {
      pthread_mutex_unlock(&fz_proc_lock);
      return 1;
    }
    if (timeout_ms > 0) {
      int64_t elapsed = fz_now_ms() - start;
      if (elapsed >= timeout_ms) {
        kill(state->pid, SIGKILL);
        (void)waitpid(state->pid, &status, 0);
        timed_out = 1;
        break;
      }
      int remaining_ms = (int)(timeout_ms - elapsed);
      int poll_timeout_ms = remaining_ms > 50 ? 50 : remaining_ms;
      poll_timeout_ms = fz_async_effective_timeout_ms(poll_timeout_ms);
      if (fz_proc_poll_streams(state, poll_timeout_ms) < 0) {
        pthread_mutex_unlock(&fz_proc_lock);
        fz_proc_set_last_error("proc_wait: stream poll failed");
        return -1;
      }
    } else {
      int poll_timeout_ms = fz_async_effective_timeout_ms(50);
      if (fz_proc_poll_streams(state, poll_timeout_ms) < 0) {
        pthread_mutex_unlock(&fz_proc_lock);
        fz_proc_set_last_error("proc_wait: stream poll failed");
        return -1;
      }
    }
    if (timeout_ms > 0 && (fz_now_ms() - start) >= timeout_ms) {
      kill(state->pid, SIGKILL);
      (void)waitpid(state->pid, &status, 0);
      timed_out = 1;
      break;
    }
  }

  int exit_code = -1;
  if (timed_out) {
    exit_code = -124;
  } else if (WIFEXITED(status)) {
    exit_code = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    exit_code = 128 + WTERMSIG(status);
  }
  fz_last_exit_class = fz_exit_class_from_status(timed_out, status, 0);
  fz_proc_finalize(state, exit_code);
  pthread_mutex_unlock(&fz_proc_lock);
  fz_proc_set_last_error("");
  return 0;
}

int32_t fz_native_proc_run(int32_t command_id) {
  int32_t handle = fz_native_proc_spawn(command_id);
  if (handle < 0) {
    return -1;
  }
  int32_t waited = fz_native_proc_wait(handle, fz_proc_default_timeout_ms);
  if (waited < 0) {
    return -1;
  }
  pthread_mutex_lock(&fz_proc_lock);
  fz_proc_state* state = fz_proc_state_get(handle);
  int32_t exit_code = (state == NULL) ? -1 : state->exit_code;
  pthread_mutex_unlock(&fz_proc_lock);
  return exit_code;
}

int32_t fz_native_proc_runl(
    int32_t command_id,
    int32_t args_list_id,
    int32_t env_map_id,
    int32_t stdin_id) {
  int32_t handle = fz_native_proc_spawnl(command_id, args_list_id, env_map_id, stdin_id);
  if (handle < 0) {
    return -1;
  }
  int32_t waited = fz_native_proc_wait(handle, fz_proc_default_timeout_ms);
  if (waited < 0) {
    return -1;
  }
  pthread_mutex_lock(&fz_proc_lock);
  fz_proc_state* state = fz_proc_state_get(handle);
  int32_t exit_code = (state == NULL) ? -1 : state->exit_code;
  pthread_mutex_unlock(&fz_proc_lock);
  return exit_code;
}

int32_t fz_native_proc_argv_new(void) { return fz_runtime_list_new(); }
int32_t fz_native_proc_argv_push(int32_t argv_list_id, int32_t value_id) {
  return fz_runtime_list_push(argv_list_id, value_id);
}
int32_t fz_native_proc_env_new(void) { return fz_runtime_map_new(); }
int32_t fz_native_proc_env_set(int32_t env_map_id, int32_t key_id, int32_t value_id) {
  return fz_runtime_map_set(env_map_id, key_id, value_id);
}
int32_t fz_native_proc_spawn_cmd(
    int32_t command_id,
    int32_t argv_list_id,
    int32_t env_map_id,
    int32_t stdin_id) {
  return fz_native_proc_spawnl(command_id, argv_list_id, env_map_id, stdin_id);
}
int32_t fz_native_proc_run_cmd(
    int32_t command_id,
    int32_t argv_list_id,
    int32_t env_map_id,
    int32_t stdin_id) {
  return fz_native_proc_runl(command_id, argv_list_id, env_map_id, stdin_id);
}

int32_t fz_native_proc_poll(int32_t handle) {
  int wait_result = fz_native_proc_wait(handle, 0);
  if (wait_result < 0) {
    return -1;
  }
  return wait_result == 0 ? 1 : 0;
}

static int32_t fz_native_proc_read_stream_chunk(int32_t handle, int32_t max_bytes, int use_stdout) {
  if (max_bytes <= 0) {
    max_bytes = 4096;
  }
  pthread_mutex_lock(&fz_proc_lock);
  fz_proc_state* state = fz_proc_state_get(handle);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_proc_lock);
    return fz_intern_slice("", 0);
  }
  if (!state->done) {
    (void)fz_drain_fd(state->stdout_fd, &state->stdout_buf);
    (void)fz_drain_fd(state->stderr_fd, &state->stderr_buf);
  }
  fz_bytes_buf* buf = use_stdout ? &state->stdout_buf : &state->stderr_buf;
  size_t* cursor = use_stdout ? &state->stdout_read_pos : &state->stderr_read_pos;
  size_t remaining = buf->len > *cursor ? (buf->len - *cursor) : 0;
  size_t take = remaining < (size_t)max_bytes ? remaining : (size_t)max_bytes;
  int32_t out = fz_intern_slice(buf->data == NULL ? "" : (buf->data + *cursor), take);
  *cursor += take;
  pthread_mutex_unlock(&fz_proc_lock);
  return out;
}

int32_t fz_native_proc_read_stdout(int32_t handle, int32_t max_bytes) {
  return fz_native_proc_read_stream_chunk(handle, max_bytes, 1);
}

int32_t fz_native_proc_read_stderr(int32_t handle, int32_t max_bytes) {
  return fz_native_proc_read_stream_chunk(handle, max_bytes, 0);
}

int32_t fz_native_proc_event(int32_t handle) {
  int wait_result = fz_native_proc_wait(handle, 0);
  if (wait_result < 0) {
    return -1;
  }
  if (wait_result > 0) {
    return 0;
  }
  pthread_mutex_lock(&fz_proc_lock);
  fz_proc_state* state = fz_proc_state_get(handle);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_proc_lock);
    return -1;
  }
  int emit = state->exit_notified ? 0 : 1;
  state->exit_notified = 1;
  pthread_mutex_unlock(&fz_proc_lock);
  return emit;
}

int32_t fz_native_proc_stdout(int32_t handle) {
  int wait_result = fz_native_proc_wait(handle, 0);
  if (wait_result < 0) {
    return fz_proc_last_error_id;
  }
  pthread_mutex_lock(&fz_proc_lock);
  fz_proc_state* state = fz_proc_state_get(handle);
  int32_t value = (state == NULL) ? 0 : state->stdout_id;
  pthread_mutex_unlock(&fz_proc_lock);
  return value;
}

int32_t fz_native_proc_stderr(int32_t handle) {
  int wait_result = fz_native_proc_wait(handle, 0);
  if (wait_result < 0) {
    return fz_proc_last_error_id;
  }
  pthread_mutex_lock(&fz_proc_lock);
  fz_proc_state* state = fz_proc_state_get(handle);
  int32_t value = (state == NULL) ? 0 : state->stderr_id;
  pthread_mutex_unlock(&fz_proc_lock);
  return value;
}

int32_t fz_native_proc_exit_code(int32_t handle) {
  int wait_result = fz_native_proc_wait(handle, 0);
  if (wait_result < 0) {
    return -1;
  }
  if (wait_result > 0) {
    return -2;
  }
  pthread_mutex_lock(&fz_proc_lock);
  fz_proc_state* state = fz_proc_state_get(handle);
  int32_t value = (state == NULL) ? -1 : state->exit_code;
  pthread_mutex_unlock(&fz_proc_lock);
  return value;
}

int32_t fz_native_proc_exec_timeout(int32_t timeout_ms) {
  if (timeout_ms > 0) {
    fz_proc_default_timeout_ms = timeout_ms;
  }
  return 0;
}

int32_t fz_native_proc_close(int32_t handle) {
  int32_t waited = fz_native_proc_wait(handle, fz_proc_default_timeout_ms);
  if (waited < 0) {
    return -1;
  }
  pthread_mutex_lock(&fz_proc_lock);
  fz_proc_state* state = fz_proc_state_get(handle);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_proc_lock);
    fz_proc_set_last_error("proc_close: invalid handle");
    return -1;
  }
  fz_bytes_buf_free(&state->stdout_buf);
  fz_bytes_buf_free(&state->stderr_buf);
  memset(state, 0, sizeof(*state));
  pthread_mutex_unlock(&fz_proc_lock);
  fz_proc_set_last_error("");
  return 0;
}

int32_t fz_native_proc_exit_class(void) {
  return fz_last_exit_class;
}

"#
}
