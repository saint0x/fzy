pub(super) fn runtime_shim_section_proc() -> &'static str {
    r#"
static int fz_env_key_match(const char* entry, const char* key, size_t key_len) {
  if (entry == NULL || key == NULL) {
    return 0;
  }
  return strncmp(entry, key, key_len) == 0 && entry[key_len] == '=';
}

static char** fz_clone_env_with_overrides(char** overrides, int override_count) {
  int base_count = 0;
  while (environ != NULL && environ[base_count] != NULL) {
    base_count++;
  }
  int cap = base_count + override_count + 1;
  char** envp = (char**)calloc((size_t)cap, sizeof(char*));
  if (envp == NULL) {
    return NULL;
  }
  int count = 0;
  for (int i = 0; i < base_count; i++) {
    envp[count] = strdup(environ[i]);
    if (envp[count] == NULL) {
      for (int j = 0; j < count; j++) free(envp[j]);
      free(envp);
      return NULL;
    }
    count++;
  }
  for (int i = 0; i < override_count; i++) {
    const char* item = overrides[i];
    const char* eq = item == NULL ? NULL : strchr(item, '=');
    if (eq == NULL || eq == item) {
      continue;
    }
    size_t key_len = (size_t)(eq - item);
    int replaced = 0;
    for (int j = 0; j < count; j++) {
      if (fz_env_key_match(envp[j], item, key_len)) {
        char* dup = strdup(item);
        if (dup == NULL) {
          continue;
        }
        free(envp[j]);
        envp[j] = dup;
        replaced = 1;
        break;
      }
    }
    if (!replaced && count < cap - 1) {
      envp[count] = strdup(item);
      if (envp[count] != NULL) {
        count++;
      }
    }
  }
  envp[count] = NULL;
  return envp;
}

static void fz_free_env(char** envp) {
  if (envp == NULL) {
    return;
  }
  for (int i = 0; envp[i] != NULL; i++) {
    free(envp[i]);
  }
  free(envp);
}

static int32_t fz_native_proc_spawn_argv(
    const char* executable,
    char* const* argv,
    char* const* envp,
    const char* stdin_payload) {
  if (executable == NULL || executable[0] == '\0' || argv == NULL || argv[0] == NULL) {
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: invalid argv");
    return -1;
  }

  int out_pipe[2];
  int err_pipe[2];
  int in_pipe[2] = {-1, -1};
  if (pipe(out_pipe) != 0) {
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: stdout pipe failed");
    return -1;
  }
  if (pipe(err_pipe) != 0) {
    close(out_pipe[0]);
    close(out_pipe[1]);
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: stderr pipe failed");
    return -1;
  }
  if (stdin_payload != NULL && pipe(in_pipe) != 0) {
    close(out_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[0]);
    close(err_pipe[1]);
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: stdin pipe failed");
    return -1;
  }
  (void)fz_mark_cloexec(out_pipe[0]);
  (void)fz_mark_cloexec(err_pipe[0]);

  posix_spawn_file_actions_t file_actions;
  if (posix_spawn_file_actions_init(&file_actions) != 0) {
    close(out_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[0]);
    close(err_pipe[1]);
    if (in_pipe[0] >= 0) {
      close(in_pipe[0]);
      close(in_pipe[1]);
    }
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: file actions init failed");
    return -1;
  }
  int file_actions_ok = 1;
  if (posix_spawn_file_actions_adddup2(&file_actions, out_pipe[1], STDOUT_FILENO) != 0) {
    file_actions_ok = 0;
  }
  if (file_actions_ok
      && posix_spawn_file_actions_adddup2(&file_actions, err_pipe[1], STDERR_FILENO) != 0) {
    file_actions_ok = 0;
  }
  if (file_actions_ok && in_pipe[0] >= 0
      && posix_spawn_file_actions_adddup2(&file_actions, in_pipe[0], STDIN_FILENO) != 0) {
    file_actions_ok = 0;
  }
  if (file_actions_ok
      && posix_spawn_file_actions_addclose(&file_actions, out_pipe[0]) != 0) {
    file_actions_ok = 0;
  }
  if (file_actions_ok
      && posix_spawn_file_actions_addclose(&file_actions, out_pipe[1]) != 0) {
    file_actions_ok = 0;
  }
  if (file_actions_ok
      && posix_spawn_file_actions_addclose(&file_actions, err_pipe[0]) != 0) {
    file_actions_ok = 0;
  }
  if (file_actions_ok
      && posix_spawn_file_actions_addclose(&file_actions, err_pipe[1]) != 0) {
    file_actions_ok = 0;
  }
  if (file_actions_ok && in_pipe[0] >= 0
      && posix_spawn_file_actions_addclose(&file_actions, in_pipe[0]) != 0) {
    file_actions_ok = 0;
  }
  if (file_actions_ok && in_pipe[1] >= 0
      && posix_spawn_file_actions_addclose(&file_actions, in_pipe[1]) != 0) {
    file_actions_ok = 0;
  }
  if (!file_actions_ok) {
    (void)posix_spawn_file_actions_destroy(&file_actions);
    close(out_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[0]);
    close(err_pipe[1]);
    if (in_pipe[0] >= 0) {
      close(in_pipe[0]);
      close(in_pipe[1]);
    }
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: file actions setup failed");
    return -1;
  }

  pid_t pid = 0;
  int spawn_rc = posix_spawnp(
      &pid,
      executable,
      &file_actions,
      NULL,
      argv,
      envp == NULL ? environ : envp);
  (void)posix_spawn_file_actions_destroy(&file_actions);
  if (spawn_rc != 0 || pid <= 0) {
    close(out_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[0]);
    close(err_pipe[1]);
    if (in_pipe[0] >= 0) {
      close(in_pipe[0]);
      close(in_pipe[1]);
    }
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: posix_spawnp failed");
    return -1;
  }

  if (in_pipe[0] >= 0) {
    close(in_pipe[0]);
    size_t remaining = strlen(stdin_payload);
    const char* cursor = stdin_payload;
    while (remaining > 0) {
      ssize_t wrote = write(in_pipe[1], cursor, remaining);
      if (wrote < 0) {
        if (errno == EINTR) {
          continue;
        }
        break;
      }
      if (wrote == 0) {
        break;
      }
      cursor += wrote;
      remaining -= (size_t)wrote;
    }
    close(in_pipe[1]);
  }

  close(out_pipe[1]);
  close(err_pipe[1]);
  (void)fz_set_nonblocking(out_pipe[0]);
  (void)fz_set_nonblocking(err_pipe[0]);

  pthread_mutex_lock(&fz_proc_lock);
  int32_t handle = fz_proc_state_alloc(pid, out_pipe[0], err_pipe[0]);
  pthread_mutex_unlock(&fz_proc_lock);
  if (handle < 0) {
    kill(pid, SIGKILL);
    close(out_pipe[0]);
    close(err_pipe[0]);
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: state allocation failed");
    return -1;
  }
  fz_proc_set_last_error("");
  return handle;
}

int32_t fz_native_proc_spawn(int32_t command_id) {
  const char* command = fz_lookup_string(command_id);
  if (command == NULL || command[0] == '\0') {
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: empty command");
    return -1;
  }
  char* const argv[] = {"sh", "-lc", (char*)command, NULL};
  return fz_native_proc_spawn_argv("sh", argv, environ, NULL);
}

static int fz_clone_list_items(int32_t list_handle, char*** out_items, int* out_count) {
  if (out_items == NULL || out_count == NULL) {
    return -1;
  }
  *out_items = NULL;
  *out_count = 0;
  if (list_handle <= 0) {
    return 0;
  }
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(list_handle);
  if (list == NULL || list->count <= 0) {
    pthread_mutex_unlock(&fz_collections_lock);
    return 0;
  }
  int count = list->count;
  char** items = (char**)calloc((size_t)count, sizeof(char*));
  if (items == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  for (int i = 0; i < count; i++) {
    const char* src = list->items[i] == NULL ? "" : list->items[i];
    items[i] = strdup(src);
    if (items[i] == NULL) {
      for (int j = 0; j < i; j++) {
        free(items[j]);
      }
      free(items);
      pthread_mutex_unlock(&fz_collections_lock);
      return -1;
    }
  }
  pthread_mutex_unlock(&fz_collections_lock);
  *out_items = items;
  *out_count = count;
  return 0;
}

static int fz_clone_map_entries_as_env(int32_t map_handle, char*** out_items, int* out_count) {
  if (out_items == NULL || out_count == NULL) {
    return -1;
  }
  *out_items = NULL;
  *out_count = 0;
  if (map_handle <= 0) {
    return 0;
  }
  pthread_mutex_lock(&fz_collections_lock);
  fz_map_state* map = fz_map_get(map_handle);
  if (map == NULL || map->count <= 0) {
    pthread_mutex_unlock(&fz_collections_lock);
    return 0;
  }
  int count = map->count;
  char** entries = (char**)calloc((size_t)count, sizeof(char*));
  if (entries == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  for (int i = 0; i < count; i++) {
    const char* key = map->keys[i] == NULL ? "" : map->keys[i];
    const char* value = map->values[i] == NULL ? "" : map->values[i];
    size_t n = strlen(key) + strlen(value) + 2;
    entries[i] = (char*)malloc(n);
    if (entries[i] == NULL) {
      for (int j = 0; j < i; j++) {
        free(entries[j]);
      }
      free(entries);
      pthread_mutex_unlock(&fz_collections_lock);
      return -1;
    }
    snprintf(entries[i], n, "%s=%s", key, value);
  }
  pthread_mutex_unlock(&fz_collections_lock);
  *out_items = entries;
  *out_count = count;
  return 0;
}

int32_t fz_native_proc_spawnl(
    int32_t command_id,
    int32_t args_list_id,
    int32_t env_map_id,
    int32_t stdin_id) {
  const char* command = fz_lookup_string(command_id);
  const char* stdin_payload = fz_lookup_string(stdin_id);
  if (command == NULL || command[0] == '\0') {
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawnl: empty command");
    return -1;
  }

  char** arg_items = NULL;
  int arg_count = 0;
  if (fz_clone_list_items(args_list_id, &arg_items, &arg_count) != 0) {
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawnl: args_list clone failed");
    return -1;
  }

  char** env_items = NULL;
  int env_count = 0;
  if (fz_clone_map_entries_as_env(env_map_id, &env_items, &env_count) != 0) {
    fz_free_string_list(arg_items, arg_count);
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawnl: env_map clone failed");
    return -1;
  }

  int argv_count = arg_count + 2;
  char** argv = (char**)calloc((size_t)argv_count, sizeof(char*));
  if (argv == NULL) {
    fz_free_string_list(arg_items, arg_count);
    fz_free_string_list(env_items, env_count);
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawnl: argv alloc failed");
    return -1;
  }
  argv[0] = (char*)command;
  for (int i = 0; i < arg_count; i++) {
    argv[i + 1] = arg_items[i];
  }
  argv[argv_count - 1] = NULL;

  char** envp = fz_clone_env_with_overrides(env_items, env_count);
  int32_t handle = fz_native_proc_spawn_argv(
      command,
      argv,
      envp == NULL ? environ : envp,
      (stdin_payload == NULL || stdin_payload[0] == '\0') ? NULL : stdin_payload);

  fz_free_env(envp);
  free(argv);
  fz_free_string_list(arg_items, arg_count);
  fz_free_string_list(env_items, env_count);
  return handle;
}

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
    if (timeout_ms > 0 && (fz_now_ms() - start) >= timeout_ms) {
      kill(state->pid, SIGKILL);
      (void)waitpid(state->pid, &status, 0);
      timed_out = 1;
      break;
    }
    usleep(10 * 1000);
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
  return handle;
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
  return handle;
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

int32_t fz_native_proc_exit_class(void) {
  return fz_last_exit_class;
}

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
  pthread_mutex_lock(&fz_spawn_lock);
  fz_spawn_state* state = fz_spawn_state_by_handle_locked(handle);
  if (state == NULL || !state->in_use) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  state->cancelled = 1;
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

int32_t fz_native_task_context(void) {
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
      return 0;
    }
    pthread_mutex_unlock(&fz_spawn_lock);
    int32_t joined = fz_native_join(next_handle);
    if (joined < 0) {
      return joined;
    }
  }
}

int32_t fz_native_task_group_cancel(int32_t group_id) {
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
    }
  }
  group->in_use = 0;
  group->active_count = 0;
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
  fz_async_deadline_ms = fz_now_ms() + (int64_t)timeout_ms;
  return 0;
}

int32_t fz_native_deadline(int32_t deadline_ms) {
  fz_async_deadline_ms = (int64_t)deadline_ms;
  return 0;
}

int32_t fz_native_cancel(void) {
  fz_async_cancelled = 1;
  return 0;
}

int32_t fz_native_recv(void) {
  if (fz_async_cancelled) {
    return -1;
  }
  if (fz_async_deadline_ms > 0 && fz_now_ms() > fz_async_deadline_ms) {
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

int32_t fz_native_net_poll_next(void) {
  return -1;
}

int32_t fz_host_init(void) {
  pthread_mutex_lock(&fz_host_lock);
  fz_host_initialized = 1;
  for (int i = 0; i < 64; i++) {
    fz_host_callbacks[i] = NULL;
  }
  pthread_mutex_unlock(&fz_host_lock);
  return 0;
}

int32_t fz_host_shutdown(void) {
  pthread_mutex_lock(&fz_host_lock);
  fz_host_initialized = 0;
  pthread_mutex_unlock(&fz_host_lock);
  return 0;
}

int32_t fz_host_cleanup(void) {
  pthread_mutex_lock(&fz_host_lock);
  for (int i = 0; i < 64; i++) {
    fz_host_callbacks[i] = NULL;
  }
  pthread_mutex_unlock(&fz_host_lock);
  return 0;
}

int32_t fz_host_register_callback_i32(int32_t slot, fz_callback_i32_v0 cb) {
  if (slot < 0 || slot >= 64 || cb == NULL) {
    return -1;
  }
  pthread_mutex_lock(&fz_host_lock);
  if (!fz_host_initialized) {
    pthread_mutex_unlock(&fz_host_lock);
    return -2;
  }
  fz_host_callbacks[slot] = cb;
  pthread_mutex_unlock(&fz_host_lock);
  return 0;
}

int32_t fz_host_invoke_callback_i32(int32_t slot, int32_t arg) {
  if (slot < 0 || slot >= 64) {
    return -1;
  }
  pthread_mutex_lock(&fz_host_lock);
  fz_callback_i32_v0 cb = fz_host_callbacks[slot];
  pthread_mutex_unlock(&fz_host_lock);
  if (cb == NULL) {
    return -2;
  }
  return cb(arg);
}
"#
}
