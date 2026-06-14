pub(super) fn section() -> &'static str {
    r#"
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

static int fz_proc_poll_streams(fz_proc_state* state, int timeout_ms) {
  if (state == NULL) {
    return -1;
  }
  struct pollfd pfds[2];
  int count = 0;
  if (state->stdout_fd >= 0) {
    pfds[count].fd = state->stdout_fd;
    pfds[count].events = POLLIN | POLLHUP | POLLERR;
    pfds[count].revents = 0;
    count++;
  }
  if (state->stderr_fd >= 0) {
    pfds[count].fd = state->stderr_fd;
    pfds[count].events = POLLIN | POLLHUP | POLLERR;
    pfds[count].revents = 0;
    count++;
  }
  if (count == 0) {
    if (timeout_ms > 0) {
      usleep((useconds_t)timeout_ms * 1000);
    }
    return 0;
  }
  for (;;) {
    int ready = poll(pfds, (nfds_t)count, timeout_ms);
    if (ready >= 0) {
      return ready;
    }
    if (errno == EINTR) {
      continue;
    }
    return -1;
  }
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
  pthread_mutex_lock(&fz_list_lock);
  fz_list_state* list = fz_list_get(list_handle);
  if (list == NULL || list->count <= 0) {
    pthread_mutex_unlock(&fz_list_lock);
    return 0;
  }
  int count = list->count;
  char** items = (char**)calloc((size_t)count, sizeof(char*));
  if (items == NULL) {
    pthread_mutex_unlock(&fz_list_lock);
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
      pthread_mutex_unlock(&fz_list_lock);
      return -1;
    }
  }
  pthread_mutex_unlock(&fz_list_lock);
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
  pthread_mutex_lock(&fz_map_lock);
  fz_map_state* map = fz_map_get(map_handle);
  if (map == NULL || map->count <= 0) {
    pthread_mutex_unlock(&fz_map_lock);
    return 0;
  }
  int count = map->count;
  char** entries = (char**)calloc((size_t)count, sizeof(char*));
  if (entries == NULL) {
    pthread_mutex_unlock(&fz_map_lock);
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
      pthread_mutex_unlock(&fz_map_lock);
      return -1;
    }
    snprintf(entries[i], n, "%s=%s", key, value);
  }
  pthread_mutex_unlock(&fz_map_lock);
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

"#
}
