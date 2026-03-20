pub(super) fn runtime_shim_section_services() -> &'static str {
    r#"
static int32_t fz_log_emit(const char* level, const char* message, const char* fields) {
  if (level == NULL) level = "info";
  if (message == NULL) message = "";
  if (fields == NULL) fields = "{}";
  int64_t ts = fz_now_ms();
  if (fz_log_json) {
    fprintf(stdout, "{\"ts\":%lld,\"level\":\"%s\",\"msg\":\"", (long long)ts, level);
    for (const char* p = message; *p; p++) {
      if (*p == '"' || *p == '\\') fputc('\\', stdout);
      fputc(*p, stdout);
    }
    fprintf(stdout, "\",\"fields\":%s}\n", fields[0] == '\0' ? "{}" : fields);
  } else if (fields[0] != '\0' && strcmp(fields, "{}") != 0) {
    fprintf(stdout, "[%lld] %s %s | fields=%s\n", (long long)ts, level, message, fields);
  } else {
    fprintf(stdout, "[%lld] %s %s\n", (long long)ts, level, message);
  }
  fflush(stdout);
  return 0;
}

int32_t fz_native_log_info(int32_t message_id, int32_t fields_id) {
  return fz_log_emit("info", fz_lookup_string(message_id), fz_lookup_string(fields_id));
}

int32_t fz_native_log_warn(int32_t message_id, int32_t fields_id) {
  return fz_log_emit("warn", fz_lookup_string(message_id), fz_lookup_string(fields_id));
}

int32_t fz_native_log_error(int32_t message_id, int32_t fields_id) {
  return fz_log_emit("error", fz_lookup_string(message_id), fz_lookup_string(fields_id));
}

int32_t fz_native_log_fields_map(int32_t map_handle) {
  return fz_native_json_from_map(map_handle);
}

int32_t fz_native_log_set_json(int32_t enabled) {
  fz_log_json = enabled != 0 ? 1 : 0;
  return 0;
}

int32_t fz_native_log_correlation_id(int32_t conn_fd) {
  return fz_native_net_request_id(conn_fd);
}

int32_t fz_native_time_sleep_ms(int32_t ms) {
  if (ms > 0) {
    usleep((useconds_t)ms * 1000);
  }
  return 0;
}

int32_t fz_native_time_elapsed_ms(int32_t start_ms) {
  int64_t now = fz_now_ms();
  return (int32_t)(now - (int64_t)start_ms);
}

int32_t fz_native_time_deadline_after(int32_t delta_ms) {
  int64_t now = fz_now_ms();
  return (int32_t)(now + (int64_t)delta_ms);
}

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

int32_t fz_native_fs_open(void) {
  pthread_mutex_lock(&fz_fs_lock);
  int fd = fz_fs_ensure_open();
  pthread_mutex_unlock(&fz_fs_lock);
  return fd;
}

int32_t fz_native_fs_write(void) {
  pthread_mutex_lock(&fz_fs_lock);
  int fd = fz_fs_ensure_open();
  if (fd < 0) {
    pthread_mutex_unlock(&fz_fs_lock);
    return -1;
  }
  const char* payload = "fozzy\n";
  ssize_t wrote = write(fd, payload, strlen(payload));
  pthread_mutex_unlock(&fz_fs_lock);
  return wrote < 0 ? -1 : (int32_t)wrote;
}

int32_t fz_native_fs_read(void) {
  pthread_mutex_lock(&fz_fs_lock);
  int fd = fz_fs_ensure_open();
  if (fd < 0) {
    pthread_mutex_unlock(&fz_fs_lock);
    return -1;
  }
  lseek(fd, 0, SEEK_SET);
  char buf[4096];
  ssize_t got = read(fd, buf, sizeof(buf));
  pthread_mutex_unlock(&fz_fs_lock);
  return got < 0 ? -1 : (int32_t)got;
}

int32_t fz_native_fs_flush(void) {
  pthread_mutex_lock(&fz_fs_lock);
  int fd = fz_fs_ensure_open();
  int rc = (fd < 0) ? -1 : fsync(fd);
  pthread_mutex_unlock(&fz_fs_lock);
  return rc == 0 ? 0 : -1;
}

int32_t fz_native_fs_fsync(void) {
  return fz_native_fs_flush();
}

int32_t fz_native_fs_atomic_write(void) {
  pthread_mutex_lock(&fz_fs_lock);
  const char* path = fz_fs_path();
  (void)path;
  int fd = open(fz_fs_tmp_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
  if (fd < 0) {
    pthread_mutex_unlock(&fz_fs_lock);
    return -1;
  }
  const char* payload = "{}\n";
  int ok = 0;
  if (write(fd, payload, strlen(payload)) < 0) {
    ok = -1;
  }
  if (fsync(fd) != 0) {
    ok = -1;
  }
  close(fd);
  pthread_mutex_unlock(&fz_fs_lock);
  return ok;
}

int32_t fz_native_fs_rename_atomic(void) {
  pthread_mutex_lock(&fz_fs_lock);
  const char* path = fz_fs_path();
  int rc = rename(fz_fs_tmp_path, path);
  pthread_mutex_unlock(&fz_fs_lock);
  return rc == 0 ? 0 : -1;
}

int32_t fz_native_fs_read_file(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') {
    return fz_intern_slice("", 0);
  }
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    fz_set_last_error(errno, 3, "fs.read_file failed");
    return fz_intern_slice("", 0);
  }
  fz_bytes_buf buf;
  fz_bytes_buf_init(&buf);
  char tmp[4096];
  for (;;) {
    ssize_t got = read(fd, tmp, sizeof(tmp));
    if (got > 0) {
      if (fz_bytes_buf_append(&buf, tmp, (size_t)got) != 0) {
        break;
      }
      continue;
    }
    if (got == 0) break;
    if (errno == EINTR) continue;
    break;
  }
  close(fd);
  int32_t out = fz_intern_slice(buf.data == NULL ? "" : buf.data, buf.len);
  fz_bytes_buf_free(&buf);
  return out;
}

int32_t fz_native_fs_write_file(int32_t path_id, int32_t content_id) {
  const char* path = fz_lookup_string(path_id);
  const char* content = fz_lookup_string(content_id);
  if (path == NULL || path[0] == '\0') {
    return -1;
  }
  if (content == NULL) content = "";
  int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
  if (fd < 0) {
    fz_set_last_error(errno, 3, "fs.write_file open failed");
    return -1;
  }
  size_t left = strlen(content);
  const char* p = content;
  while (left > 0) {
    ssize_t wrote = write(fd, p, left);
    if (wrote < 0) {
      if (errno == EINTR) continue;
      close(fd);
      fz_set_last_error(errno, 3, "fs.write_file write failed");
      return -1;
    }
    if (wrote == 0) break;
    p += wrote;
    left -= (size_t)wrote;
  }
  close(fd);
  return 0;
}

static int fz_storage_write_atomic_path(const char* path, const char* content) {
  if (path == NULL || path[0] == '\0') {
    return -1;
  }
  if (content == NULL) {
    content = "";
  }
  char tmp_path[2048];
  int written = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
  if (written <= 0 || (size_t)written >= sizeof(tmp_path)) {
    return -1;
  }
  int fd = open(tmp_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
  if (fd < 0) {
    return -1;
  }
  size_t left = strlen(content);
  const char* p = content;
  while (left > 0) {
    ssize_t n = write(fd, p, left);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      close(fd);
      return -1;
    }
    if (n == 0) {
      break;
    }
    p += n;
    left -= (size_t)n;
  }
  if (fsync(fd) != 0) {
    close(fd);
    return -1;
  }
  close(fd);
  return rename(tmp_path, path) == 0 ? 0 : -1;
}

int32_t fz_native_storage_append(int32_t path_id, int32_t line_id) {
  const char* path = fz_lookup_string(path_id);
  const char* line = fz_lookup_string(line_id);
  if (path == NULL || path[0] == '\0') {
    return -1;
  }
  if (line == NULL) {
    line = "";
  }
  int fd = open(path, O_CREAT | O_APPEND | O_WRONLY, 0644);
  if (fd < 0) {
    return -1;
  }
  size_t len = strlen(line);
  if (len > 0 && write(fd, line, len) < 0) {
    close(fd);
    return -1;
  }
  if (write(fd, "\n", 1) < 0) {
    close(fd);
    return -1;
  }
  close(fd);
  return 0;
}

int32_t fz_native_storage_atomic_append(int32_t path_id, int32_t line_id) {
  const char* path = fz_lookup_string(path_id);
  const char* line = fz_lookup_string(line_id);
  if (path == NULL || path[0] == '\0') {
    return -1;
  }
  if (line == NULL) {
    line = "";
  }
  int32_t existing_id = fz_native_fs_read_file(path_id);
  const char* existing = fz_lookup_string(existing_id);
  if (existing == NULL) {
    existing = "";
  }
  size_t existing_len = strlen(existing);
  size_t line_len = strlen(line);
  char* payload = (char*)malloc(existing_len + line_len + 3);
  if (payload == NULL) {
    return -1;
  }
  size_t used = 0;
  if (existing_len > 0) {
    memcpy(payload + used, existing, existing_len);
    used += existing_len;
    if (payload[used - 1] != '\n') {
      payload[used++] = '\n';
    }
  }
  if (line_len > 0) {
    memcpy(payload + used, line, line_len);
    used += line_len;
  }
  payload[used++] = '\n';
  payload[used] = '\0';
  int rc = fz_storage_write_atomic_path(path, payload);
  free(payload);
  return rc == 0 ? 0 : -1;
}

int32_t fz_native_storage_kv_open(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') {
    return -1;
  }
  int32_t map_handle = fz_runtime_map_new();
  int32_t file_json_id = fz_native_fs_read_file(path_id);
  const char* raw = fz_lookup_string(file_json_id);
  if (raw != NULL && raw[0] != '\0') {
    int32_t parsed_handle = fz_native_json_to_map(file_json_id);
    if (parsed_handle > 0) {
      map_handle = parsed_handle;
    }
  }
  pthread_mutex_lock(&fz_collections_lock);
  int32_t kv_handle = fz_storage_kv_alloc();
  fz_storage_kv_state* kv = fz_storage_kv_get(kv_handle);
  if (kv != NULL) {
    kv->path_id = path_id;
    kv->map_handle = map_handle;
  }
  pthread_mutex_unlock(&fz_collections_lock);
  return kv == NULL ? -1 : kv_handle;
}

int32_t fz_native_storage_kv_get(int32_t kv_handle, int32_t key_id) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_storage_kv_state* kv = fz_storage_kv_get(kv_handle);
  if (kv == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return fz_intern_slice("", 0);
  }
  int32_t map_handle = kv->map_handle;
  pthread_mutex_unlock(&fz_collections_lock);
  return fz_runtime_map_get(map_handle, key_id);
}

int32_t fz_native_storage_kv_put(int32_t kv_handle, int32_t key_id, int32_t value_id) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_storage_kv_state* kv = fz_storage_kv_get(kv_handle);
  if (kv == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  int32_t path_id = kv->path_id;
  int32_t map_handle = kv->map_handle;
  pthread_mutex_unlock(&fz_collections_lock);
  int rc = fz_runtime_map_set(map_handle, key_id, value_id);
  if (rc != 0) {
    return -1;
  }
  int32_t json_id = fz_native_json_from_map(map_handle);
  const char* path = fz_lookup_string(path_id);
  const char* content = fz_lookup_string(json_id);
  return fz_storage_write_atomic_path(path, content) == 0 ? 0 : -1;
}

int32_t fz_native_fs_mkdir(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') return -1;
  if (mkdir(path, 0755) == 0 || errno == EEXIST) return 0;
  return -1;
}

int32_t fz_native_fs_exists(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') return 0;
  struct stat st;
  return stat(path, &st) == 0 ? 1 : 0;
}

int32_t fz_native_fs_stat_size(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') return -1;
  struct stat st;
  if (stat(path, &st) != 0) return -1;
  return (int32_t)st.st_size;
}

int32_t fz_native_fs_listdir(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') return -1;
  DIR* dir = opendir(path);
  if (dir == NULL) return -1;
  pthread_mutex_lock(&fz_collections_lock);
  int32_t list_handle = fz_list_alloc();
  fz_list_state* list = fz_list_get(list_handle);
  if (list != NULL) {
    struct dirent* ent = NULL;
    while ((ent = readdir(dir)) != NULL) {
      if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
      (void)fz_list_push_cstr(list, ent->d_name);
    }
  }
  pthread_mutex_unlock(&fz_collections_lock);
  closedir(dir);
  return list_handle;
}

int32_t fz_native_fs_remove_file(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') return -1;
  return unlink(path) == 0 ? 0 : -1;
}

int32_t fz_native_fs_temp_file(int32_t prefix_id) {
  const char* prefix = fz_lookup_string(prefix_id);
  if (prefix == NULL || prefix[0] == '\0') prefix = "fz";
  char tmpl[512];
  snprintf(tmpl, sizeof(tmpl), "/tmp/%s-XXXXXX", prefix);
  int fd = mkstemp(tmpl);
  if (fd < 0) return fz_intern_slice("", 0);
  close(fd);
  return fz_intern_slice(tmpl, strlen(tmpl));
}

int32_t fz_native_path_join(int32_t left_id, int32_t right_id) {
  const char* left = fz_lookup_string(left_id);
  const char* right = fz_lookup_string(right_id);
  if (left == NULL) left = "";
  if (right == NULL) right = "";
  size_t left_len = strlen(left);
  size_t right_len = strlen(right);
  int need_sep = left_len > 0 && left[left_len - 1] != '/';
  char* out = (char*)malloc(left_len + right_len + (need_sep ? 2 : 1));
  if (out == NULL) return 0;
  strcpy(out, left);
  if (need_sep) strcat(out, "/");
  strcat(out, right);
  return fz_intern_owned(out);
}

int32_t fz_native_path_normalize(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL) path = "";
  char* out = strdup(path);
  if (out == NULL) return 0;
  size_t w = 0;
  for (size_t r = 0; out[r] != '\0'; r++) {
    if (out[r] == '/' && w > 0 && out[w - 1] == '/') continue;
    out[w++] = out[r];
  }
  if (w > 1 && out[w - 1] == '/') w--;
  out[w] = '\0';
  return fz_intern_owned(out);
}

int32_t fz_native_net_bind(void) {
  (void)pthread_once(&fz_env_bootstrap_once, fz_env_bootstrap);
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    char msg[256];
    snprintf(msg, sizeof(msg), "http.bind failed: socket() errno=%d (%s)", errno, strerror(errno));
    fz_set_last_error(errno, 3, msg);
    return -1;
  }
  (void)fz_mark_cloexec(fd);
  int yes = 1;
  (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = fz_default_addr();
  addr.sin_port = htons((uint16_t)fz_default_port());
  if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
    char host[64];
    const char* rendered = inet_ntop(AF_INET, &addr.sin_addr, host, sizeof(host));
    if (rendered == NULL) {
      rendered = fz_default_host_name();
    }
    int bind_port = (int)ntohs(addr.sin_port);
    char msg[320];
    snprintf(
        msg,
        sizeof(msg),
        "http.bind failed on %s:%d errno=%d (%s); set FZ_HOST/FZ_PORT or AGENT_HOST/AGENT_PORT",
        rendered,
        bind_port,
        errno,
        strerror(errno));
    fz_set_last_error(errno, 3, msg);
    close(fd);
    return -1;
  }
  pthread_mutex_lock(&fz_listener_lock);
  fz_listener_fd = fd;
  pthread_mutex_unlock(&fz_listener_lock);
  fz_set_last_error(0, 0, "");
  return fd;
}

int32_t fz_native_net_listen(int32_t fd) {
  int listener = fd;
  if (listener < 0) {
    pthread_mutex_lock(&fz_listener_lock);
    listener = fz_listener_fd;
    pthread_mutex_unlock(&fz_listener_lock);
  }
  if (listener < 0) {
    fz_set_last_error(EINVAL, 3, "http.listen failed: no listener fd (call http.bind first)");
    return -1;
  }
  if (listen(listener, 128) != 0) {
    char msg[256];
    snprintf(
        msg,
        sizeof(msg),
        "http.listen failed fd=%d backlog=128 errno=%d (%s)",
        listener,
        errno,
        strerror(errno));
    fz_set_last_error(errno, 3, msg);
    return -1;
  }
  fz_log_bind_target(listener);
  fz_set_last_error(0, 0, "");
  return 0;
}

int32_t fz_native_net_accept(void) {
  int listener = -1;
  pthread_mutex_lock(&fz_listener_lock);
  listener = fz_listener_fd;
  pthread_mutex_unlock(&fz_listener_lock);
  if (listener < 0) {
    fz_set_last_error(EINVAL, 3, "http.accept failed: listener not initialized");
    return -1;
  }
  struct sockaddr_in peer;
  socklen_t peer_len = sizeof(peer);
  int conn_fd = accept(listener, (struct sockaddr*)&peer, &peer_len);
  if (conn_fd < 0) {
    if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
      char msg[256];
      snprintf(
          msg,
          sizeof(msg),
          "http.accept failed listener=%d errno=%d (%s)",
          listener,
          errno,
          strerror(errno));
      fz_set_last_error(errno, 3, msg);
    }
    return -1;
  }
  (void)fz_mark_cloexec(conn_fd);
  char peer_addr[64];
  const char* rendered = inet_ntop(AF_INET, &peer.sin_addr, peer_addr, sizeof(peer_addr));
  if (rendered == NULL) {
    rendered = "";
  }
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 1);
  if (state != NULL) {
    state->remote_addr_id = fz_intern_slice(rendered, strlen(rendered));
    state->request_id = 0;
    state->header_count = 0;
    state->query_count = 0;
    state->param_count = 0;
  }
  pthread_mutex_unlock(&fz_conn_lock);
  fz_set_last_error(0, 0, "");
  return conn_fd;
}

int32_t fz_native_net_read(int32_t conn_fd) {
  if (conn_fd < 0) {
    return -1;
  }
  char* req = (char*)malloc(FZ_MAX_HTTP_READ + 1);
  if (req == NULL) {
    return -1;
  }
  int total = 0;
  int header_end = -1;
  int64_t content_length = -1;
  while (total < FZ_MAX_HTTP_READ) {
    ssize_t got = recv(conn_fd, req + total, (size_t)(FZ_MAX_HTTP_READ - total), 0);
    if (got < 0) {
      if (errno == EINTR) {
        continue;
      }
      free(req);
      return -1;
    }
    if (got == 0) {
      break;
    }
    total += (int)got;
    req[total] = '\0';
    if (header_end < 0) {
      header_end = fz_find_header_end(req, total);
      if (header_end >= 0) {
        content_length = fz_parse_content_length(req, header_end);
      }
    }
    if (header_end >= 0) {
      if (content_length >= 0) {
        if (total >= header_end + content_length) {
          break;
        }
      } else {
        break;
      }
    }
  }
  if (total <= 0) {
    free(req);
    return total;
  }
  if (header_end < 0) {
    free(req);
    return -1;
  }

  const char* line_end = strstr(req, "\r\n");
  if (line_end == NULL) {
    free(req);
    return -1;
  }
  const char* sp1 = memchr(req, ' ', (size_t)(line_end - req));
  if (sp1 == NULL) {
    free(req);
    return -1;
  }
  const char* sp2 = memchr(sp1 + 1, ' ', (size_t)(line_end - (sp1 + 1)));
  if (sp2 == NULL) {
    free(req);
    return -1;
  }

  size_t method_len = (size_t)(sp1 - req);
  size_t path_len = (size_t)(sp2 - (sp1 + 1));
  const char* version = sp2 + 1;
  int version_len = (int)(line_end - version);

  int body_len = total - header_end;
  if (content_length >= 0 && body_len > content_length) {
    body_len = (int)content_length;
  }
  if (body_len < 0) {
    body_len = 0;
  }

  const char* raw_path = sp1 + 1;
  const char* query_mark = memchr(raw_path, '?', path_len);
  size_t clean_path_len = query_mark == NULL ? path_len : (size_t)(query_mark - raw_path);

  int32_t method_id = fz_intern_slice(req, method_len);
  int32_t path_id = fz_intern_slice(raw_path, clean_path_len);
  int32_t body_id = fz_intern_slice(req + header_end, (size_t)body_len);
  int keep_alive = fz_parse_keep_alive(req, header_end, version, version_len);

  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 1);
  if (state != NULL) {
    state->method_id = method_id;
    state->path_id = path_id;
    state->body_id = body_id;
    state->keep_alive = keep_alive;
    state->header_count = 0;
    state->query_count = 0;
    state->param_count = 0;
    fz_conn_request_counter += 1;
    char rid[64];
    snprintf(rid, sizeof(rid), "req-%d", fz_conn_request_counter);
    state->request_id = fz_intern_slice(rid, strlen(rid));
    const char* cursor = line_end + 2;
    while (cursor < req + header_end && state->header_count < FZ_MAX_CONN_META) {
      const char* next = strstr(cursor, "\r\n");
      if (next == NULL || next <= cursor) break;
      const char* colon = memchr(cursor, ':', (size_t)(next - cursor));
      if (colon != NULL) {
        const char* v = colon + 1;
        while (v < next && (*v == ' ' || *v == '\t')) v++;
        state->header_key_ids[state->header_count] = fz_intern_slice(cursor, (size_t)(colon - cursor));
        state->header_value_ids[state->header_count] = fz_intern_slice(v, (size_t)(next - v));
        state->header_count++;
      }
      cursor = next + 2;
    }
    if (query_mark != NULL) {
      const char* q = query_mark + 1;
      const char* q_end = raw_path + path_len;
      while (q < q_end && state->query_count < FZ_MAX_CONN_META) {
        const char* amp = memchr(q, '&', (size_t)(q_end - q));
        const char* token_end = amp == NULL ? q_end : amp;
        const char* eq = memchr(q, '=', (size_t)(token_end - q));
        if (eq == NULL) {
          state->query_key_ids[state->query_count] = fz_intern_slice(q, (size_t)(token_end - q));
          state->query_value_ids[state->query_count] = fz_intern_slice("", 0);
          state->query_count++;
        } else {
          state->query_key_ids[state->query_count] = fz_intern_slice(q, (size_t)(eq - q));
          state->query_value_ids[state->query_count] = fz_intern_slice(eq + 1, (size_t)(token_end - (eq + 1)));
          state->query_count++;
        }
        if (amp == NULL) break;
        q = amp + 1;
      }
    }
  }
  pthread_mutex_unlock(&fz_conn_lock);

  free(req);
  return total;
}

int32_t fz_native_net_method(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  int32_t value = state == NULL ? 0 : state->method_id;
  pthread_mutex_unlock(&fz_conn_lock);
  return value;
}

int32_t fz_native_net_path(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  int32_t value = state == NULL ? 0 : state->path_id;
  pthread_mutex_unlock(&fz_conn_lock);
  return value;
}

int32_t fz_native_net_body(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  int32_t value = state == NULL ? 0 : state->body_id;
  pthread_mutex_unlock(&fz_conn_lock);
  return value;
}

int32_t fz_native_net_body_json(int32_t conn_fd) {
  int32_t body_id = fz_native_net_body(conn_fd);
  return fz_native_json_parse(body_id);
}

int32_t fz_native_net_body_bind(int32_t conn_fd) {
  int32_t out_map = fz_runtime_map_new();
  if (out_map < 0) {
    return -1;
  }
  int32_t body = fz_native_net_body_json(conn_fd);
  if (body <= 0) {
    (void)fz_runtime_map_set(
        out_map,
        fz_intern_slice("__error", 7),
        fz_intern_slice("invalid JSON body", 17));
    return out_map;
  }
  int32_t body_id = fz_json_value_get_id(body);
  const char* raw = fz_lookup_string(body_id);
  const char* p = fz_json_ws(raw);
  if (p == NULL || *p != '{') {
    (void)fz_runtime_map_set(
        out_map,
        fz_intern_slice("__error", 7),
        fz_intern_slice("body must be JSON object", 24));
    return out_map;
  }
  p = fz_json_ws(p + 1);
  if (*p == '}') {
    return out_map;
  }
  for (;;) {
    char* key = NULL;
    if (fz_json_parse_string(&p, &key) != 0) {
      (void)fz_runtime_map_set(
          out_map,
          fz_intern_slice("__error", 7),
          fz_intern_slice("invalid JSON object key", 23));
      free(key);
      return out_map;
    }
    p = fz_json_ws(p);
    if (*p != ':') {
      (void)fz_runtime_map_set(
          out_map,
          fz_intern_slice("__error", 7),
          fz_intern_slice("invalid JSON object syntax", 26));
      free(key);
      return out_map;
    }
    p = fz_json_ws(p + 1);
    const char* value_start = p;
    if (fz_json_skip_value_token(&p, 0) != 0) {
      (void)fz_runtime_map_set(
          out_map,
          fz_intern_slice("__error", 7),
          fz_intern_slice("invalid JSON object value", 25));
      free(key);
      return out_map;
    }
    const char* value_end = p;
    int32_t key_id = fz_intern_slice(key == NULL ? "" : key, strlen(key == NULL ? "" : key));
    free(key);

    const char* q = value_start;
    char* string_value = NULL;
    int decoded = fz_json_parse_string(&q, &string_value) == 0 && fz_json_ws(q) == value_end;
    if (decoded) {
      int32_t value_id = fz_intern_slice(string_value == NULL ? "" : string_value, strlen(string_value == NULL ? "" : string_value));
      free(string_value);
      (void)fz_runtime_map_set(out_map, key_id, value_id);
    } else {
      free(string_value);
      int32_t value_id = fz_intern_slice(value_start, (size_t)(value_end - value_start));
      (void)fz_runtime_map_set(out_map, key_id, value_id);
    }
    p = fz_json_ws(p);
    if (*p == ',') {
      p = fz_json_ws(p + 1);
      continue;
    }
    if (*p == '}') {
      return out_map;
    }
    (void)fz_runtime_map_set(
        out_map,
        fz_intern_slice("__error", 7),
        fz_intern_slice("invalid JSON object terminator", 30));
    return out_map;
  }
}

int32_t fz_native_net_header(int32_t conn_fd, int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL || key == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return fz_intern_slice("", 0);
  }
  for (int i = 0; i < state->header_count; i++) {
    const char* k = fz_lookup_string(state->header_key_ids[i]);
    if (k != NULL && strcasecmp(k, key) == 0) {
      int32_t value = state->header_value_ids[i];
      pthread_mutex_unlock(&fz_conn_lock);
      return value;
    }
  }
  pthread_mutex_unlock(&fz_conn_lock);
  return fz_intern_slice("", 0);
}

int32_t fz_native_net_query(int32_t conn_fd, int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL || key == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return fz_intern_slice("", 0);
  }
  for (int i = 0; i < state->query_count; i++) {
    const char* k = fz_lookup_string(state->query_key_ids[i]);
    if (k != NULL && strcmp(k, key) == 0) {
      int32_t value = state->query_value_ids[i];
      pthread_mutex_unlock(&fz_conn_lock);
      return value;
    }
  }
  pthread_mutex_unlock(&fz_conn_lock);
  return fz_intern_slice("", 0);
}

int32_t fz_native_net_param(int32_t conn_fd, int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL || key == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return fz_intern_slice("", 0);
  }
  for (int i = 0; i < state->param_count; i++) {
    const char* k = fz_lookup_string(state->param_key_ids[i]);
    if (k != NULL && strcmp(k, key) == 0) {
      int32_t value = state->param_value_ids[i];
      pthread_mutex_unlock(&fz_conn_lock);
      return value;
    }
  }
  pthread_mutex_unlock(&fz_conn_lock);
  return fz_intern_slice("", 0);
}

int32_t fz_native_net_headers(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return -1;
  }
  pthread_mutex_lock(&fz_collections_lock);
  int32_t list_handle = fz_list_alloc();
  fz_list_state* list = fz_list_get(list_handle);
  if (list != NULL) {
    for (int i = 0; i < state->header_count; i++) {
      const char* k = fz_lookup_string(state->header_key_ids[i]);
      const char* v = fz_lookup_string(state->header_value_ids[i]);
      size_t n = strlen(k == NULL ? "" : k) + strlen(v == NULL ? "" : v) + 3;
      char* kv = (char*)malloc(n);
      if (kv == NULL) continue;
      snprintf(kv, n, "%s:%s", k == NULL ? "" : k, v == NULL ? "" : v);
      (void)fz_list_push_cstr(list, kv);
      free(kv);
    }
  }
  pthread_mutex_unlock(&fz_collections_lock);
  pthread_mutex_unlock(&fz_conn_lock);
  return list_handle;
}

int32_t fz_native_net_request_id(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  int32_t value = state == NULL ? 0 : state->request_id;
  pthread_mutex_unlock(&fz_conn_lock);
  return value;
}

int32_t fz_native_net_remote_addr(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  int32_t value = state == NULL ? 0 : state->remote_addr_id;
  pthread_mutex_unlock(&fz_conn_lock);
  return value;
}

static int fz_route_match_path_and_capture(fz_conn_state* state, const char* pattern) {
  if (state == NULL || pattern == NULL) {
    return 0;
  }
  const char* path = fz_lookup_string(state->path_id);
  if (path == NULL) path = "";
  state->param_count = 0;
  const char* p = path;
  const char* t = pattern;
  while (*p == '/') p++;
  while (*t == '/') t++;
  for (;;) {
    const char* p_end = strchr(p, '/');
    const char* t_end = strchr(t, '/');
    size_t p_len = p_end == NULL ? strlen(p) : (size_t)(p_end - p);
    size_t t_len = t_end == NULL ? strlen(t) : (size_t)(t_end - t);
    if (p_len == 0 && t_len == 0) return 1;
    if (p_len == 0 || t_len == 0) return 0;
    if (t[0] == ':') {
      if (state->param_count < FZ_MAX_ROUTE_PARAMS) {
        state->param_key_ids[state->param_count] = fz_intern_slice(t + 1, t_len - 1);
        state->param_value_ids[state->param_count] = fz_intern_slice(p, p_len);
        state->param_count++;
      }
    } else if (p_len != t_len || strncmp(p, t, p_len) != 0) {
      return 0;
    }
    if (p_end == NULL && t_end == NULL) return 1;
    if (p_end == NULL || t_end == NULL) return 0;
    p = p_end + 1;
    t = t_end + 1;
  }
}

int32_t fz_native_route_match(int32_t conn_fd, int32_t method_id, int32_t pattern_id) {
  const char* method = fz_lookup_string(method_id);
  const char* pattern = fz_lookup_string(pattern_id);
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return 0;
  }
  if (method != NULL && method[0] != '\0') {
    const char* req_method = fz_lookup_string(state->method_id);
    if (req_method == NULL || strcmp(req_method, method) != 0) {
      pthread_mutex_unlock(&fz_conn_lock);
      return 0;
    }
  }
  int ok = fz_route_match_path_and_capture(state, pattern == NULL ? "" : pattern);
  pthread_mutex_unlock(&fz_conn_lock);
  return ok ? 1 : 0;
}

int32_t fz_native_route_write_404(int32_t conn_fd) {
  return fz_native_net_write(conn_fd, 404, fz_intern_slice("not found", 9));
}

int32_t fz_native_route_write_405(int32_t conn_fd) {
  return fz_native_net_write(conn_fd, 405, fz_intern_slice("method not allowed", 18));
}

int32_t fz_native_net_write_response(
    int32_t conn_fd,
    int32_t status_code,
    int32_t content_type_id,
    int32_t body_id,
    int32_t close_after) {
  const char* content_type = fz_lookup_string(content_type_id);
  const char* body = fz_lookup_string(body_id);
  return fz_send_http_response(conn_fd, status_code, content_type, body, close_after != 0);
}

int32_t fz_native_net_write(int32_t conn_fd, int32_t status_code, int32_t body_id) {
  int close_after = 1;
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state != NULL) {
    close_after = state->keep_alive ? 0 : 1;
  }
  pthread_mutex_unlock(&fz_conn_lock);
  return fz_send_http_response(
      conn_fd,
      status_code,
      "text/plain; charset=utf-8",
      fz_lookup_string(body_id),
      close_after);
}

static char* fz_json_escape_string_bytes(const char* raw) {
  if (raw == NULL) {
    raw = "";
  }
  size_t len = strlen(raw);
  size_t cap = (len * 6) + 1;
  char* out = (char*)malloc(cap);
  if (out == NULL) {
    return NULL;
  }
  size_t used = 0;
  for (size_t i = 0; i < len; i++) {
    unsigned char ch = (unsigned char)raw[i];
    if (ch == '\"' || ch == '\\') {
      out[used++] = '\\';
      out[used++] = (char)ch;
      continue;
    }
    switch (ch) {
      case '\b':
        out[used++] = '\\';
        out[used++] = 'b';
        break;
      case '\f':
        out[used++] = '\\';
        out[used++] = 'f';
        break;
      case '\n':
        out[used++] = '\\';
        out[used++] = 'n';
        break;
      case '\r':
        out[used++] = '\\';
        out[used++] = 'r';
        break;
      case '\t':
        out[used++] = '\\';
        out[used++] = 't';
        break;
      default:
        if (ch < 0x20) {
          (void)snprintf(out + used, cap - used, "\\u%04x", (unsigned int)ch);
          used += 6;
        } else {
          out[used++] = (char)ch;
        }
        break;
    }
  }
  out[used] = '\0';
  return out;
}

static int32_t fz_json_wrap_invalid_payload(const char* raw) {
  char* escaped = fz_json_escape_string_bytes(raw);
  if (escaped == NULL) {
    const char* fallback =
        "{\"error\":\"invalid_json_payload\",\"message\":\"http.write_json could not allocate sanitize buffer\"}";
    return fz_intern_slice(fallback, strlen(fallback));
  }
  const char* prefix =
      "{\"error\":\"invalid_json_payload\",\"message\":\"http.write_json sanitized non-JSON body\",\"raw\":\"";
  const char* suffix = "\"}";
  size_t total = strlen(prefix) + strlen(escaped) + strlen(suffix) + 1;
  char* wrapped = (char*)malloc(total);
  if (wrapped == NULL) {
    free(escaped);
    const char* fallback =
        "{\"error\":\"invalid_json_payload\",\"message\":\"http.write_json sanitize alloc failed\"}";
    return fz_intern_slice(fallback, strlen(fallback));
  }
  snprintf(wrapped, total, "%s%s%s", prefix, escaped, suffix);
  free(escaped);
  return fz_intern_owned(wrapped);
}

int32_t fz_native_net_write_json(int32_t conn_fd, int32_t status_code, int32_t body_id) {
  const char* body = fz_lookup_string(body_id);
  if (body == NULL || body[0] == '\0') {
    body = "null";
  }
  const char* send_body = body;
  int32_t replacement_id = 0;
  const char* start = NULL;
  const char* end = NULL;
  if (fz_json_parse_value_slice(body, &start, &end) != 0) {
    replacement_id = fz_json_wrap_invalid_payload(body);
    send_body = fz_lookup_string(replacement_id);
    fz_set_last_error(
        EINVAL,
        3,
        "http.write_json received invalid JSON body; response was sanitized");
  } else {
    fz_set_last_error(0, 0, "");
  }
  int close_after = 1;
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state != NULL) {
    close_after = state->keep_alive ? 0 : 1;
  }
  pthread_mutex_unlock(&fz_conn_lock);
  return fz_send_http_response(
      conn_fd,
      status_code,
      "application/json",
      send_body,
      close_after);
}

int32_t fz_native_close(int32_t fd) {
  if (fd >= 0) {
    shutdown(fd, SHUT_RDWR);
    close(fd);
  }
  fz_conn_state_drop(fd);
  return 0;
}

static const char* fz_json_skip_ws(const char* p) {
  while (p != NULL && (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')) {
    p++;
  }
  return p;
}

static int fz_json_parse_string(const char** cursor, char** out) {
  if (cursor == NULL || *cursor == NULL || out == NULL) {
    return -1;
  }
  const char* p = fz_json_skip_ws(*cursor);
  if (p == NULL || *p != '\"') {
    return -1;
  }
  p++;
  size_t cap = 32;
  size_t len = 0;
  char* buf = (char*)malloc(cap);
  if (buf == NULL) {
    return -1;
  }
  while (*p != '\0') {
    char ch = *p++;
    if (ch == '\"') {
      buf[len] = '\0';
      *out = buf;
      *cursor = p;
      return 0;
    }
    if (ch == '\\') {
      char esc = *p++;
      if (esc == '\0') {
        free(buf);
        return -1;
      }
      switch (esc) {
        case '\"': ch = '\"'; break;
        case '\\': ch = '\\'; break;
        case '/': ch = '/'; break;
        case 'b': ch = '\b'; break;
        case 'f': ch = '\f'; break;
        case 'n': ch = '\n'; break;
        case 'r': ch = '\r'; break;
        case 't': ch = '\t'; break;
        case 'u':
          for (int i = 0; i < 4; i++) {
            if (!isxdigit((unsigned char)p[i])) {
              free(buf);
              return -1;
            }
          }
          p += 4;
          ch = '?';
          break;
        default:
          free(buf);
          return -1;
      }
    }
    if (len + 2 > cap) {
      cap *= 2;
      char* next = (char*)realloc(buf, cap);
      if (next == NULL) {
        free(buf);
        return -1;
      }
      buf = next;
    }
    buf[len++] = ch;
  }
  free(buf);
  return -1;
}

static int fz_parse_json_string_array(const char* raw, char*** out_items, int* out_count) {
  if (out_items == NULL || out_count == NULL) {
    return -1;
  }
  *out_items = NULL;
  *out_count = 0;
  if (raw == NULL || raw[0] == '\0') {
    return 0;
  }
  const char* p = fz_json_skip_ws(raw);
  if (*p != '[') {
    return -1;
  }
  p = fz_json_skip_ws(p + 1);
  int cap = 4;
  int count = 0;
  char** items = (char**)calloc((size_t)cap, sizeof(char*));
  if (items == NULL) {
    return -1;
  }
  if (*p == ']') {
    *out_items = items;
    *out_count = 0;
    return 0;
  }
  for (;;) {
    char* item = NULL;
    if (fz_json_parse_string(&p, &item) != 0) {
      for (int i = 0; i < count; i++) free(items[i]);
      free(items);
      return -1;
    }
    if (count >= cap) {
      cap *= 2;
      char** next = (char**)realloc(items, (size_t)cap * sizeof(char*));
      if (next == NULL) {
        free(item);
        for (int i = 0; i < count; i++) free(items[i]);
        free(items);
        return -1;
      }
      items = next;
    }
    items[count++] = item;
    p = fz_json_skip_ws(p);
    if (*p == ',') {
      p = fz_json_skip_ws(p + 1);
      continue;
    }
    if (*p == ']') {
      break;
    }
    for (int i = 0; i < count; i++) free(items[i]);
    free(items);
    return -1;
  }
  *out_items = items;
  *out_count = count;
  return 0;
}

static int fz_parse_json_env_object(const char* raw, char*** out_items, int* out_count) {
  if (out_items == NULL || out_count == NULL) {
    return -1;
  }
  *out_items = NULL;
  *out_count = 0;
  if (raw == NULL || raw[0] == '\0') {
    return 0;
  }
  const char* p = fz_json_skip_ws(raw);
  if (*p != '{') {
    return -1;
  }
  p = fz_json_skip_ws(p + 1);
  int cap = 4;
  int count = 0;
  char** entries = (char**)calloc((size_t)cap, sizeof(char*));
  if (entries == NULL) {
    return -1;
  }
  if (*p == '}') {
    *out_items = entries;
    *out_count = 0;
    return 0;
  }
  for (;;) {
    char* key = NULL;
    char* value = NULL;
    if (fz_json_parse_string(&p, &key) != 0) {
      for (int i = 0; i < count; i++) free(entries[i]);
      free(entries);
      return -1;
    }
    p = fz_json_skip_ws(p);
    if (*p != ':') {
      free(key);
      for (int i = 0; i < count; i++) free(entries[i]);
      free(entries);
      return -1;
    }
    p = fz_json_skip_ws(p + 1);
    if (fz_json_parse_string(&p, &value) != 0) {
      free(key);
      for (int i = 0; i < count; i++) free(entries[i]);
      free(entries);
      return -1;
    }
    size_t n = strlen(key) + strlen(value) + 2;
    char* joined = (char*)malloc(n);
    if (joined == NULL) {
      free(key);
      free(value);
      for (int i = 0; i < count; i++) free(entries[i]);
      free(entries);
      return -1;
    }
    snprintf(joined, n, "%s=%s", key, value);
    free(key);
    free(value);
    if (count >= cap) {
      cap *= 2;
      char** next = (char**)realloc(entries, (size_t)cap * sizeof(char*));
      if (next == NULL) {
        free(joined);
        for (int i = 0; i < count; i++) free(entries[i]);
        free(entries);
        return -1;
      }
      entries = next;
    }
    entries[count++] = joined;
    p = fz_json_skip_ws(p);
    if (*p == ',') {
      p = fz_json_skip_ws(p + 1);
      continue;
    }
    if (*p == '}') {
      break;
    }
    for (int i = 0; i < count; i++) free(entries[i]);
    free(entries);
    return -1;
  }
  *out_items = entries;
  *out_count = count;
  return 0;
}

static void fz_free_string_list(char** items, int count) {
  if (items == NULL) {
    return;
  }
  for (int i = 0; i < count; i++) {
    free(items[i]);
  }
  free(items);
}

"#
}
