pub(super) fn runtime_shim_section_services() -> &'static str {
    r#"
static int32_t fz_log_level_value(const char* level) {
  if (level == NULL) return 0;
  if (strcmp(level, "error") == 0) return 2;
  if (strcmp(level, "warn") == 0) return 1;
  return 0;
}

static int32_t fz_log_stream_mode = -1;

static FILE* fz_log_stream(void) {
  int32_t target = fz_log_sink == 1 ? 1 : 0;
  FILE* stream = target == 1 ? stderr : stdout;
  if (fz_log_stream_mode != target) {
    setvbuf(stream, NULL, _IOLBF, 0);
    fz_log_stream_mode = target;
  }
  return stream;
}

static int32_t fz_log_emit(const char* level, const char* message, const char* fields) {
  if (level == NULL) level = "info";
  if (message == NULL) message = "";
  if (fields == NULL) fields = "{}";
  if (!fz_log_enabled) {
    return 0;
  }
  if (fz_log_level_value(level) < fz_log_min_level) {
    return 0;
  }
  int64_t ts = fz_now_ms();
  FILE* stream = fz_log_stream();
  if (fz_log_json) {
    fprintf(stream, "{\"ts\":%lld,\"level\":\"%s\",\"msg\":\"", (long long)ts, level);
    for (const char* p = message; *p; p++) {
      if (*p == '"' || *p == '\\') fputc('\\', stream);
      fputc(*p, stream);
    }
    fprintf(stream, "\",\"fields\":%s}\n", fields[0] == '\0' ? "{}" : fields);
  } else if (fields[0] != '\0' && strcmp(fields, "{}") != 0) {
    fprintf(stream, "[%lld] %s %s | fields=%s\n", (long long)ts, level, message, fields);
  } else {
    fprintf(stream, "[%lld] %s %s\n", (long long)ts, level, message);
  }
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

int32_t fz_native_log_set_enabled(int32_t enabled) {
  fz_log_enabled = enabled != 0 ? 1 : 0;
  return 0;
}

int32_t fz_native_log_set_level(int32_t level_id) {
  const char* level = fz_lookup_string(level_id);
  if (level == NULL || level[0] == '\0' || strcmp(level, "info") == 0) {
    fz_log_min_level = 0;
    return 0;
  }
  if (strcmp(level, "warn") == 0) {
    fz_log_min_level = 1;
    return 0;
  }
  if (strcmp(level, "error") == 0) {
    fz_log_min_level = 2;
    return 0;
  }
  fz_set_last_error(EINVAL, 3, "log.set_level failed: expected info, warn, or error");
  return -1;
}

int32_t fz_native_log_set_sink(int32_t sink_id) {
  const char* sink = fz_lookup_string(sink_id);
  if (sink == NULL || sink[0] == '\0' || strcmp(sink, "stdout") == 0) {
    fz_log_sink = 0;
    return 0;
  }
  if (strcmp(sink, "stderr") == 0) {
    fz_log_sink = 1;
    return 0;
  }
  fz_set_last_error(EINVAL, 3, "log.set_sink failed: expected stdout or stderr");
  return -1;
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

int32_t fz_native_crypto_random_hex(int32_t len_bytes) {
  if (len_bytes < 0) {
    fz_set_last_error(EINVAL, 3, "crypto.random_hex failed: len must be >= 0");
    return fz_intern_slice("", 0);
  }
  size_t len = (size_t)len_bytes;
  uint8_t* raw = len == 0 ? NULL : (uint8_t*)malloc(len);
  if (len > 0 && raw == NULL) {
    fz_set_last_error(ENOMEM, 3, "crypto.random_hex failed: alloc failed");
    return fz_intern_slice("", 0);
  }
  if (fz_crypto_fill_random(raw, len) != 0) {
    if (raw != NULL) {
      fz_crypto_memzero(raw, len);
    }
    free(raw);
    fz_set_last_error(errno == 0 ? EIO : errno, 3, "crypto.random_hex failed: entropy unavailable");
    return fz_intern_slice("", 0);
  }
  char* encoded = fz_crypto_hex_encode(raw == NULL ? (const uint8_t*)"" : raw, len);
  if (raw != NULL) {
    fz_crypto_memzero(raw, len);
  }
  free(raw);
  if (encoded == NULL) {
    fz_set_last_error(ENOMEM, 3, "crypto.random_hex failed: hex encode alloc failed");
    return fz_intern_slice("", 0);
  }
  fz_set_last_error(0, 0, "");
  return fz_intern_owned(encoded);
}

int32_t fz_native_crypto_random_base64(int32_t len_bytes) {
  if (len_bytes < 0) {
    fz_set_last_error(EINVAL, 3, "crypto.random_base64 failed: len must be >= 0");
    return fz_intern_slice("", 0);
  }
  size_t len = (size_t)len_bytes;
  uint8_t* raw = len == 0 ? NULL : (uint8_t*)malloc(len);
  if (len > 0 && raw == NULL) {
    fz_set_last_error(ENOMEM, 3, "crypto.random_base64 failed: alloc failed");
    return fz_intern_slice("", 0);
  }
  if (fz_crypto_fill_random(raw, len) != 0) {
    if (raw != NULL) {
      fz_crypto_memzero(raw, len);
    }
    free(raw);
    fz_set_last_error(errno == 0 ? EIO : errno, 3, "crypto.random_base64 failed: entropy unavailable");
    return fz_intern_slice("", 0);
  }
  char* encoded = fz_crypto_base64_encode_alloc(raw == NULL ? (const uint8_t*)"" : raw, len);
  if (raw != NULL) {
    fz_crypto_memzero(raw, len);
  }
  free(raw);
  if (encoded == NULL) {
    fz_set_last_error(ENOMEM, 3, "crypto.random_base64 failed: base64 encode alloc failed");
    return fz_intern_slice("", 0);
  }
  fz_set_last_error(0, 0, "");
  return fz_intern_owned(encoded);
}

int32_t fz_native_crypto_sha256(int32_t input_id) {
  const char* input = fz_lookup_string(input_id);
  size_t len = input == NULL ? 0 : strlen(input);
  uint8_t digest[32];
  fz_sha256_hash((const uint8_t*)(input == NULL ? "" : input), len, digest);
  char* encoded = fz_crypto_hex_encode(digest, sizeof(digest));
  fz_crypto_memzero(digest, sizeof(digest));
  if (encoded == NULL) {
    fz_set_last_error(ENOMEM, 3, "crypto.sha256 failed: hex encode alloc failed");
    return fz_intern_slice("", 0);
  }
  fz_set_last_error(0, 0, "");
  return fz_intern_owned(encoded);
}

int32_t fz_native_crypto_hmac_sha256(int32_t key_id, int32_t data_id) {
  const char* key = fz_lookup_string(key_id);
  const char* data = fz_lookup_string(data_id);
  uint8_t digest[32];
  fz_hmac_sha256_hash(
      (const uint8_t*)(key == NULL ? "" : key),
      key == NULL ? 0 : strlen(key),
      (const uint8_t*)(data == NULL ? "" : data),
      data == NULL ? 0 : strlen(data),
      digest);
  char* encoded = fz_crypto_hex_encode(digest, sizeof(digest));
  fz_crypto_memzero(digest, sizeof(digest));
  if (encoded == NULL) {
    fz_set_last_error(ENOMEM, 3, "crypto.hmac_sha256 failed: hex encode alloc failed");
    return fz_intern_slice("", 0);
  }
  fz_set_last_error(0, 0, "");
  return fz_intern_owned(encoded);
}

int32_t fz_native_crypto_constant_time_eq(int32_t left_id, int32_t right_id) {
  const char* left = fz_lookup_string(left_id);
  const char* right = fz_lookup_string(right_id);
  size_t left_len = left == NULL ? 0 : strlen(left);
  size_t right_len = right == NULL ? 0 : strlen(right);
  size_t max_len = left_len > right_len ? left_len : right_len;
  unsigned char diff = (unsigned char)(left_len ^ right_len);
  for (size_t i = 0; i < max_len; i++) {
    unsigned char a = i < left_len ? (unsigned char)left[i] : 0;
    unsigned char b = i < right_len ? (unsigned char)right[i] : 0;
    diff |= (unsigned char)(a ^ b);
  }
  fz_set_last_error(0, 0, "");
  return diff == 0 ? 1 : 0;
}

int32_t fz_native_crypto_base64_encode(int32_t input_id) {
  const char* input = fz_lookup_string(input_id);
  size_t len = input == NULL ? 0 : strlen(input);
  char* encoded = fz_crypto_base64_encode_alloc((const uint8_t*)(input == NULL ? "" : input), len);
  if (encoded == NULL) {
    fz_set_last_error(ENOMEM, 3, "crypto.base64_encode failed: alloc failed");
    return fz_intern_slice("", 0);
  }
  fz_set_last_error(0, 0, "");
  return fz_intern_owned(encoded);
}

int32_t fz_native_crypto_base64_decode(int32_t input_id) {
  const char* input = fz_lookup_string(input_id);
  uint8_t* decoded = NULL;
  size_t decoded_len = 0;
  if (fz_crypto_base64_decode_alloc(input == NULL ? "" : input, &decoded, &decoded_len) != 0) {
    fz_set_last_error(EINVAL, 3, "crypto.base64_decode failed: invalid base64 input");
    return fz_intern_slice("", 0);
  }
  if (decoded != NULL && memchr(decoded, '\0', decoded_len) != NULL) {
    fz_crypto_memzero(decoded, decoded_len);
    free(decoded);
    fz_set_last_error(EINVAL, 3, "crypto.base64_decode failed: decoded bytes are not text-safe");
    return fz_intern_slice("", 0);
  }
  int32_t out = fz_intern_slice((const char*)(decoded == NULL ? (const uint8_t*)"" : decoded), decoded_len);
  if (decoded != NULL) {
    fz_crypto_memzero(decoded, decoded_len);
  }
  free(decoded);
  fz_set_last_error(0, 0, "");
  return out;
}

int32_t fz_native_crypto_base64_url_encode(int32_t input_id) {
  const char* input = fz_lookup_string(input_id);
  size_t len = input == NULL ? 0 : strlen(input);
  char* encoded =
      fz_crypto_base64_url_encode_alloc((const uint8_t*)(input == NULL ? "" : input), len);
  if (encoded == NULL) {
    fz_set_last_error(ENOMEM, 3, "crypto.base64_url_encode failed: alloc failed");
    return fz_intern_slice("", 0);
  }
  fz_set_last_error(0, 0, "");
  return fz_intern_owned(encoded);
}

int32_t fz_native_crypto_base64_url_decode(int32_t input_id) {
  const char* input = fz_lookup_string(input_id);
  uint8_t* decoded = NULL;
  size_t decoded_len = 0;
  if (fz_crypto_base64_url_decode_alloc(input == NULL ? "" : input, &decoded, &decoded_len) != 0) {
    fz_set_last_error(EINVAL, 3, "crypto.base64_url_decode failed: invalid base64url input");
    return fz_intern_slice("", 0);
  }
  if (decoded != NULL && memchr(decoded, '\0', decoded_len) != NULL) {
    fz_crypto_memzero(decoded, decoded_len);
    free(decoded);
    fz_set_last_error(EINVAL, 3, "crypto.base64_url_decode failed: decoded bytes are not text-safe");
    return fz_intern_slice("", 0);
  }
  int32_t out = fz_intern_slice((const char*)(decoded == NULL ? (const uint8_t*)"" : decoded), decoded_len);
  if (decoded != NULL) {
    fz_crypto_memzero(decoded, decoded_len);
  }
  free(decoded);
  fz_set_last_error(0, 0, "");
  return out;
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

int32_t fz_native_fs_open(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') {
    fz_set_last_error(EINVAL, 3, "fs.open failed: path must not be empty");
    return -1;
  }
  int fd = open(path, O_CREAT | O_RDWR, 0644);
  if (fd < 0) {
    fz_set_last_error(errno, 3, "fs.open failed");
    return -1;
  }
  (void)fz_mark_cloexec(fd);
  return fd;
}

int32_t fz_native_fs_close(int32_t handle) {
  if (handle < 0) {
    fz_set_last_error(EINVAL, 3, "fs.close failed: invalid handle");
    return -1;
  }
  if (close(handle) != 0) {
    fz_set_last_error(errno, 3, "fs.close failed");
    return -1;
  }
  return 0;
}

int32_t fz_native_fs_write(int32_t handle, int32_t content_id) {
  const char* content = fz_lookup_string(content_id);
  if (handle < 0) {
    fz_set_last_error(EINVAL, 3, "fs.write failed: invalid handle");
    return -1;
  }
  if (content == NULL) content = "";
  if (lseek(handle, 0, SEEK_END) < 0) {
    fz_set_last_error(errno, 3, "fs.write failed: seek failed");
    return -1;
  }
  size_t left = strlen(content);
  const char* p = content;
  while (left > 0) {
    ssize_t wrote = write(handle, p, left);
    if (wrote < 0) {
      if (errno == EINTR) continue;
      fz_set_last_error(errno, 3, "fs.write failed");
      return -1;
    }
    if (wrote == 0) {
      break;
    }
    p += wrote;
    left -= (size_t)wrote;
  }
  return 0;
}

int32_t fz_native_fs_read(int32_t handle, int32_t limit) {
  if (handle < 0) {
    fz_set_last_error(EINVAL, 3, "fs.read failed: invalid handle");
    return fz_intern_slice("", 0);
  }
  if (limit < 0) {
    fz_set_last_error(EINVAL, 3, "fs.read failed: limit must be >= 0");
    return fz_intern_slice("", 0);
  }
  if (lseek(handle, 0, SEEK_SET) < 0) {
    fz_set_last_error(errno, 3, "fs.read failed: seek failed");
    return fz_intern_slice("", 0);
  }
  size_t cap = (size_t)limit;
  if (cap > 1048576) cap = 1048576;
  fz_bytes_buf buf;
  fz_bytes_buf_init(&buf);
  char tmp[4096];
  while (buf.len < cap) {
    size_t chunk = sizeof(tmp);
    if (cap - buf.len < chunk) {
      chunk = cap - buf.len;
    }
    if (chunk == 0) {
      break;
    }
    ssize_t got = read(handle, tmp, chunk);
    if (got > 0) {
      if (fz_bytes_buf_append(&buf, tmp, (size_t)got) != 0) {
        fz_set_last_error(ENOMEM, 3, "fs.read failed: buffer alloc failed");
        break;
      }
      continue;
    }
    if (got == 0) break;
    if (errno == EINTR) continue;
    fz_set_last_error(errno, 3, "fs.read failed");
    break;
  }
  int32_t out = fz_intern_slice(buf.data == NULL ? "" : buf.data, buf.len);
  fz_bytes_buf_free(&buf);
  return out;
}

int32_t fz_native_fs_flush(int32_t handle) {
  if (handle < 0) {
    fz_set_last_error(EINVAL, 3, "fs.flush failed: invalid handle");
    return -1;
  }
  return fsync(handle) == 0 ? 0 : -1;
}

int32_t fz_native_fs_fsync(int32_t handle) {
  if (handle < 0) {
    fz_set_last_error(EINVAL, 3, "fs.fsync failed: invalid handle");
    return -1;
  }
  if (fsync(handle) != 0) {
    fz_set_last_error(errno, 3, "fs.fsync failed");
    return -1;
  }
  return 0;
}

int32_t fz_native_fs_lock(int32_t handle) {
  if (handle < 0) {
    fz_set_last_error(EINVAL, 3, "fs.lock failed: invalid handle");
    return -1;
  }
  if (lockf(handle, F_LOCK, 0) != 0) {
    fz_set_last_error(errno, 3, "fs.lock failed");
    return -1;
  }
  return 0;
}

int32_t fz_native_fs_atomic_write(int32_t path_id, int32_t body_id) {
  const char* path = fz_lookup_string(path_id);
  const char* payload = fz_lookup_string(body_id);
  if (path == NULL || path[0] == '\0') {
    fz_set_last_error(EINVAL, 3, "fs.atomic_write failed: invalid path");
    return -1;
  }
  if (payload == NULL) {
    payload = "";
  }
  char tmp_path[2048];
  int written = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
  if (written <= 0 || (size_t)written >= sizeof(tmp_path)) {
    fz_set_last_error(ENAMETOOLONG, 3, "fs.atomic_write failed: temp path too long");
    return -1;
  }
  int fd = open(tmp_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
  if (fd < 0) {
    fz_set_last_error(errno, 3, "fs.atomic_write failed: open temp file");
    return -1;
  }
  size_t left = strlen(payload);
  const char* cursor = payload;
  while (left > 0) {
    ssize_t n = write(fd, cursor, left);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      close(fd);
      fz_set_last_error(errno, 3, "fs.atomic_write failed: write temp file");
      return -1;
    }
    if (n == 0) {
      break;
    }
    cursor += n;
    left -= (size_t)n;
  }
  if (fsync(fd) != 0) {
    int err = errno;
    close(fd);
    fz_set_last_error(err, 3, "fs.atomic_write failed: fsync temp file");
    return -1;
  }
  close(fd);
  if (rename(tmp_path, path) != 0) {
    fz_set_last_error(errno, 3, "fs.atomic_write failed: rename temp file");
    return -1;
  }
  return 0;
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
  pthread_mutex_lock(&fz_storage_kv_lock);
  for (int i = 0; i < FZ_MAX_STORAGE_KV; i++) {
    if (!fz_storage_kv[i].in_use) {
      continue;
    }
    const char* existing_path = fz_lookup_string(fz_storage_kv[i].path_id);
    if (existing_path == NULL || strcmp(existing_path, path) != 0) {
      continue;
    }
    int32_t kv_handle = fz_storage_kv_alloc();
    fz_storage_kv_state* kv = fz_storage_kv_get(kv_handle);
    if (kv != NULL) {
      kv->path_id = fz_storage_kv[i].path_id;
      kv->map_handle = fz_storage_kv[i].map_handle;
    }
    pthread_mutex_unlock(&fz_storage_kv_lock);
    return kv == NULL ? -1 : kv_handle;
  }
  pthread_mutex_unlock(&fz_storage_kv_lock);
  int32_t map_handle = fz_runtime_map_new();
  int32_t file_json_id = fz_native_fs_read_file(path_id);
  const char* raw = fz_lookup_string(file_json_id);
  if (raw != NULL && raw[0] != '\0') {
    int32_t parsed_handle = fz_native_json_to_map(file_json_id);
    if (parsed_handle > 0) {
      map_handle = parsed_handle;
    }
  }
  pthread_mutex_lock(&fz_storage_kv_lock);
  int32_t kv_handle = fz_storage_kv_alloc();
  fz_storage_kv_state* kv = fz_storage_kv_get(kv_handle);
  if (kv != NULL) {
    kv->path_id = path_id;
    kv->map_handle = map_handle;
  }
  pthread_mutex_unlock(&fz_storage_kv_lock);
  return kv == NULL ? -1 : kv_handle;
}

int32_t fz_native_storage_kv_close(int32_t kv_handle) {
  pthread_mutex_lock(&fz_storage_kv_lock);
  fz_storage_kv_state* kv = fz_storage_kv_get(kv_handle);
  if (kv == NULL) {
    pthread_mutex_unlock(&fz_storage_kv_lock);
    return -1;
  }
  memset(kv, 0, sizeof(*kv));
  pthread_mutex_unlock(&fz_storage_kv_lock);
  return 0;
}

int32_t fz_native_storage_kv_get(int32_t kv_handle, int32_t key_id) {
  pthread_mutex_lock(&fz_storage_kv_lock);
  fz_storage_kv_state* kv = fz_storage_kv_get(kv_handle);
  if (kv == NULL) {
    pthread_mutex_unlock(&fz_storage_kv_lock);
    return fz_intern_slice("", 0);
  }
  int32_t map_handle = kv->map_handle;
  pthread_mutex_unlock(&fz_storage_kv_lock);
  return fz_runtime_map_get(map_handle, key_id);
}

int32_t fz_native_storage_kv_put(int32_t kv_handle, int32_t key_id, int32_t value_id) {
  pthread_mutex_lock(&fz_storage_kv_lock);
  fz_storage_kv_state* kv = fz_storage_kv_get(kv_handle);
  if (kv == NULL) {
    pthread_mutex_unlock(&fz_storage_kv_lock);
    return -1;
  }
  int32_t path_id = kv->path_id;
  int32_t map_handle = kv->map_handle;
  pthread_mutex_unlock(&fz_storage_kv_lock);
  int rc = fz_runtime_map_set(map_handle, key_id, value_id);
  if (rc != 0) {
    return -1;
  }
  int32_t json_id = fz_native_json_from_map(map_handle);
  const char* path = fz_lookup_string(path_id);
  const char* content = fz_lookup_string(json_id);
  return fz_storage_write_atomic_path(path, content) == 0 ? 0 : -1;
}

static int fz_fs_read_lstat(const char* path, struct stat* st, const char* context) {
  if (path == NULL || path[0] == '\0' || st == NULL) {
    errno = EINVAL;
    fz_set_last_error(EINVAL, 3, context);
    return -1;
  }
  if (lstat(path, st) == 0) {
    return 0;
  }
  fz_set_last_error(errno, 3, context);
  return -1;
}

static char* fz_fs_join_owned(const char* left, const char* right) {
  if (left == NULL) left = "";
  if (right == NULL) right = "";
  size_t left_len = strlen(left);
  size_t right_len = strlen(right);
  int need_sep = left_len > 0 && left[left_len - 1] != '/';
  char* out = (char*)malloc(left_len + right_len + (need_sep ? 2 : 1));
  if (out == NULL) {
    errno = ENOMEM;
    return NULL;
  }
  strcpy(out, left);
  if (need_sep) strcat(out, "/");
  strcat(out, right);
  return out;
}

static int fz_fs_mkdirs_owned(char* path) {
  if (path == NULL || path[0] == '\0') {
    errno = EINVAL;
    return -1;
  }
  size_t len = strlen(path);
  if (len == 0) {
    errno = EINVAL;
    return -1;
  }
  for (size_t i = 1; i < len; i++) {
    if (path[i] != '/') continue;
    path[i] = '\0';
    if (path[0] != '\0' && mkdir(path, 0755) != 0 && errno != EEXIST) {
      path[i] = '/';
      return -1;
    }
    path[i] = '/';
  }
  if (mkdir(path, 0755) != 0 && errno != EEXIST) {
    return -1;
  }
  return 0;
}

static int fz_fs_ensure_parent_dirs(const char* path, const char* context) {
  if (path == NULL || path[0] == '\0') {
    fz_set_last_error(EINVAL, 3, context);
    return -1;
  }
  const char* slash = strrchr(path, '/');
  if (slash == NULL) {
    return 0;
  }
  size_t len = (size_t)(slash - path);
  if (len == 0) {
    return 0;
  }
  char* parent = (char*)malloc(len + 1);
  if (parent == NULL) {
    fz_set_last_error(ENOMEM, 3, context);
    return -1;
  }
  memcpy(parent, path, len);
  parent[len] = '\0';
  int rc = fz_fs_mkdirs_owned(parent);
  if (rc != 0) {
    fz_set_last_error(errno, 3, context);
  }
  free(parent);
  return rc;
}

static int fz_fs_copy_file_path(const char* src, const char* dst, const char* context) {
  struct stat st;
  if (fz_fs_read_lstat(src, &st, context) != 0) {
    return -1;
  }
  if (!S_ISREG(st.st_mode)) {
    fz_set_last_error(EINVAL, 3, context);
    return -1;
  }
  if (fz_fs_ensure_parent_dirs(dst, context) != 0) {
    return -1;
  }
  int in_fd = open(src, O_RDONLY);
  if (in_fd < 0) {
    fz_set_last_error(errno, 3, context);
    return -1;
  }
  int out_fd = open(dst, O_CREAT | O_TRUNC | O_WRONLY, st.st_mode & 0777 ? st.st_mode & 0777 : 0644);
  if (out_fd < 0) {
    close(in_fd);
    fz_set_last_error(errno, 3, context);
    return -1;
  }
  char buf[8192];
  int rc = 0;
  for (;;) {
    ssize_t got = read(in_fd, buf, sizeof(buf));
    if (got == 0) {
      break;
    }
    if (got < 0) {
      if (errno == EINTR) continue;
      rc = -1;
      break;
    }
    char* p = buf;
    ssize_t left = got;
    while (left > 0) {
      ssize_t wrote = write(out_fd, p, (size_t)left);
      if (wrote < 0) {
        if (errno == EINTR) continue;
        rc = -1;
        left = 0;
        break;
      }
      p += wrote;
      left -= wrote;
    }
    if (rc != 0) {
      break;
    }
  }
  if (rc == 0 && fsync(out_fd) != 0) {
    rc = -1;
  }
  int saved_errno = errno;
  close(in_fd);
  close(out_fd);
  if (rc != 0) {
    errno = saved_errno;
    fz_set_last_error(errno, 3, context);
    return -1;
  }
  return 0;
}

static int fz_fs_remove_path(const char* path, const char* context) {
  struct stat st;
  if (fz_fs_read_lstat(path, &st, context) != 0) {
    return -1;
  }
  if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
    DIR* dir = opendir(path);
    if (dir == NULL) {
      fz_set_last_error(errno, 3, context);
      return -1;
    }
    int rc = 0;
    struct dirent* ent = NULL;
    while ((ent = readdir(dir)) != NULL) {
      if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
      char* child = fz_fs_join_owned(path, ent->d_name);
      if (child == NULL) {
        rc = -1;
        break;
      }
      if (fz_fs_remove_path(child, context) != 0) {
        free(child);
        rc = -1;
        break;
      }
      free(child);
    }
    int saved_errno = errno;
    closedir(dir);
    if (rc != 0) {
      errno = saved_errno;
      return -1;
    }
    if (rmdir(path) != 0) {
      fz_set_last_error(errno, 3, context);
      return -1;
    }
    return 0;
  }
  if (unlink(path) != 0) {
    fz_set_last_error(errno, 3, context);
    return -1;
  }
  return 0;
}

static int fz_fs_copy_tree_path(const char* src, const char* dst, const char* context) {
  struct stat st;
  if (fz_fs_read_lstat(src, &st, context) != 0) {
    return -1;
  }
  if (S_ISLNK(st.st_mode)) {
    fz_set_last_error(EINVAL, 3, context);
    return -1;
  }
  if (S_ISREG(st.st_mode)) {
    return fz_fs_copy_file_path(src, dst, context);
  }
  if (!S_ISDIR(st.st_mode)) {
    fz_set_last_error(EINVAL, 3, context);
    return -1;
  }
  char* dst_owned = strdup(dst);
  if (dst_owned == NULL) {
    fz_set_last_error(ENOMEM, 3, context);
    return -1;
  }
  if (fz_fs_mkdirs_owned(dst_owned) != 0) {
    free(dst_owned);
    fz_set_last_error(errno, 3, context);
    return -1;
  }
  free(dst_owned);
  DIR* dir = opendir(src);
  if (dir == NULL) {
    fz_set_last_error(errno, 3, context);
    return -1;
  }
  int rc = 0;
  struct dirent* ent = NULL;
  while ((ent = readdir(dir)) != NULL) {
    if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
    char* src_child = fz_fs_join_owned(src, ent->d_name);
    char* dst_child = fz_fs_join_owned(dst, ent->d_name);
    if (src_child == NULL || dst_child == NULL) {
      free(src_child);
      free(dst_child);
      errno = ENOMEM;
      rc = -1;
      break;
    }
    if (fz_fs_copy_tree_path(src_child, dst_child, context) != 0) {
      free(src_child);
      free(dst_child);
      rc = -1;
      break;
    }
    free(src_child);
    free(dst_child);
  }
  int saved_errno = errno;
  closedir(dir);
  if (rc != 0) {
    errno = saved_errno;
    return -1;
  }
  return 0;
}

static int fz_compare_cstr_ptrs(const void* left, const void* right) {
  const char* const* a = (const char* const*)left;
  const char* const* b = (const char* const*)right;
  const char* av = (a != NULL && *a != NULL) ? *a : "";
  const char* bv = (b != NULL && *b != NULL) ? *b : "";
  return strcmp(av, bv);
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
  return lstat(path, &st) == 0 ? 1 : 0;
}

int32_t fz_native_fs_is_file(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  struct stat st;
  if (fz_fs_read_lstat(path, &st, "fs.is_file failed") != 0) return 0;
  return S_ISREG(st.st_mode) ? 1 : 0;
}

int32_t fz_native_fs_is_dir(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  struct stat st;
  if (fz_fs_read_lstat(path, &st, "fs.is_dir failed") != 0) return 0;
  return S_ISDIR(st.st_mode) ? 1 : 0;
}

int32_t fz_native_fs_is_symlink(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  struct stat st;
  if (fz_fs_read_lstat(path, &st, "fs.is_symlink failed") != 0) return 0;
  return S_ISLNK(st.st_mode) ? 1 : 0;
}

int32_t fz_native_fs_stat_size(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  struct stat st;
  if (fz_fs_read_lstat(path, &st, "fs.stat_size failed") != 0) return -1;
  return (int32_t)st.st_size;
}

int32_t fz_native_fs_stat_mtime(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  struct stat st;
  if (fz_fs_read_lstat(path, &st, "fs.stat_mtime failed") != 0) return -1;
  return (int32_t)st.st_mtime;
}

int32_t fz_native_fs_listdir(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') return -1;
  DIR* dir = opendir(path);
  if (dir == NULL) {
    fz_set_last_error(errno, 3, "fs.listdir failed");
    return -1;
  }
  pthread_mutex_lock(&fz_list_lock);
  int32_t list_handle = fz_list_alloc();
  fz_list_state* list = fz_list_get(list_handle);
  if (list != NULL) {
    struct dirent* ent = NULL;
    while ((ent = readdir(dir)) != NULL) {
      if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
      (void)fz_list_push_cstr(list, ent->d_name);
    }
    if (list->count > 1) {
      qsort(list->items, (size_t)list->count, sizeof(char*), fz_compare_cstr_ptrs);
    }
  }
  pthread_mutex_unlock(&fz_list_lock);
  closedir(dir);
  return list_handle;
}

int32_t fz_native_fs_remove_file(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') return -1;
  return unlink(path) == 0 ? 0 : -1;
}

int32_t fz_native_fs_remove(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  return fz_fs_remove_path(path, "fs.remove failed");
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

int32_t fz_native_fs_copy_file(int32_t src_id, int32_t dst_id) {
  const char* src = fz_lookup_string(src_id);
  const char* dst = fz_lookup_string(dst_id);
  return fz_fs_copy_file_path(src, dst, "fs.copy_file failed");
}

int32_t fz_native_fs_copy_tree(int32_t src_id, int32_t dst_id) {
  const char* src = fz_lookup_string(src_id);
  const char* dst = fz_lookup_string(dst_id);
  return fz_fs_copy_tree_path(src, dst, "fs.copy_tree failed");
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

static const char* fz_path_last_segment(const char* path) {
  const char* last = strrchr(path, '/');
  if (last == NULL) return path;
  if (last[1] == '\0') return last;
  return last + 1;
}

int32_t fz_native_path_basename(int32_t path_id) {
  int32_t normalized_id = fz_native_path_normalize(path_id);
  const char* normalized = fz_lookup_string(normalized_id);
  if (normalized == NULL || normalized[0] == '\0') return fz_intern_slice(".", 1);
  if (strcmp(normalized, "/") == 0) return fz_intern_slice("/", 1);
  const char* base = fz_path_last_segment(normalized);
  if (base[0] == '\0') return fz_intern_slice(".", 1);
  return fz_intern_slice(base, strlen(base));
}

int32_t fz_native_path_dirname(int32_t path_id) {
  int32_t normalized_id = fz_native_path_normalize(path_id);
  const char* normalized = fz_lookup_string(normalized_id);
  if (normalized == NULL || normalized[0] == '\0') return fz_intern_slice(".", 1);
  if (strcmp(normalized, "/") == 0) return fz_intern_slice("/", 1);
  const char* last = strrchr(normalized, '/');
  if (last == NULL) return fz_intern_slice(".", 1);
  if (last == normalized) return fz_intern_slice("/", 1);
  return fz_intern_slice(normalized, (size_t)(last - normalized));
}

int32_t fz_native_path_stem(int32_t path_id) {
  int32_t base_id = fz_native_path_basename(path_id);
  const char* base = fz_lookup_string(base_id);
  if (base == NULL || base[0] == '\0' || strcmp(base, "/") == 0 || strcmp(base, ".") == 0) {
    return fz_intern_slice(base == NULL ? "" : base, base == NULL ? 0 : strlen(base));
  }
  const char* dot = strrchr(base, '.');
  if (dot == NULL || dot == base) return fz_intern_slice(base, strlen(base));
  return fz_intern_slice(base, (size_t)(dot - base));
}

int32_t fz_native_path_extension(int32_t path_id) {
  int32_t base_id = fz_native_path_basename(path_id);
  const char* base = fz_lookup_string(base_id);
  if (base == NULL || base[0] == '\0' || strcmp(base, "/") == 0 || strcmp(base, ".") == 0) {
    return fz_intern_slice("", 0);
  }
  const char* dot = strrchr(base, '.');
  if (dot == NULL || dot == base || dot[1] == '\0') return fz_intern_slice("", 0);
  return fz_intern_slice(dot + 1, strlen(dot + 1));
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
    fz_conn_state_reset_request_body(state);
    fz_conn_state_reset_response_headers(state);
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

static int fz_wait_for_fd_event(int fd, short events, int timeout_ms) {
  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = events;
  pfd.revents = 0;
  for (;;) {
    if (fz_async_current_task_cancelled()) {
      errno = ECANCELED;
      return -1;
    }
    if (fz_async_deadline_expired()) {
      errno = ETIMEDOUT;
      return -1;
    }
    int effective_timeout_ms = fz_async_effective_timeout_ms(timeout_ms);
    int ready = poll(&pfd, 1, effective_timeout_ms);
    if (ready > 0) {
      return 0;
    }
    if (ready == 0) {
      errno = ETIMEDOUT;
      return -1;
    }
    if (errno == EINTR) {
      continue;
    }
    return -1;
  }
}

int32_t fz_native_net_poll_register(int32_t fd) {
  if (fd < 0) {
    fz_set_last_error(EINVAL, 3, "http.poll_register failed: invalid handle");
    return -1;
  }
  pthread_mutex_lock(&fz_net_poll_lock);
  for (int i = 0; i < FZ_MAX_NET_POLL_WATCHES; i++) {
    if (fz_net_poll_watches[i].in_use && fz_net_poll_watches[i].fd == fd) {
      fz_net_poll_watches[i].events = POLLIN;
      pthread_mutex_unlock(&fz_net_poll_lock);
      fz_set_last_error(0, 0, "");
      return 0;
    }
  }
  for (int i = 0; i < FZ_MAX_NET_POLL_WATCHES; i++) {
    if (!fz_net_poll_watches[i].in_use) {
      fz_net_poll_watches[i].in_use = 1;
      fz_net_poll_watches[i].fd = fd;
      fz_net_poll_watches[i].events = POLLIN;
      pthread_mutex_unlock(&fz_net_poll_lock);
      fz_set_last_error(0, 0, "");
      return 0;
    }
  }
  pthread_mutex_unlock(&fz_net_poll_lock);
  fz_set_last_error(ENOSPC, 3, "http.poll_register failed: poll watch queue full");
  return -1;
}

int32_t fz_native_net_read_headers(int32_t conn_fd) {
  if (conn_fd < 0) {
    fz_set_last_error(EINVAL, 3, "http.read_headers failed: invalid connection handle");
    return -1;
  }
  char* req = (char*)malloc(FZ_MAX_HTTP_READ + 1);
  if (req == NULL) {
    fz_set_last_error(ENOMEM, 3, "http.read_headers failed: allocation failed");
    return -1;
  }
  int total = 0;
  int header_end = -1;
  while (total < FZ_MAX_HTTP_READ) {
    ssize_t got = recv(conn_fd, req + total, (size_t)(FZ_MAX_HTTP_READ - total), 0);
    if (got < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        if (fz_wait_for_fd_event(conn_fd, POLLIN, 2500) == 0) {
          continue;
        }
      }
      char msg[256];
      snprintf(
          msg,
          sizeof(msg),
          "http.read_headers failed fd=%d errno=%d (%s)",
          conn_fd,
          errno,
          strerror(errno));
      fz_set_last_error(errno, 3, msg);
      free(req);
      return -1;
    }
    if (got == 0) {
      if (total == 0) {
        fz_set_last_error(
            ECONNRESET,
            3,
            "http.read_headers failed: peer closed before a complete request was received");
        free(req);
        return -1;
      }
      break;
    }
    total += (int)got;
    req[total] = '\0';
    if (header_end < 0) {
      header_end = fz_find_header_end(req, total);
      if (header_end >= 0) {
        break;
      }
    }
  }
  if (header_end < 0) {
    fz_set_last_error(
        EPROTO,
        3,
        "http.read_headers failed: request headers were incomplete or malformed");
    free(req);
    return -1;
  }

  const char* line_end = strstr(req, "\r\n");
  if (line_end == NULL) {
    fz_set_last_error(EPROTO, 3, "http.read_headers failed: missing request line terminator");
    free(req);
    return -1;
  }
  const char* sp1 = memchr(req, ' ', (size_t)(line_end - req));
  if (sp1 == NULL) {
    fz_set_last_error(EPROTO, 3, "http.read_headers failed: malformed request method/path");
    free(req);
    return -1;
  }
  const char* sp2 = memchr(sp1 + 1, ' ', (size_t)(line_end - (sp1 + 1)));
  if (sp2 == NULL) {
    fz_set_last_error(EPROTO, 3, "http.read_headers failed: malformed request path/version");
    free(req);
    return -1;
  }

  size_t method_len = (size_t)(sp1 - req);
  size_t path_len = (size_t)(sp2 - (sp1 + 1));
  const char* version = sp2 + 1;
  int version_len = (int)(line_end - version);
  const char* raw_path = sp1 + 1;
  const char* query_mark = memchr(raw_path, '?', path_len);
  size_t clean_path_len = query_mark == NULL ? path_len : (size_t)(query_mark - raw_path);

  int32_t method_id = fz_intern_slice(req, method_len);
  int32_t path_id = fz_intern_slice(raw_path, clean_path_len);
  int keep_alive = fz_parse_keep_alive(req, header_end, version, version_len);
  int64_t content_length = fz_parse_content_length(req, header_end);
  int chunked = fz_parse_chunked_flag(req, header_end);
  size_t prefetched_body_len = total > header_end ? (size_t)(total - header_end) : 0;

  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 1);
  if (state != NULL) {
    fz_conn_state_reset_request_body(state);
    fz_conn_state_reset_response_headers(state);
    state->method_id = method_id;
    state->path_id = path_id;
    state->keep_alive = keep_alive;
    state->header_count = 0;
    state->query_count = 0;
    state->param_count = 0;
    state->request_headers_ready = 1;
    state->request_body_active = 1;
    if (chunked) {
      state->request_body_mode = 2;
      state->request_body_remaining = -1;
      state->request_chunk_remaining = 0;
      state->request_body_eof = 0;
    } else if (content_length > 0) {
      state->request_body_mode = 1;
      state->request_body_remaining = content_length;
      state->request_chunk_remaining = 0;
      state->request_body_eof = 0;
    } else {
      state->request_body_mode = 0;
      state->request_body_remaining = 0;
      state->request_chunk_remaining = 0;
      state->request_body_eof = 1;
    }
    state->request_meta_buf = req;
    state->request_meta_len = (size_t)total;
    if (prefetched_body_len > 0) {
      state->request_body_buf = (char*)malloc(prefetched_body_len + 1);
      if (state->request_body_buf != NULL) {
        memcpy(state->request_body_buf, req + header_end, prefetched_body_len);
        state->request_body_buf[prefetched_body_len] = '\0';
        state->request_body_buf_len = prefetched_body_len;
        state->request_body_buf_pos = 0;
      }
    }
    if (state->request_body_mode == 1 && state->request_body_remaining >= 0) {
      state->request_body_remaining -= (int64_t)prefetched_body_len;
      if (state->request_body_remaining <= 0) {
        state->request_body_remaining = 0;
        state->request_body_eof = 1;
      }
    }
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
        state->header_key_offsets[state->header_count] = (uint32_t)(cursor - req);
        state->header_key_lens[state->header_count] = (uint32_t)(colon - cursor);
        state->header_value_offsets[state->header_count] = (uint32_t)(v - req);
        state->header_value_lens[state->header_count] = (uint32_t)(next - v);
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
          state->query_key_offsets[state->query_count] = (uint32_t)(q - req);
          state->query_key_lens[state->query_count] = (uint32_t)(token_end - q);
          state->query_value_offsets[state->query_count] = 0;
          state->query_value_lens[state->query_count] = 0;
          state->query_count++;
        } else {
          state->query_key_offsets[state->query_count] = (uint32_t)(q - req);
          state->query_key_lens[state->query_count] = (uint32_t)(eq - q);
          state->query_value_offsets[state->query_count] = (uint32_t)((eq + 1) - req);
          state->query_value_lens[state->query_count] = (uint32_t)(token_end - (eq + 1));
          state->query_count++;
        }
        if (amp == NULL) break;
        q = amp + 1;
      }
    }
  }
  pthread_mutex_unlock(&fz_conn_lock);

  fz_set_last_error(0, 0, "");
  if (state == NULL) {
    free(req);
  }
  return 0;
}

int32_t fz_native_net_read(int32_t conn_fd) {
  if (fz_native_net_read_headers(conn_fd) != 0) {
    return -1;
  }
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    fz_set_last_error(EINVAL, 3, "http.read failed: connection state unavailable");
    return -1;
  }
  fz_bytes_buf body;
  fz_bytes_buf_init(&body);
  size_t prefetched = state->request_body_buf_len - state->request_body_buf_pos;
  if (state->request_body_mode == 1 && prefetched > 0 && state->request_body_remaining <= 0) {
    state->request_body_remaining = (int64_t)prefetched;
    state->request_body_eof = 0;
  }
  while (!state->request_body_eof) {
    char* chunk = NULL;
    size_t chunk_len = 0;
    int rc = fz_conn_read_body_chunk(state, &chunk, &chunk_len, 4096);
    if (rc < 0) {
      if (chunk != NULL) {
        free(chunk);
      }
      fz_bytes_buf_free(&body);
      pthread_mutex_unlock(&fz_conn_lock);
      fz_set_last_error(EIO, 3, "http.read failed while streaming request body");
      return -1;
    }
    if (chunk != NULL) {
      if (fz_bytes_buf_append(&body, chunk, chunk_len) != 0) {
        free(chunk);
        fz_bytes_buf_free(&body);
        pthread_mutex_unlock(&fz_conn_lock);
        fz_set_last_error(ENOMEM, 3, "http.read failed buffering request body");
        return -1;
      }
      free(chunk);
    }
    if (rc > 0) {
      break;
    }
  }
  state->body_id = fz_intern_slice(body.data == NULL ? "" : body.data, body.len);
  state->request_body_fully_buffered = 1;
  state->request_body_active = 0;
  fz_bytes_buf_free(&body);
  pthread_mutex_unlock(&fz_conn_lock);
  fz_set_last_error(0, 0, "");
  return 0;
}

int32_t fz_native_net_poll_next(void) {
  struct pollfd pfds[FZ_MAX_NET_POLL_WATCHES];
  int slots[FZ_MAX_NET_POLL_WATCHES];
  int count = 0;
  pthread_mutex_lock(&fz_net_poll_lock);
  for (int i = 0; i < FZ_MAX_NET_POLL_WATCHES; i++) {
    if (!fz_net_poll_watches[i].in_use) {
      continue;
    }
    pfds[count].fd = fz_net_poll_watches[i].fd;
    pfds[count].events = fz_net_poll_watches[i].events | POLLERR | POLLHUP;
    pfds[count].revents = 0;
    slots[count] = i;
    count++;
  }
  pthread_mutex_unlock(&fz_net_poll_lock);

  if (count == 0) {
    fz_set_last_error(EINVAL, 3, "http.poll_next failed: no registered sockets");
    return -1;
  }

  for (;;) {
    int ready = poll(pfds, (nfds_t)count, 2500);
    if (ready > 0) {
      for (int i = 0; i < count; i++) {
        if (pfds[i].revents == 0) {
          continue;
        }
        int fd = pfds[i].fd;
        pthread_mutex_lock(&fz_net_poll_lock);
        fz_net_poll_watches[slots[i]].in_use = 0;
        fz_net_poll_watches[slots[i]].fd = -1;
        fz_net_poll_watches[slots[i]].events = 0;
        pthread_mutex_unlock(&fz_net_poll_lock);
        fz_set_last_error(0, 0, "");
        return fd;
      }
      fz_set_last_error(EIO, 3, "http.poll_next failed: poll reported readiness without events");
      return -1;
    }
    if (ready == 0) {
      fz_set_last_error(ETIMEDOUT, 3, "http.poll_next timed out waiting for socket readiness");
      return -1;
    }
    if (errno == EINTR) {
      continue;
    }
    char msg[256];
    snprintf(msg, sizeof(msg), "http.poll_next failed errno=%d (%s)", errno, strerror(errno));
    fz_set_last_error(errno, 3, msg);
    return -1;
  }
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

int32_t fz_native_net_body_read(int32_t conn_fd, int32_t max_bytes) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return fz_intern_slice("", 0);
  }
  size_t prefetched = state->request_body_buf_len - state->request_body_buf_pos;
  if (state->request_body_mode == 1 && prefetched > 0 && state->request_body_remaining <= 0) {
    state->request_body_remaining = (int64_t)prefetched;
    state->request_body_eof = 0;
  }
  if (state->request_body_fully_buffered) {
    const char* body = fz_lookup_string(state->body_id);
    if (body == NULL) {
      pthread_mutex_unlock(&fz_conn_lock);
      return fz_intern_slice("", 0);
    }
    size_t total = strlen(body);
    size_t start = state->request_body_buf_pos;
    if (start >= total || max_bytes <= 0) {
      state->request_body_eof = 1;
      pthread_mutex_unlock(&fz_conn_lock);
      return fz_intern_slice("", 0);
    }
    size_t take = (size_t)max_bytes;
    if (take > total - start) {
      take = total - start;
    }
    state->request_body_buf_pos += take;
    if (state->request_body_buf_pos >= total) {
      state->request_body_eof = 1;
    }
    int32_t out = fz_intern_slice(body + start, take);
    pthread_mutex_unlock(&fz_conn_lock);
    return out;
  }
  char* chunk = NULL;
  size_t chunk_len = 0;
  int rc = fz_conn_read_body_chunk(state, &chunk, &chunk_len, max_bytes);
  if (rc < 0) {
    pthread_mutex_unlock(&fz_conn_lock);
    if (chunk != NULL) {
      free(chunk);
    }
    return fz_intern_slice("", 0);
  }
  int32_t out = fz_intern_slice(chunk == NULL ? "" : chunk, chunk_len);
  if (chunk != NULL) {
    free(chunk);
  }
  pthread_mutex_unlock(&fz_conn_lock);
  return out;
}

int32_t fz_native_net_body_eof(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  int32_t value = (state == NULL || state->request_body_eof) ? 1 : 0;
  pthread_mutex_unlock(&fz_conn_lock);
  return value;
}

int32_t fz_native_net_body_discard(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  int rc = state == NULL ? -1 : fz_conn_discard_body(state);
  pthread_mutex_unlock(&fz_conn_lock);
  return rc;
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
    if (fz_conn_state_meta_key_eq(
            state,
            state->header_key_offsets[i],
            state->header_key_lens[i],
            key,
            1)) {
      int32_t value = fz_conn_state_intern_meta_slice(
          state, state->header_value_offsets[i], state->header_value_lens[i]);
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
    if (fz_conn_state_meta_key_eq(
            state,
            state->query_key_offsets[i],
            state->query_key_lens[i],
            key,
            0)) {
      int32_t value = fz_conn_state_intern_meta_slice(
          state, state->query_value_offsets[i], state->query_value_lens[i]);
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
  pthread_mutex_lock(&fz_list_lock);
  int32_t list_handle = fz_list_alloc();
  fz_list_state* list = fz_list_get(list_handle);
  if (list != NULL) {
    for (int i = 0; i < state->header_count; i++) {
      size_t key_len = 0;
      size_t value_len = 0;
      const char* k = fz_conn_state_meta_slice_ptr(
          state, state->header_key_offsets[i], state->header_key_lens[i], &key_len);
      const char* v = fz_conn_state_meta_slice_ptr(
          state, state->header_value_offsets[i], state->header_value_lens[i], &value_len);
      size_t n = key_len + value_len + 2;
      char* kv = (char*)malloc(n);
      if (kv == NULL) continue;
      if (key_len > 0) memcpy(kv, k, key_len);
      kv[key_len] = ':';
      if (value_len > 0) memcpy(kv + key_len + 1, v, value_len);
      kv[key_len + value_len + 1] = '\0';
      (void)fz_list_push_cstr(list, kv);
      free(kv);
    }
  }
  pthread_mutex_unlock(&fz_list_lock);
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

int32_t fz_native_net_response_header_set(int32_t conn_fd, int32_t key_id, int32_t value_id) {
  const char* key = fz_lookup_string(key_id);
  if (key == NULL || key[0] == '\0') {
    return -1;
  }
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return -1;
  }
  for (int i = 0; i < state->response_header_count; i++) {
    const char* existing = fz_lookup_string(state->response_header_key_ids[i]);
    if (existing != NULL && strcasecmp(existing, key) == 0) {
      state->response_header_value_ids[i] = value_id;
      pthread_mutex_unlock(&fz_conn_lock);
      return 0;
    }
  }
  if (state->response_header_count >= FZ_MAX_CONN_META) {
    pthread_mutex_unlock(&fz_conn_lock);
    return -1;
  }
  state->response_header_key_ids[state->response_header_count] = key_id;
  state->response_header_value_ids[state->response_header_count] = value_id;
  state->response_header_count++;
  pthread_mutex_unlock(&fz_conn_lock);
  return 0;
}

int32_t fz_native_net_response_header_add(int32_t conn_fd, int32_t key_id, int32_t value_id) {
  const char* key = fz_lookup_string(key_id);
  if (key == NULL || key[0] == '\0') {
    return -1;
  }
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL || state->response_header_count >= FZ_MAX_CONN_META) {
    pthread_mutex_unlock(&fz_conn_lock);
    return -1;
  }
  state->response_header_key_ids[state->response_header_count] = key_id;
  state->response_header_value_ids[state->response_header_count] = value_id;
  state->response_header_count++;
  pthread_mutex_unlock(&fz_conn_lock);
  return 0;
}

int32_t fz_native_net_response_header_clear(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state != NULL) {
    fz_conn_state_reset_response_headers(state);
  }
  pthread_mutex_unlock(&fz_conn_lock);
  return 0;
}

int32_t fz_native_net_websocket_accept(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return -1;
  }
  const char* upgrade = "";
  size_t upgrade_len = 0;
  const char* connection = "";
  size_t connection_len = 0;
  const char* ws_key = "";
  size_t ws_key_len = 0;
  const char* ws_version = "";
  size_t ws_version_len = 0;
  for (int i = 0; i < state->header_count; i++) {
    size_t value_len = 0;
    const char* value = fz_conn_state_meta_slice_ptr(
        state, state->header_value_offsets[i], state->header_value_lens[i], &value_len);
    if (fz_conn_state_meta_key_eq(
            state,
            state->header_key_offsets[i],
            state->header_key_lens[i],
            "upgrade",
            1)) {
      upgrade = value;
      upgrade_len = value_len;
    } else if (fz_conn_state_meta_key_eq(
                   state,
                   state->header_key_offsets[i],
                   state->header_key_lens[i],
                   "connection",
                   1)) {
      connection = value;
      connection_len = value_len;
    } else if (fz_conn_state_meta_key_eq(
                   state,
                   state->header_key_offsets[i],
                   state->header_key_lens[i],
                   "sec-websocket-key",
                   1)) {
      ws_key = value;
      ws_key_len = value_len;
    } else if (fz_conn_state_meta_key_eq(
                   state,
                   state->header_key_offsets[i],
                   state->header_key_lens[i],
                   "sec-websocket-version",
                   1)) {
      ws_version = value;
      ws_version_len = value_len;
    }
  }
  if (upgrade == NULL || upgrade_len != 9 || strncasecmp(upgrade, "websocket", upgrade_len) != 0
      || connection == NULL || fz_contains_ci(connection, connection_len, "upgrade") == 0
      || ws_key == NULL || ws_key_len == 0
      || ws_version == NULL || ws_version_len != 2 || strncmp(ws_version, "13", ws_version_len) != 0) {
    pthread_mutex_unlock(&fz_conn_lock);
    return -1;
  }
  const char* guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  size_t guid_len = strlen(guid);
  size_t concat_len = ws_key_len + guid_len;
  char* concat = (char*)malloc(concat_len + 1);
  if (concat == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return -1;
  }
  memcpy(concat, ws_key, ws_key_len);
  memcpy(concat + ws_key_len, guid, guid_len);
  concat[concat_len] = '\0';
  uint8_t digest[20];
  fz_sha1_compute((const uint8_t*)concat, concat_len, digest);
  free(concat);
  char* accept_value = fz_base64_encode(digest, sizeof(digest));
  if (accept_value == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return -1;
  }
  if (state->response_header_count + 3 <= FZ_MAX_CONN_META) {
    state->response_header_key_ids[state->response_header_count] = fz_intern_slice("Upgrade", 7);
    state->response_header_value_ids[state->response_header_count] = fz_intern_slice("websocket", 9);
    state->response_header_count++;
    state->response_header_key_ids[state->response_header_count] = fz_intern_slice("Connection", 10);
    state->response_header_value_ids[state->response_header_count] = fz_intern_slice("Upgrade", 7);
    state->response_header_count++;
    state->response_header_key_ids[state->response_header_count] = fz_intern_slice("Sec-WebSocket-Accept", 20);
    state->response_header_value_ids[state->response_header_count] = fz_intern_slice(accept_value, strlen(accept_value));
    state->response_header_count++;
  }
  free(accept_value);
  int rc = fz_send_http_response_state(state, 101, "", "", 0);
  if (rc != 0) {
    pthread_mutex_unlock(&fz_conn_lock);
    return -1;
  }
  int32_t handle = fz_websocket_state_alloc(conn_fd);
  pthread_mutex_unlock(&fz_conn_lock);
  return handle;
}

int32_t fz_native_net_websocket_read(int32_t ws_handle, int32_t max_bytes) {
  fz_websocket_state* ws = fz_websocket_state_get(ws_handle);
  if (ws == NULL) {
    return fz_intern_slice("", 0);
  }
  int32_t kind_id = 0;
  int32_t close_code = 0;
  int32_t error_id = 0;
  int32_t payload_id = fz_websocket_read_frame(ws, max_bytes, &kind_id, &close_code, &error_id);
  ws->last_kind_id = kind_id;
  ws->close_code = close_code;
  ws->last_error_id = error_id;
  return payload_id;
}

int32_t fz_native_net_websocket_kind(int32_t ws_handle) {
  fz_websocket_state* ws = fz_websocket_state_get(ws_handle);
  return ws == NULL ? fz_intern_slice("error", 5) : ws->last_kind_id;
}

int32_t fz_native_net_websocket_close_code(int32_t ws_handle) {
  fz_websocket_state* ws = fz_websocket_state_get(ws_handle);
  return ws == NULL ? 0 : ws->close_code;
}

int32_t fz_native_net_websocket_error(int32_t ws_handle) {
  fz_websocket_state* ws = fz_websocket_state_get(ws_handle);
  return ws == NULL ? fz_intern_slice("websocket not found", 19) : ws->last_error_id;
}

int32_t fz_native_net_websocket_write_text(int32_t ws_handle, int32_t payload_id) {
  fz_websocket_state* ws = fz_websocket_state_get(ws_handle);
  const char* payload = fz_lookup_string(payload_id);
  return ws == NULL ? -1 : fz_websocket_write_frame(ws->fd, 0x1u, payload, strlen(payload == NULL ? "" : payload));
}

int32_t fz_native_net_websocket_write_binary(int32_t ws_handle, int32_t payload_id) {
  fz_websocket_state* ws = fz_websocket_state_get(ws_handle);
  const char* payload = fz_lookup_string(payload_id);
  return ws == NULL ? -1 : fz_websocket_write_frame(ws->fd, 0x2u, payload, strlen(payload == NULL ? "" : payload));
}

int32_t fz_native_net_websocket_ping(int32_t ws_handle, int32_t payload_id) {
  fz_websocket_state* ws = fz_websocket_state_get(ws_handle);
  const char* payload = fz_lookup_string(payload_id);
  return ws == NULL ? -1 : fz_websocket_write_frame(ws->fd, 0x9u, payload, strlen(payload == NULL ? "" : payload));
}

int32_t fz_native_net_websocket_pong(int32_t ws_handle, int32_t payload_id) {
  fz_websocket_state* ws = fz_websocket_state_get(ws_handle);
  const char* payload = fz_lookup_string(payload_id);
  return ws == NULL ? -1 : fz_websocket_write_frame(ws->fd, 0xAu, payload, strlen(payload == NULL ? "" : payload));
}

int32_t fz_native_net_websocket_close(int32_t ws_handle, int32_t code, int32_t reason_id) {
  fz_websocket_state* ws = fz_websocket_state_get(ws_handle);
  if (ws == NULL) {
    return -1;
  }
  const char* reason = fz_lookup_string(reason_id);
  size_t reason_len = strlen(reason == NULL ? "" : reason);
  char* payload = (char*)malloc(reason_len + 2);
  if (payload == NULL) {
    return -1;
  }
  payload[0] = (char)((code >> 8) & 0xFF);
  payload[1] = (char)(code & 0xFF);
  if (reason_len > 0) {
    memcpy(payload + 2, reason, reason_len);
  }
  int rc = fz_websocket_write_frame(ws->fd, 0x8u, payload, reason_len + 2);
  free(payload);
  ws->closed = 1;
  return rc;
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
  for (int i = 0; i < FZ_MAX_WEBSOCKETS; i++) {
    if (fz_websocket_states[i].in_use && fz_websocket_states[i].fd == fd) {
      memset(&fz_websocket_states[i], 0, sizeof(fz_websocket_states[i]));
    }
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
