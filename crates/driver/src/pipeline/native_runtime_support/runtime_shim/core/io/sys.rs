pub(super) fn section() -> &'static str {
    r#"
static int32_t fz_exit_class_from_status(int timed_out, int status, int spawn_error) {
  if (spawn_error) {
    return 3;
  }
  if (timed_out) {
    return 2;
  }
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status) == 0 ? 0 : 1;
  }
  if (WIFSIGNALED(status)) {
    return 1;
  }
  return 1;
}

static const char* fz_fs_path(void) {
  if (fz_fs_base_path[0] != '\0') {
    return fz_fs_base_path;
  }
  const char* from_env = getenv("FZ_FS_PATH");
  if (from_env == NULL || from_env[0] == '\0') {
    from_env = "/tmp/fozzy_native_store.dat";
  }
  snprintf(fz_fs_base_path, sizeof(fz_fs_base_path), "%s", from_env);
  snprintf(fz_fs_tmp_path, sizeof(fz_fs_tmp_path), "%s.tmp", from_env);
  return fz_fs_base_path;
}

static int fz_fs_ensure_open(void) {
  if (fz_fs_fd >= 0) {
    return fz_fs_fd;
  }
  const char* path = fz_fs_path();
  int fd = open(path, O_CREAT | O_RDWR, 0644);
  if (fd < 0) {
    return -1;
  }
  (void)fz_mark_cloexec(fd);
  fz_fs_fd = fd;
  return fd;
}

static void fz_http_headers_clear(void) {
  pthread_mutex_lock(&fz_http_lock);
  fz_http_header_count = 0;
  pthread_mutex_unlock(&fz_http_lock);
}

static void fz_conn_state_reset_request_body(fz_conn_state* state) {
  if (state == NULL) {
    return;
  }
  if (state->request_meta_buf != NULL) {
    free(state->request_meta_buf);
  }
  state->request_meta_buf = NULL;
  state->request_meta_len = 0;
  if (state->request_body_buf != NULL) {
    free(state->request_body_buf);
  }
  state->request_body_buf = NULL;
  state->request_body_buf_len = 0;
  state->request_body_buf_pos = 0;
  state->header_count = 0;
  state->query_count = 0;
  state->request_headers_ready = 0;
  state->request_body_mode = 0;
  state->request_body_eof = 1;
  state->request_body_fully_buffered = 0;
  state->request_body_active = 0;
  state->request_body_remaining = 0;
  state->request_chunk_remaining = 0;
  state->body_id = 0;
}

static void fz_conn_state_reset_response_headers(fz_conn_state* state) {
  if (state == NULL) {
    return;
  }
  state->response_header_count = 0;
}

static const char* fz_conn_state_meta_slice_ptr(fz_conn_state* state, uint32_t offset, uint32_t len, size_t* out_len) {
  if (out_len != NULL) {
    *out_len = 0;
  }
  if (state == NULL || state->request_meta_buf == NULL) {
    return "";
  }
  size_t start = (size_t)offset;
  size_t width = (size_t)len;
  if (start > state->request_meta_len || width > (state->request_meta_len - start)) {
    return "";
  }
  if (out_len != NULL) {
    *out_len = width;
  }
  return state->request_meta_buf + start;
}

static int32_t fz_conn_state_intern_meta_slice(fz_conn_state* state, uint32_t offset, uint32_t len) {
  size_t slice_len = 0;
  const char* slice = fz_conn_state_meta_slice_ptr(state, offset, len, &slice_len);
  return fz_intern_slice(slice, slice_len);
}

static int fz_conn_state_meta_key_eq(fz_conn_state* state, uint32_t offset, uint32_t len, const char* key, int case_insensitive) {
  size_t slice_len = 0;
  const char* slice = fz_conn_state_meta_slice_ptr(state, offset, len, &slice_len);
  if (key == NULL) {
    return slice_len == 0 ? 1 : 0;
  }
  size_t key_len = strlen(key);
  if (slice_len != key_len) {
    return 0;
  }
  return case_insensitive ? strncasecmp(slice, key, slice_len) == 0 : strncmp(slice, key, slice_len) == 0;
}

"#
}
