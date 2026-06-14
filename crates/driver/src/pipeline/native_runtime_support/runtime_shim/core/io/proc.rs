pub(super) fn section() -> &'static str {
    r#"
static void fz_bytes_buf_init(fz_bytes_buf* buf) {
  buf->data = NULL;
  buf->len = 0;
  buf->cap = 0;
}

static void fz_bytes_buf_free(fz_bytes_buf* buf) {
  if (buf->data != NULL) {
    free(buf->data);
  }
  buf->data = NULL;
  buf->len = 0;
  buf->cap = 0;
}

static int fz_bytes_buf_append(fz_bytes_buf* buf, const char* data, size_t len) {
  if (len == 0) {
    return 0;
  }
  size_t needed = buf->len + len + 1;
  if (needed > buf->cap) {
    size_t next_cap = buf->cap == 0 ? 4096 : buf->cap;
    while (next_cap < needed) {
      next_cap *= 2;
    }
    char* next = (char*)realloc(buf->data, next_cap);
    if (next == NULL) {
      return -1;
    }
    buf->data = next;
    buf->cap = next_cap;
  }
  memcpy(buf->data + buf->len, data, len);
  buf->len += len;
  buf->data[buf->len] = '\0';
  return 0;
}

static int fz_drain_fd(int fd, fz_bytes_buf* buf) {
  if (fd < 0) {
    return 0;
  }
  char tmp[4096];
  for (;;) {
    ssize_t got = read(fd, tmp, sizeof(tmp));
    if (got > 0) {
      if (fz_bytes_buf_append(buf, tmp, (size_t)got) != 0) {
        return -1;
      }
      continue;
    }
    if (got == 0) {
      return 1;
    }
    if (errno == EINTR) {
      continue;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return 0;
    }
    return -1;
  }
}

static int fz_set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int fz_mark_cloexec(int fd) {
  int flags = fcntl(fd, F_GETFD, 0);
  if (flags < 0) {
    return -1;
  }
  return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static fz_proc_state* fz_proc_state_get(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_PROC_STATES) {
    return NULL;
  }
  fz_proc_state* state = &fz_proc_states[handle - 1];
  if (!state->in_use) {
    return NULL;
  }
  return state;
}

static fz_http_stream_state* fz_http_stream_state_get(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_HTTP_STREAMS) {
    return NULL;
  }
  fz_http_stream_state* state = &fz_http_stream_states[handle - 1];
  if (!state->in_use) {
    return NULL;
  }
  return state;
}

static void fz_proc_set_last_error(const char* msg) {
  if (msg == NULL) {
    msg = "proc error";
  }
  fz_proc_last_error_id = fz_intern_slice(msg, strlen(msg));
}

static int32_t fz_proc_state_alloc(pid_t pid, int stdout_fd, int stderr_fd) {
  for (int i = 0; i < FZ_MAX_PROC_STATES; i++) {
    if (!fz_proc_states[i].in_use) {
      fz_proc_states[i].in_use = 1;
      fz_proc_states[i].pid = pid;
      fz_proc_states[i].stdout_fd = stdout_fd;
      fz_proc_states[i].stderr_fd = stderr_fd;
      fz_proc_states[i].done = 0;
      fz_proc_states[i].exit_notified = 0;
      fz_proc_states[i].exit_code = -1;
      fz_proc_states[i].stdout_read_pos = 0;
      fz_proc_states[i].stderr_read_pos = 0;
      fz_proc_states[i].stdout_id = 0;
      fz_proc_states[i].stderr_id = 0;
      fz_bytes_buf_init(&fz_proc_states[i].stdout_buf);
      fz_bytes_buf_init(&fz_proc_states[i].stderr_buf);
      return i + 1;
    }
  }
  return -1;
}

static int32_t fz_http_stream_state_alloc(pid_t pid, int stdout_fd, int stderr_fd, int32_t status_code) {
  for (int i = 0; i < FZ_MAX_HTTP_STREAMS; i++) {
    if (!fz_http_stream_states[i].in_use) {
      memset(&fz_http_stream_states[i], 0, sizeof(fz_http_stream_states[i]));
      fz_http_stream_states[i].in_use = 1;
      fz_http_stream_states[i].pid = pid;
      fz_http_stream_states[i].stdout_fd = stdout_fd;
      fz_http_stream_states[i].stderr_fd = stderr_fd;
      fz_http_stream_states[i].done = 0;
      fz_http_stream_states[i].eof = 0;
      fz_http_stream_states[i].closed = 0;
      fz_http_stream_states[i].exit_code = -1;
      fz_http_stream_states[i].status_code = status_code;
      fz_http_stream_states[i].error_id = fz_intern_slice("", 0);
      fz_http_stream_states[i].stdout_read_pos = 0;
      fz_bytes_buf_init(&fz_http_stream_states[i].stdout_buf);
      fz_bytes_buf_init(&fz_http_stream_states[i].stderr_buf);
      return i + 1;
    }
  }
  return -1;
}

static fz_websocket_state* fz_websocket_state_get(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_WEBSOCKETS) {
    return NULL;
  }
  fz_websocket_state* state = &fz_websocket_states[handle - 1];
  return state->in_use ? state : NULL;
}

static int32_t fz_websocket_state_alloc(int fd) {
  for (int i = 0; i < FZ_MAX_WEBSOCKETS; i++) {
    if (!fz_websocket_states[i].in_use) {
      memset(&fz_websocket_states[i], 0, sizeof(fz_websocket_states[i]));
      fz_websocket_states[i].in_use = 1;
      fz_websocket_states[i].fd = fd;
      fz_websocket_states[i].last_kind_id = fz_intern_slice("open", 4);
      fz_websocket_states[i].last_error_id = fz_intern_slice("", 0);
      return i + 1;
    }
  }
  return -1;
}

"#
}
