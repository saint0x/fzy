pub(super) fn section() -> &'static str {
    r#"
static void fz_http_set_last_result(int status_code, const char* body, const char* err) {
  if (body == NULL) {
    body = "";
  }
  if (err == NULL) {
    err = "";
  }
  pthread_mutex_lock(&fz_http_lock);
  fz_http_last_status = status_code;
  fz_http_last_body_id = fz_intern_slice(body, strlen(body));
  fz_http_last_error_id = fz_intern_slice(err, strlen(err));
  pthread_mutex_unlock(&fz_http_lock);
}

static int fz_http_extract_status(char* payload, size_t payload_len, int* status_code, size_t* body_len) {
  if (status_code != NULL) {
    *status_code = 0;
  }
  if (body_len != NULL) {
    *body_len = payload_len;
  }
  if (payload == NULL || payload_len == 0) {
    return -1;
  }
  ssize_t i = (ssize_t)payload_len - 1;
  while (i >= 0 && (payload[i] == '\n' || payload[i] == '\r' || payload[i] == ' ' || payload[i] == '\t')) {
    i--;
  }
  if (i < 2) {
    return -1;
  }
  if (!isdigit((unsigned char)payload[i]) || !isdigit((unsigned char)payload[i - 1]) || !isdigit((unsigned char)payload[i - 2])) {
    return -1;
  }
  int parsed = (payload[i - 2] - '0') * 100 + (payload[i - 1] - '0') * 10 + (payload[i] - '0');
  ssize_t j = i - 3;
  while (j >= 0 && (payload[j] == '\n' || payload[j] == '\r')) {
    j--;
  }
  if (status_code != NULL) {
    *status_code = parsed;
  }
  if (body_len != NULL) {
    *body_len = (size_t)(j + 1);
  }
  return 0;
}

static int fz_http_parse_status_line(const char* header_block, size_t header_len) {
  if (header_block == NULL || header_len == 0) {
    return 0;
  }
  const char* line_end = NULL;
  for (size_t i = 0; i + 1 < header_len; i++) {
    if (header_block[i] == '\r' && header_block[i + 1] == '\n') {
      line_end = header_block + i;
      break;
    }
  }
  if (line_end == NULL) {
    return 0;
  }
  const char* first_space = memchr(header_block, ' ', (size_t)(line_end - header_block));
  if (first_space == NULL || (line_end - first_space) < 4) {
    return 0;
  }
  if (!isdigit((unsigned char)first_space[1]) || !isdigit((unsigned char)first_space[2])
      || !isdigit((unsigned char)first_space[3])) {
    return 0;
  }
  return (first_space[1] - '0') * 100 + (first_space[2] - '0') * 10 + (first_space[3] - '0');
}

static void fz_bytes_buf_consume_prefix(fz_bytes_buf* buf, size_t count) {
  if (buf == NULL || count == 0) {
    return;
  }
  if (count >= buf->len) {
    buf->len = 0;
    if (buf->data != NULL) {
      buf->data[0] = '\0';
    }
    return;
  }
  memmove(buf->data, buf->data + count, buf->len - count);
  buf->len -= count;
  buf->data[buf->len] = '\0';
}

static int fz_http_stream_read_response_headers(
    int stdout_fd,
    fz_bytes_buf* body_buf,
    int* status_code_out) {
  if (status_code_out != NULL) {
    *status_code_out = 0;
  }
  fz_bytes_buf scratch;
  fz_bytes_buf_init(&scratch);
  for (;;) {
    for (size_t i = 0; i + 3 < scratch.len; i++) {
      if (scratch.data[i] == '\r' && scratch.data[i + 1] == '\n' && scratch.data[i + 2] == '\r'
          && scratch.data[i + 3] == '\n') {
        size_t header_len = i + 4;
        int status = fz_http_parse_status_line(scratch.data, header_len);
        if (status > 0 && status < 200 && status != 101) {
          fz_bytes_buf_consume_prefix(&scratch, header_len);
          break;
        }
        if (status_code_out != NULL) {
          *status_code_out = status;
        }
        if (scratch.len > header_len) {
          if (fz_bytes_buf_append(body_buf, scratch.data + header_len, scratch.len - header_len)
              != 0) {
            fz_bytes_buf_free(&scratch);
            return -1;
          }
        }
        fz_bytes_buf_free(&scratch);
        return status > 0 ? 0 : -1;
      }
    }

    char tmp[4096];
    ssize_t got = read(stdout_fd, tmp, sizeof(tmp));
    if (got > 0) {
      if (fz_bytes_buf_append(&scratch, tmp, (size_t)got) != 0) {
        fz_bytes_buf_free(&scratch);
        return -1;
      }
      continue;
    }
    if (got == 0) {
      fz_bytes_buf_free(&scratch);
      return -1;
    }
    if (errno == EINTR) {
      continue;
    }
    fz_bytes_buf_free(&scratch);
    return -1;
  }
}

static void fz_http_stream_refresh_error_locked(fz_http_stream_state* state, const char* fallback) {
  if (state == NULL) {
    return;
  }
  const char* msg = fallback == NULL ? "" : fallback;
  if (state->stderr_buf.data != NULL && state->stderr_buf.len > 0) {
    msg = state->stderr_buf.data;
  }
  state->error_id = fz_intern_slice(msg, strlen(msg));
}

static void fz_http_stream_compact_stdout_locked(fz_http_stream_state* state) {
  if (state == NULL || state->stdout_read_pos == 0) {
    return;
  }
  if (state->stdout_read_pos >= state->stdout_buf.len) {
    state->stdout_buf.len = 0;
    state->stdout_read_pos = 0;
    if (state->stdout_buf.data != NULL) {
      state->stdout_buf.data[0] = '\0';
    }
    return;
  }
  memmove(
      state->stdout_buf.data,
      state->stdout_buf.data + state->stdout_read_pos,
      state->stdout_buf.len - state->stdout_read_pos);
  state->stdout_buf.len -= state->stdout_read_pos;
  state->stdout_buf.data[state->stdout_buf.len] = '\0';
  state->stdout_read_pos = 0;
}

static void fz_http_stream_finish_locked(fz_http_stream_state* state, int wait_blocking) {
  if (state == NULL || state->done) {
    return;
  }
  int status = 0;
  pid_t waited = waitpid(state->pid, &status, wait_blocking ? 0 : WNOHANG);
  if (waited <= 0) {
    return;
  }
  state->done = 1;
  if (WIFEXITED(status)) {
    state->exit_code = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    state->exit_code = 128 + WTERMSIG(status);
  } else {
    state->exit_code = -1;
  }
  if (state->stderr_fd >= 0) {
    (void)fz_drain_fd(state->stderr_fd, &state->stderr_buf);
  }
  if (state->exit_code != 0 && (state->stderr_buf.data == NULL || state->stderr_buf.len == 0)) {
    char msg[128];
    snprintf(msg, sizeof(msg), "http stream transport exited=%d", state->exit_code);
    fz_http_stream_refresh_error_locked(state, msg);
  } else {
    fz_http_stream_refresh_error_locked(state, "");
  }
}

static int fz_http_stream_drain_locked(fz_http_stream_state* state) {
  if (state == NULL || state->closed) {
    return -1;
  }
  if (fz_async_current_task_cancelled()) {
    if (!state->done && state->pid > 0) {
      kill(state->pid, SIGTERM);
      fz_http_stream_finish_locked(state, 1);
    }
    state->eof = 1;
    fz_http_stream_refresh_error_locked(state, "http stream cancelled");
    return -1;
  }
  if (fz_async_deadline_expired()) {
    if (!state->done && state->pid > 0) {
      kill(state->pid, SIGTERM);
      fz_http_stream_finish_locked(state, 1);
    }
    state->eof = 1;
    fz_http_stream_refresh_error_locked(state, "http stream deadline expired");
    return -1;
  }
  size_t before_stdout = state->stdout_buf.len;
  size_t before_stderr = state->stderr_buf.len;
  int before_eof = state->eof;
  int before_done = state->done;
  if (state->stdout_fd >= 0) {
    int rc = fz_drain_fd(state->stdout_fd, &state->stdout_buf);
    if (rc < 0) {
      fz_http_stream_refresh_error_locked(state, "http stream stdout read failed");
      return -1;
    }
    if (rc == 1) {
      close(state->stdout_fd);
      state->stdout_fd = -1;
      state->eof = 1;
    }
  }
  if (state->stderr_fd >= 0) {
    int rc = fz_drain_fd(state->stderr_fd, &state->stderr_buf);
    if (rc < 0) {
      fz_http_stream_refresh_error_locked(state, "http stream stderr read failed");
      return -1;
    }
    if (rc == 1) {
      close(state->stderr_fd);
      state->stderr_fd = -1;
    }
  }
  fz_http_stream_finish_locked(state, 0);
  if (state->stderr_buf.len != before_stderr || (state->done && !before_done)) {
    fz_http_stream_refresh_error_locked(state, "");
  }
  if (state->stdout_buf.len != before_stdout || state->eof != before_eof || state->done != before_done
      || state->stderr_buf.len != before_stderr) {
    return 1;
  }
  return 0;
}

static int32_t fz_http_stream_consume_chunk_locked(fz_http_stream_state* state, int32_t max_bytes) {
  if (state == NULL) {
    return fz_intern_slice("", 0);
  }
  size_t unread = state->stdout_buf.len > state->stdout_read_pos
      ? (state->stdout_buf.len - state->stdout_read_pos)
      : 0;
  if (unread == 0) {
    if (state->eof) {
      return fz_intern_slice("", 0);
    }
    return 0;
  }
  size_t limit = max_bytes <= 0 ? unread : (size_t)max_bytes;
  if (limit > unread) {
    limit = unread;
  }
  int32_t out = fz_intern_slice(state->stdout_buf.data + state->stdout_read_pos, limit);
  state->stdout_read_pos += limit;
  fz_http_stream_compact_stdout_locked(state);
  return out;
}

static int32_t fz_http_stream_consume_line_locked(fz_http_stream_state* state) {
  if (state == NULL) {
    return fz_intern_slice("", 0);
  }
  size_t unread = state->stdout_buf.len > state->stdout_read_pos
      ? (state->stdout_buf.len - state->stdout_read_pos)
      : 0;
  if (unread == 0) {
    return state->eof ? fz_intern_slice("", 0) : 0;
  }
  char* start = state->stdout_buf.data + state->stdout_read_pos;
  char* newline = memchr(start, '\n', unread);
  if (newline == NULL) {
    if (!state->eof) {
      return 0;
    }
    size_t len = unread;
    if (len > 0 && start[len - 1] == '\r') {
      len--;
    }
    int32_t out = fz_intern_slice(start, len);
    state->stdout_read_pos += unread;
    fz_http_stream_compact_stdout_locked(state);
    return out;
  }
  size_t len = (size_t)(newline - start);
  if (len > 0 && start[len - 1] == '\r') {
    len--;
  }
  int32_t out = fz_intern_slice(start, len);
  state->stdout_read_pos += (size_t)(newline - start) + 1;
  fz_http_stream_compact_stdout_locked(state);
  return out;
}

static int32_t fz_http_stream_close_locked(fz_http_stream_state* state) {
  if (state == NULL) {
    return -1;
  }
  if (!state->done && state->pid > 0) {
    kill(state->pid, SIGTERM);
    fz_http_stream_finish_locked(state, 1);
  }
  if (state->stdout_fd >= 0) {
    close(state->stdout_fd);
    state->stdout_fd = -1;
  }
  if (state->stderr_fd >= 0) {
    close(state->stderr_fd);
    state->stderr_fd = -1;
  }
  fz_bytes_buf_free(&state->stdout_buf);
  fz_bytes_buf_free(&state->stderr_buf);
  memset(state, 0, sizeof(*state));
  return 0;
}

"#
}
