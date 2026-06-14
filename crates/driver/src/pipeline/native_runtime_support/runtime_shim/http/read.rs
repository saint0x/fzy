pub(super) fn section() -> &'static str {
    r#"
int32_t fz_native_http_request_stream(int32_t method_id, int32_t endpoint_id, int32_t body_id) {
  (void)pthread_once(&fz_env_bootstrap_once, fz_env_bootstrap);
  const char* method = fz_lookup_string(method_id);
  const char* endpoint = fz_lookup_string(endpoint_id);
  const char* body = fz_lookup_string(body_id);
  if (method == NULL || method[0] == '\0') {
    method = "GET";
  }
  if (endpoint == NULL || endpoint[0] == '\0') {
    fz_last_exit_class = 3;
    fz_set_last_error(EINVAL, 3, "http_request_stream failed: endpoint is empty");
    fz_http_set_last_result(0, "", "http_request_stream: empty endpoint");
    return -1;
  }
  if (body == NULL) {
    body = "";
  }

  char* header_buf[FZ_MAX_HTTP_HEADERS];
  int header_count = 0;
  pthread_mutex_lock(&fz_http_lock);
  for (int i = 0; i < fz_http_header_count && i < FZ_MAX_HTTP_HEADERS; i++) {
    const char* key = fz_lookup_string(fz_http_headers[i].key_id);
    const char* value = fz_lookup_string(fz_http_headers[i].value_id);
    if (key == NULL || key[0] == '\0') {
      continue;
    }
    if (value == NULL) {
      value = "";
    }
    (void)fz_http_header_upsert(header_buf, &header_count, key, value);
  }
  fz_http_header_count = 0;
  pthread_mutex_unlock(&fz_http_lock);

  int has_body = body[0] != '\0';
  int max_args = 24 + (header_count * 2);
  char** argv = (char**)calloc((size_t)max_args, sizeof(char*));
  if (argv == NULL) {
    for (int i = 0; i < header_count; i++) free(header_buf[i]);
    fz_last_exit_class = 3;
    fz_set_last_error(ENOMEM, 3, "http_request_stream failed: argv alloc failed");
    fz_http_set_last_result(0, "", "http_request_stream: alloc failed");
    return -1;
  }
  int ai = 0;
  argv[ai++] = "curl";
  argv[ai++] = "-sS";
  argv[ai++] = "-N";
  argv[ai++] = "-X";
  argv[ai++] = (char*)method;
  argv[ai++] = (char*)endpoint;
  argv[ai++] = "-D";
  argv[ai++] = "-";
  for (int i = 0; i < header_count; i++) {
    argv[ai++] = "-H";
    argv[ai++] = header_buf[i];
  }
  if (has_body) {
    argv[ai++] = "--data";
    argv[ai++] = (char*)body;
  }
  argv[ai++] = "--connect-timeout";
  argv[ai++] = "10";
  argv[ai++] = "--max-time";
  argv[ai++] = "300";
  argv[ai++] = NULL;

  int out_pipe[2];
  int err_pipe[2];
  if (pipe(out_pipe) != 0) {
    free(argv);
    for (int i = 0; i < header_count; i++) free(header_buf[i]);
    fz_last_exit_class = 3;
    fz_set_last_error(errno, 3, "http_request_stream failed: pipe failed");
    fz_http_set_last_result(0, "", "http_request_stream: pipe failed");
    return -1;
  }
  if (pipe(err_pipe) != 0) {
    close(out_pipe[0]);
    close(out_pipe[1]);
    free(argv);
    for (int i = 0; i < header_count; i++) free(header_buf[i]);
    fz_last_exit_class = 3;
    fz_set_last_error(errno, 3, "http_request_stream failed: stderr pipe failed");
    fz_http_set_last_result(0, "", "http_request_stream: stderr pipe failed");
    return -1;
  }

  pid_t pid = fork();
  if (pid < 0) {
    close(out_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[0]);
    close(err_pipe[1]);
    free(argv);
    for (int i = 0; i < header_count; i++) free(header_buf[i]);
    fz_last_exit_class = 3;
    fz_set_last_error(errno, 3, "http_request_stream failed: fork failed");
    fz_http_set_last_result(0, "", "http_request_stream: fork failed");
    return -1;
  }

  if (pid == 0) {
    (void)dup2(out_pipe[1], STDOUT_FILENO);
    (void)dup2(err_pipe[1], STDERR_FILENO);
    close(out_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[0]);
    close(err_pipe[1]);
    execvp("curl", argv);
    argv[0] = "/usr/bin/curl";
    execv("/usr/bin/curl", argv);
    argv[0] = "/opt/homebrew/bin/curl";
    execv("/opt/homebrew/bin/curl", argv);
    dprintf(STDERR_FILENO, "http_request_stream failed: unable to exec curl (%s)\n", strerror(errno));
    _exit(127);
  }

  close(out_pipe[1]);
  close(err_pipe[1]);
  fz_bytes_buf initial_body;
  fz_bytes_buf_init(&initial_body);
  int status_code = 0;
  int headers_ok = fz_http_stream_read_response_headers(out_pipe[0], &initial_body, &status_code);
  if (headers_ok != 0) {
    close(out_pipe[0]);
    close(err_pipe[0]);
    int status = 0;
    (void)waitpid(pid, &status, 0);
    free(argv);
    for (int i = 0; i < header_count; i++) free(header_buf[i]);
    fz_last_exit_class = 3;
    fz_set_last_error(-1, 3, "http_request_stream failed: invalid response headers");
    fz_http_set_last_result(0, "", "http_request_stream: invalid response headers");
    fz_bytes_buf_free(&initial_body);
    return -1;
  }

  (void)fz_set_nonblocking(out_pipe[0]);
  (void)fz_set_nonblocking(err_pipe[0]);
  pthread_mutex_lock(&fz_http_lock);
  int32_t handle = fz_http_stream_state_alloc(pid, out_pipe[0], err_pipe[0], status_code);
  if (handle > 0) {
    fz_http_stream_state* state = fz_http_stream_state_get(handle);
    if (state != NULL && initial_body.len > 0) {
      (void)fz_bytes_buf_append(&state->stdout_buf, initial_body.data, initial_body.len);
    }
    fz_http_last_status = status_code;
    fz_http_last_body_id = fz_intern_slice("", 0);
    fz_http_last_error_id = fz_intern_slice("", 0);
  }
  pthread_mutex_unlock(&fz_http_lock);
  free(argv);
  for (int i = 0; i < header_count; i++) free(header_buf[i]);
  fz_bytes_buf_free(&initial_body);
  if (handle <= 0) {
    close(out_pipe[0]);
    close(err_pipe[0]);
    kill(pid, SIGTERM);
    (void)waitpid(pid, NULL, 0);
    fz_last_exit_class = 3;
    fz_set_last_error(ENOMEM, 3, "http_request_stream failed: stream state alloc failed");
    fz_http_set_last_result(status_code, "", "http_request_stream: stream state alloc failed");
    return -1;
  }
  fz_set_last_error(0, 0, "");
  return handle;
}

int32_t fz_native_http_post_json_stream(int32_t endpoint_id, int32_t body_id) {
  (void)fz_native_http_header(
      fz_intern_slice("content-type", 12), fz_intern_slice("application/json", 16));
  return fz_native_http_request_stream(fz_intern_slice("POST", 4), endpoint_id, body_id);
}

int32_t fz_native_http_stream_read(int32_t handle, int32_t max_bytes) {
  for (;;) {
    pthread_mutex_lock(&fz_http_lock);
    fz_http_stream_state* state = fz_http_stream_state_get(handle);
    if (state == NULL || state->closed) {
      pthread_mutex_unlock(&fz_http_lock);
      return fz_intern_slice("", 0);
    }
    int32_t out = fz_http_stream_consume_chunk_locked(state, max_bytes);
    if (fz_lookup_string(out)[0] != '\0') {
      pthread_mutex_unlock(&fz_http_lock);
      return out;
    }
    if (state->eof) {
      pthread_mutex_unlock(&fz_http_lock);
      return fz_intern_slice("", 0);
    }
    int progress = fz_http_stream_drain_locked(state);
    pthread_mutex_unlock(&fz_http_lock);
    if (progress < 0) {
      return fz_intern_slice("", 0);
    }
    if (progress == 0) {
      int sleep_ms = fz_async_effective_timeout_ms(1);
      if (sleep_ms <= 0) {
        pthread_mutex_lock(&fz_http_lock);
        state = fz_http_stream_state_get(handle);
        if (state != NULL && !state->closed) {
          (void)fz_http_stream_drain_locked(state);
        }
        pthread_mutex_unlock(&fz_http_lock);
        return fz_intern_slice("", 0);
      }
      usleep((useconds_t)sleep_ms * 1000);
    }
  }
}

int32_t fz_native_http_stream_read_line(int32_t handle) {
  for (;;) {
    pthread_mutex_lock(&fz_http_lock);
    fz_http_stream_state* state = fz_http_stream_state_get(handle);
    if (state == NULL || state->closed) {
      pthread_mutex_unlock(&fz_http_lock);
      return fz_intern_slice("", 0);
    }
    int32_t out = fz_http_stream_consume_line_locked(state);
    if (out != 0) {
      pthread_mutex_unlock(&fz_http_lock);
      return out;
    }
    if (state->eof) {
      pthread_mutex_unlock(&fz_http_lock);
      return fz_intern_slice("", 0);
    }
    int progress = fz_http_stream_drain_locked(state);
    pthread_mutex_unlock(&fz_http_lock);
    if (progress < 0) {
      return fz_intern_slice("", 0);
    }
    if (progress == 0) {
      int sleep_ms = fz_async_effective_timeout_ms(1);
      if (sleep_ms <= 0) {
        pthread_mutex_lock(&fz_http_lock);
        state = fz_http_stream_state_get(handle);
        if (state != NULL && !state->closed) {
          (void)fz_http_stream_drain_locked(state);
        }
        pthread_mutex_unlock(&fz_http_lock);
        return fz_intern_slice("", 0);
      }
      usleep((useconds_t)sleep_ms * 1000);
    }
  }
}

int32_t fz_native_http_stream_eof(int32_t handle) {
  pthread_mutex_lock(&fz_http_lock);
  fz_http_stream_state* state = fz_http_stream_state_get(handle);
  if (state == NULL || state->closed) {
    pthread_mutex_unlock(&fz_http_lock);
    return 1;
  }
  (void)fz_http_stream_drain_locked(state);
  size_t unread = state->stdout_buf.len > state->stdout_read_pos
      ? (state->stdout_buf.len - state->stdout_read_pos)
      : 0;
  int eof = state->eof && unread == 0 ? 1 : 0;
  pthread_mutex_unlock(&fz_http_lock);
  return eof;
}

int32_t fz_native_http_stream_status(int32_t handle) {
  pthread_mutex_lock(&fz_http_lock);
  fz_http_stream_state* state = fz_http_stream_state_get(handle);
  int32_t status = state == NULL ? 0 : state->status_code;
  pthread_mutex_unlock(&fz_http_lock);
  return status;
}

int32_t fz_native_http_stream_error(int32_t handle) {
  pthread_mutex_lock(&fz_http_lock);
  fz_http_stream_state* state = fz_http_stream_state_get(handle);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_http_lock);
    return fz_intern_slice("", 0);
  }
  (void)fz_http_stream_drain_locked(state);
  int32_t error_id = state->error_id;
  pthread_mutex_unlock(&fz_http_lock);
  return error_id;
}

int32_t fz_native_http_stream_close(int32_t handle) {
  pthread_mutex_lock(&fz_http_lock);
  fz_http_stream_state* state = fz_http_stream_state_get(handle);
  int32_t rc = fz_http_stream_close_locked(state);
  pthread_mutex_unlock(&fz_http_lock);
  return rc;
}

int32_t fz_native_http_last_status(void) {
  pthread_mutex_lock(&fz_http_lock);
  int32_t value = fz_http_last_status;
  pthread_mutex_unlock(&fz_http_lock);
  return value;
}

int32_t fz_native_http_last_body(void) {
  pthread_mutex_lock(&fz_http_lock);
  int32_t value = fz_http_last_body_id;
  pthread_mutex_unlock(&fz_http_lock);
  return value;
}

int32_t fz_native_http_last_error(void) {
  pthread_mutex_lock(&fz_http_lock);
  int32_t value = fz_http_last_error_id;
  pthread_mutex_unlock(&fz_http_lock);
  return value;
}

int32_t fz_native_error_code(void) {
  return fz_last_error_code;
}

int32_t fz_native_error_class(void) {
  return fz_last_error_class;
}

int32_t fz_native_error_message(void) {
  return fz_last_error_message_id;
}

int32_t fz_native_error_context(int32_t ctx_id) {
  const char* ctx = fz_lookup_string(ctx_id);
  const char* msg = fz_lookup_string(fz_last_error_message_id);
  if (ctx == NULL || ctx[0] == '\0') {
    return 0;
  }
  if (msg == NULL) {
    msg = "";
  }
  if (msg[0] == '\0') {
    fz_last_error_message_id = ctx_id;
    return 0;
  }
  const char* parts[3] = {msg, ": ", ctx};
  int32_t joined = fz_native_str_concat_parts(parts, 3);
  if (joined == 0) {
    return -1;
  }
  fz_last_error_message_id = joined;
  return 0;
}

"#
}
