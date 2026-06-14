pub(super) fn section() -> &'static str {
    r#"
static int32_t fz_native_http_post_json_inner(int32_t endpoint_id, int32_t body_id, int return_body) {
  (void)pthread_once(&fz_env_bootstrap_once, fz_env_bootstrap);
  const char* endpoint = fz_lookup_string(endpoint_id);
  const char* body = fz_lookup_string(body_id);
  if (endpoint == NULL || endpoint[0] == '\0') {
    fz_last_exit_class = 3;
    fz_set_last_error(EINVAL, 3, "http_post_json failed: endpoint is empty");
    fz_http_set_last_result(0, "", "http_post_json: empty endpoint");
    return return_body ? fz_intern_slice("", 0) : -1;
  }
  if (body == NULL || body[0] == '\0') {
    body = "{}";
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

  (void)fz_http_header_upsert(header_buf, &header_count, "content-type", "application/json");

  int max_args = 20 + (header_count * 2);
  char** argv = (char**)calloc((size_t)max_args, sizeof(char*));
  if (argv == NULL) {
    for (int i = 0; i < header_count; i++) free(header_buf[i]);
    fz_last_exit_class = 3;
    fz_set_last_error(ENOMEM, 3, "http_post_json failed: argv alloc failed");
    fz_http_set_last_result(0, "", "http_post_json: alloc failed");
    return return_body ? fz_intern_slice("", 0) : -1;
  }
  int ai = 0;
  argv[ai++] = "curl";
  argv[ai++] = "-sS";
  argv[ai++] = "-X";
  argv[ai++] = "POST";
  argv[ai++] = (char*)endpoint;
  for (int i = 0; i < header_count; i++) {
    argv[ai++] = "-H";
    argv[ai++] = header_buf[i];
  }
  argv[ai++] = "--data";
  argv[ai++] = (char*)body;
  argv[ai++] = "--connect-timeout";
  argv[ai++] = "10";
  argv[ai++] = "--max-time";
  argv[ai++] = "60";
  argv[ai++] = "-w";
  argv[ai++] = "\n%{http_code}";
  argv[ai++] = NULL;

  int out_pipe[2];
  int err_pipe[2];
  if (pipe(out_pipe) != 0) {
    free(argv);
    for (int i = 0; i < header_count; i++) free(header_buf[i]);
    fz_last_exit_class = 3;
    fz_set_last_error(errno, 3, "http_post_json failed: pipe failed");
    fz_http_set_last_result(0, "", "http_post_json: pipe failed");
    return return_body ? fz_intern_slice("", 0) : -1;
  }
  if (pipe(err_pipe) != 0) {
    close(out_pipe[0]);
    close(out_pipe[1]);
    free(argv);
    for (int i = 0; i < header_count; i++) free(header_buf[i]);
    fz_last_exit_class = 3;
    fz_set_last_error(errno, 3, "http_post_json failed: stderr pipe failed");
    fz_http_set_last_result(0, "", "http_post_json: stderr pipe failed");
    return return_body ? fz_intern_slice("", 0) : -1;
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
    fz_set_last_error(errno, 3, "http_post_json failed: fork failed");
    fz_http_set_last_result(0, "", "http_post_json: fork failed");
    return return_body ? fz_intern_slice("", 0) : -1;
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
    dprintf(STDERR_FILENO, "http_post_json failed: unable to exec curl (%s)\n", strerror(errno));
    _exit(127);
  }

  close(out_pipe[1]);
  close(err_pipe[1]);
  fz_bytes_buf out;
  fz_bytes_buf_init(&out);
  fz_bytes_buf err;
  fz_bytes_buf_init(&err);
  for (;;) {
    char tmp[4096];
    ssize_t got = read(out_pipe[0], tmp, sizeof(tmp));
    if (got > 0) {
      if (fz_bytes_buf_append(&out, tmp, (size_t)got) != 0) {
        break;
      }
      continue;
    }
    if (got == 0) {
      break;
    }
    if (errno == EINTR) {
      continue;
    }
    break;
  }
  close(out_pipe[0]);
  for (;;) {
    char tmp[4096];
    ssize_t got = read(err_pipe[0], tmp, sizeof(tmp));
    if (got > 0) {
      if (fz_bytes_buf_append(&err, tmp, (size_t)got) != 0) {
        break;
      }
      continue;
    }
    if (got == 0) {
      break;
    }
    if (errno == EINTR) {
      continue;
    }
    break;
  }
  close(err_pipe[0]);

  int status = 0;
  int waited = waitpid(pid, &status, 0);
  free(argv);
  for (int i = 0; i < header_count; i++) free(header_buf[i]);
  if (waited < 0) {
    fz_last_exit_class = 3;
    fz_set_last_error(errno, 3, "http_post_json failed: waitpid failed");
    fz_http_set_last_result(0, "", "http_post_json: waitpid failed");
    fz_bytes_buf_free(&out);
    fz_bytes_buf_free(&err);
    return return_body ? fz_intern_slice("", 0) : -1;
  }
  fz_last_exit_class = fz_exit_class_from_status(0, status, 0);

  int status_code = 0;
  size_t body_len = out.len;
  int parsed_status = fz_http_extract_status(out.data, out.len, &status_code, &body_len);
  const char* body_text = out.data == NULL ? "" : out.data;
  const char* err_text = err.data == NULL ? "" : err.data;
  char saved = '\0';
  if (out.data != NULL && body_len < out.len) {
    saved = out.data[body_len];
    out.data[body_len] = '\0';
  }
  int32_t body_value_id = fz_intern_slice(body_text, strlen(body_text));
  if (out.data != NULL && body_len < out.len) {
    out.data[body_len] = saved;
  }
  int transport_status = status_code > 0 ? status_code : 599;
  if (WIFEXITED(status) && WEXITSTATUS(status) == 0 && parsed_status == 0) {
    fz_http_set_last_result(status_code, body_text, err_text);
    fz_set_last_error(0, 0, "");
    fz_bytes_buf_free(&out);
    fz_bytes_buf_free(&err);
    return return_body ? body_value_id : 0;
  }

  if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
    const char* msg = "http_post_json failed: missing HTTP status trailer from transport";
    fz_http_set_last_result(transport_status, body_text, msg);
    fz_set_last_error(transport_status, 3, msg);
    int32_t fallback = strlen(body_text) > 0 ? body_value_id : fz_intern_slice(msg, strlen(msg));
    fz_bytes_buf_free(&out);
    fz_bytes_buf_free(&err);
    return return_body ? fallback : transport_status;
  }
  if (WIFEXITED(status)) {
    char msg[256];
    snprintf(
        msg,
        sizeof(msg),
        "http_post_json failed: curl exit=%d endpoint=%s",
        WEXITSTATUS(status),
        endpoint);
    const char* err_msg = (err_text[0] != '\0') ? err_text : msg;
    const char* body_for_failure = (body_text[0] != '\0') ? body_text : err_msg;
    int32_t failure_body_id = fz_intern_slice(body_for_failure, strlen(body_for_failure));
    fz_http_set_last_result(transport_status, body_for_failure, err_msg);
    fz_set_last_error(WEXITSTATUS(status), 3, msg);
    fz_bytes_buf_free(&out);
    fz_bytes_buf_free(&err);
    return return_body ? failure_body_id : WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    char msg[256];
    snprintf(
        msg,
        sizeof(msg),
        "http_post_json failed: curl terminated by signal=%d endpoint=%s",
        WTERMSIG(status),
        endpoint);
    const char* err_msg = (err_text[0] != '\0') ? err_text : msg;
    const char* body_for_failure = (body_text[0] != '\0') ? body_text : err_msg;
    int32_t failure_body_id = fz_intern_slice(body_for_failure, strlen(body_for_failure));
    fz_http_set_last_result(transport_status, body_for_failure, err_msg);
    fz_set_last_error(128 + WTERMSIG(status), 3, msg);
    fz_bytes_buf_free(&out);
    fz_bytes_buf_free(&err);
    return return_body ? failure_body_id : (128 + WTERMSIG(status));
  }
  {
    const char* msg = "http_post_json failed: unknown child status";
    const char* err_msg = (err_text[0] != '\0') ? err_text : msg;
    const char* body_for_failure = (body_text[0] != '\0') ? body_text : err_msg;
    int32_t failure_body_id = fz_intern_slice(body_for_failure, strlen(body_for_failure));
    fz_http_set_last_result(transport_status, body_for_failure, err_msg);
    fz_set_last_error(-1, 3, msg);
    fz_bytes_buf_free(&out);
    fz_bytes_buf_free(&err);
    return return_body ? failure_body_id : -1;
  }
}

int32_t fz_native_http_post_json(int32_t endpoint_id, int32_t body_id) {
  return fz_native_http_post_json_inner(endpoint_id, body_id, 0);
}

int32_t fz_native_http_post_json_capture(int32_t endpoint_id, int32_t body_id) {
  return fz_native_http_post_json_inner(endpoint_id, body_id, 1);
}

"#
}
