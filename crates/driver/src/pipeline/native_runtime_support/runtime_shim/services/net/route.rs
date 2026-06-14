pub(super) fn section() -> &'static str {
    r#"
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

"#
}
