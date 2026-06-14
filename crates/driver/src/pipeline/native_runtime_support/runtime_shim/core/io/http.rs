pub(super) fn section() -> &'static str {
    r#"
static int fz_send_all(int fd, const char* data, size_t len) {
  size_t sent = 0;
  while (sent < len) {
    ssize_t wrote = send(fd, data + sent, len - sent, 0);
    if (wrote < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (wrote == 0) {
      return -1;
    }
    sent += (size_t)wrote;
  }
  return 0;
}

static const char* fz_http_reason(int status_code) {
  switch (status_code) {
    case 200: return "OK";
    case 201: return "Created";
    case 202: return "Accepted";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 409: return "Conflict";
    case 422: return "Unprocessable Entity";
    case 429: return "Too Many Requests";
    case 500: return "Internal Server Error";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    default: return "OK";
  }
}

static fz_conn_state* fz_conn_state_for(int fd, int create_if_missing) {
  fz_conn_state* free_slot = NULL;
  for (int i = 0; i < FZ_MAX_CONN_STATES; i++) {
    if (fz_conn_states[i].in_use && fz_conn_states[i].fd == fd) {
      return &fz_conn_states[i];
    }
    if (!fz_conn_states[i].in_use && free_slot == NULL) {
      free_slot = &fz_conn_states[i];
    }
  }
  if (!create_if_missing || free_slot == NULL) {
    return NULL;
  }
  memset(free_slot, 0, sizeof(*free_slot));
  free_slot->in_use = 1;
  free_slot->fd = fd;
  return free_slot;
}

static void fz_conn_state_drop(int fd) {
  pthread_mutex_lock(&fz_conn_lock);
  for (int i = 0; i < FZ_MAX_CONN_STATES; i++) {
    if (fz_conn_states[i].in_use && fz_conn_states[i].fd == fd) {
      fz_conn_state_reset_request_body(&fz_conn_states[i]);
      memset(&fz_conn_states[i], 0, sizeof(fz_conn_states[i]));
      break;
    }
  }
  pthread_mutex_unlock(&fz_conn_lock);
}

static int fz_find_header_end(const char* buf, int len) {
  for (int i = 0; i + 3 < len; i++) {
    if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
      return i + 4;
    }
  }
  return -1;
}

static int fz_contains_ci(const char* hay, size_t hay_len, const char* needle) {
  size_t needle_len = strlen(needle);
  if (needle_len == 0 || hay_len < needle_len) {
    return 0;
  }
  for (size_t i = 0; i + needle_len <= hay_len; i++) {
    size_t j = 0;
    while (j < needle_len) {
      char a = (char)tolower((unsigned char)hay[i + j]);
      char b = (char)tolower((unsigned char)needle[j]);
      if (a != b) {
        break;
      }
      j++;
    }
    if (j == needle_len) {
      return 1;
    }
  }
  return 0;
}

static int64_t fz_parse_content_length(const char* headers, int header_len) {
  const char* cursor = headers;
  const char* end = headers + header_len;
  while (cursor < end) {
    const char* line_end = strstr(cursor, "\r\n");
    if (line_end == NULL || line_end > end) {
      break;
    }
    if (line_end == cursor) {
      break;
    }
    size_t line_len = (size_t)(line_end - cursor);
    if (line_len >= 15 && strncasecmp(cursor, "Content-Length:", 15) == 0) {
      const char* value = cursor + 15;
      while (value < line_end && (*value == ' ' || *value == '\t')) {
        value++;
      }
      char tmp[32];
      size_t max = (size_t)(line_end - value);
      if (max >= sizeof(tmp)) {
        max = sizeof(tmp) - 1;
      }
      memcpy(tmp, value, max);
      tmp[max] = '\0';
      char* parse_end = NULL;
      long long parsed = strtoll(tmp, &parse_end, 10);
      if (parse_end != tmp && parsed >= 0) {
        return parsed;
      }
    }
    cursor = line_end + 2;
  }
  return -1;
}

static int fz_parse_keep_alive(const char* headers, int header_len, const char* version, int version_len) {
  int keep_alive = (version_len >= 8 && strncasecmp(version, "HTTP/1.1", 8) == 0) ? 1 : 0;
  const char* cursor = headers;
  const char* end = headers + header_len;
  while (cursor < end) {
    const char* line_end = strstr(cursor, "\r\n");
    if (line_end == NULL || line_end > end) {
      break;
    }
    if (line_end == cursor) {
      break;
    }
    size_t line_len = (size_t)(line_end - cursor);
    if (line_len >= 11 && strncasecmp(cursor, "Connection:", 11) == 0) {
      const char* value = cursor + 11;
      while (value < line_end && (*value == ' ' || *value == '\t')) {
        value++;
      }
      size_t value_len = (size_t)(line_end - value);
      if (fz_contains_ci(value, value_len, "close")) {
        keep_alive = 0;
      } else if (fz_contains_ci(value, value_len, "keep-alive")) {
        keep_alive = 1;
      }
      break;
    }
    cursor = line_end + 2;
  }
  return keep_alive;
}

static int fz_parse_chunked_flag(const char* headers, int header_len) {
  const char* cursor = headers;
  const char* end = headers + header_len;
  while (cursor < end) {
    const char* line_end = strstr(cursor, "\r\n");
    if (line_end == NULL || line_end > end) {
      break;
    }
    if (line_end == cursor) {
      break;
    }
    size_t line_len = (size_t)(line_end - cursor);
    if (line_len >= 18 && strncasecmp(cursor, "Transfer-Encoding:", 18) == 0) {
      const char* value = cursor + 18;
      while (value < line_end && (*value == ' ' || *value == '\t')) {
        value++;
      }
      if (fz_contains_ci(value, (size_t)(line_end - value), "chunked")) {
        return 1;
      }
    }
    cursor = line_end + 2;
  }
  return 0;
}

static int fz_send_http_response_state(
    fz_conn_state* state,
    int status_code,
    const char* content_type,
    const char* body,
    int close_after) {
  if (state == NULL || state->fd < 0) {
    return -1;
  }
  if (content_type == NULL || content_type[0] == '\0') {
    content_type = "text/plain; charset=utf-8";
  }
  if (body == NULL) {
    body = "";
  }
  int body_len = (int)strlen(body);
  const char* reason = fz_http_reason(status_code);
  if (!close_after && state->request_body_eof == 0) {
    close_after = 1;
  }
  int websocket_upgrade = 0;
  for (int i = 0; i < state->response_header_count; i++) {
    const char* key = fz_lookup_string(state->response_header_key_ids[i]);
    const char* value = fz_lookup_string(state->response_header_value_ids[i]);
    if (key == NULL || value == NULL) {
      continue;
    }
    if (strncasecmp(key, "upgrade", 7) == 0 && strcasecmp(value, "websocket") == 0) {
      websocket_upgrade = 1;
      break;
    }
  }
  fz_bytes_buf header;
  fz_bytes_buf_init(&header);
  char status_line[256];
  int status_len = 0;
  if (status_code == 101 && websocket_upgrade) {
    status_len = snprintf(
        status_line,
        sizeof(status_line),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Connection: Upgrade\r\n");
  } else {
    status_len = snprintf(
        status_line,
        sizeof(status_line),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: %s\r\n",
        status_code,
        reason,
        content_type,
        body_len,
        close_after ? "close" : "keep-alive");
  }
  if (status_len <= 0 || fz_bytes_buf_append(&header, status_line, (size_t)status_len) != 0) {
    fz_bytes_buf_free(&header);
    return -1;
  }
  for (int i = 0; i < state->response_header_count; i++) {
    const char* key = fz_lookup_string(state->response_header_key_ids[i]);
    const char* value = fz_lookup_string(state->response_header_value_ids[i]);
    if (key == NULL || key[0] == '\0' || value == NULL) {
      continue;
    }
    if (strncasecmp(key, "content-type", 12) == 0
        || strncasecmp(key, "content-length", 14) == 0
        || strncasecmp(key, "connection", 10) == 0) {
      continue;
    }
    if (fz_bytes_buf_append(&header, key, strlen(key)) != 0
        || fz_bytes_buf_append(&header, ": ", 2) != 0
        || fz_bytes_buf_append(&header, value, strlen(value)) != 0
        || fz_bytes_buf_append(&header, "\r\n", 2) != 0) {
      fz_bytes_buf_free(&header);
      return -1;
    }
  }
  if (fz_bytes_buf_append(&header, "\r\n", 2) != 0) {
    fz_bytes_buf_free(&header);
    return -1;
  }
  if (fz_send_all(state->fd, header.data == NULL ? "" : header.data, header.len) != 0) {
    fz_bytes_buf_free(&header);
    return -1;
  }
  fz_bytes_buf_free(&header);
  if (body_len > 0 && fz_send_all(state->fd, body, (size_t)body_len) != 0) {
    return -1;
  }
  fz_conn_state_reset_response_headers(state);
  if (close_after) {
    shutdown(state->fd, SHUT_RDWR);
    close(state->fd);
    fz_conn_state_drop(state->fd);
  }
  return 0;
}

static int fz_send_http_response(int conn_fd, int status_code, const char* content_type, const char* body, int close_after) {
  fz_conn_state* state = NULL;
  pthread_mutex_lock(&fz_conn_lock);
  state = fz_conn_state_for(conn_fd, 1);
  if (state != NULL) {
    state->fd = conn_fd;
  }
  pthread_mutex_unlock(&fz_conn_lock);
  int rc = fz_send_http_response_state(state, status_code, content_type, body, close_after);
  return rc;
}

"#
}
