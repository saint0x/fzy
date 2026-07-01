pub(super) fn section() -> &'static str {
    r#"
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
