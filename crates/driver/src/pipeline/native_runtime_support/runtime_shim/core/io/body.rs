pub(super) fn section() -> &'static str {
    r#"
static int fz_conn_recv_into_body_buffer(fz_conn_state* state, size_t want, int timeout_ms) {
  if (state == NULL || state->fd < 0) {
    return -1;
  }
  while ((state->request_body_buf_len - state->request_body_buf_pos) < want) {
    char tmp[4096];
    ssize_t got = recv(state->fd, tmp, sizeof(tmp), 0);
    if (got < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        if (fz_wait_for_fd_event(state->fd, POLLIN, timeout_ms) == 0) {
          continue;
        }
      }
      return -1;
    }
    if (got == 0) {
      return 0;
    }
    size_t unread = state->request_body_buf_len - state->request_body_buf_pos;
    char* next = (char*)malloc(unread + (size_t)got + 1);
    if (next == NULL) {
      return -1;
    }
    if (unread > 0 && state->request_body_buf != NULL) {
      memcpy(next, state->request_body_buf + state->request_body_buf_pos, unread);
    }
    memcpy(next + unread, tmp, (size_t)got);
    next[unread + (size_t)got] = '\0';
    if (state->request_body_buf != NULL) {
      free(state->request_body_buf);
    }
    state->request_body_buf = next;
    state->request_body_buf_len = unread + (size_t)got;
    state->request_body_buf_pos = 0;
  }
  return 1;
}

static int fz_conn_read_body_chunk(fz_conn_state* state, char** out_ptr, size_t* out_len, int32_t max_bytes) {
  if (state == NULL || out_ptr == NULL || out_len == NULL) {
    return -1;
  }
  *out_ptr = NULL;
  *out_len = 0;
  if (max_bytes <= 0) {
    state->request_body_eof = 1;
    return 1;
  }
  if (state->request_body_eof) {
    return 1;
  }
  if (state->request_body_mode == 1) {
    if (state->request_body_remaining <= 0) {
      state->request_body_eof = 1;
      return 1;
    }
    size_t to_take = (size_t)max_bytes;
    if ((int64_t)to_take > state->request_body_remaining) {
      to_take = (size_t)state->request_body_remaining;
    }
    size_t have = state->request_body_buf_len - state->request_body_buf_pos;
    if (have < to_take) {
      int rc = fz_conn_recv_into_body_buffer(state, to_take, 2500);
      if (rc <= 0) {
        return -1;
      }
      have = state->request_body_buf_len - state->request_body_buf_pos;
    }
    if (have < to_take) {
      to_take = have;
    }
    char* chunk = (char*)malloc(to_take + 1);
    if (chunk == NULL) {
      return -1;
    }
    if (to_take > 0) {
      memcpy(chunk, state->request_body_buf + state->request_body_buf_pos, to_take);
      state->request_body_buf_pos += to_take;
      state->request_body_remaining -= (int64_t)to_take;
    }
    chunk[to_take] = '\0';
    if (state->request_body_buf_pos >= state->request_body_buf_len) {
      free(state->request_body_buf);
      state->request_body_buf = NULL;
      state->request_body_buf_len = 0;
      state->request_body_buf_pos = 0;
    }
    if (state->request_body_remaining <= 0) {
      state->request_body_eof = 1;
    }
    *out_ptr = chunk;
    *out_len = to_take;
    return 0;
  }
  if (state->request_body_mode == 2) {
    if (state->request_chunk_remaining == 0) {
      for (;;) {
        int ready = fz_conn_recv_into_body_buffer(state, 2, 2500);
        if (ready <= 0) {
          return -1;
        }
        char* scan = state->request_body_buf + state->request_body_buf_pos;
        size_t scan_len = state->request_body_buf_len - state->request_body_buf_pos;
        char* line_end = NULL;
        for (size_t i = 0; i + 1 < scan_len; i++) {
          if (scan[i] == '\r' && scan[i + 1] == '\n') {
            line_end = scan + i;
            break;
          }
        }
        if (line_end == NULL) {
          int more = fz_conn_recv_into_body_buffer(state, scan_len + 2, 2500);
          if (more <= 0) {
            return -1;
          }
          continue;
        }
        size_t line_len = (size_t)(line_end - scan);
        char size_line[64];
        if (line_len >= sizeof(size_line)) {
          return -1;
        }
        memcpy(size_line, scan, line_len);
        size_line[line_len] = '\0';
        char* semi = strchr(size_line, ';');
        if (semi != NULL) {
          *semi = '\0';
        }
        char* parse_end = NULL;
        long long chunk_size = strtoll(size_line, &parse_end, 16);
        if (parse_end == size_line || chunk_size < 0) {
          return -1;
        }
        state->request_body_buf_pos += line_len + 2;
        if (state->request_body_buf_pos >= state->request_body_buf_len) {
          free(state->request_body_buf);
          state->request_body_buf = NULL;
          state->request_body_buf_len = 0;
          state->request_body_buf_pos = 0;
        }
        if (chunk_size == 0) {
          (void)fz_conn_recv_into_body_buffer(state, 2, 2500);
          if (state->request_body_buf_len - state->request_body_buf_pos >= 2) {
            state->request_body_buf_pos += 2;
          }
          state->request_body_eof = 1;
          return 1;
        }
        state->request_chunk_remaining = chunk_size;
        break;
      }
    }
    size_t to_take = (size_t)max_bytes;
    if ((int64_t)to_take > state->request_chunk_remaining) {
      to_take = (size_t)state->request_chunk_remaining;
    }
    if ((state->request_body_buf_len - state->request_body_buf_pos) < to_take) {
      int rc = fz_conn_recv_into_body_buffer(state, to_take, 2500);
      if (rc <= 0) {
        return -1;
      }
    }
    char* chunk = (char*)malloc(to_take + 1);
    if (chunk == NULL) {
      return -1;
    }
    memcpy(chunk, state->request_body_buf + state->request_body_buf_pos, to_take);
    state->request_body_buf_pos += to_take;
    state->request_chunk_remaining -= (int64_t)to_take;
    chunk[to_take] = '\0';
    if (state->request_chunk_remaining == 0) {
      if ((state->request_body_buf_len - state->request_body_buf_pos) < 2) {
        int rc = fz_conn_recv_into_body_buffer(state, 2, 2500);
        if (rc <= 0) {
          free(chunk);
          return -1;
        }
      }
      state->request_body_buf_pos += 2;
    }
    if (state->request_body_buf_pos >= state->request_body_buf_len) {
      free(state->request_body_buf);
      state->request_body_buf = NULL;
      state->request_body_buf_len = 0;
      state->request_body_buf_pos = 0;
    }
    *out_ptr = chunk;
    *out_len = to_take;
    return 0;
  }
  state->request_body_eof = 1;
  return 1;
}

static int fz_conn_discard_body(fz_conn_state* state) {
  if (state == NULL) {
    return -1;
  }
  while (!state->request_body_eof) {
    char* chunk = NULL;
    size_t chunk_len = 0;
    int rc = fz_conn_read_body_chunk(state, &chunk, &chunk_len, 4096);
    if (chunk != NULL) {
      free(chunk);
    }
    if (rc < 0) {
      return -1;
    }
    if (rc > 0) {
      break;
    }
  }
  return 0;
}

"#
}
