pub(super) fn section() -> &'static str {
    r#"
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

"#
}
