pub(super) fn section() -> &'static str {
    r#"
int32_t fz_native_net_method(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  int32_t value = state == NULL ? 0 : state->method_id;
  pthread_mutex_unlock(&fz_conn_lock);
  return value;
}

int32_t fz_native_net_path(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  int32_t value = state == NULL ? 0 : state->path_id;
  pthread_mutex_unlock(&fz_conn_lock);
  return value;
}

int32_t fz_native_net_body(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  int32_t value = state == NULL ? 0 : state->body_id;
  pthread_mutex_unlock(&fz_conn_lock);
  return value;
}

int32_t fz_native_net_body_read(int32_t conn_fd, int32_t max_bytes) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return fz_intern_slice("", 0);
  }
  size_t prefetched = state->request_body_buf_len - state->request_body_buf_pos;
  if (state->request_body_mode == 1 && prefetched > 0 && state->request_body_remaining <= 0) {
    state->request_body_remaining = (int64_t)prefetched;
    state->request_body_eof = 0;
  }
  if (state->request_body_fully_buffered) {
    const char* body = fz_lookup_string(state->body_id);
    if (body == NULL) {
      pthread_mutex_unlock(&fz_conn_lock);
      return fz_intern_slice("", 0);
    }
    size_t total = strlen(body);
    size_t start = state->request_body_buf_pos;
    if (start >= total || max_bytes <= 0) {
      state->request_body_eof = 1;
      pthread_mutex_unlock(&fz_conn_lock);
      return fz_intern_slice("", 0);
    }
    size_t take = (size_t)max_bytes;
    if (take > total - start) {
      take = total - start;
    }
    state->request_body_buf_pos += take;
    if (state->request_body_buf_pos >= total) {
      state->request_body_eof = 1;
    }
    int32_t out = fz_intern_slice(body + start, take);
    pthread_mutex_unlock(&fz_conn_lock);
    return out;
  }
  char* chunk = NULL;
  size_t chunk_len = 0;
  int rc = fz_conn_read_body_chunk(state, &chunk, &chunk_len, max_bytes);
  if (rc < 0) {
    pthread_mutex_unlock(&fz_conn_lock);
    if (chunk != NULL) {
      free(chunk);
    }
    return fz_intern_slice("", 0);
  }
  int32_t out = fz_intern_slice(chunk == NULL ? "" : chunk, chunk_len);
  if (chunk != NULL) {
    free(chunk);
  }
  pthread_mutex_unlock(&fz_conn_lock);
  return out;
}

int32_t fz_native_net_body_eof(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  int32_t value = (state == NULL || state->request_body_eof) ? 1 : 0;
  pthread_mutex_unlock(&fz_conn_lock);
  return value;
}

int32_t fz_native_net_body_discard(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  int rc = state == NULL ? -1 : fz_conn_discard_body(state);
  pthread_mutex_unlock(&fz_conn_lock);
  return rc;
}

int32_t fz_native_net_body_json(int32_t conn_fd) {
  int32_t body_id = fz_native_net_body(conn_fd);
  return fz_native_json_parse(body_id);
}

int32_t fz_native_net_body_bind(int32_t conn_fd) {
  int32_t out_map = fz_runtime_map_new();
  if (out_map < 0) {
    return -1;
  }
  int32_t body = fz_native_net_body_json(conn_fd);
  if (body <= 0) {
    (void)fz_runtime_map_set(
        out_map,
        fz_intern_slice("__error", 7),
        fz_intern_slice("invalid JSON body", 17));
    return out_map;
  }
  int32_t body_id = fz_json_value_get_id(body);
  const char* raw = fz_lookup_string(body_id);
  const char* p = fz_json_ws(raw);
  if (p == NULL || *p != '{') {
    (void)fz_runtime_map_set(
        out_map,
        fz_intern_slice("__error", 7),
        fz_intern_slice("body must be JSON object", 24));
    return out_map;
  }
  p = fz_json_ws(p + 1);
  if (*p == '}') {
    return out_map;
  }
  for (;;) {
    char* key = NULL;
    if (fz_json_parse_string(&p, &key) != 0) {
      (void)fz_runtime_map_set(
          out_map,
          fz_intern_slice("__error", 7),
          fz_intern_slice("invalid JSON object key", 23));
      free(key);
      return out_map;
    }
    p = fz_json_ws(p);
    if (*p != ':') {
      (void)fz_runtime_map_set(
          out_map,
          fz_intern_slice("__error", 7),
          fz_intern_slice("invalid JSON object syntax", 26));
      free(key);
      return out_map;
    }
    p = fz_json_ws(p + 1);
    const char* value_start = p;
    if (fz_json_skip_value_token(&p, 0) != 0) {
      (void)fz_runtime_map_set(
          out_map,
          fz_intern_slice("__error", 7),
          fz_intern_slice("invalid JSON object value", 25));
      free(key);
      return out_map;
    }
    const char* value_end = p;
    int32_t key_id = fz_intern_slice(key == NULL ? "" : key, strlen(key == NULL ? "" : key));
    free(key);

    const char* q = value_start;
    char* string_value = NULL;
    int decoded = fz_json_parse_string(&q, &string_value) == 0 && fz_json_ws(q) == value_end;
    if (decoded) {
      int32_t value_id = fz_intern_slice(string_value == NULL ? "" : string_value, strlen(string_value == NULL ? "" : string_value));
      free(string_value);
      (void)fz_runtime_map_set(out_map, key_id, value_id);
    } else {
      free(string_value);
      int32_t value_id = fz_intern_slice(value_start, (size_t)(value_end - value_start));
      (void)fz_runtime_map_set(out_map, key_id, value_id);
    }
    p = fz_json_ws(p);
    if (*p == ',') {
      p = fz_json_ws(p + 1);
      continue;
    }
    if (*p == '}') {
      return out_map;
    }
    (void)fz_runtime_map_set(
        out_map,
        fz_intern_slice("__error", 7),
        fz_intern_slice("invalid JSON object terminator", 30));
    return out_map;
  }
}

int32_t fz_native_net_header(int32_t conn_fd, int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL || key == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return fz_intern_slice("", 0);
  }
  for (int i = 0; i < state->header_count; i++) {
    if (fz_conn_state_meta_key_eq(
            state,
            state->header_key_offsets[i],
            state->header_key_lens[i],
            key,
            1)) {
      int32_t value = fz_conn_state_intern_meta_slice(
          state, state->header_value_offsets[i], state->header_value_lens[i]);
      pthread_mutex_unlock(&fz_conn_lock);
      return value;
    }
  }
  pthread_mutex_unlock(&fz_conn_lock);
  return fz_intern_slice("", 0);
}

int32_t fz_native_net_query(int32_t conn_fd, int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL || key == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return fz_intern_slice("", 0);
  }
  for (int i = 0; i < state->query_count; i++) {
    if (fz_conn_state_meta_key_eq(
            state,
            state->query_key_offsets[i],
            state->query_key_lens[i],
            key,
            0)) {
      int32_t value = fz_conn_state_intern_meta_slice(
          state, state->query_value_offsets[i], state->query_value_lens[i]);
      pthread_mutex_unlock(&fz_conn_lock);
      return value;
    }
  }
  pthread_mutex_unlock(&fz_conn_lock);
  return fz_intern_slice("", 0);
}

int32_t fz_native_net_param(int32_t conn_fd, int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL || key == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return fz_intern_slice("", 0);
  }
  for (int i = 0; i < state->param_count; i++) {
    const char* k = fz_lookup_string(state->param_key_ids[i]);
    if (k != NULL && strcmp(k, key) == 0) {
      int32_t value = state->param_value_ids[i];
      pthread_mutex_unlock(&fz_conn_lock);
      return value;
    }
  }
  pthread_mutex_unlock(&fz_conn_lock);
  return fz_intern_slice("", 0);
}

int32_t fz_native_net_headers(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return -1;
  }
  pthread_mutex_lock(&fz_list_lock);
  int32_t list_handle = fz_list_alloc();
  fz_list_state* list = fz_list_get(list_handle);
  if (list != NULL) {
    for (int i = 0; i < state->header_count; i++) {
      size_t key_len = 0;
      size_t value_len = 0;
      const char* k = fz_conn_state_meta_slice_ptr(
          state, state->header_key_offsets[i], state->header_key_lens[i], &key_len);
      const char* v = fz_conn_state_meta_slice_ptr(
          state, state->header_value_offsets[i], state->header_value_lens[i], &value_len);
      size_t n = key_len + value_len + 2;
      char* kv = (char*)malloc(n);
      if (kv == NULL) continue;
      if (key_len > 0) memcpy(kv, k, key_len);
      kv[key_len] = ':';
      if (value_len > 0) memcpy(kv + key_len + 1, v, value_len);
      kv[key_len + value_len + 1] = '\0';
      (void)fz_list_push_cstr(list, kv);
      free(kv);
    }
  }
  pthread_mutex_unlock(&fz_list_lock);
  pthread_mutex_unlock(&fz_conn_lock);
  return list_handle;
}

int32_t fz_native_net_request_id(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  int32_t value = state == NULL ? 0 : state->request_id;
  pthread_mutex_unlock(&fz_conn_lock);
  return value;
}

int32_t fz_native_net_remote_addr(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  int32_t value = state == NULL ? 0 : state->remote_addr_id;
  pthread_mutex_unlock(&fz_conn_lock);
  return value;
}

int32_t fz_native_net_response_header_set(int32_t conn_fd, int32_t key_id, int32_t value_id) {
  const char* key = fz_lookup_string(key_id);
  if (key == NULL || key[0] == '\0') {
    return -1;
  }
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return -1;
  }
  for (int i = 0; i < state->response_header_count; i++) {
    const char* existing = fz_lookup_string(state->response_header_key_ids[i]);
    if (existing != NULL && strcasecmp(existing, key) == 0) {
      state->response_header_value_ids[i] = value_id;
      pthread_mutex_unlock(&fz_conn_lock);
      return 0;
    }
  }
  if (state->response_header_count >= FZ_MAX_CONN_META) {
    pthread_mutex_unlock(&fz_conn_lock);
    return -1;
  }
  state->response_header_key_ids[state->response_header_count] = key_id;
  state->response_header_value_ids[state->response_header_count] = value_id;
  state->response_header_count++;
  pthread_mutex_unlock(&fz_conn_lock);
  return 0;
}

int32_t fz_native_net_response_header_add(int32_t conn_fd, int32_t key_id, int32_t value_id) {
  const char* key = fz_lookup_string(key_id);
  if (key == NULL || key[0] == '\0') {
    return -1;
  }
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL || state->response_header_count >= FZ_MAX_CONN_META) {
    pthread_mutex_unlock(&fz_conn_lock);
    return -1;
  }
  state->response_header_key_ids[state->response_header_count] = key_id;
  state->response_header_value_ids[state->response_header_count] = value_id;
  state->response_header_count++;
  pthread_mutex_unlock(&fz_conn_lock);
  return 0;
}

int32_t fz_native_net_response_header_clear(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state != NULL) {
    fz_conn_state_reset_response_headers(state);
  }
  pthread_mutex_unlock(&fz_conn_lock);
  return 0;
}

"#
}
