pub(super) fn section() -> &'static str {
    r#"
int32_t fz_native_net_websocket_accept(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return -1;
  }
  const char* upgrade = "";
  size_t upgrade_len = 0;
  const char* connection = "";
  size_t connection_len = 0;
  const char* ws_key = "";
  size_t ws_key_len = 0;
  const char* ws_version = "";
  size_t ws_version_len = 0;
  for (int i = 0; i < state->header_count; i++) {
    size_t value_len = 0;
    const char* value = fz_conn_state_meta_slice_ptr(
        state, state->header_value_offsets[i], state->header_value_lens[i], &value_len);
    if (fz_conn_state_meta_key_eq(
            state,
            state->header_key_offsets[i],
            state->header_key_lens[i],
            "upgrade",
            1)) {
      upgrade = value;
      upgrade_len = value_len;
    } else if (fz_conn_state_meta_key_eq(
                   state,
                   state->header_key_offsets[i],
                   state->header_key_lens[i],
                   "connection",
                   1)) {
      connection = value;
      connection_len = value_len;
    } else if (fz_conn_state_meta_key_eq(
                   state,
                   state->header_key_offsets[i],
                   state->header_key_lens[i],
                   "sec-websocket-key",
                   1)) {
      ws_key = value;
      ws_key_len = value_len;
    } else if (fz_conn_state_meta_key_eq(
                   state,
                   state->header_key_offsets[i],
                   state->header_key_lens[i],
                   "sec-websocket-version",
                   1)) {
      ws_version = value;
      ws_version_len = value_len;
    }
  }
  if (upgrade == NULL || upgrade_len != 9 || strncasecmp(upgrade, "websocket", upgrade_len) != 0
      || connection == NULL || fz_contains_ci(connection, connection_len, "upgrade") == 0
      || ws_key == NULL || ws_key_len == 0
      || ws_version == NULL || ws_version_len != 2 || strncmp(ws_version, "13", ws_version_len) != 0) {
    pthread_mutex_unlock(&fz_conn_lock);
    return -1;
  }
  const char* guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  size_t guid_len = strlen(guid);
  size_t concat_len = ws_key_len + guid_len;
  char* concat = (char*)malloc(concat_len + 1);
  if (concat == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return -1;
  }
  memcpy(concat, ws_key, ws_key_len);
  memcpy(concat + ws_key_len, guid, guid_len);
  concat[concat_len] = '\0';
  uint8_t digest[20];
  fz_sha1_compute((const uint8_t*)concat, concat_len, digest);
  free(concat);
  char* accept_value = fz_base64_encode(digest, sizeof(digest));
  if (accept_value == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return -1;
  }
  if (state->response_header_count + 3 <= FZ_MAX_CONN_META) {
    state->response_header_key_ids[state->response_header_count] = fz_intern_slice("Upgrade", 7);
    state->response_header_value_ids[state->response_header_count] = fz_intern_slice("websocket", 9);
    state->response_header_count++;
    state->response_header_key_ids[state->response_header_count] = fz_intern_slice("Connection", 10);
    state->response_header_value_ids[state->response_header_count] = fz_intern_slice("Upgrade", 7);
    state->response_header_count++;
    state->response_header_key_ids[state->response_header_count] = fz_intern_slice("Sec-WebSocket-Accept", 20);
    state->response_header_value_ids[state->response_header_count] = fz_intern_slice(accept_value, strlen(accept_value));
    state->response_header_count++;
  }
  free(accept_value);
  int rc = fz_send_http_response_state(state, 101, "", "", 0);
  if (rc != 0) {
    pthread_mutex_unlock(&fz_conn_lock);
    return -1;
  }
  int32_t handle = fz_websocket_state_alloc(conn_fd);
  pthread_mutex_unlock(&fz_conn_lock);
  return handle;
}

int32_t fz_native_net_websocket_read(int32_t ws_handle, int32_t max_bytes) {
  fz_websocket_state* ws = fz_websocket_state_get(ws_handle);
  if (ws == NULL) {
    return fz_intern_slice("", 0);
  }
  int32_t kind_id = 0;
  int32_t close_code = 0;
  int32_t error_id = 0;
  int32_t payload_id = fz_websocket_read_frame(ws, max_bytes, &kind_id, &close_code, &error_id);
  ws->last_kind_id = kind_id;
  ws->close_code = close_code;
  ws->last_error_id = error_id;
  return payload_id;
}

int32_t fz_native_net_websocket_kind(int32_t ws_handle) {
  fz_websocket_state* ws = fz_websocket_state_get(ws_handle);
  return ws == NULL ? fz_intern_slice("error", 5) : ws->last_kind_id;
}

int32_t fz_native_net_websocket_close_code(int32_t ws_handle) {
  fz_websocket_state* ws = fz_websocket_state_get(ws_handle);
  return ws == NULL ? 0 : ws->close_code;
}

int32_t fz_native_net_websocket_error(int32_t ws_handle) {
  fz_websocket_state* ws = fz_websocket_state_get(ws_handle);
  return ws == NULL ? fz_intern_slice("websocket not found", 19) : ws->last_error_id;
}

int32_t fz_native_net_websocket_write_text(int32_t ws_handle, int32_t payload_id) {
  fz_websocket_state* ws = fz_websocket_state_get(ws_handle);
  const char* payload = fz_lookup_string(payload_id);
  return ws == NULL ? -1 : fz_websocket_write_frame(ws->fd, 0x1u, payload, strlen(payload == NULL ? "" : payload));
}

int32_t fz_native_net_websocket_write_binary(int32_t ws_handle, int32_t payload_id) {
  fz_websocket_state* ws = fz_websocket_state_get(ws_handle);
  const char* payload = fz_lookup_string(payload_id);
  return ws == NULL ? -1 : fz_websocket_write_frame(ws->fd, 0x2u, payload, strlen(payload == NULL ? "" : payload));
}

int32_t fz_native_net_websocket_ping(int32_t ws_handle, int32_t payload_id) {
  fz_websocket_state* ws = fz_websocket_state_get(ws_handle);
  const char* payload = fz_lookup_string(payload_id);
  return ws == NULL ? -1 : fz_websocket_write_frame(ws->fd, 0x9u, payload, strlen(payload == NULL ? "" : payload));
}

int32_t fz_native_net_websocket_pong(int32_t ws_handle, int32_t payload_id) {
  fz_websocket_state* ws = fz_websocket_state_get(ws_handle);
  const char* payload = fz_lookup_string(payload_id);
  return ws == NULL ? -1 : fz_websocket_write_frame(ws->fd, 0xAu, payload, strlen(payload == NULL ? "" : payload));
}

int32_t fz_native_net_websocket_close(int32_t ws_handle, int32_t code, int32_t reason_id) {
  fz_websocket_state* ws = fz_websocket_state_get(ws_handle);
  if (ws == NULL) {
    return -1;
  }
  const char* reason = fz_lookup_string(reason_id);
  size_t reason_len = strlen(reason == NULL ? "" : reason);
  char* payload = (char*)malloc(reason_len + 2);
  if (payload == NULL) {
    return -1;
  }
  payload[0] = (char)((code >> 8) & 0xFF);
  payload[1] = (char)(code & 0xFF);
  if (reason_len > 0) {
    memcpy(payload + 2, reason, reason_len);
  }
  int rc = fz_websocket_write_frame(ws->fd, 0x8u, payload, reason_len + 2);
  free(payload);
  ws->closed = 1;
  return rc;
}

"#
}
