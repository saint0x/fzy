pub(super) fn section() -> &'static str {
    r#"

static int32_t fz_log_level_value(const char* level) {
  if (level == NULL) return 0;
  if (strcmp(level, "error") == 0) return 2;
  if (strcmp(level, "warn") == 0) return 1;
  return 0;
}

static int32_t fz_log_stream_mode = -1;

static FILE* fz_log_stream(void) {
  int32_t target = fz_log_sink == 1 ? 1 : 0;
  FILE* stream = target == 1 ? stderr : stdout;
  if (fz_log_stream_mode != target) {
    setvbuf(stream, NULL, _IOLBF, 0);
    fz_log_stream_mode = target;
  }
  return stream;
}

static int32_t fz_log_emit(const char* level, const char* message, const char* fields) {
  if (level == NULL) level = "info";
  if (message == NULL) message = "";
  if (fields == NULL) fields = "{}";
  if (!fz_log_enabled) {
    return 0;
  }
  if (fz_log_level_value(level) < fz_log_min_level) {
    return 0;
  }
  int64_t ts = fz_now_ms();
  FILE* stream = fz_log_stream();
  if (fz_log_json) {
    fprintf(stream, "{\"ts\":%lld,\"level\":\"%s\",\"msg\":\"", (long long)ts, level);
    for (const char* p = message; *p; p++) {
      if (*p == '"' || *p == '\\') fputc('\\', stream);
      fputc(*p, stream);
    }
    fprintf(stream, "\",\"fields\":%s}\n", fields[0] == '\0' ? "{}" : fields);
  } else if (fields[0] != '\0' && strcmp(fields, "{}") != 0) {
    fprintf(stream, "[%lld] %s %s | fields=%s\n", (long long)ts, level, message, fields);
  } else {
    fprintf(stream, "[%lld] %s %s\n", (long long)ts, level, message);
  }
  return 0;
}

int32_t fz_native_log_info(int32_t message_id, int32_t fields_id) {
  return fz_log_emit("info", fz_lookup_string(message_id), fz_lookup_string(fields_id));
}

int32_t fz_native_log_warn(int32_t message_id, int32_t fields_id) {
  return fz_log_emit("warn", fz_lookup_string(message_id), fz_lookup_string(fields_id));
}

int32_t fz_native_log_error(int32_t message_id, int32_t fields_id) {
  return fz_log_emit("error", fz_lookup_string(message_id), fz_lookup_string(fields_id));
}

int32_t fz_native_log_fields_map(int32_t map_handle) {
  return fz_native_json_from_map(map_handle);
}

int32_t fz_native_log_set_json(int32_t enabled) {
  fz_log_json = enabled != 0 ? 1 : 0;
  return 0;
}

int32_t fz_native_log_set_enabled(int32_t enabled) {
  fz_log_enabled = enabled != 0 ? 1 : 0;
  return 0;
}

int32_t fz_native_log_set_level(int32_t level_id) {
  const char* level = fz_lookup_string(level_id);
  if (level == NULL || level[0] == '\0' || strcmp(level, "info") == 0) {
    fz_log_min_level = 0;
    return 0;
  }
  if (strcmp(level, "warn") == 0) {
    fz_log_min_level = 1;
    return 0;
  }
  if (strcmp(level, "error") == 0) {
    fz_log_min_level = 2;
    return 0;
  }
  fz_set_last_error(EINVAL, 3, "log.set_level failed: expected info, warn, or error");
  return -1;
}

int32_t fz_native_log_set_sink(int32_t sink_id) {
  const char* sink = fz_lookup_string(sink_id);
  if (sink == NULL || sink[0] == '\0' || strcmp(sink, "stdout") == 0) {
    fz_log_sink = 0;
    return 0;
  }
  if (strcmp(sink, "stderr") == 0) {
    fz_log_sink = 1;
    return 0;
  }
  fz_set_last_error(EINVAL, 3, "log.set_sink failed: expected stdout or stderr");
  return -1;
}

int32_t fz_native_log_correlation_id(int32_t conn_fd) {
  return fz_native_net_request_id(conn_fd);
}

int32_t fz_native_time_sleep_ms(int32_t ms) {
  if (ms > 0) {
    usleep((useconds_t)ms * 1000);
  }
  return 0;
}

int32_t fz_native_time_elapsed_ms(int32_t start_ms) {
  int64_t now = fz_now_ms();
  return (int32_t)(now - (int64_t)start_ms);
}

int32_t fz_native_time_deadline_after(int32_t delta_ms) {
  int64_t now = fz_now_ms();
  return (int32_t)(now + (int64_t)delta_ms);
}

int32_t fz_native_crypto_random_hex(int32_t len_bytes) {
  if (len_bytes < 0) {
    fz_set_last_error(EINVAL, 3, "crypto.random_hex failed: len must be >= 0");
    return fz_intern_slice("", 0);
  }
  size_t len = (size_t)len_bytes;
  uint8_t* raw = len == 0 ? NULL : (uint8_t*)malloc(len);
  if (len > 0 && raw == NULL) {
    fz_set_last_error(ENOMEM, 3, "crypto.random_hex failed: alloc failed");
    return fz_intern_slice("", 0);
  }
  if (fz_crypto_fill_random(raw, len) != 0) {
    if (raw != NULL) {
      fz_crypto_memzero(raw, len);
    }
    free(raw);
    fz_set_last_error(errno == 0 ? EIO : errno, 3, "crypto.random_hex failed: entropy unavailable");
    return fz_intern_slice("", 0);
  }
  char* encoded = fz_crypto_hex_encode(raw == NULL ? (const uint8_t*)"" : raw, len);
  if (raw != NULL) {
    fz_crypto_memzero(raw, len);
  }
  free(raw);
  if (encoded == NULL) {
    fz_set_last_error(ENOMEM, 3, "crypto.random_hex failed: hex encode alloc failed");
    return fz_intern_slice("", 0);
  }
  fz_set_last_error(0, 0, "");
  return fz_intern_owned(encoded);
}

int32_t fz_native_crypto_random_base64(int32_t len_bytes) {
  if (len_bytes < 0) {
    fz_set_last_error(EINVAL, 3, "crypto.random_base64 failed: len must be >= 0");
    return fz_intern_slice("", 0);
  }
  size_t len = (size_t)len_bytes;
  uint8_t* raw = len == 0 ? NULL : (uint8_t*)malloc(len);
  if (len > 0 && raw == NULL) {
    fz_set_last_error(ENOMEM, 3, "crypto.random_base64 failed: alloc failed");
    return fz_intern_slice("", 0);
  }
  if (fz_crypto_fill_random(raw, len) != 0) {
    if (raw != NULL) {
      fz_crypto_memzero(raw, len);
    }
    free(raw);
    fz_set_last_error(errno == 0 ? EIO : errno, 3, "crypto.random_base64 failed: entropy unavailable");
    return fz_intern_slice("", 0);
  }
  char* encoded = fz_crypto_base64_encode_alloc(raw == NULL ? (const uint8_t*)"" : raw, len);
  if (raw != NULL) {
    fz_crypto_memzero(raw, len);
  }
  free(raw);
  if (encoded == NULL) {
    fz_set_last_error(ENOMEM, 3, "crypto.random_base64 failed: base64 encode alloc failed");
    return fz_intern_slice("", 0);
  }
  fz_set_last_error(0, 0, "");
  return fz_intern_owned(encoded);
}

int32_t fz_native_crypto_sha256(int32_t input_id) {
  const char* input = fz_lookup_string(input_id);
  size_t len = input == NULL ? 0 : strlen(input);
  uint8_t digest[32];
  fz_sha256_hash((const uint8_t*)(input == NULL ? "" : input), len, digest);
  char* encoded = fz_crypto_hex_encode(digest, sizeof(digest));
  fz_crypto_memzero(digest, sizeof(digest));
  if (encoded == NULL) {
    fz_set_last_error(ENOMEM, 3, "crypto.sha256 failed: hex encode alloc failed");
    return fz_intern_slice("", 0);
  }
  fz_set_last_error(0, 0, "");
  return fz_intern_owned(encoded);
}

int32_t fz_native_crypto_hmac_sha256(int32_t key_id, int32_t data_id) {
  const char* key = fz_lookup_string(key_id);
  const char* data = fz_lookup_string(data_id);
  uint8_t digest[32];
  fz_hmac_sha256_hash(
      (const uint8_t*)(key == NULL ? "" : key),
      key == NULL ? 0 : strlen(key),
      (const uint8_t*)(data == NULL ? "" : data),
      data == NULL ? 0 : strlen(data),
      digest);
  char* encoded = fz_crypto_hex_encode(digest, sizeof(digest));
  fz_crypto_memzero(digest, sizeof(digest));
  if (encoded == NULL) {
    fz_set_last_error(ENOMEM, 3, "crypto.hmac_sha256 failed: hex encode alloc failed");
    return fz_intern_slice("", 0);
  }
  fz_set_last_error(0, 0, "");
  return fz_intern_owned(encoded);
}

int32_t fz_native_crypto_constant_time_eq(int32_t left_id, int32_t right_id) {
  const char* left = fz_lookup_string(left_id);
  const char* right = fz_lookup_string(right_id);
  size_t left_len = left == NULL ? 0 : strlen(left);
  size_t right_len = right == NULL ? 0 : strlen(right);
  size_t max_len = left_len > right_len ? left_len : right_len;
  unsigned char diff = (unsigned char)(left_len ^ right_len);
  for (size_t i = 0; i < max_len; i++) {
    unsigned char a = i < left_len ? (unsigned char)left[i] : 0;
    unsigned char b = i < right_len ? (unsigned char)right[i] : 0;
    diff |= (unsigned char)(a ^ b);
  }
  fz_set_last_error(0, 0, "");
  return diff == 0 ? 1 : 0;
}

int32_t fz_native_crypto_base64_encode(int32_t input_id) {
  const char* input = fz_lookup_string(input_id);
  size_t len = input == NULL ? 0 : strlen(input);
  char* encoded = fz_crypto_base64_encode_alloc((const uint8_t*)(input == NULL ? "" : input), len);
  if (encoded == NULL) {
    fz_set_last_error(ENOMEM, 3, "crypto.base64_encode failed: alloc failed");
    return fz_intern_slice("", 0);
  }
  fz_set_last_error(0, 0, "");
  return fz_intern_owned(encoded);
}

int32_t fz_native_crypto_base64_decode(int32_t input_id) {
  const char* input = fz_lookup_string(input_id);
  uint8_t* decoded = NULL;
  size_t decoded_len = 0;
  if (fz_crypto_base64_decode_alloc(input == NULL ? "" : input, &decoded, &decoded_len) != 0) {
    fz_set_last_error(EINVAL, 3, "crypto.base64_decode failed: invalid base64 input");
    return fz_intern_slice("", 0);
  }
  if (decoded != NULL && memchr(decoded, '\0', decoded_len) != NULL) {
    fz_crypto_memzero(decoded, decoded_len);
    free(decoded);
    fz_set_last_error(EINVAL, 3, "crypto.base64_decode failed: decoded bytes are not text-safe");
    return fz_intern_slice("", 0);
  }
  int32_t out = fz_intern_slice((const char*)(decoded == NULL ? (const uint8_t*)"" : decoded), decoded_len);
  if (decoded != NULL) {
    fz_crypto_memzero(decoded, decoded_len);
  }
  free(decoded);
  fz_set_last_error(0, 0, "");
  return out;
}

int32_t fz_native_crypto_base64_url_encode(int32_t input_id) {
  const char* input = fz_lookup_string(input_id);
  size_t len = input == NULL ? 0 : strlen(input);
  char* encoded =
      fz_crypto_base64_url_encode_alloc((const uint8_t*)(input == NULL ? "" : input), len);
  if (encoded == NULL) {
    fz_set_last_error(ENOMEM, 3, "crypto.base64_url_encode failed: alloc failed");
    return fz_intern_slice("", 0);
  }
  fz_set_last_error(0, 0, "");
  return fz_intern_owned(encoded);
}

int32_t fz_native_crypto_base64_url_decode(int32_t input_id) {
  const char* input = fz_lookup_string(input_id);
  uint8_t* decoded = NULL;
  size_t decoded_len = 0;
  if (fz_crypto_base64_url_decode_alloc(input == NULL ? "" : input, &decoded, &decoded_len) != 0) {
    fz_set_last_error(EINVAL, 3, "crypto.base64_url_decode failed: invalid base64url input");
    return fz_intern_slice("", 0);
  }
  if (decoded != NULL && memchr(decoded, '\0', decoded_len) != NULL) {
    fz_crypto_memzero(decoded, decoded_len);
    free(decoded);
    fz_set_last_error(EINVAL, 3, "crypto.base64_url_decode failed: decoded bytes are not text-safe");
    return fz_intern_slice("", 0);
  }
  int32_t out = fz_intern_slice((const char*)(decoded == NULL ? (const uint8_t*)"" : decoded), decoded_len);
  if (decoded != NULL) {
    fz_crypto_memzero(decoded, decoded_len);
  }
  free(decoded);
  fz_set_last_error(0, 0, "");
  return out;
}

"#
}
