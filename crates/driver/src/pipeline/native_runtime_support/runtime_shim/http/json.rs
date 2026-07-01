pub(super) fn section() -> &'static str {
    r#"
static int fz_http_header_key_matches(const char* header_line, const char* key) {
  if (header_line == NULL || key == NULL) {
    return 0;
  }
  const char* colon = strchr(header_line, ':');
  if (colon == NULL) {
    return 0;
  }
  size_t key_len = strlen(key);
  size_t header_key_len = (size_t)(colon - header_line);
  while (header_key_len > 0 && isspace((unsigned char)header_line[header_key_len - 1])) {
    header_key_len--;
  }
  return header_key_len == key_len && strncasecmp(header_line, key, key_len) == 0;
}

static int fz_http_header_upsert(char** header_buf, int* header_count, const char* key, const char* value) {
  if (header_buf == NULL || header_count == NULL || key == NULL || key[0] == '\0') {
    return -1;
  }
  if (value == NULL) {
    value = "";
  }
  size_t n = strlen(key) + strlen(value) + 3;
  char* kv = (char*)malloc(n);
  if (kv == NULL) {
    return -1;
  }
  snprintf(kv, n, "%s: %s", key, value);
  for (int i = 0; i < *header_count; i++) {
    if (fz_http_header_key_matches(header_buf[i], key)) {
      free(header_buf[i]);
      header_buf[i] = kv;
      return 0;
    }
  }
  if (*header_count >= FZ_MAX_HTTP_HEADERS) {
    free(kv);
    return -1;
  }
  header_buf[*header_count] = kv;
  (*header_count)++;
  return 0;
}

int32_t fz_native_json_from_list(int32_t list_handle) {
  pthread_mutex_lock(&fz_list_lock);
  fz_list_state* list = fz_list_get(list_handle);
  if (list == NULL) {
    pthread_mutex_unlock(&fz_list_lock);
    return fz_intern_slice("[]", 2);
  }
  fz_bytes_buf out;
  fz_bytes_buf_init(&out);
  if (fz_bytes_buf_append(&out, "[", 1) != 0) {
    pthread_mutex_unlock(&fz_list_lock);
    return 0;
  }
  for (int i = 0; i < list->count; i++) {
    if (i > 0 && fz_bytes_buf_append(&out, ",", 1) != 0) {
      fz_bytes_buf_free(&out);
      pthread_mutex_unlock(&fz_list_lock);
      return 0;
    }
    const char* raw = list->items[i];
    if (raw == NULL || raw[0] == '\0') {
      raw = "null";
    }
    if (fz_bytes_buf_append(&out, raw, strlen(raw)) != 0) {
      fz_bytes_buf_free(&out);
      pthread_mutex_unlock(&fz_list_lock);
      return 0;
    }
  }
  if (fz_bytes_buf_append(&out, "]", 1) != 0) {
    fz_bytes_buf_free(&out);
    pthread_mutex_unlock(&fz_list_lock);
    return 0;
  }
  pthread_mutex_unlock(&fz_list_lock);
  return fz_intern_owned(out.data);
}

int32_t fz_native_json_from_map(int32_t map_handle) {
  pthread_mutex_lock(&fz_map_lock);
  fz_map_state* map = fz_map_get(map_handle);
  if (map == NULL) {
    pthread_mutex_unlock(&fz_map_lock);
    return fz_intern_slice("{}", 2);
  }
  fz_bytes_buf out;
  fz_bytes_buf_init(&out);
  if (fz_bytes_buf_append(&out, "{", 1) != 0) {
    pthread_mutex_unlock(&fz_map_lock);
    return 0;
  }
  for (int i = 0; i < map->count; i++) {
    if (i > 0 && fz_bytes_buf_append(&out, ",", 1) != 0) {
      fz_bytes_buf_free(&out);
      pthread_mutex_unlock(&fz_map_lock);
      return 0;
    }
    if (fz_bytes_buf_append(&out, "\"", 1) != 0
        || fz_bytes_buf_append_json_escaped(&out, map->keys[i] == NULL ? "" : map->keys[i]) != 0
        || fz_bytes_buf_append(&out, "\":", 2) != 0) {
      fz_bytes_buf_free(&out);
      pthread_mutex_unlock(&fz_map_lock);
      return 0;
    }
    const char* raw = map->values[i];
    if (raw == NULL || raw[0] == '\0') {
      raw = "null";
    }
    if (fz_bytes_buf_append(&out, raw, strlen(raw)) != 0) {
      fz_bytes_buf_free(&out);
      pthread_mutex_unlock(&fz_map_lock);
      return 0;
    }
  }
  if (fz_bytes_buf_append(&out, "}", 1) != 0) {
    fz_bytes_buf_free(&out);
    pthread_mutex_unlock(&fz_map_lock);
    return 0;
  }
  pthread_mutex_unlock(&fz_map_lock);
  return fz_intern_owned(out.data);
}

int32_t fz_native_json_to_list(int32_t json_id) {
  int32_t value_id = fz_json_value_get_id(json_id);
  const char* raw = fz_lookup_string(value_id);
  const char* p = fz_json_ws(raw);
  if (p == NULL || *p != '[') {
    return -1;
  }
  int32_t handle = fz_runtime_list_new();
  if (handle <= 0) {
    return -1;
  }
  p = fz_json_ws(p + 1);
  if (*p == ']') {
    return handle;
  }
  for (;;) {
    const char* value_start = p;
    if (fz_json_skip_value_token(&p, 0) != 0) {
      return -1;
    }
    int32_t item_id = fz_json_value_intern_text_from_slice(value_start, p);
    if (item_id <= 0 || fz_runtime_list_push(handle, item_id) != 0) {
      return -1;
    }
    p = fz_json_ws(p);
    if (*p == ',') {
      p = fz_json_ws(p + 1);
      continue;
    }
    if (*p == ']') {
      return handle;
    }
    return -1;
  }
  return handle;
}

int32_t fz_native_json_to_map(int32_t json_id) {
  int32_t value_id = fz_json_value_get_id(json_id);
  const char* raw = fz_lookup_string(value_id);
  const char* p = fz_json_ws(raw);
  if (p == NULL || *p != '{') {
    return -1;
  }
  int32_t handle = fz_runtime_map_new();
  if (handle <= 0) {
    return -1;
  }
  p = fz_json_ws(p + 1);
  if (*p == '}') {
    return handle;
  }
  for (;;) {
    char* key = NULL;
    if (fz_json_parse_string(&p, &key) != 0) {
      free(key);
      return -1;
    }
    p = fz_json_ws(p);
    if (*p != ':') {
      free(key);
      return -1;
    }
    p = fz_json_ws(p + 1);
    const char* value_start = p;
    if (fz_json_skip_value_token(&p, 0) != 0) {
      free(key);
      return -1;
    }
    int32_t key_id = fz_intern_owned(key);
    int32_t mapped_value_id = fz_json_value_intern_text_from_slice(value_start, p);
    if (key_id <= 0 || mapped_value_id <= 0 || fz_runtime_map_set(handle, key_id, mapped_value_id) != 0) {
      return -1;
    }
    p = fz_json_ws(p);
    if (*p == ',') {
      p = fz_json_ws(p + 1);
      continue;
    }
    if (*p == '}') {
      return handle;
    }
    return -1;
  }
  return handle;
}

int32_t fz_native_json_keys(int32_t json_value_handle) {
  int32_t value_id = fz_json_value_get_id(json_value_handle);
  const char* raw = fz_lookup_string(value_id);
  if (raw == NULL) {
    return -1;
  }
  const char* p = fz_json_ws(raw);
  if (p == NULL || *p != '{') {
    return -1;
  }
  pthread_mutex_lock(&fz_list_lock);
  int32_t handle = fz_list_alloc();
  fz_list_state* list = fz_list_get(handle);
  pthread_mutex_unlock(&fz_list_lock);
  if (list == NULL) {
    return -1;
  }
  p = fz_json_ws(p + 1);
  if (*p == '}') {
    return handle;
  }
  for (;;) {
    char* key = NULL;
    if (fz_json_parse_string(&p, &key) != 0) {
      free(key);
      return -1;
    }
    pthread_mutex_lock(&fz_list_lock);
    list = fz_list_get(handle);
    if (list != NULL) {
      (void)fz_list_push_cstr(list, key == NULL ? "" : key);
    }
    pthread_mutex_unlock(&fz_list_lock);
    free(key);
    p = fz_json_ws(p);
    if (*p != ':') {
      return -1;
    }
    p = fz_json_ws(p + 1);
    if (fz_json_skip_value_token(&p, 0) != 0) {
      return -1;
    }
    p = fz_json_ws(p);
    if (*p == ',') {
      p = fz_json_ws(p + 1);
      continue;
    }
    if (*p == '}') {
      return handle;
    }
    return -1;
  }
}

int32_t fz_native_json_parse(int32_t json_id) {
  const char* raw = fz_lookup_string(json_id);
  const char* start = NULL;
  const char* end = NULL;
  if (fz_json_parse_value_slice(raw, &start, &end) != 0) {
    return -1;
  }
  return fz_json_value_alloc_from_slice(start, end);
}

static int fz_json_parse_index_key(const char* key, int* out_index) {
  if (key == NULL || key[0] == '\0' || out_index == NULL) {
    return -1;
  }
  long value = 0;
  for (const unsigned char* p = (const unsigned char*)key; *p != '\0'; p++) {
    if (!isdigit(*p)) {
      return -1;
    }
    value = (value * 10) + (*p - '0');
    if (value > INT_MAX) {
      return -1;
    }
  }
  *out_index = (int)value;
  return 0;
}

int32_t fz_native_json_get(int32_t json_value_handle, int32_t key_id) {
  int32_t value_id = fz_json_value_get_id(json_value_handle);
  const char* raw = fz_lookup_string(value_id);
  const char* key = fz_lookup_string(key_id);
  const char* start = NULL;
  const char* end = NULL;
  const char* root = fz_json_ws(raw);
  int rc = -1;
  if (root != NULL && *root == '[') {
    int index = -1;
    if (fz_json_parse_index_key(key, &index) == 0) {
      rc = fz_json_array_lookup(raw, index, &start, &end);
    } else {
      rc = 0;
    }
  } else {
    rc = fz_json_object_lookup(raw, key == NULL ? "" : key, &start, &end);
  }
  if (rc <= 0) {
    return -1;
  }
  return fz_json_value_alloc_from_slice(start, end);
}

int32_t fz_native_json_get_str(int32_t json_value_handle, int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  int32_t child = fz_native_json_get(json_value_handle, key_id);
  if (child <= 0) {
    if (key != NULL && strcmp(key, "raw") == 0) {
      int32_t value_id = fz_json_value_get_id(json_value_handle);
      const char* raw = fz_lookup_string(value_id);
      if (raw == NULL) {
        return fz_intern_slice("", 0);
      }
      return fz_intern_slice(raw, strlen(raw));
    }
    return fz_intern_slice("", 0);
  }
  int32_t value_id = fz_json_value_get_id(child);
  const char* raw = fz_lookup_string(value_id);
  if (raw == NULL) {
    return fz_intern_slice("", 0);
  }
  const char* p = raw;
  char* out = NULL;
  if (fz_json_parse_string(&p, &out) != 0) {
    return fz_intern_slice("", 0);
  }
  p = fz_json_ws(p);
  if (*p != '\0' || out == NULL) {
    free(out);
    return fz_intern_slice("", 0);
  }
  return fz_intern_owned(out);
}

int32_t fz_native_json_has(int32_t json_value_handle, int32_t key_id) {
  int32_t value_id = fz_json_value_get_id(json_value_handle);
  const char* raw = fz_lookup_string(value_id);
  const char* key = fz_lookup_string(key_id);
  const char* start = NULL;
  const char* end = NULL;
  const char* root = fz_json_ws(raw);
  int rc = -1;
  if (root != NULL && *root == '[') {
    int index = -1;
    if (fz_json_parse_index_key(key, &index) == 0) {
      rc = fz_json_array_lookup(raw, index, &start, &end);
    } else {
      rc = 0;
    }
  } else {
    rc = fz_json_object_lookup(raw, key == NULL ? "" : key, &start, &end);
  }
  return rc > 0 ? 1 : 0;
}

int32_t fz_native_json_path(int32_t json_value_handle, int32_t path_id) {
  int32_t current = json_value_handle;
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') {
    return current;
  }
  const char* p = fz_json_ws(path);
  if (*p == '$') {
    p++;
  }
  if (*p == '.') {
    p++;
  }

  while (*p != '\0') {
    p = fz_json_ws(p);
    if (*p == '\0') {
      break;
    }
    if (*p == '.') {
      p++;
      continue;
    }
    if (*p == '[') {
      p++;
      int idx = 0;
      if (!isdigit((unsigned char)*p)) {
        return -1;
      }
      while (isdigit((unsigned char)*p)) {
        idx = (idx * 10) + (*p - '0');
        p++;
      }
      if (*p != ']') {
        return -1;
      }
      p++;
      int32_t value_id = fz_json_value_get_id(current);
      const char* raw = fz_lookup_string(value_id);
      const char* start = NULL;
      const char* end = NULL;
      int rc = fz_json_array_lookup(raw, idx, &start, &end);
      if (rc <= 0) {
        return -1;
      }
      current = fz_json_value_alloc_from_slice(start, end);
      if (current <= 0) {
        return -1;
      }
      continue;
    }
    const char* key_start = p;
    while (*p != '\0' && *p != '.' && *p != '[' && !isspace((unsigned char)*p)) {
      p++;
    }
    if (p == key_start) {
      return -1;
    }
    int32_t key_id = fz_intern_slice(key_start, (size_t)(p - key_start));
    current = fz_native_json_get(current, key_id);
    if (current <= 0) {
      return -1;
    }
  }

  return current;
}

"#
}
