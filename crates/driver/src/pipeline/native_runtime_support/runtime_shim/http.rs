pub(super) fn runtime_shim_section_http() -> &'static str {
    r#"
static int32_t fz_native_str_concat_parts(const char** parts, int count) {
  if (count <= 0) {
    return fz_intern_slice("", 0);
  }
  size_t total = 1;
  for (int i = 0; i < count; i++) {
    const char* part = parts[i] == NULL ? "" : parts[i];
    total += strlen(part);
  }
  char* out = (char*)malloc(total);
  if (out == NULL) {
    return 0;
  }
  size_t used = 0;
  for (int i = 0; i < count; i++) {
    const char* part = parts[i] == NULL ? "" : parts[i];
    size_t len = strlen(part);
    if (len > 0) {
      memcpy(out + used, part, len);
      used += len;
    }
  }
  out[used] = '\0';
  return fz_intern_owned(out);
}

int32_t fz_native_str_concat2(int32_t a_id, int32_t b_id) {
  const char* parts[2] = {fz_lookup_string(a_id), fz_lookup_string(b_id)};
  return fz_native_str_concat_parts(parts, 2);
}

int32_t fz_native_str_concat3(int32_t a_id, int32_t b_id, int32_t c_id) {
  const char* parts[3] = {fz_lookup_string(a_id), fz_lookup_string(b_id), fz_lookup_string(c_id)};
  return fz_native_str_concat_parts(parts, 3);
}

int32_t fz_native_str_concat4(int32_t a_id, int32_t b_id, int32_t c_id, int32_t d_id) {
  const char* parts[4] = {
      fz_lookup_string(a_id), fz_lookup_string(b_id), fz_lookup_string(c_id), fz_lookup_string(d_id)};
  return fz_native_str_concat_parts(parts, 4);
}

int32_t fz_native_str_from_i32(int32_t value) {
  char rendered[32];
  snprintf(rendered, sizeof(rendered), "%d", value);
  return fz_intern_slice(rendered, strlen(rendered));
}

int32_t fz_native_str_from_bool(int32_t value) {
  const char* rendered = value == 0 ? "false" : "true";
  return fz_intern_slice(rendered, strlen(rendered));
}

int32_t fz_native_str_repeat(int32_t value_id, int32_t count) {
  const char* value = fz_lookup_string(value_id);
  if (value == NULL || count <= 0) {
    return fz_intern_slice("", 0);
  }
  size_t value_len = strlen(value);
  if (value_len == 0) {
    return fz_intern_slice("", 0);
  }
  size_t total = value_len * (size_t)count;
  char* out = (char*)malloc(total + 1);
  if (out == NULL) {
    return 0;
  }
  size_t used = 0;
  for (int32_t i = 0; i < count; i++) {
    memcpy(out + used, value, value_len);
    used += value_len;
  }
  out[used] = '\0';
  return fz_intern_owned(out);
}

int32_t fz_native_str_contains(int32_t value_id, int32_t needle_id) {
  const char* value = fz_lookup_string(value_id);
  const char* needle = fz_lookup_string(needle_id);
  if (value == NULL || needle == NULL) {
    return 0;
  }
  return strstr(value, needle) != NULL ? 1 : 0;
}

int32_t fz_native_str_starts_with(int32_t value_id, int32_t prefix_id) {
  const char* value = fz_lookup_string(value_id);
  const char* prefix = fz_lookup_string(prefix_id);
  if (value == NULL || prefix == NULL) {
    return 0;
  }
  size_t prefix_len = strlen(prefix);
  return strncmp(value, prefix, prefix_len) == 0 ? 1 : 0;
}

int32_t fz_native_str_ends_with(int32_t value_id, int32_t suffix_id) {
  const char* value = fz_lookup_string(value_id);
  const char* suffix = fz_lookup_string(suffix_id);
  if (value == NULL || suffix == NULL) {
    return 0;
  }
  size_t value_len = strlen(value);
  size_t suffix_len = strlen(suffix);
  if (suffix_len > value_len) {
    return 0;
  }
  return memcmp(value + (value_len - suffix_len), suffix, suffix_len) == 0 ? 1 : 0;
}

int32_t fz_native_str_trim(int32_t value_id) {
  const char* value = fz_lookup_string(value_id);
  if (value == NULL) {
    return fz_intern_slice("", 0);
  }
  const unsigned char* start = (const unsigned char*)value;
  while (*start != '\0' && isspace(*start)) {
    start++;
  }
  const unsigned char* end = start + strlen((const char*)start);
  while (end > start && isspace(*(end - 1))) {
    end--;
  }
  return fz_intern_slice((const char*)start, (size_t)(end - start));
}

int32_t fz_native_str_replace(int32_t value_id, int32_t from_id, int32_t to_id) {
  const char* value = fz_lookup_string(value_id);
  const char* from = fz_lookup_string(from_id);
  const char* to = fz_lookup_string(to_id);
  if (value == NULL) value = "";
  if (from == NULL) from = "";
  if (to == NULL) to = "";

  size_t value_len = strlen(value);
  size_t from_len = strlen(from);
  size_t to_len = strlen(to);
  if (from_len == 0) {
    return fz_intern_slice(value, value_len);
  }

  size_t occurrences = 0;
  const char* cursor = value;
  while ((cursor = strstr(cursor, from)) != NULL) {
    occurrences++;
    cursor += from_len;
  }
  if (occurrences == 0) {
    return fz_intern_slice(value, value_len);
  }
  size_t out_len = value_len;
  if (to_len >= from_len) {
    out_len += occurrences * (to_len - from_len);
  } else {
    out_len -= occurrences * (from_len - to_len);
  }
  char* out = (char*)malloc(out_len + 1);
  if (out == NULL) {
    return 0;
  }
  const char* src = value;
  char* dst = out;
  while (1) {
    const char* hit = strstr(src, from);
    if (hit == NULL) {
      size_t tail = strlen(src);
      memcpy(dst, src, tail);
      dst += tail;
      break;
    }
    size_t prefix = (size_t)(hit - src);
    memcpy(dst, src, prefix);
    dst += prefix;
    if (to_len > 0) {
      memcpy(dst, to, to_len);
      dst += to_len;
    }
    src = hit + from_len;
  }
  *dst = '\0';
  return fz_intern_owned(out);
}

int32_t fz_native_str_len(int32_t value_id) {
  const char* value = fz_lookup_string(value_id);
  return value == NULL ? 0 : (int32_t)strlen(value);
}

int32_t fz_native_str_visible_len_ansi(int32_t value_id) {
  const unsigned char* value = (const unsigned char*)fz_lookup_string(value_id);
  if (value == NULL) {
    return 0;
  }
  int32_t visible = 0;
  size_t index = 0;
  while (value[index] != '\0') {
    if (value[index] == 0x1b && value[index + 1] == '[') {
      index += 2;
      while (value[index] != '\0' && value[index] != 'm') {
        index++;
      }
      if (value[index] == 'm') {
        index++;
      }
      continue;
    }
    visible++;
    index++;
  }
  return visible;
}

int32_t fz_native_str_slice(int32_t value_id, int32_t start, int32_t end_exclusive) {
  const char* value = fz_lookup_string(value_id);
  if (value == NULL) {
    return fz_intern_slice("", 0);
  }
  int32_t value_len = (int32_t)strlen(value);
  int32_t begin = start < 0 ? 0 : start;
  if (begin > value_len) {
    begin = value_len;
  }
  int32_t end = end_exclusive < 0 ? 0 : end_exclusive;
  if (end > value_len) {
    end = value_len;
  }
  if (end <= begin) {
    return fz_intern_slice("", 0);
  }
  return fz_intern_slice(value + begin, (size_t)(end - begin));
}

int32_t fz_native_str_upper_ascii(int32_t value_id) {
  const char* value = fz_lookup_string(value_id);
  if (value == NULL) {
    return fz_intern_slice("", 0);
  }
  size_t len = strlen(value);
  char* out = (char*)malloc(len + 1);
  if (out == NULL) {
    return 0;
  }
  for (size_t i = 0; i < len; i++) {
    unsigned char ch = (unsigned char)value[i];
    out[i] = (char)(ch >= 'a' && ch <= 'z' ? (ch - ('a' - 'A')) : ch);
  }
  out[len] = '\0';
  return fz_intern_owned(out);
}

int32_t fz_native_str_lower_ascii(int32_t value_id) {
  const char* value = fz_lookup_string(value_id);
  if (value == NULL) {
    return fz_intern_slice("", 0);
  }
  size_t len = strlen(value);
  char* out = (char*)malloc(len + 1);
  if (out == NULL) {
    return 0;
  }
  for (size_t i = 0; i < len; i++) {
    unsigned char ch = (unsigned char)value[i];
    out[i] = (char)(ch >= 'A' && ch <= 'Z' ? (ch + ('a' - 'A')) : ch);
  }
  out[len] = '\0';
  return fz_intern_owned(out);
}

int32_t fz_native_str_split(int32_t value_id, int32_t sep_id) {
  const char* value = fz_lookup_string(value_id);
  const char* sep = fz_lookup_string(sep_id);
  if (value == NULL) value = "";
  if (sep == NULL) sep = "";
  int32_t list = fz_runtime_list_new();
  if (list < 0) {
    return -1;
  }
  size_t sep_len = strlen(sep);
  if (sep_len == 0) {
    (void)fz_runtime_list_push(list, fz_intern_slice(value, strlen(value)));
    return list;
  }
  const char* cursor = value;
  while (1) {
    const char* hit = strstr(cursor, sep);
    if (hit == NULL) {
      (void)fz_runtime_list_push(list, fz_intern_slice(cursor, strlen(cursor)));
      break;
    }
    (void)fz_runtime_list_push(list, fz_intern_slice(cursor, (size_t)(hit - cursor)));
    cursor = hit + sep_len;
  }
  return list;
}

int32_t fz_native_list_new(void) { return fz_runtime_list_new(); }
int32_t fz_native_list_push(int32_t handle, int32_t value_id) {
  return fz_runtime_list_push(handle, value_id);
}
int32_t fz_native_list_pop(int32_t handle) { return fz_runtime_list_pop(handle); }
int32_t fz_native_list_len(int32_t handle) { return fz_runtime_list_len(handle); }
int32_t fz_native_list_get(int32_t handle, int32_t index) {
  return fz_runtime_list_get(handle, index);
}
int32_t fz_native_list_set(int32_t handle, int32_t index, int32_t value_id) {
  return fz_runtime_list_set(handle, index, value_id);
}
int32_t fz_native_list_clear(int32_t handle) { return fz_runtime_list_clear(handle); }
int32_t fz_native_list_join(int32_t handle, int32_t sep_id) {
  return fz_runtime_list_join(handle, sep_id);
}

int32_t fz_native_map_new(void) { return fz_runtime_map_new(); }
int32_t fz_native_map_set(int32_t handle, int32_t key_id, int32_t value_id) {
  return fz_runtime_map_set(handle, key_id, value_id);
}
int32_t fz_native_map_get(int32_t handle, int32_t key_id) {
  return fz_runtime_map_get(handle, key_id);
}
int32_t fz_native_map_has(int32_t handle, int32_t key_id) {
  return fz_runtime_map_has(handle, key_id);
}
int32_t fz_native_map_delete(int32_t handle, int32_t key_id) {
  return fz_runtime_map_delete(handle, key_id);
}
int32_t fz_native_map_keys(int32_t handle) { return fz_runtime_map_keys(handle); }
int32_t fz_native_map_len(int32_t handle) { return fz_runtime_map_len(handle); }

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
  size_t total = 3;
  for (int i = 0; i < list->count; i++) {
    const char* raw = list->items[i];
    total += strlen(raw == NULL || raw[0] == '\0' ? "null" : raw) + 1;
  }
  char* out = (char*)malloc(total);
  if (out == NULL) {
    pthread_mutex_unlock(&fz_list_lock);
    return 0;
  }
  size_t used = 0;
  out[used++] = '[';
  for (int i = 0; i < list->count; i++) {
    if (i > 0) out[used++] = ',';
    const char* raw = list->items[i];
    if (raw == NULL || raw[0] == '\0') {
      raw = "null";
    }
    size_t n = strlen(raw);
    memcpy(out + used, raw, n);
    used += n;
  }
  out[used++] = ']';
  out[used] = '\0';
  pthread_mutex_unlock(&fz_list_lock);
  return fz_intern_owned(out);
}

int32_t fz_native_json_from_map(int32_t map_handle) {
  pthread_mutex_lock(&fz_map_lock);
  fz_map_state* map = fz_map_get(map_handle);
  if (map == NULL) {
    pthread_mutex_unlock(&fz_map_lock);
    return fz_intern_slice("{}", 2);
  }
  size_t total = 3;
  for (int i = 0; i < map->count; i++) {
    char* k = fz_json_escape_owned(map->keys[i] == NULL ? "" : map->keys[i]);
    const char* raw = map->values[i];
    if (k != NULL) {
      total += strlen(k) + strlen(raw == NULL || raw[0] == '\0' ? "null" : raw) + 5;
    }
    free(k);
  }
  char* out = (char*)malloc(total);
  if (out == NULL) {
    pthread_mutex_unlock(&fz_map_lock);
    return 0;
  }
  size_t used = 0;
  out[used++] = '{';
  for (int i = 0; i < map->count; i++) {
    if (i > 0) out[used++] = ',';
    char* k = fz_json_escape_owned(map->keys[i] == NULL ? "" : map->keys[i]);
    if (k == NULL) {
      free(k);
      out[used++] = '\"';
      out[used++] = '\"';
      out[used++] = ':';
      memcpy(out + used, "null", 4);
      used += 4;
      continue;
    }
    out[used++] = '\"';
    size_t kn = strlen(k);
    memcpy(out + used, k, kn);
    used += kn;
    out[used++] = '\"';
    out[used++] = ':';
    const char* raw = map->values[i];
    if (raw == NULL || raw[0] == '\0') {
      raw = "null";
    }
    size_t vn = strlen(raw);
    memcpy(out + used, raw, vn);
    used += vn;
    free(k);
  }
  out[used++] = '}';
  out[used] = '\0';
  pthread_mutex_unlock(&fz_map_lock);
  return fz_intern_owned(out);
}

int32_t fz_native_json_to_list(int32_t json_id) {
  int32_t value_id = fz_json_value_get_id(json_id);
  const char* raw = fz_lookup_string(value_id);
  char** items = NULL;
  int count = 0;
  if (fz_parse_json_string_array(raw, &items, &count) != 0) {
    return -1;
  }
  pthread_mutex_lock(&fz_list_lock);
  int32_t handle = fz_list_alloc();
  fz_list_state* list = fz_list_get(handle);
  if (list != NULL) {
    for (int i = 0; i < count; i++) {
      (void)fz_list_push_cstr(list, items[i] == NULL ? "" : items[i]);
    }
  }
  pthread_mutex_unlock(&fz_list_lock);
  fz_free_string_list(items, count);
  return handle;
}

int32_t fz_native_json_to_map(int32_t json_id) {
  int32_t value_id = fz_json_value_get_id(json_id);
  const char* raw = fz_lookup_string(value_id);
  char** pairs = NULL;
  int count = 0;
  if (fz_parse_json_env_object(raw, &pairs, &count) != 0) {
    return -1;
  }
  pthread_mutex_lock(&fz_map_lock);
  int32_t handle = fz_map_alloc();
  fz_map_state* map = fz_map_get(handle);
  if (map != NULL) {
    for (int i = 0; i < count && map->count < FZ_MAX_MAP_ENTRIES; i++) {
      char* eq = strchr(pairs[i], '=');
      if (eq == NULL) continue;
      *eq = '\0';
      map->keys[map->count] = strdup(pairs[i]);
      map->values[map->count] = strdup(eq + 1);
      if (map->keys[map->count] != NULL && map->values[map->count] != NULL) {
        map->count++;
      }
    }
  }
  pthread_mutex_unlock(&fz_map_lock);
  fz_free_string_list(pairs, count);
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

static void fz_http_set_last_result(int status_code, const char* body, const char* err) {
  if (body == NULL) {
    body = "";
  }
  if (err == NULL) {
    err = "";
  }
  pthread_mutex_lock(&fz_http_lock);
  fz_http_last_status = status_code;
  fz_http_last_body_id = fz_intern_slice(body, strlen(body));
  fz_http_last_error_id = fz_intern_slice(err, strlen(err));
  pthread_mutex_unlock(&fz_http_lock);
}

static int fz_http_extract_status(char* payload, size_t payload_len, int* status_code, size_t* body_len) {
  if (status_code != NULL) {
    *status_code = 0;
  }
  if (body_len != NULL) {
    *body_len = payload_len;
  }
  if (payload == NULL || payload_len == 0) {
    return -1;
  }
  ssize_t i = (ssize_t)payload_len - 1;
  while (i >= 0 && (payload[i] == '\n' || payload[i] == '\r' || payload[i] == ' ' || payload[i] == '\t')) {
    i--;
  }
  if (i < 2) {
    return -1;
  }
  if (!isdigit((unsigned char)payload[i]) || !isdigit((unsigned char)payload[i - 1]) || !isdigit((unsigned char)payload[i - 2])) {
    return -1;
  }
  int parsed = (payload[i - 2] - '0') * 100 + (payload[i - 1] - '0') * 10 + (payload[i] - '0');
  ssize_t j = i - 3;
  while (j >= 0 && (payload[j] == '\n' || payload[j] == '\r')) {
    j--;
  }
  if (status_code != NULL) {
    *status_code = parsed;
  }
  if (body_len != NULL) {
    *body_len = (size_t)(j + 1);
  }
  return 0;
}

static int fz_http_parse_status_line(const char* header_block, size_t header_len) {
  if (header_block == NULL || header_len == 0) {
    return 0;
  }
  const char* line_end = NULL;
  for (size_t i = 0; i + 1 < header_len; i++) {
    if (header_block[i] == '\r' && header_block[i + 1] == '\n') {
      line_end = header_block + i;
      break;
    }
  }
  if (line_end == NULL) {
    return 0;
  }
  const char* first_space = memchr(header_block, ' ', (size_t)(line_end - header_block));
  if (first_space == NULL || (line_end - first_space) < 4) {
    return 0;
  }
  if (!isdigit((unsigned char)first_space[1]) || !isdigit((unsigned char)first_space[2])
      || !isdigit((unsigned char)first_space[3])) {
    return 0;
  }
  return (first_space[1] - '0') * 100 + (first_space[2] - '0') * 10 + (first_space[3] - '0');
}

static void fz_bytes_buf_consume_prefix(fz_bytes_buf* buf, size_t count) {
  if (buf == NULL || count == 0) {
    return;
  }
  if (count >= buf->len) {
    buf->len = 0;
    if (buf->data != NULL) {
      buf->data[0] = '\0';
    }
    return;
  }
  memmove(buf->data, buf->data + count, buf->len - count);
  buf->len -= count;
  buf->data[buf->len] = '\0';
}

static int fz_http_stream_read_response_headers(
    int stdout_fd,
    fz_bytes_buf* body_buf,
    int* status_code_out) {
  if (status_code_out != NULL) {
    *status_code_out = 0;
  }
  fz_bytes_buf scratch;
  fz_bytes_buf_init(&scratch);
  for (;;) {
    for (size_t i = 0; i + 3 < scratch.len; i++) {
      if (scratch.data[i] == '\r' && scratch.data[i + 1] == '\n' && scratch.data[i + 2] == '\r'
          && scratch.data[i + 3] == '\n') {
        size_t header_len = i + 4;
        int status = fz_http_parse_status_line(scratch.data, header_len);
        if (status > 0 && status < 200 && status != 101) {
          fz_bytes_buf_consume_prefix(&scratch, header_len);
          break;
        }
        if (status_code_out != NULL) {
          *status_code_out = status;
        }
        if (scratch.len > header_len) {
          if (fz_bytes_buf_append(body_buf, scratch.data + header_len, scratch.len - header_len)
              != 0) {
            fz_bytes_buf_free(&scratch);
            return -1;
          }
        }
        fz_bytes_buf_free(&scratch);
        return status > 0 ? 0 : -1;
      }
    }

    char tmp[4096];
    ssize_t got = read(stdout_fd, tmp, sizeof(tmp));
    if (got > 0) {
      if (fz_bytes_buf_append(&scratch, tmp, (size_t)got) != 0) {
        fz_bytes_buf_free(&scratch);
        return -1;
      }
      continue;
    }
    if (got == 0) {
      fz_bytes_buf_free(&scratch);
      return -1;
    }
    if (errno == EINTR) {
      continue;
    }
    fz_bytes_buf_free(&scratch);
    return -1;
  }
}

static void fz_http_stream_refresh_error_locked(fz_http_stream_state* state, const char* fallback) {
  if (state == NULL) {
    return;
  }
  const char* msg = fallback == NULL ? "" : fallback;
  if (state->stderr_buf.data != NULL && state->stderr_buf.len > 0) {
    msg = state->stderr_buf.data;
  }
  state->error_id = fz_intern_slice(msg, strlen(msg));
}

static void fz_http_stream_compact_stdout_locked(fz_http_stream_state* state) {
  if (state == NULL || state->stdout_read_pos == 0) {
    return;
  }
  if (state->stdout_read_pos >= state->stdout_buf.len) {
    state->stdout_buf.len = 0;
    state->stdout_read_pos = 0;
    if (state->stdout_buf.data != NULL) {
      state->stdout_buf.data[0] = '\0';
    }
    return;
  }
  memmove(
      state->stdout_buf.data,
      state->stdout_buf.data + state->stdout_read_pos,
      state->stdout_buf.len - state->stdout_read_pos);
  state->stdout_buf.len -= state->stdout_read_pos;
  state->stdout_buf.data[state->stdout_buf.len] = '\0';
  state->stdout_read_pos = 0;
}

static void fz_http_stream_finish_locked(fz_http_stream_state* state, int wait_blocking) {
  if (state == NULL || state->done) {
    return;
  }
  int status = 0;
  pid_t waited = waitpid(state->pid, &status, wait_blocking ? 0 : WNOHANG);
  if (waited <= 0) {
    return;
  }
  state->done = 1;
  if (WIFEXITED(status)) {
    state->exit_code = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    state->exit_code = 128 + WTERMSIG(status);
  } else {
    state->exit_code = -1;
  }
  if (state->stderr_fd >= 0) {
    (void)fz_drain_fd(state->stderr_fd, &state->stderr_buf);
  }
  if (state->exit_code != 0 && (state->stderr_buf.data == NULL || state->stderr_buf.len == 0)) {
    char msg[128];
    snprintf(msg, sizeof(msg), "http stream transport exited=%d", state->exit_code);
    fz_http_stream_refresh_error_locked(state, msg);
  } else {
    fz_http_stream_refresh_error_locked(state, "");
  }
}

static int fz_http_stream_drain_locked(fz_http_stream_state* state) {
  if (state == NULL || state->closed) {
    return -1;
  }
  if (fz_async_current_task_cancelled()) {
    if (!state->done && state->pid > 0) {
      kill(state->pid, SIGTERM);
      fz_http_stream_finish_locked(state, 1);
    }
    state->eof = 1;
    fz_http_stream_refresh_error_locked(state, "http stream cancelled");
    return -1;
  }
  if (fz_async_deadline_expired()) {
    if (!state->done && state->pid > 0) {
      kill(state->pid, SIGTERM);
      fz_http_stream_finish_locked(state, 1);
    }
    state->eof = 1;
    fz_http_stream_refresh_error_locked(state, "http stream deadline expired");
    return -1;
  }
  size_t before_stdout = state->stdout_buf.len;
  size_t before_stderr = state->stderr_buf.len;
  int before_eof = state->eof;
  int before_done = state->done;
  if (state->stdout_fd >= 0) {
    int rc = fz_drain_fd(state->stdout_fd, &state->stdout_buf);
    if (rc < 0) {
      fz_http_stream_refresh_error_locked(state, "http stream stdout read failed");
      return -1;
    }
    if (rc == 1) {
      close(state->stdout_fd);
      state->stdout_fd = -1;
      state->eof = 1;
    }
  }
  if (state->stderr_fd >= 0) {
    int rc = fz_drain_fd(state->stderr_fd, &state->stderr_buf);
    if (rc < 0) {
      fz_http_stream_refresh_error_locked(state, "http stream stderr read failed");
      return -1;
    }
    if (rc == 1) {
      close(state->stderr_fd);
      state->stderr_fd = -1;
    }
  }
  fz_http_stream_finish_locked(state, 0);
  if (state->stderr_buf.len != before_stderr || (state->done && !before_done)) {
    fz_http_stream_refresh_error_locked(state, "");
  }
  if (state->stdout_buf.len != before_stdout || state->eof != before_eof || state->done != before_done
      || state->stderr_buf.len != before_stderr) {
    return 1;
  }
  return 0;
}

static int32_t fz_http_stream_consume_chunk_locked(fz_http_stream_state* state, int32_t max_bytes) {
  if (state == NULL) {
    return fz_intern_slice("", 0);
  }
  size_t unread = state->stdout_buf.len > state->stdout_read_pos
      ? (state->stdout_buf.len - state->stdout_read_pos)
      : 0;
  if (unread == 0) {
    if (state->eof) {
      return fz_intern_slice("", 0);
    }
    return 0;
  }
  size_t limit = max_bytes <= 0 ? unread : (size_t)max_bytes;
  if (limit > unread) {
    limit = unread;
  }
  int32_t out = fz_intern_slice(state->stdout_buf.data + state->stdout_read_pos, limit);
  state->stdout_read_pos += limit;
  fz_http_stream_compact_stdout_locked(state);
  return out;
}

static int32_t fz_http_stream_consume_line_locked(fz_http_stream_state* state) {
  if (state == NULL) {
    return fz_intern_slice("", 0);
  }
  size_t unread = state->stdout_buf.len > state->stdout_read_pos
      ? (state->stdout_buf.len - state->stdout_read_pos)
      : 0;
  if (unread == 0) {
    return state->eof ? fz_intern_slice("", 0) : 0;
  }
  char* start = state->stdout_buf.data + state->stdout_read_pos;
  char* newline = memchr(start, '\n', unread);
  if (newline == NULL) {
    if (!state->eof) {
      return 0;
    }
    size_t len = unread;
    if (len > 0 && start[len - 1] == '\r') {
      len--;
    }
    int32_t out = fz_intern_slice(start, len);
    state->stdout_read_pos += unread;
    fz_http_stream_compact_stdout_locked(state);
    return out;
  }
  size_t len = (size_t)(newline - start);
  if (len > 0 && start[len - 1] == '\r') {
    len--;
  }
  int32_t out = fz_intern_slice(start, len);
  state->stdout_read_pos += (size_t)(newline - start) + 1;
  fz_http_stream_compact_stdout_locked(state);
  return out;
}

static int32_t fz_http_stream_close_locked(fz_http_stream_state* state) {
  if (state == NULL) {
    return -1;
  }
  if (!state->done && state->pid > 0) {
    kill(state->pid, SIGTERM);
    fz_http_stream_finish_locked(state, 1);
  }
  if (state->stdout_fd >= 0) {
    close(state->stdout_fd);
    state->stdout_fd = -1;
  }
  if (state->stderr_fd >= 0) {
    close(state->stderr_fd);
    state->stderr_fd = -1;
  }
  fz_bytes_buf_free(&state->stdout_buf);
  fz_bytes_buf_free(&state->stderr_buf);
  memset(state, 0, sizeof(*state));
  return 0;
}

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

int32_t fz_native_http_request_stream(int32_t method_id, int32_t endpoint_id, int32_t body_id) {
  (void)pthread_once(&fz_env_bootstrap_once, fz_env_bootstrap);
  const char* method = fz_lookup_string(method_id);
  const char* endpoint = fz_lookup_string(endpoint_id);
  const char* body = fz_lookup_string(body_id);
  if (method == NULL || method[0] == '\0') {
    method = "GET";
  }
  if (endpoint == NULL || endpoint[0] == '\0') {
    fz_last_exit_class = 3;
    fz_set_last_error(EINVAL, 3, "http_request_stream failed: endpoint is empty");
    fz_http_set_last_result(0, "", "http_request_stream: empty endpoint");
    return -1;
  }
  if (body == NULL) {
    body = "";
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

  int has_body = body[0] != '\0';
  int max_args = 24 + (header_count * 2);
  char** argv = (char**)calloc((size_t)max_args, sizeof(char*));
  if (argv == NULL) {
    for (int i = 0; i < header_count; i++) free(header_buf[i]);
    fz_last_exit_class = 3;
    fz_set_last_error(ENOMEM, 3, "http_request_stream failed: argv alloc failed");
    fz_http_set_last_result(0, "", "http_request_stream: alloc failed");
    return -1;
  }
  int ai = 0;
  argv[ai++] = "curl";
  argv[ai++] = "-sS";
  argv[ai++] = "-N";
  argv[ai++] = "-X";
  argv[ai++] = (char*)method;
  argv[ai++] = (char*)endpoint;
  argv[ai++] = "-D";
  argv[ai++] = "-";
  for (int i = 0; i < header_count; i++) {
    argv[ai++] = "-H";
    argv[ai++] = header_buf[i];
  }
  if (has_body) {
    argv[ai++] = "--data";
    argv[ai++] = (char*)body;
  }
  argv[ai++] = "--connect-timeout";
  argv[ai++] = "10";
  argv[ai++] = "--max-time";
  argv[ai++] = "300";
  argv[ai++] = NULL;

  int out_pipe[2];
  int err_pipe[2];
  if (pipe(out_pipe) != 0) {
    free(argv);
    for (int i = 0; i < header_count; i++) free(header_buf[i]);
    fz_last_exit_class = 3;
    fz_set_last_error(errno, 3, "http_request_stream failed: pipe failed");
    fz_http_set_last_result(0, "", "http_request_stream: pipe failed");
    return -1;
  }
  if (pipe(err_pipe) != 0) {
    close(out_pipe[0]);
    close(out_pipe[1]);
    free(argv);
    for (int i = 0; i < header_count; i++) free(header_buf[i]);
    fz_last_exit_class = 3;
    fz_set_last_error(errno, 3, "http_request_stream failed: stderr pipe failed");
    fz_http_set_last_result(0, "", "http_request_stream: stderr pipe failed");
    return -1;
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
    fz_set_last_error(errno, 3, "http_request_stream failed: fork failed");
    fz_http_set_last_result(0, "", "http_request_stream: fork failed");
    return -1;
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
    dprintf(STDERR_FILENO, "http_request_stream failed: unable to exec curl (%s)\n", strerror(errno));
    _exit(127);
  }

  close(out_pipe[1]);
  close(err_pipe[1]);
  fz_bytes_buf initial_body;
  fz_bytes_buf_init(&initial_body);
  int status_code = 0;
  int headers_ok = fz_http_stream_read_response_headers(out_pipe[0], &initial_body, &status_code);
  if (headers_ok != 0) {
    close(out_pipe[0]);
    close(err_pipe[0]);
    int status = 0;
    (void)waitpid(pid, &status, 0);
    free(argv);
    for (int i = 0; i < header_count; i++) free(header_buf[i]);
    fz_last_exit_class = 3;
    fz_set_last_error(-1, 3, "http_request_stream failed: invalid response headers");
    fz_http_set_last_result(0, "", "http_request_stream: invalid response headers");
    fz_bytes_buf_free(&initial_body);
    return -1;
  }

  (void)fz_set_nonblocking(out_pipe[0]);
  (void)fz_set_nonblocking(err_pipe[0]);
  pthread_mutex_lock(&fz_http_lock);
  int32_t handle = fz_http_stream_state_alloc(pid, out_pipe[0], err_pipe[0], status_code);
  if (handle > 0) {
    fz_http_stream_state* state = fz_http_stream_state_get(handle);
    if (state != NULL && initial_body.len > 0) {
      (void)fz_bytes_buf_append(&state->stdout_buf, initial_body.data, initial_body.len);
    }
    fz_http_last_status = status_code;
    fz_http_last_body_id = fz_intern_slice("", 0);
    fz_http_last_error_id = fz_intern_slice("", 0);
  }
  pthread_mutex_unlock(&fz_http_lock);
  free(argv);
  for (int i = 0; i < header_count; i++) free(header_buf[i]);
  fz_bytes_buf_free(&initial_body);
  if (handle <= 0) {
    close(out_pipe[0]);
    close(err_pipe[0]);
    kill(pid, SIGTERM);
    (void)waitpid(pid, NULL, 0);
    fz_last_exit_class = 3;
    fz_set_last_error(ENOMEM, 3, "http_request_stream failed: stream state alloc failed");
    fz_http_set_last_result(status_code, "", "http_request_stream: stream state alloc failed");
    return -1;
  }
  fz_set_last_error(0, 0, "");
  return handle;
}

int32_t fz_native_http_post_json_stream(int32_t endpoint_id, int32_t body_id) {
  (void)fz_native_http_header(
      fz_intern_slice("content-type", 12), fz_intern_slice("application/json", 16));
  return fz_native_http_request_stream(fz_intern_slice("POST", 4), endpoint_id, body_id);
}

int32_t fz_native_http_stream_read(int32_t handle, int32_t max_bytes) {
  for (;;) {
    pthread_mutex_lock(&fz_http_lock);
    fz_http_stream_state* state = fz_http_stream_state_get(handle);
    if (state == NULL || state->closed) {
      pthread_mutex_unlock(&fz_http_lock);
      return fz_intern_slice("", 0);
    }
    int32_t out = fz_http_stream_consume_chunk_locked(state, max_bytes);
    if (fz_lookup_string(out)[0] != '\0') {
      pthread_mutex_unlock(&fz_http_lock);
      return out;
    }
    if (state->eof) {
      pthread_mutex_unlock(&fz_http_lock);
      return fz_intern_slice("", 0);
    }
    int progress = fz_http_stream_drain_locked(state);
    pthread_mutex_unlock(&fz_http_lock);
    if (progress < 0) {
      return fz_intern_slice("", 0);
    }
    if (progress == 0) {
      int sleep_ms = fz_async_effective_timeout_ms(1);
      if (sleep_ms <= 0) {
        pthread_mutex_lock(&fz_http_lock);
        state = fz_http_stream_state_get(handle);
        if (state != NULL && !state->closed) {
          (void)fz_http_stream_drain_locked(state);
        }
        pthread_mutex_unlock(&fz_http_lock);
        return fz_intern_slice("", 0);
      }
      usleep((useconds_t)sleep_ms * 1000);
    }
  }
}

int32_t fz_native_http_stream_read_line(int32_t handle) {
  for (;;) {
    pthread_mutex_lock(&fz_http_lock);
    fz_http_stream_state* state = fz_http_stream_state_get(handle);
    if (state == NULL || state->closed) {
      pthread_mutex_unlock(&fz_http_lock);
      return fz_intern_slice("", 0);
    }
    int32_t out = fz_http_stream_consume_line_locked(state);
    if (out != 0) {
      pthread_mutex_unlock(&fz_http_lock);
      return out;
    }
    if (state->eof) {
      pthread_mutex_unlock(&fz_http_lock);
      return fz_intern_slice("", 0);
    }
    int progress = fz_http_stream_drain_locked(state);
    pthread_mutex_unlock(&fz_http_lock);
    if (progress < 0) {
      return fz_intern_slice("", 0);
    }
    if (progress == 0) {
      int sleep_ms = fz_async_effective_timeout_ms(1);
      if (sleep_ms <= 0) {
        pthread_mutex_lock(&fz_http_lock);
        state = fz_http_stream_state_get(handle);
        if (state != NULL && !state->closed) {
          (void)fz_http_stream_drain_locked(state);
        }
        pthread_mutex_unlock(&fz_http_lock);
        return fz_intern_slice("", 0);
      }
      usleep((useconds_t)sleep_ms * 1000);
    }
  }
}

int32_t fz_native_http_stream_eof(int32_t handle) {
  pthread_mutex_lock(&fz_http_lock);
  fz_http_stream_state* state = fz_http_stream_state_get(handle);
  if (state == NULL || state->closed) {
    pthread_mutex_unlock(&fz_http_lock);
    return 1;
  }
  (void)fz_http_stream_drain_locked(state);
  size_t unread = state->stdout_buf.len > state->stdout_read_pos
      ? (state->stdout_buf.len - state->stdout_read_pos)
      : 0;
  int eof = state->eof && unread == 0 ? 1 : 0;
  pthread_mutex_unlock(&fz_http_lock);
  return eof;
}

int32_t fz_native_http_stream_status(int32_t handle) {
  pthread_mutex_lock(&fz_http_lock);
  fz_http_stream_state* state = fz_http_stream_state_get(handle);
  int32_t status = state == NULL ? 0 : state->status_code;
  pthread_mutex_unlock(&fz_http_lock);
  return status;
}

int32_t fz_native_http_stream_error(int32_t handle) {
  pthread_mutex_lock(&fz_http_lock);
  fz_http_stream_state* state = fz_http_stream_state_get(handle);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_http_lock);
    return fz_intern_slice("", 0);
  }
  (void)fz_http_stream_drain_locked(state);
  int32_t error_id = state->error_id;
  pthread_mutex_unlock(&fz_http_lock);
  return error_id;
}

int32_t fz_native_http_stream_close(int32_t handle) {
  pthread_mutex_lock(&fz_http_lock);
  fz_http_stream_state* state = fz_http_stream_state_get(handle);
  int32_t rc = fz_http_stream_close_locked(state);
  pthread_mutex_unlock(&fz_http_lock);
  return rc;
}

int32_t fz_native_http_last_status(void) {
  pthread_mutex_lock(&fz_http_lock);
  int32_t value = fz_http_last_status;
  pthread_mutex_unlock(&fz_http_lock);
  return value;
}

int32_t fz_native_http_last_body(void) {
  pthread_mutex_lock(&fz_http_lock);
  int32_t value = fz_http_last_body_id;
  pthread_mutex_unlock(&fz_http_lock);
  return value;
}

int32_t fz_native_http_last_error(void) {
  pthread_mutex_lock(&fz_http_lock);
  int32_t value = fz_http_last_error_id;
  pthread_mutex_unlock(&fz_http_lock);
  return value;
}

int32_t fz_native_error_code(void) {
  return fz_last_error_code;
}

int32_t fz_native_error_class(void) {
  return fz_last_error_class;
}

int32_t fz_native_error_message(void) {
  return fz_last_error_message_id;
}

int32_t fz_native_error_context(int32_t ctx_id) {
  const char* ctx = fz_lookup_string(ctx_id);
  const char* msg = fz_lookup_string(fz_last_error_message_id);
  if (ctx == NULL || ctx[0] == '\0') {
    return 0;
  }
  if (msg == NULL) {
    msg = "";
  }
  size_t n = strlen(msg) + strlen(ctx) + 4;
  char* out = (char*)malloc(n);
  if (out == NULL) {
    return -1;
  }
  snprintf(out, n, "%s: %s", msg, ctx);
  fz_last_error_message_id = fz_intern_owned(out);
  return 0;
}

"#
}
