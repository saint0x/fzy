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

int32_t fz_native_str_slice(int32_t value_id, int32_t start, int32_t span) {
  const char* value = fz_lookup_string(value_id);
  if (value == NULL || span <= 0) {
    return fz_intern_slice("", 0);
  }
  int32_t value_len = (int32_t)strlen(value);
  int32_t begin = start < 0 ? 0 : start;
  if (begin > value_len) {
    begin = value_len;
  }
  int32_t max_span = value_len - begin;
  int32_t take = span > max_span ? max_span : span;
  return fz_intern_slice(value + begin, (size_t)take);
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

int32_t fz_native_json_from_list(int32_t list_handle) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(list_handle);
  if (list == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return fz_intern_slice("[]", 2);
  }
  size_t total = 3;
  for (int i = 0; i < list->count; i++) {
    char* escaped = fz_json_escape_owned(list->items[i] == NULL ? "" : list->items[i]);
    if (escaped == NULL) continue;
    total += strlen(escaped) + 3;
    free(escaped);
  }
  char* out = (char*)malloc(total);
  if (out == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return 0;
  }
  size_t used = 0;
  out[used++] = '[';
  for (int i = 0; i < list->count; i++) {
    if (i > 0) out[used++] = ',';
    char* escaped = fz_json_escape_owned(list->items[i] == NULL ? "" : list->items[i]);
    if (escaped == NULL) {
      out[used++] = '\"';
      out[used++] = '\"';
      continue;
    }
    out[used++] = '\"';
    size_t n = strlen(escaped);
    memcpy(out + used, escaped, n);
    used += n;
    out[used++] = '\"';
    free(escaped);
  }
  out[used++] = ']';
  out[used] = '\0';
  pthread_mutex_unlock(&fz_collections_lock);
  return fz_intern_owned(out);
}

int32_t fz_native_json_from_map(int32_t map_handle) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_map_state* map = fz_map_get(map_handle);
  if (map == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return fz_intern_slice("{}", 2);
  }
  size_t total = 3;
  for (int i = 0; i < map->count; i++) {
    char* k = fz_json_escape_owned(map->keys[i] == NULL ? "" : map->keys[i]);
    char* v = fz_json_escape_owned(map->values[i] == NULL ? "" : map->values[i]);
    if (k != NULL && v != NULL) {
      total += strlen(k) + strlen(v) + 7;
    }
    free(k);
    free(v);
  }
  char* out = (char*)malloc(total);
  if (out == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return 0;
  }
  size_t used = 0;
  out[used++] = '{';
  for (int i = 0; i < map->count; i++) {
    if (i > 0) out[used++] = ',';
    char* k = fz_json_escape_owned(map->keys[i] == NULL ? "" : map->keys[i]);
    char* v = fz_json_escape_owned(map->values[i] == NULL ? "" : map->values[i]);
    if (k == NULL || v == NULL) {
      free(k);
      free(v);
      out[used++] = '\"';
      out[used++] = '\"';
      out[used++] = ':';
      out[used++] = '\"';
      out[used++] = '\"';
      continue;
    }
    out[used++] = '\"';
    size_t kn = strlen(k);
    memcpy(out + used, k, kn);
    used += kn;
    out[used++] = '\"';
    out[used++] = ':';
    out[used++] = '\"';
    size_t vn = strlen(v);
    memcpy(out + used, v, vn);
    used += vn;
    out[used++] = '\"';
    free(k);
    free(v);
  }
  out[used++] = '}';
  out[used] = '\0';
  pthread_mutex_unlock(&fz_collections_lock);
  return fz_intern_owned(out);
}

int32_t fz_native_json_to_list(int32_t json_id) {
  const char* raw = fz_lookup_string(json_id);
  char** items = NULL;
  int count = 0;
  if (fz_parse_json_string_array(raw, &items, &count) != 0) {
    return -1;
  }
  pthread_mutex_lock(&fz_collections_lock);
  int32_t handle = fz_list_alloc();
  fz_list_state* list = fz_list_get(handle);
  if (list != NULL) {
    for (int i = 0; i < count; i++) {
      (void)fz_list_push_cstr(list, items[i] == NULL ? "" : items[i]);
    }
  }
  pthread_mutex_unlock(&fz_collections_lock);
  fz_free_string_list(items, count);
  return handle;
}

int32_t fz_native_json_to_map(int32_t json_id) {
  const char* raw = fz_lookup_string(json_id);
  char** pairs = NULL;
  int count = 0;
  if (fz_parse_json_env_object(raw, &pairs, &count) != 0) {
    return -1;
  }
  pthread_mutex_lock(&fz_collections_lock);
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
  pthread_mutex_unlock(&fz_collections_lock);
  fz_free_string_list(pairs, count);
  return handle;
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

int32_t fz_native_json_get(int32_t json_value_handle, int32_t key_id) {
  int32_t value_id = fz_json_value_get_id(json_value_handle);
  const char* raw = fz_lookup_string(value_id);
  const char* key = fz_lookup_string(key_id);
  const char* start = NULL;
  const char* end = NULL;
  int rc = fz_json_object_lookup(raw, key == NULL ? "" : key, &start, &end);
  if (rc <= 0) {
    return -1;
  }
  return fz_json_value_alloc_from_slice(start, end);
}

int32_t fz_native_json_get_str(int32_t json_value_handle, int32_t key_id) {
  int32_t child = fz_native_json_get(json_value_handle, key_id);
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
  int rc = fz_json_object_lookup(raw, key == NULL ? "" : key, &start, &end);
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
  if (strstr(endpoint, "api.anthropic.com") != NULL) {
    const char* key = fz_env_get_bootstrapped("ANTHROPIC_API_KEY");
    if (key == NULL || key[0] == '\0') {
      const char* msg =
          "http_post_json failed: ANTHROPIC_API_KEY missing; export it or define it in .env";
      fz_last_exit_class = 3;
      fz_set_last_error(22, 3, msg);
      fz_http_set_last_result(0, "", msg);
      return return_body ? fz_intern_slice("", 0) : -1;
    }
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
    size_t n = strlen(key) + strlen(value) + 3;
    char* kv = (char*)malloc(n);
    if (kv == NULL) {
      continue;
    }
    snprintf(kv, n, "%s: %s", key, value);
    header_buf[header_count++] = kv;
  }
  fz_http_header_count = 0;
  pthread_mutex_unlock(&fz_http_lock);

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
