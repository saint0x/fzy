pub(super) fn section() -> &'static str {
    r#"
static char* fz_json_escape_owned(const char* input) {
  if (input == NULL) {
    input = "";
  }
  size_t in_len = strlen(input);
  size_t cap = (in_len * 6) + 1;
  char* out = (char*)malloc(cap);
  if (out == NULL) {
    return NULL;
  }
  size_t j = 0;
  for (size_t i = 0; i < in_len; i++) {
    unsigned char ch = (unsigned char)input[i];
    switch (ch) {
      case '\"': out[j++] = '\\'; out[j++] = '\"'; break;
      case '\\': out[j++] = '\\'; out[j++] = '\\'; break;
      case '\b': out[j++] = '\\'; out[j++] = 'b'; break;
      case '\f': out[j++] = '\\'; out[j++] = 'f'; break;
      case '\n': out[j++] = '\\'; out[j++] = 'n'; break;
      case '\r': out[j++] = '\\'; out[j++] = 'r'; break;
      case '\t': out[j++] = '\\'; out[j++] = 't'; break;
      default:
        if (ch < 0x20) {
          static const char* hex = "0123456789abcdef";
          out[j++] = '\\';
          out[j++] = 'u';
          out[j++] = '0';
          out[j++] = '0';
          out[j++] = hex[(ch >> 4) & 0xF];
          out[j++] = hex[ch & 0xF];
        } else {
          out[j++] = (char)ch;
        }
        break;
    }
  }
  out[j] = '\0';
  return out;
}

static int fz_bytes_buf_append_json_escaped(fz_bytes_buf* buf, const char* input) {
  if (buf == NULL) {
    return -1;
  }
  if (input == NULL) {
    input = "";
  }
  for (const unsigned char* p = (const unsigned char*)input; *p != '\0'; p++) {
    unsigned char ch = *p;
    switch (ch) {
      case '\"':
        if (fz_bytes_buf_append(buf, "\\\"", 2) != 0) return -1;
        break;
      case '\\':
        if (fz_bytes_buf_append(buf, "\\\\", 2) != 0) return -1;
        break;
      case '\b':
        if (fz_bytes_buf_append(buf, "\\b", 2) != 0) return -1;
        break;
      case '\f':
        if (fz_bytes_buf_append(buf, "\\f", 2) != 0) return -1;
        break;
      case '\n':
        if (fz_bytes_buf_append(buf, "\\n", 2) != 0) return -1;
        break;
      case '\r':
        if (fz_bytes_buf_append(buf, "\\r", 2) != 0) return -1;
        break;
      case '\t':
        if (fz_bytes_buf_append(buf, "\\t", 2) != 0) return -1;
        break;
      default:
        if (ch < 0x20) {
          char escaped[6] = {'\\', 'u', '0', '0', 0, 0};
          static const char* hex = "0123456789abcdef";
          escaped[4] = hex[(ch >> 4) & 0xF];
          escaped[5] = hex[ch & 0xF];
          if (fz_bytes_buf_append(buf, escaped, sizeof(escaped)) != 0) return -1;
        } else if (fz_bytes_buf_append(buf, (const char*)p, 1) != 0) {
          return -1;
        }
        break;
    }
  }
  return 0;
}

static int32_t fz_json_value_alloc(int32_t value_id) {
  if (value_id <= 0) {
    return -1;
  }
  pthread_mutex_lock(&fz_json_lock);
  if (fz_json_value_capacity == 0) {
    fz_json_values = (fz_json_value_state*)calloc(
        (size_t)FZ_INITIAL_JSON_VALUE_CAPACITY, sizeof(fz_json_value_state));
    if (fz_json_values == NULL) {
      pthread_mutex_unlock(&fz_json_lock);
      return -1;
    }
    fz_json_value_capacity = FZ_INITIAL_JSON_VALUE_CAPACITY;
  }
  for (int32_t i = 0; i < fz_json_value_capacity; i++) {
    if (!fz_json_values[i].in_use) {
      fz_json_values[i].in_use = 1;
      fz_json_values[i].value_id = value_id;
      pthread_mutex_unlock(&fz_json_lock);
      return i + 1;
    }
  }
  int32_t next_capacity = fz_json_value_capacity;
  if (next_capacity < FZ_INITIAL_JSON_VALUE_CAPACITY) {
    next_capacity = FZ_INITIAL_JSON_VALUE_CAPACITY;
  }
  if (next_capacity > INT32_MAX / 2) {
    pthread_mutex_unlock(&fz_json_lock);
    return -1;
  }
  next_capacity *= 2;
  size_t old_capacity = (size_t)fz_json_value_capacity;
  size_t new_capacity = (size_t)next_capacity;
  fz_json_value_state* next = (fz_json_value_state*)realloc(
      fz_json_values, new_capacity * sizeof(fz_json_value_state));
  if (next == NULL) {
    pthread_mutex_unlock(&fz_json_lock);
    return -1;
  }
  memset(next + old_capacity, 0, (new_capacity - old_capacity) * sizeof(fz_json_value_state));
  fz_json_values = next;
  fz_json_value_capacity = next_capacity;
  fz_json_values[old_capacity].in_use = 1;
  fz_json_values[old_capacity].value_id = value_id;
  pthread_mutex_unlock(&fz_json_lock);
  return (int32_t)old_capacity + 1;
}

static int32_t fz_json_value_get_id(int32_t handle) {
  if (handle <= 0 || handle > fz_json_value_capacity || fz_json_values == NULL) {
    return 0;
  }
  pthread_mutex_lock(&fz_json_lock);
  fz_json_value_state* slot = &fz_json_values[handle - 1];
  int32_t value_id = slot->in_use ? slot->value_id : 0;
  pthread_mutex_unlock(&fz_json_lock);
  return value_id;
}

static int32_t fz_json_value_alloc_from_slice(const char* start, const char* end) {
  if (start == NULL || end == NULL || end < start) {
    return -1;
  }
  int32_t value_id = fz_intern_slice(start, (size_t)(end - start));
  if (value_id <= 0) {
    return -1;
  }
  return fz_json_value_alloc(value_id);
}

static int32_t fz_json_value_intern_text_from_slice(const char* start, const char* end) {
  if (start == NULL || end == NULL || end < start) {
    return 0;
  }
  const char* cursor = start;
  char* decoded = NULL;
  if (fz_json_parse_string(&cursor, &decoded) == 0 && cursor == end) {
    return fz_intern_owned(decoded);
  }
  free(decoded);
  return fz_intern_slice(start, (size_t)(end - start));
}

static const char* fz_json_ws(const char* p) {
  while (p != NULL && (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')) {
    p++;
  }
  return p;
}

static int fz_json_match_lit(const char** cursor, const char* lit) {
  const char* p = fz_json_ws(*cursor);
  size_t n = strlen(lit);
  if (strncmp(p, lit, n) != 0) {
    return -1;
  }
  *cursor = p + n;
  return 0;
}

static int fz_json_skip_string_token(const char** cursor) {
  const char* p = fz_json_ws(*cursor);
  if (p == NULL || *p != '\"') {
    return -1;
  }
  p++;
  while (*p != '\0') {
    if (*p == '\"') {
      *cursor = p + 1;
      return 0;
    }
    if (*p == '\\') {
      p++;
      if (*p == '\0') {
        return -1;
      }
      if (*p == 'u') {
        p++;
        for (int i = 0; i < 4; i++) {
          if (!isxdigit((unsigned char)p[i])) {
            return -1;
          }
        }
        p += 4;
        continue;
      }
      p++;
      continue;
    }
    p++;
  }
  return -1;
}

static int fz_json_skip_number_token(const char** cursor) {
  const char* p = fz_json_ws(*cursor);
  if (p == NULL) {
    return -1;
  }
  if (*p == '-') {
    p++;
  }
  if (*p == '0') {
    p++;
  } else if (isdigit((unsigned char)*p)) {
    while (isdigit((unsigned char)*p)) p++;
  } else {
    return -1;
  }
  if (*p == '.') {
    p++;
    if (!isdigit((unsigned char)*p)) {
      return -1;
    }
    while (isdigit((unsigned char)*p)) p++;
  }
  if (*p == 'e' || *p == 'E') {
    p++;
    if (*p == '+' || *p == '-') {
      p++;
    }
    if (!isdigit((unsigned char)*p)) {
      return -1;
    }
    while (isdigit((unsigned char)*p)) p++;
  }
  *cursor = p;
  return 0;
}

static int fz_json_skip_value_token(const char** cursor, int depth);

static int fz_json_skip_array_token(const char** cursor, int depth) {
  if (depth > 256) {
    return -1;
  }
  const char* p = fz_json_ws(*cursor);
  if (p == NULL || *p != '[') {
    return -1;
  }
  p = fz_json_ws(p + 1);
  if (*p == ']') {
    *cursor = p + 1;
    return 0;
  }
  for (;;) {
    if (fz_json_skip_value_token(&p, depth + 1) != 0) {
      return -1;
    }
    p = fz_json_ws(p);
    if (*p == ',') {
      p = fz_json_ws(p + 1);
      continue;
    }
    if (*p == ']') {
      *cursor = p + 1;
      return 0;
    }
    return -1;
  }
}

static int fz_json_skip_object_token(const char** cursor, int depth) {
  if (depth > 256) {
    return -1;
  }
  const char* p = fz_json_ws(*cursor);
  if (p == NULL || *p != '{') {
    return -1;
  }
  p = fz_json_ws(p + 1);
  if (*p == '}') {
    *cursor = p + 1;
    return 0;
  }
  for (;;) {
    if (fz_json_skip_string_token(&p) != 0) {
      return -1;
    }
    p = fz_json_ws(p);
    if (*p != ':') {
      return -1;
    }
    p = fz_json_ws(p + 1);
    if (fz_json_skip_value_token(&p, depth + 1) != 0) {
      return -1;
    }
    p = fz_json_ws(p);
    if (*p == ',') {
      p = fz_json_ws(p + 1);
      continue;
    }
    if (*p == '}') {
      *cursor = p + 1;
      return 0;
    }
    return -1;
  }
}

static int fz_json_skip_value_token(const char** cursor, int depth) {
  const char* p = fz_json_ws(*cursor);
  if (p == NULL || *p == '\0') {
    return -1;
  }
  int rc = -1;
  switch (*p) {
    case '\"': rc = fz_json_skip_string_token(&p); break;
    case '{': rc = fz_json_skip_object_token(&p, depth); break;
    case '[': rc = fz_json_skip_array_token(&p, depth); break;
    case 't': rc = fz_json_match_lit(&p, "true"); break;
    case 'f': rc = fz_json_match_lit(&p, "false"); break;
    case 'n': rc = fz_json_match_lit(&p, "null"); break;
    default: rc = fz_json_skip_number_token(&p); break;
  }
  if (rc == 0) {
    *cursor = p;
  }
  return rc;
}

static int fz_json_parse_value_slice(const char* raw, const char** out_start, const char** out_end) {
  if (raw == NULL || out_start == NULL || out_end == NULL) {
    return -1;
  }
  const char* start = fz_json_ws(raw);
  const char* p = start;
  if (fz_json_skip_value_token(&p, 0) != 0) {
    return -1;
  }
  p = fz_json_ws(p);
  if (*p != '\0') {
    return -1;
  }
  *out_start = start;
  *out_end = p;
  return 0;
}

static int fz_json_object_lookup(const char* raw, const char* key, const char** out_start, const char** out_end) {
  if (raw == NULL || key == NULL || out_start == NULL || out_end == NULL) {
    return -1;
  }
  const char* p = fz_json_ws(raw);
  if (*p != '{') {
    return -1;
  }
  p = fz_json_ws(p + 1);
  if (*p == '}') {
    return 0;
  }
  for (;;) {
    char* candidate = NULL;
    if (fz_json_parse_string(&p, &candidate) != 0) {
      return -1;
    }
    p = fz_json_ws(p);
    if (*p != ':') {
      free(candidate);
      return -1;
    }
    p = fz_json_ws(p + 1);
    const char* value_start = p;
    if (fz_json_skip_value_token(&p, 0) != 0) {
      free(candidate);
      return -1;
    }
    const char* value_end = p;
    int matches = strcmp(candidate == NULL ? "" : candidate, key) == 0;
    free(candidate);
    if (matches) {
      *out_start = value_start;
      *out_end = value_end;
      return 1;
    }
    p = fz_json_ws(p);
    if (*p == ',') {
      p = fz_json_ws(p + 1);
      continue;
    }
    if (*p == '}') {
      return 0;
    }
    return -1;
  }
}

static int fz_json_array_lookup(const char* raw, int index, const char** out_start, const char** out_end) {
  if (raw == NULL || index < 0 || out_start == NULL || out_end == NULL) {
    return -1;
  }
  const char* p = fz_json_ws(raw);
  if (*p != '[') {
    return -1;
  }
  p = fz_json_ws(p + 1);
  if (*p == ']') {
    return 0;
  }
  int at = 0;
  for (;;) {
    const char* value_start = p;
    if (fz_json_skip_value_token(&p, 0) != 0) {
      return -1;
    }
    const char* value_end = p;
    if (at == index) {
      *out_start = value_start;
      *out_end = value_end;
      return 1;
    }
    at++;
    p = fz_json_ws(p);
    if (*p == ',') {
      p = fz_json_ws(p + 1);
      continue;
    }
    if (*p == ']') {
      return 0;
    }
    return -1;
  }
}


"#
}
