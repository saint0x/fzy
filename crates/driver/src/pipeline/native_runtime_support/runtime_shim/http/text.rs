pub(super) fn section() -> &'static str {
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

"#
}
