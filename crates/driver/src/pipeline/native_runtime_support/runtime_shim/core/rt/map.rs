pub(super) fn section() -> &'static str {
    r#"
static int32_t fz_runtime_map_new(void) {
  pthread_mutex_lock(&fz_map_lock);
  int32_t handle = fz_map_alloc();
  pthread_mutex_unlock(&fz_map_lock);
  return handle;
}

static int32_t fz_runtime_map_set(int32_t handle, int32_t key_id, int32_t value_id) {
  const char* key = fz_lookup_string(key_id);
  const char* value = fz_lookup_string(value_id);
  if (key == NULL || key[0] == '\0') {
    return -1;
  }
  if (value == NULL) value = "";
  pthread_mutex_lock(&fz_map_lock);
  fz_map_state* map = fz_map_get(handle);
  if (map == NULL) {
    pthread_mutex_unlock(&fz_map_lock);
    return -1;
  }
  int idx = fz_map_find_index(map, key);
  if (idx >= 0) {
    char* dup = strdup(value);
    if (dup == NULL) {
      pthread_mutex_unlock(&fz_map_lock);
      return -1;
    }
    free(map->values[idx]);
    map->values[idx] = dup;
    pthread_mutex_unlock(&fz_map_lock);
    return 0;
  }
  if (fz_map_reserve(map, map->count + 1) != 0) {
    pthread_mutex_unlock(&fz_map_lock);
    return -1;
  }
  map->keys[map->count] = strdup(key);
  map->values[map->count] = strdup(value);
  if (map->keys[map->count] == NULL || map->values[map->count] == NULL) {
    free(map->keys[map->count]);
    free(map->values[map->count]);
    map->keys[map->count] = NULL;
    map->values[map->count] = NULL;
    pthread_mutex_unlock(&fz_map_lock);
    return -1;
  }
  map->count++;
  pthread_mutex_unlock(&fz_map_lock);
  return 0;
}

static int32_t fz_runtime_map_get(int32_t handle, int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  pthread_mutex_lock(&fz_map_lock);
  fz_map_state* map = fz_map_get(handle);
  if (map == NULL || key == NULL) {
    pthread_mutex_unlock(&fz_map_lock);
    return fz_intern_slice("", 0);
  }
  int idx = fz_map_find_index(map, key);
  const char* value = (idx >= 0 && map->values[idx] != NULL) ? map->values[idx] : "";
  int32_t out = fz_intern_slice(value, strlen(value));
  pthread_mutex_unlock(&fz_map_lock);
  return out;
}

static int32_t fz_runtime_map_has(int32_t handle, int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  pthread_mutex_lock(&fz_map_lock);
  fz_map_state* map = fz_map_get(handle);
  int ok = (map != NULL && key != NULL && fz_map_find_index(map, key) >= 0) ? 1 : 0;
  pthread_mutex_unlock(&fz_map_lock);
  return ok;
}

static int32_t fz_runtime_map_delete(int32_t handle, int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  pthread_mutex_lock(&fz_map_lock);
  fz_map_state* map = fz_map_get(handle);
  if (map == NULL || key == NULL) {
    pthread_mutex_unlock(&fz_map_lock);
    return -1;
  }
  int idx = fz_map_find_index(map, key);
  if (idx < 0) {
    pthread_mutex_unlock(&fz_map_lock);
    return 0;
  }
  free(map->keys[idx]);
  free(map->values[idx]);
  for (int i = idx; i + 1 < map->count; i++) {
    map->keys[i] = map->keys[i + 1];
    map->values[i] = map->values[i + 1];
  }
  map->count--;
  map->keys[map->count] = NULL;
  map->values[map->count] = NULL;
  pthread_mutex_unlock(&fz_map_lock);
  return 1;
}

static int32_t fz_runtime_map_keys(int32_t handle) {
  pthread_mutex_lock(&fz_list_lock);
  int32_t list_handle = fz_list_alloc();
  fz_list_state* list = fz_list_get(list_handle);
  pthread_mutex_unlock(&fz_list_lock);
  if (list == NULL) {
    return -1;
  }
  pthread_mutex_lock(&fz_map_lock);
  fz_map_state* map = fz_map_get(handle);
  if (map == NULL) {
    pthread_mutex_unlock(&fz_map_lock);
    return -1;
  }
  pthread_mutex_lock(&fz_list_lock);
  for (int i = 0; i < map->count; i++) {
    (void)fz_list_push_cstr(list, map->keys[i] == NULL ? "" : map->keys[i]);
  }
  pthread_mutex_unlock(&fz_list_lock);
  pthread_mutex_unlock(&fz_map_lock);
  return list_handle;
}

static int32_t fz_runtime_map_len(int32_t handle) {
  pthread_mutex_lock(&fz_map_lock);
  fz_map_state* map = fz_map_get(handle);
  int32_t len = map == NULL ? -1 : map->count;
  pthread_mutex_unlock(&fz_map_lock);
  return len;
}

"#
}
