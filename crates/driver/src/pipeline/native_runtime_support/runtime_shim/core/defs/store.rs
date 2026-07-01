pub(super) fn section() -> &'static str {
    r#"
static void fz_map_reset(fz_map_state* map) {
  if (map == NULL) {
    return;
  }
  for (int32_t i = 0; i < map->count; i++) {
    free(map->keys[i]);
    free(map->values[i]);
  }
  free(map->keys);
  free(map->values);
  memset(map, 0, sizeof(*map));
}

static int fz_map_reserve(fz_map_state* map, int32_t need) {
  if (map == NULL || need < 0) {
    return -1;
  }
  if (need <= map->cap) {
    return 0;
  }
  int32_t next_cap = map->cap <= 0 ? FZ_INITIAL_MAP_ENTRY_CAPACITY : map->cap;
  while (next_cap < need) {
    if (next_cap > (INT32_MAX / 2)) {
      next_cap = need;
      break;
    }
    next_cap *= 2;
  }
  size_t old_cap = (size_t)map->cap;
  char** next_keys = (char**)realloc(map->keys, (size_t)next_cap * sizeof(char*));
  if (next_keys == NULL) {
    return -1;
  }
  map->keys = next_keys;
  char** next_values = (char**)realloc(map->values, (size_t)next_cap * sizeof(char*));
  if (next_values == NULL) {
    return -1;
  }
  map->values = next_values;
  memset(map->keys + old_cap, 0, ((size_t)next_cap - old_cap) * sizeof(char*));
  memset(map->values + old_cap, 0, ((size_t)next_cap - old_cap) * sizeof(char*));
  map->cap = next_cap;
  return 0;
}

static int32_t fz_map_alloc(void) {
  if (fz_map_capacity == 0) {
    fz_maps = (fz_map_state*)calloc((size_t)FZ_INITIAL_MAP_CAPACITY, sizeof(fz_map_state));
    if (fz_maps == NULL) {
      return -1;
    }
    fz_map_capacity = FZ_INITIAL_MAP_CAPACITY;
  }
  for (int32_t i = 0; i < fz_map_capacity; i++) {
    if (!fz_maps[i].in_use) {
      memset(&fz_maps[i], 0, sizeof(fz_maps[i]));
      fz_maps[i].in_use = 1;
      return i + 1;
    }
  }
  int32_t next_capacity = fz_map_capacity;
  if (next_capacity < FZ_INITIAL_MAP_CAPACITY) {
    next_capacity = FZ_INITIAL_MAP_CAPACITY;
  }
  if (next_capacity > INT32_MAX / 2) {
    return -1;
  }
  next_capacity *= 2;
  size_t old_capacity = (size_t)fz_map_capacity;
  size_t new_capacity = (size_t)next_capacity;
  fz_map_state* next =
      (fz_map_state*)realloc(fz_maps, new_capacity * sizeof(fz_map_state));
  if (next == NULL) {
    return -1;
  }
  memset(next + old_capacity, 0, (new_capacity - old_capacity) * sizeof(fz_map_state));
  fz_maps = next;
  fz_map_capacity = next_capacity;
  fz_maps[old_capacity].in_use = 1;
  return (int32_t)old_capacity + 1;
}

static fz_map_state* fz_map_get(int32_t handle) {
  if (handle <= 0 || handle > fz_map_capacity || fz_maps == NULL) {
    return NULL;
  }
  fz_map_state* map = &fz_maps[handle - 1];
  return map->in_use ? map : NULL;
}

static int fz_map_find_index(fz_map_state* map, const char* key) {
  if (map == NULL || key == NULL) {
    return -1;
  }
  for (int i = 0; i < map->count; i++) {
    if (map->keys[i] != NULL && strcmp(map->keys[i], key) == 0) {
      return i;
    }
  }
  return -1;
}

static int32_t fz_storage_kv_alloc(void) {
  if (fz_storage_kv_capacity == 0) {
    fz_storage_kv = (fz_storage_kv_state*)calloc(
        (size_t)FZ_INITIAL_STORAGE_KV_CAPACITY, sizeof(fz_storage_kv_state));
    if (fz_storage_kv == NULL) {
      return -1;
    }
    fz_storage_kv_capacity = FZ_INITIAL_STORAGE_KV_CAPACITY;
  }
  for (int32_t i = 0; i < fz_storage_kv_capacity; i++) {
    if (!fz_storage_kv[i].in_use) {
      memset(&fz_storage_kv[i], 0, sizeof(fz_storage_kv[i]));
      fz_storage_kv[i].in_use = 1;
      return i + 1;
    }
  }
  int32_t next_capacity = fz_storage_kv_capacity;
  if (next_capacity < FZ_INITIAL_STORAGE_KV_CAPACITY) {
    next_capacity = FZ_INITIAL_STORAGE_KV_CAPACITY;
  }
  if (next_capacity > INT32_MAX / 2) {
    return -1;
  }
  next_capacity *= 2;
  size_t old_capacity = (size_t)fz_storage_kv_capacity;
  size_t new_capacity = (size_t)next_capacity;
  fz_storage_kv_state* next = (fz_storage_kv_state*)realloc(
      fz_storage_kv, new_capacity * sizeof(fz_storage_kv_state));
  if (next == NULL) {
    return -1;
  }
  memset(
      next + old_capacity, 0, (new_capacity - old_capacity) * sizeof(fz_storage_kv_state));
  fz_storage_kv = next;
  fz_storage_kv_capacity = next_capacity;
  fz_storage_kv[old_capacity].in_use = 1;
  return (int32_t)old_capacity + 1;
}

static fz_storage_kv_state* fz_storage_kv_get(int32_t handle) {
  if (handle <= 0 || handle > fz_storage_kv_capacity || fz_storage_kv == NULL) {
    return NULL;
  }
  fz_storage_kv_state* kv = &fz_storage_kv[handle - 1];
  return kv->in_use ? kv : NULL;
}

"#
}
