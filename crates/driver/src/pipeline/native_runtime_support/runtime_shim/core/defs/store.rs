pub(super) fn section() -> &'static str {
    r#"
static int32_t fz_map_alloc(void) {
  for (int i = 0; i < FZ_MAX_MAPS; i++) {
    if (!fz_maps[i].in_use) {
      memset(&fz_maps[i], 0, sizeof(fz_maps[i]));
      fz_maps[i].in_use = 1;
      return i + 1;
    }
  }
  return -1;
}

static fz_map_state* fz_map_get(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_MAPS) {
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
  for (int i = 0; i < FZ_MAX_STORAGE_KV; i++) {
    if (!fz_storage_kv[i].in_use) {
      memset(&fz_storage_kv[i], 0, sizeof(fz_storage_kv[i]));
      fz_storage_kv[i].in_use = 1;
      return i + 1;
    }
  }
  return -1;
}

static fz_storage_kv_state* fz_storage_kv_get(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_STORAGE_KV) {
    return NULL;
  }
  fz_storage_kv_state* kv = &fz_storage_kv[handle - 1];
  return kv->in_use ? kv : NULL;
}

"#
}
