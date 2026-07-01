pub(super) fn section() -> &'static str {
    r#"
static void fz_numeric_vec_reset(fz_numeric_vec_state* vec) {
  if (vec == NULL) {
    return;
  }
  free(vec->items);
  memset(vec, 0, sizeof(*vec));
}

static int32_t fz_numeric_vec_alloc(void) {
  for (int i = 0; i < FZ_MAX_LISTS; i++) {
    if (!fz_numeric_vecs[i].in_use) {
      fz_numeric_vec_reset(&fz_numeric_vecs[i]);
      fz_numeric_vecs[i].in_use = 1;
      return i + 1;
    }
  }
  return -1;
}

static fz_numeric_vec_state* fz_numeric_vec_get(uintptr_t handle) {
  if (handle == 0 || handle > FZ_MAX_LISTS) {
    return NULL;
  }
  fz_numeric_vec_state* vec = &fz_numeric_vecs[(size_t)handle - 1];
  return vec->in_use ? vec : NULL;
}

static int fz_numeric_vec_reserve(fz_numeric_vec_state* vec, int32_t need) {
  if (vec == NULL || need < 0) {
    return -1;
  }
  if (need <= vec->cap) {
    return 0;
  }
  int32_t next_cap = vec->cap <= 0 ? 16 : vec->cap;
  while (next_cap < need) {
    if (next_cap > (INT32_MAX / 2)) {
      next_cap = need;
      break;
    }
    next_cap *= 2;
  }
  size_t bytes = (size_t)next_cap * sizeof(uint32_t);
  uint32_t* next_items = (uint32_t*)realloc(vec->items, bytes);
  if (next_items == NULL) {
    return -1;
  }
  vec->items = next_items;
  vec->cap = next_cap;
  return 0;
}

static int fz_numeric_vec_push_bits32(fz_numeric_vec_state* vec, uint32_t bits) {
  if (vec == NULL) {
    return -1;
  }
  if (fz_numeric_vec_reserve(vec, vec->count + 1) != 0) {
    return -1;
  }
  vec->items[vec->count++] = bits;
  return 0;
}

int32_t fz_native_vec_len(uintptr_t handle) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_numeric_vec_state* vec = fz_numeric_vec_get(handle);
  int32_t len = vec == NULL ? 0 : vec->count;
  pthread_mutex_unlock(&fz_collections_lock);
  return len;
}

int32_t fz_native_vec_get_i32(uintptr_t handle, int32_t index) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_numeric_vec_state* vec = fz_numeric_vec_get(handle);
  if (vec == NULL || vec->element_kind != 2 || index < 0 || index >= vec->count) {
    pthread_mutex_unlock(&fz_collections_lock);
    return 0;
  }
  int32_t value = 0;
  uint32_t bits = vec->items[index];
  memcpy(&value, &bits, sizeof(value));
  pthread_mutex_unlock(&fz_collections_lock);
  return value;
}

int32_t fz_native_vec_get_u32(uintptr_t handle, int32_t index) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_numeric_vec_state* vec = fz_numeric_vec_get(handle);
  if (vec == NULL || vec->element_kind != 3 || index < 0 || index >= vec->count) {
    pthread_mutex_unlock(&fz_collections_lock);
    return 0;
  }
  int32_t value = (int32_t)vec->items[index];
  pthread_mutex_unlock(&fz_collections_lock);
  return value;
}

float fz_native_vec_get_f32(uintptr_t handle, int32_t index) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_numeric_vec_state* vec = fz_numeric_vec_get(handle);
  if (vec == NULL || vec->element_kind != 1 || index < 0 || index >= vec->count) {
    pthread_mutex_unlock(&fz_collections_lock);
    return 0.0f;
  }
  float value = 0.0f;
  uint32_t bits = vec->items[index];
  memcpy(&value, &bits, sizeof(value));
  pthread_mutex_unlock(&fz_collections_lock);
  return value;
}

uint64_t fz_native_agg_new(int32_t tag, int32_t count) {
  if (count < 0 || count > FZ_MAX_AGGREGATE_ITEMS) {
    return 0;
  }
  pthread_mutex_lock(&fz_aggregate_lock);
  int32_t handle = fz_aggregate_alloc();
  if (handle > 0) {
    fz_aggregate_state* aggregate = &fz_aggregates[handle - 1];
    if (count > 0) {
      aggregate->items = (uint64_t*)calloc((size_t)count, sizeof(uint64_t));
      if (aggregate->items == NULL) {
        memset(aggregate, 0, sizeof(*aggregate));
        handle = -1;
      }
    }
    if (handle > 0) {
      aggregate->tag = tag;
      aggregate->count = count;
    }
  }
  pthread_mutex_unlock(&fz_aggregate_lock);
  return handle > 0 ? (uint64_t)handle : 0;
}

int32_t fz_native_agg_set_i64(uint64_t handle, int32_t index, uint64_t value) {
  pthread_mutex_lock(&fz_aggregate_lock);
  fz_aggregate_state* aggregate = fz_aggregate_get(handle);
  if (aggregate == NULL || index < 0 || index >= aggregate->count) {
    pthread_mutex_unlock(&fz_aggregate_lock);
    return -1;
  }
  aggregate->items[index] = value;
  pthread_mutex_unlock(&fz_aggregate_lock);
  return 0;
}

uint64_t fz_native_agg_get_i64(uint64_t handle, int32_t index) {
  pthread_mutex_lock(&fz_aggregate_lock);
  fz_aggregate_state* aggregate = fz_aggregate_get(handle);
  if (aggregate == NULL || index < 0 || index >= aggregate->count) {
    pthread_mutex_unlock(&fz_aggregate_lock);
    return 0;
  }
  uint64_t value = aggregate->items[index];
  pthread_mutex_unlock(&fz_aggregate_lock);
  return value;
}

int32_t fz_native_agg_drop(uint64_t handle) {
  pthread_mutex_lock(&fz_aggregate_lock);
  fz_aggregate_state* aggregate = fz_aggregate_get(handle);
  if (aggregate == NULL) {
    pthread_mutex_unlock(&fz_aggregate_lock);
    return -1;
  }
  free(aggregate->items);
  memset(aggregate, 0, sizeof(*aggregate));
  pthread_mutex_unlock(&fz_aggregate_lock);
  return 0;
}

int32_t fz_native_agg_tag(uint64_t handle) {
  pthread_mutex_lock(&fz_aggregate_lock);
  fz_aggregate_state* aggregate = fz_aggregate_get(handle);
  int32_t tag = aggregate == NULL ? 0 : aggregate->tag;
  pthread_mutex_unlock(&fz_aggregate_lock);
  return tag;
}

"#
}
