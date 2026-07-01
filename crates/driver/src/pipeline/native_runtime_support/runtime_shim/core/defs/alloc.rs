pub(super) fn section() -> &'static str {
    r#"
static int32_t fz_list_alloc(void) {
  for (int i = 0; i < FZ_MAX_LISTS; i++) {
    if (!fz_lists[i].in_use) {
      memset(&fz_lists[i], 0, sizeof(fz_lists[i]));
      fz_lists[i].in_use = 1;
      return i + 1;
    }
  }
  return -1;
}

static int32_t fz_aggregate_alloc(void) {
  if (fz_aggregate_capacity == 0) {
    fz_aggregates = (fz_aggregate_state*)calloc(
        (size_t)FZ_INITIAL_AGGREGATE_CAPACITY, sizeof(fz_aggregate_state));
    if (fz_aggregates == NULL) {
      return -1;
    }
    fz_aggregate_capacity = FZ_INITIAL_AGGREGATE_CAPACITY;
  }
  for (int32_t i = 0; i < fz_aggregate_capacity; i++) {
    if (!fz_aggregates[i].in_use) {
      memset(&fz_aggregates[i], 0, sizeof(fz_aggregates[i]));
      fz_aggregates[i].in_use = 1;
      return i + 1;
    }
  }
  int32_t next_capacity = fz_aggregate_capacity;
  if (next_capacity < FZ_INITIAL_AGGREGATE_CAPACITY) {
    next_capacity = FZ_INITIAL_AGGREGATE_CAPACITY;
  }
  if (next_capacity > INT32_MAX / 2) {
    return -1;
  }
  next_capacity *= 2;
  size_t old_capacity = (size_t)fz_aggregate_capacity;
  size_t new_capacity = (size_t)next_capacity;
  fz_aggregate_state* next = (fz_aggregate_state*)realloc(
      fz_aggregates, new_capacity * sizeof(fz_aggregate_state));
  if (next == NULL) {
    return -1;
  }
  memset(next + old_capacity, 0, (new_capacity - old_capacity) * sizeof(fz_aggregate_state));
  fz_aggregates = next;
  fz_aggregate_capacity = next_capacity;
  fz_aggregates[old_capacity].in_use = 1;
  return (int32_t)old_capacity + 1;
}

static int32_t fz_bytes_alloc(void) {
  for (int i = 0; i < FZ_MAX_BYTES; i++) {
    if (!fz_bytes[i].in_use) {
      memset(&fz_bytes[i], 0, sizeof(fz_bytes[i]));
      fz_bytes[i].in_use = 1;
      return i + 1;
    }
  }
  return -1;
}

static fz_bytes_state* fz_bytes_get(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_BYTES) {
    return NULL;
  }
  fz_bytes_state* bytes = &fz_bytes[handle - 1];
  return bytes->in_use ? bytes : NULL;
}

static fz_aggregate_state* fz_aggregate_get(uint64_t handle) {
  if (handle == 0 || handle > (uint64_t)fz_aggregate_capacity || fz_aggregates == NULL) {
    return NULL;
  }
  fz_aggregate_state* aggregate = &fz_aggregates[(size_t)handle - 1];
  return aggregate->in_use ? aggregate : NULL;
}

static fz_list_state* fz_list_get(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_LISTS) {
    return NULL;
  }
  fz_list_state* list = &fz_lists[handle - 1];
  return list->in_use ? list : NULL;
}

static int fz_list_push_cstr(fz_list_state* list, const char* value) {
  if (list == NULL || list->count >= FZ_MAX_LIST_ITEMS) {
    return -1;
  }
  if (value == NULL) {
    value = "";
  }
  char* dup = strdup(value);
  if (dup == NULL) {
    return -1;
  }
  list->items[list->count++] = dup;
  return 0;
}

static int32_t fz_array_alloc(void) {
  for (int i = 0; i < FZ_MAX_LISTS; i++) {
    if (!fz_arrays[i].in_use) {
      memset(&fz_arrays[i], 0, sizeof(fz_arrays[i]));
      fz_arrays[i].in_use = 1;
      return i + 1;
    }
  }
  return -1;
}

static fz_array_state* fz_array_get(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_LISTS) {
    return NULL;
  }
  fz_array_state* array = &fz_arrays[handle - 1];
  return array->in_use ? array : NULL;
}

static int fz_array_push_i32(fz_array_state* array, int32_t value) {
  if (array == NULL || array->count >= FZ_MAX_LIST_ITEMS) {
    return -1;
  }
  array->items[array->count++] = value;
  return 0;
}

"#
}
