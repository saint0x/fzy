pub(super) fn section() -> &'static str {
    r#"
static void fz_list_reset(fz_list_state* list) {
  if (list == NULL) {
    return;
  }
  for (int32_t i = 0; i < list->count; i++) {
    free(list->items[i]);
  }
  free(list->items);
  memset(list, 0, sizeof(*list));
}

static int fz_list_reserve(fz_list_state* list, int32_t need) {
  if (list == NULL || need < 0) {
    return -1;
  }
  if (need <= list->cap) {
    return 0;
  }
  int32_t next_cap = list->cap <= 0 ? FZ_INITIAL_LIST_ITEM_CAPACITY : list->cap;
  while (next_cap < need) {
    if (next_cap > (INT32_MAX / 2)) {
      next_cap = need;
      break;
    }
    next_cap *= 2;
  }
  size_t old_cap = (size_t)list->cap;
  char** next_items = (char**)realloc(list->items, (size_t)next_cap * sizeof(char*));
  if (next_items == NULL) {
    return -1;
  }
  memset(next_items + old_cap, 0, ((size_t)next_cap - old_cap) * sizeof(char*));
  list->items = next_items;
  list->cap = next_cap;
  return 0;
}

static int32_t fz_list_alloc(void) {
  if (fz_list_capacity == 0) {
    fz_lists = (fz_list_state*)calloc((size_t)FZ_INITIAL_LIST_CAPACITY, sizeof(fz_list_state));
    if (fz_lists == NULL) {
      return -1;
    }
    fz_list_capacity = FZ_INITIAL_LIST_CAPACITY;
  }
  for (int32_t i = 0; i < fz_list_capacity; i++) {
    if (!fz_lists[i].in_use) {
      memset(&fz_lists[i], 0, sizeof(fz_lists[i]));
      fz_lists[i].in_use = 1;
      return i + 1;
    }
  }
  int32_t next_capacity = fz_list_capacity;
  if (next_capacity < FZ_INITIAL_LIST_CAPACITY) {
    next_capacity = FZ_INITIAL_LIST_CAPACITY;
  }
  if (next_capacity > INT32_MAX / 2) {
    return -1;
  }
  next_capacity *= 2;
  size_t old_capacity = (size_t)fz_list_capacity;
  size_t new_capacity = (size_t)next_capacity;
  fz_list_state* next =
      (fz_list_state*)realloc(fz_lists, new_capacity * sizeof(fz_list_state));
  if (next == NULL) {
    return -1;
  }
  memset(next + old_capacity, 0, (new_capacity - old_capacity) * sizeof(fz_list_state));
  fz_lists = next;
  fz_list_capacity = next_capacity;
  fz_lists[old_capacity].in_use = 1;
  return (int32_t)old_capacity + 1;
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
  if (fz_bytes_capacity == 0) {
    fz_bytes = (fz_bytes_state*)calloc((size_t)FZ_INITIAL_BYTES_CAPACITY, sizeof(fz_bytes_state));
    if (fz_bytes == NULL) {
      return -1;
    }
    fz_bytes_capacity = FZ_INITIAL_BYTES_CAPACITY;
  }
  for (int32_t i = 0; i < fz_bytes_capacity; i++) {
    if (!fz_bytes[i].in_use) {
      memset(&fz_bytes[i], 0, sizeof(fz_bytes[i]));
      fz_bytes[i].in_use = 1;
      return i + 1;
    }
  }
  int32_t next_capacity = fz_bytes_capacity;
  if (next_capacity < FZ_INITIAL_BYTES_CAPACITY) {
    next_capacity = FZ_INITIAL_BYTES_CAPACITY;
  }
  if (next_capacity > INT32_MAX / 2) {
    return -1;
  }
  next_capacity *= 2;
  size_t old_capacity = (size_t)fz_bytes_capacity;
  size_t new_capacity = (size_t)next_capacity;
  fz_bytes_state* next =
      (fz_bytes_state*)realloc(fz_bytes, new_capacity * sizeof(fz_bytes_state));
  if (next == NULL) {
    return -1;
  }
  memset(next + old_capacity, 0, (new_capacity - old_capacity) * sizeof(fz_bytes_state));
  fz_bytes = next;
  fz_bytes_capacity = next_capacity;
  fz_bytes[old_capacity].in_use = 1;
  return (int32_t)old_capacity + 1;
}

static fz_bytes_state* fz_bytes_get(int32_t handle) {
  if (handle <= 0 || handle > fz_bytes_capacity || fz_bytes == NULL) {
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
  if (handle <= 0 || handle > fz_list_capacity || fz_lists == NULL) {
    return NULL;
  }
  fz_list_state* list = &fz_lists[handle - 1];
  return list->in_use ? list : NULL;
}

static int fz_list_push_cstr(fz_list_state* list, const char* value) {
  if (list == NULL) {
    return -1;
  }
  if (value == NULL) {
    value = "";
  }
  if (fz_list_reserve(list, list->count + 1) != 0) {
    return -1;
  }
  char* dup = strdup(value);
  if (dup == NULL) {
    return -1;
  }
  list->items[list->count++] = dup;
  return 0;
}

static void fz_array_reset(fz_array_state* array) {
  if (array == NULL) {
    return;
  }
  free(array->items);
  memset(array, 0, sizeof(*array));
}

static int fz_array_reserve(fz_array_state* array, int32_t need) {
  if (array == NULL || need < 0) {
    return -1;
  }
  if (need <= array->cap) {
    return 0;
  }
  int32_t next_cap = array->cap <= 0 ? FZ_INITIAL_ARRAY_ITEM_CAPACITY : array->cap;
  while (next_cap < need) {
    if (next_cap > (INT32_MAX / 2)) {
      next_cap = need;
      break;
    }
    next_cap *= 2;
  }
  int32_t* next_items =
      (int32_t*)realloc(array->items, (size_t)next_cap * sizeof(int32_t));
  if (next_items == NULL) {
    return -1;
  }
  array->items = next_items;
  array->cap = next_cap;
  return 0;
}

static int32_t fz_array_alloc(void) {
  if (fz_array_capacity == 0) {
    fz_arrays = (fz_array_state*)calloc((size_t)FZ_INITIAL_ARRAY_CAPACITY, sizeof(fz_array_state));
    if (fz_arrays == NULL) {
      return -1;
    }
    fz_array_capacity = FZ_INITIAL_ARRAY_CAPACITY;
  }
  for (int32_t i = 0; i < fz_array_capacity; i++) {
    if (!fz_arrays[i].in_use) {
      memset(&fz_arrays[i], 0, sizeof(fz_arrays[i]));
      fz_arrays[i].in_use = 1;
      return i + 1;
    }
  }
  int32_t next_capacity = fz_array_capacity;
  if (next_capacity < FZ_INITIAL_ARRAY_CAPACITY) {
    next_capacity = FZ_INITIAL_ARRAY_CAPACITY;
  }
  if (next_capacity > INT32_MAX / 2) {
    return -1;
  }
  next_capacity *= 2;
  size_t old_capacity = (size_t)fz_array_capacity;
  size_t new_capacity = (size_t)next_capacity;
  fz_array_state* next =
      (fz_array_state*)realloc(fz_arrays, new_capacity * sizeof(fz_array_state));
  if (next == NULL) {
    return -1;
  }
  memset(next + old_capacity, 0, (new_capacity - old_capacity) * sizeof(fz_array_state));
  fz_arrays = next;
  fz_array_capacity = next_capacity;
  fz_arrays[old_capacity].in_use = 1;
  return (int32_t)old_capacity + 1;
}

static fz_array_state* fz_array_get(int32_t handle) {
  if (handle <= 0 || handle > fz_array_capacity || fz_arrays == NULL) {
    return NULL;
  }
  fz_array_state* array = &fz_arrays[handle - 1];
  return array->in_use ? array : NULL;
}

static int fz_array_push_i32(fz_array_state* array, int32_t value) {
  if (array == NULL) {
    return -1;
  }
  if (fz_array_reserve(array, array->count + 1) != 0) {
    return -1;
  }
  array->items[array->count++] = value;
  return 0;
}

"#
}
