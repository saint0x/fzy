pub(super) fn section() -> &'static str {
    r#"
static int32_t fz_runtime_list_new(void) {
  pthread_mutex_lock(&fz_list_lock);
  int32_t handle = fz_list_alloc();
  pthread_mutex_unlock(&fz_list_lock);
  return handle;
}

static int32_t fz_runtime_list_push(int32_t handle, int32_t value_id) {
  const char* value = fz_lookup_string(value_id);
  pthread_mutex_lock(&fz_list_lock);
  fz_list_state* list = fz_list_get(handle);
  int ok = list != NULL && fz_list_push_cstr(list, value) == 0 ? 0 : -1;
  pthread_mutex_unlock(&fz_list_lock);
  return ok;
}

static int32_t fz_runtime_list_pop(int32_t handle) {
  pthread_mutex_lock(&fz_list_lock);
  fz_list_state* list = fz_list_get(handle);
  if (list == NULL || list->count <= 0) {
    pthread_mutex_unlock(&fz_list_lock);
    return fz_intern_slice("", 0);
  }
  char* item = list->items[list->count - 1];
  list->items[list->count - 1] = NULL;
  list->count--;
  int32_t id = fz_intern_slice(item == NULL ? "" : item, item == NULL ? 0 : strlen(item));
  free(item);
  pthread_mutex_unlock(&fz_list_lock);
  return id;
}

static int32_t fz_runtime_list_len(int32_t handle) {
  pthread_mutex_lock(&fz_list_lock);
  fz_list_state* list = fz_list_get(handle);
  int32_t len = list == NULL ? -1 : list->count;
  pthread_mutex_unlock(&fz_list_lock);
  return len;
}

static int32_t fz_runtime_list_get(int32_t handle, int32_t index) {
  pthread_mutex_lock(&fz_list_lock);
  fz_list_state* list = fz_list_get(handle);
  if (list == NULL || index < 0 || index >= list->count) {
    pthread_mutex_unlock(&fz_list_lock);
    return fz_intern_slice("", 0);
  }
  const char* item = list->items[index] == NULL ? "" : list->items[index];
  int32_t id = fz_intern_slice(item, strlen(item));
  pthread_mutex_unlock(&fz_list_lock);
  return id;
}

static int32_t fz_runtime_list_set(int32_t handle, int32_t index, int32_t value_id) {
  const char* value = fz_lookup_string(value_id);
  if (value == NULL) value = "";
  pthread_mutex_lock(&fz_list_lock);
  fz_list_state* list = fz_list_get(handle);
  if (list == NULL || index < 0 || index >= list->count) {
    pthread_mutex_unlock(&fz_list_lock);
    return -1;
  }
  char* dup = strdup(value);
  if (dup == NULL) {
    pthread_mutex_unlock(&fz_list_lock);
    return -1;
  }
  free(list->items[index]);
  list->items[index] = dup;
  pthread_mutex_unlock(&fz_list_lock);
  return 0;
}

static int32_t fz_runtime_list_clear(int32_t handle) {
  pthread_mutex_lock(&fz_list_lock);
  fz_list_state* list = fz_list_get(handle);
  if (list == NULL) {
    pthread_mutex_unlock(&fz_list_lock);
    return -1;
  }
  for (int i = 0; i < list->count; i++) {
    free(list->items[i]);
    list->items[i] = NULL;
  }
  list->count = 0;
  pthread_mutex_unlock(&fz_list_lock);
  return 0;
}

static int32_t fz_runtime_list_join(int32_t handle, int32_t sep_id) {
  const char* sep = fz_lookup_string(sep_id);
  if (sep == NULL) sep = "";
  pthread_mutex_lock(&fz_list_lock);
  fz_list_state* list = fz_list_get(handle);
  if (list == NULL) {
    pthread_mutex_unlock(&fz_list_lock);
    return fz_intern_slice("", 0);
  }
  size_t sep_len = strlen(sep);
  size_t total = 1;
  for (int i = 0; i < list->count; i++) {
    total += strlen(list->items[i] == NULL ? "" : list->items[i]);
    if (i > 0) total += sep_len;
  }
  char* out = (char*)malloc(total);
  if (out == NULL) {
    pthread_mutex_unlock(&fz_list_lock);
    return 0;
  }
  size_t used = 0;
  for (int i = 0; i < list->count; i++) {
    if (i > 0 && sep_len > 0) {
      memcpy(out + used, sep, sep_len);
      used += sep_len;
    }
    const char* item = list->items[i] == NULL ? "" : list->items[i];
    size_t len = strlen(item);
    if (len > 0) {
      memcpy(out + used, item, len);
      used += len;
    }
  }
  out[used] = '\0';
  pthread_mutex_unlock(&fz_list_lock);
  return fz_intern_owned(out);
}

"#
}
