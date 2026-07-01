pub(super) fn section() -> &'static str {
    r#"
static int fz_dynamic_strings_reserve_unlocked(int32_t need) {
  if (need < 0) {
    return -1;
  }
  if (need <= fz_dynamic_string_capacity) {
    return 0;
  }
  int32_t next_capacity =
      fz_dynamic_string_capacity <= 0 ? FZ_INITIAL_DYNAMIC_STRING_CAPACITY : fz_dynamic_string_capacity;
  while (next_capacity < need) {
    if (next_capacity > (INT32_MAX / 2)) {
      next_capacity = need;
      break;
    }
    next_capacity *= 2;
  }
  char** next =
      (char**)realloc(fz_dynamic_strings, (size_t)next_capacity * sizeof(char*));
  if (next == NULL) {
    return -1;
  }
  memset(
      next + fz_dynamic_string_capacity,
      0,
      ((size_t)next_capacity - (size_t)fz_dynamic_string_capacity) * sizeof(char*));
  fz_dynamic_strings = next;
  fz_dynamic_string_capacity = next_capacity;
  return 0;
}

static int fz_string_index_rehash_unlocked(int32_t need_entries) {
  if (need_entries < 16) {
    need_entries = 16;
  }
  int32_t min_capacity = FZ_INITIAL_STRING_INDEX_CAPACITY;
  if (min_capacity < 16) {
    min_capacity = 16;
  }
  int32_t target = min_capacity;
  while ((need_entries * 10) >= (target * 7)) {
    if (target > (INT32_MAX / 2)) {
      return -1;
    }
    target *= 2;
  }
  if (fz_string_index_capacity >= target && fz_string_index_ids != NULL
      && fz_string_index_hashes != NULL) {
    return 0;
  }
  int32_t* next_ids = (int32_t*)calloc((size_t)target, sizeof(int32_t));
  if (next_ids == NULL) {
    return -1;
  }
  uint32_t* next_hashes = (uint32_t*)calloc((size_t)target, sizeof(uint32_t));
  if (next_hashes == NULL) {
    free(next_ids);
    return -1;
  }
  if (fz_string_index_ids != NULL && fz_string_index_hashes != NULL && fz_string_index_capacity > 0) {
    for (int32_t i = 0; i < fz_string_index_capacity; i++) {
      int32_t id = fz_string_index_ids[i];
      if (id == 0) {
        continue;
      }
      uint32_t hash = fz_string_index_hashes[i];
      size_t slot = (size_t)hash & (size_t)(target - 1);
      while (next_ids[slot] != 0) {
        slot = (slot + 1) & (size_t)(target - 1);
      }
      next_ids[slot] = id;
      next_hashes[slot] = hash;
    }
  }
  free(fz_string_index_ids);
  free(fz_string_index_hashes);
  fz_string_index_ids = next_ids;
  fz_string_index_hashes = next_hashes;
  fz_string_index_capacity = target;
  return 0;
}

static const char* fz_lookup_string_unlocked(int32_t id) {
  if (id <= 0) {
    return "";
  }
  if (id <= fz_string_literal_count) {
    const char* literal = fz_string_literals[id - 1];
    return literal == NULL ? "" : literal;
  }
  int dynamic_index = id - fz_string_literal_count - 1;
  if (dynamic_index < 0 || dynamic_index >= fz_dynamic_string_count || fz_dynamic_strings == NULL) {
    return "";
  }
  const char* value = fz_dynamic_strings[dynamic_index];
  return value == NULL ? "" : value;
}

static uint32_t fz_string_hash_bytes(const char* data, size_t len) {
  uint32_t hash = 2166136261u;
  if (data == NULL) {
    return hash;
  }
  for (size_t i = 0; i < len; i++) {
    hash ^= (uint8_t)data[i];
    hash *= 16777619u;
  }
  return hash;
}

static int32_t fz_find_string_slice_unlocked(const char* value, size_t len, uint32_t hash) {
  if (value == NULL || fz_string_index_capacity <= 0 || fz_string_index_ids == NULL
      || fz_string_index_hashes == NULL) {
    return 0;
  }
  size_t slot = (size_t)hash & (size_t)(fz_string_index_capacity - 1);
  for (size_t probe = 0; probe < (size_t)fz_string_index_capacity; probe++) {
    int32_t id = fz_string_index_ids[slot];
    if (id == 0) {
      return 0;
    }
    if (fz_string_index_hashes[slot] == hash) {
      const char* existing = fz_lookup_string_unlocked(id);
      if (existing != NULL && strncmp(existing, value, len) == 0 && existing[len] == '\0') {
        return id;
      }
    }
    slot = (slot + 1) & (size_t)(fz_string_index_capacity - 1);
  }
  return 0;
}

static int32_t fz_find_string_cstr_unlocked(const char* value, uint32_t hash) {
  if (value == NULL) {
    return 0;
  }
  return fz_find_string_slice_unlocked(value, strlen(value), hash);
}

static void fz_string_index_insert_unlocked(int32_t id, const char* value, uint32_t hash) {
  if (id <= 0 || value == NULL) {
    return;
  }
  if (fz_string_index_capacity <= 0 || fz_string_index_ids == NULL || fz_string_index_hashes == NULL) {
    return;
  }
  size_t slot = (size_t)hash & (size_t)(fz_string_index_capacity - 1);
  for (size_t probe = 0; probe < (size_t)fz_string_index_capacity; probe++) {
    if (fz_string_index_ids[slot] == 0) {
      fz_string_index_ids[slot] = id;
      fz_string_index_hashes[slot] = hash;
      return;
    }
    slot = (slot + 1) & (size_t)(fz_string_index_capacity - 1);
  }
}

static void fz_string_index_bootstrap(void) {
  pthread_rwlock_wrlock(&fz_string_lock);
  if (fz_string_index_rehash_unlocked(fz_string_literal_count + 1) != 0) {
    pthread_rwlock_unlock(&fz_string_lock);
    return;
  }
  for (int i = 0; i < fz_string_literal_count; i++) {
    const char* literal = fz_string_literals[i];
    if (literal == NULL) {
      literal = "";
    }
    fz_string_index_insert_unlocked(i + 1, literal, fz_string_hash_bytes(literal, strlen(literal)));
  }
  pthread_rwlock_unlock(&fz_string_lock);
}

static const char* fz_lookup_string(int32_t id) {
  const char* value = "";
  (void)pthread_once(&fz_string_index_once, fz_string_index_bootstrap);
  pthread_rwlock_rdlock(&fz_string_lock);
  value = fz_lookup_string_unlocked(id);
  pthread_rwlock_unlock(&fz_string_lock);
  return value;
}

const uint8_t* fz_native_str_ptr(int32_t value_id) {
  return (const uint8_t*)fz_lookup_string(value_id);
}

static int32_t fz_intern_owned(char* owned) {
  if (owned == NULL) {
    return 0;
  }
  (void)pthread_once(&fz_string_index_once, fz_string_index_bootstrap);
  uint32_t hash = fz_string_hash_bytes(owned, strlen(owned));
  pthread_rwlock_wrlock(&fz_string_lock);
  int32_t existing_id = fz_find_string_cstr_unlocked(owned, hash);
  if (existing_id != 0) {
    pthread_rwlock_unlock(&fz_string_lock);
    free(owned);
    return existing_id;
  }
  if (fz_dynamic_strings_reserve_unlocked(fz_dynamic_string_count + 1) != 0) {
    pthread_rwlock_unlock(&fz_string_lock);
    free(owned);
    return 0;
  }
  if (fz_string_index_rehash_unlocked(fz_string_literal_count + fz_dynamic_string_count + 2) != 0) {
    pthread_rwlock_unlock(&fz_string_lock);
    free(owned);
    return 0;
  }
  int32_t index = fz_dynamic_string_count;
  fz_dynamic_strings[index] = owned;
  fz_dynamic_string_count++;
  int32_t id = fz_string_literal_count + index + 1;
  fz_string_index_insert_unlocked(id, owned, hash);
  pthread_rwlock_unlock(&fz_string_lock);
  return id;
}

static int32_t fz_intern_slice(const char* data, size_t len) {
  if (data == NULL) {
    return 0;
  }
  (void)pthread_once(&fz_string_index_once, fz_string_index_bootstrap);
  uint32_t hash = fz_string_hash_bytes(data, len);
  pthread_rwlock_rdlock(&fz_string_lock);
  int32_t existing_id = fz_find_string_slice_unlocked(data, len, hash);
  pthread_rwlock_unlock(&fz_string_lock);
  if (existing_id != 0) {
    return existing_id;
  }
  char* owned = (char*)malloc(len + 1);
  if (owned == NULL) {
    return 0;
  }
  if (len > 0) {
    memcpy(owned, data, len);
  }
  owned[len] = '\0';
  return fz_intern_owned(owned);
}

static void fz_set_last_error(int32_t code, int32_t class_id, const char* message) {
  if (message == NULL) {
    message = "";
  }
  fz_last_error_code = code;
  fz_last_error_class = class_id;
  fz_last_error_message_id = fz_intern_slice(message, strlen(message));
  const char* debug_errors = getenv("FZ_NATIVE_DEBUG_ERRORS");
  if (debug_errors != NULL && debug_errors[0] != '\0' && !(debug_errors[0] == '0' && debug_errors[1] == '\0')) {
    fprintf(stderr, "[fz-native-error] code=%d class=%d message=%s\n", code, class_id, message);
  }
}

static void fz_crypto_memzero(void* ptr, size_t len) {
  if (ptr == NULL || len == 0) {
    return;
  }
  volatile uint8_t* bytes = (volatile uint8_t*)ptr;
  while (len > 0) {
    *bytes++ = 0;
    len--;
  }
}

"#
}
