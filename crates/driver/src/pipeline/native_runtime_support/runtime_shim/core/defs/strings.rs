pub(super) fn section() -> &'static str {
    r#"
static const char* fz_lookup_string_unlocked(int32_t id) {
  if (id <= 0) {
    return "";
  }
  if (id <= fz_string_literal_count) {
    const char* literal = fz_string_literals[id - 1];
    return literal == NULL ? "" : literal;
  }
  int dynamic_index = id - fz_string_literal_count - 1;
  if (dynamic_index < 0 || dynamic_index >= fz_dynamic_string_count) {
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
  if (value == NULL) {
    return 0;
  }
  size_t slot = (size_t)hash & (FZ_STRING_INDEX_CAPACITY - 1);
  for (size_t probe = 0; probe < FZ_STRING_INDEX_CAPACITY; probe++) {
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
    slot = (slot + 1) & (FZ_STRING_INDEX_CAPACITY - 1);
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
  size_t slot = (size_t)hash & (FZ_STRING_INDEX_CAPACITY - 1);
  for (size_t probe = 0; probe < FZ_STRING_INDEX_CAPACITY; probe++) {
    if (fz_string_index_ids[slot] == 0) {
      fz_string_index_ids[slot] = id;
      fz_string_index_hashes[slot] = hash;
      return;
    }
    slot = (slot + 1) & (FZ_STRING_INDEX_CAPACITY - 1);
  }
}

static void fz_string_index_bootstrap(void) {
  pthread_rwlock_wrlock(&fz_string_lock);
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
  if (fz_dynamic_string_count >= FZ_MAX_DYNAMIC_STRINGS) {
    pthread_rwlock_unlock(&fz_string_lock);
    free(owned);
    return 0;
  }
  int index = fz_dynamic_string_count;
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
