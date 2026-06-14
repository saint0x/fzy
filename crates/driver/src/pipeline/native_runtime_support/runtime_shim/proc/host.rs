pub(super) fn section() -> &'static str {
    r#"
int32_t fz_host_init(void) {
  pthread_mutex_lock(&fz_host_lock);
  fz_host_initialized = 1;
  for (int i = 0; i < 64; i++) {
    fz_host_callbacks[i] = NULL;
  }
  fz_set_last_error(0, 0, "");
  pthread_mutex_unlock(&fz_host_lock);
  return 0;
}

int32_t fz_host_shutdown(void) {
  pthread_mutex_lock(&fz_host_lock);
  fz_host_initialized = 0;
  fz_set_last_error(0, 0, "");
  pthread_mutex_unlock(&fz_host_lock);
  return 0;
}

int32_t fz_host_cleanup(void) {
  pthread_mutex_lock(&fz_host_lock);
  for (int i = 0; i < 64; i++) {
    fz_host_callbacks[i] = NULL;
  }
  fz_set_last_error(0, 0, "");
  pthread_mutex_unlock(&fz_host_lock);
  return 0;
}

int32_t fz_host_register_callback_i32(int32_t slot, fz_callback_i32_v0 cb) {
  if (slot < 0 || slot >= 64 || cb == NULL) {
    fz_set_last_error(EINVAL, 3, "fz_host_register_callback_i32 failed: invalid slot or callback");
    return -1;
  }
  pthread_mutex_lock(&fz_host_lock);
  if (!fz_host_initialized) {
    fz_set_last_error(EINVAL, 3, "fz_host_register_callback_i32 failed: host runtime not initialized");
    pthread_mutex_unlock(&fz_host_lock);
    return -2;
  }
  fz_host_callbacks[slot] = cb;
  fz_set_last_error(0, 0, "");
  pthread_mutex_unlock(&fz_host_lock);
  return 0;
}

int32_t fz_host_invoke_callback_i32(int32_t slot, int32_t arg) {
  if (slot < 0 || slot >= 64) {
    fz_set_last_error(EINVAL, 3, "fz_host_invoke_callback_i32 failed: invalid slot");
    return -1;
  }
  pthread_mutex_lock(&fz_host_lock);
  fz_callback_i32_v0 cb = fz_host_callbacks[slot];
  pthread_mutex_unlock(&fz_host_lock);
  if (cb == NULL) {
    fz_set_last_error(EINVAL, 3, "fz_host_invoke_callback_i32 failed: callback not registered");
    return -2;
  }
  fz_set_last_error(0, 0, "");
  return cb(arg);
}

int32_t fz_host_last_error_code(void) {
  return fz_last_error_code;
}

int32_t fz_host_last_error_class(void) {
  return fz_last_error_class;
}

const char* fz_host_last_error_message(void) {
  const char* msg = fz_lookup_string(fz_last_error_message_id);
  return msg == NULL ? "" : msg;
}

"#
}
