pub(super) fn section() -> &'static str {
    r#"
static int fz_storage_write_atomic_path(const char* path, const char* content) {
  if (path == NULL || path[0] == '\0') {
    return -1;
  }
  if (content == NULL) {
    content = "";
  }
  char tmp_path[2048];
  int written = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
  if (written <= 0 || (size_t)written >= sizeof(tmp_path)) {
    return -1;
  }
  int fd = open(tmp_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
  if (fd < 0) {
    return -1;
  }
  size_t left = strlen(content);
  const char* p = content;
  while (left > 0) {
    ssize_t n = write(fd, p, left);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      close(fd);
      return -1;
    }
    if (n == 0) {
      break;
    }
    p += n;
    left -= (size_t)n;
  }
  if (fsync(fd) != 0) {
    close(fd);
    return -1;
  }
  close(fd);
  return rename(tmp_path, path) == 0 ? 0 : -1;
}

int32_t fz_native_storage_append(int32_t path_id, int32_t line_id) {
  const char* path = fz_lookup_string(path_id);
  const char* line = fz_lookup_string(line_id);
  if (path == NULL || path[0] == '\0') {
    return -1;
  }
  if (line == NULL) {
    line = "";
  }
  int fd = open(path, O_CREAT | O_APPEND | O_WRONLY, 0644);
  if (fd < 0) {
    return -1;
  }
  size_t len = strlen(line);
  if (len > 0 && write(fd, line, len) < 0) {
    close(fd);
    return -1;
  }
  if (write(fd, "\n", 1) < 0) {
    close(fd);
    return -1;
  }
  close(fd);
  return 0;
}

int32_t fz_native_storage_atomic_append(int32_t path_id, int32_t line_id) {
  const char* path = fz_lookup_string(path_id);
  const char* line = fz_lookup_string(line_id);
  if (path == NULL || path[0] == '\0') {
    return -1;
  }
  if (line == NULL) {
    line = "";
  }
  int32_t existing_id = fz_native_fs_read_file(path_id);
  const char* existing = fz_lookup_string(existing_id);
  if (existing == NULL) {
    existing = "";
  }
  size_t existing_len = strlen(existing);
  size_t line_len = strlen(line);
  char* payload = (char*)malloc(existing_len + line_len + 3);
  if (payload == NULL) {
    return -1;
  }
  size_t used = 0;
  if (existing_len > 0) {
    memcpy(payload + used, existing, existing_len);
    used += existing_len;
    if (payload[used - 1] != '\n') {
      payload[used++] = '\n';
    }
  }
  if (line_len > 0) {
    memcpy(payload + used, line, line_len);
    used += line_len;
  }
  payload[used++] = '\n';
  payload[used] = '\0';
  int rc = fz_storage_write_atomic_path(path, payload);
  free(payload);
  return rc == 0 ? 0 : -1;
}

int32_t fz_native_storage_kv_open(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') {
    return -1;
  }
  pthread_mutex_lock(&fz_storage_kv_lock);
  for (int i = 0; i < FZ_MAX_STORAGE_KV; i++) {
    if (!fz_storage_kv[i].in_use) {
      continue;
    }
    const char* existing_path = fz_lookup_string(fz_storage_kv[i].path_id);
    if (existing_path == NULL || strcmp(existing_path, path) != 0) {
      continue;
    }
    int32_t kv_handle = fz_storage_kv_alloc();
    fz_storage_kv_state* kv = fz_storage_kv_get(kv_handle);
    if (kv != NULL) {
      kv->path_id = fz_storage_kv[i].path_id;
      kv->map_handle = fz_storage_kv[i].map_handle;
    }
    pthread_mutex_unlock(&fz_storage_kv_lock);
    return kv == NULL ? -1 : kv_handle;
  }
  pthread_mutex_unlock(&fz_storage_kv_lock);
  int32_t map_handle = fz_runtime_map_new();
  int32_t file_json_id = fz_native_fs_read_file(path_id);
  const char* raw = fz_lookup_string(file_json_id);
  if (raw != NULL && raw[0] != '\0') {
    int32_t parsed_handle = fz_native_json_to_map(file_json_id);
    if (parsed_handle > 0) {
      map_handle = parsed_handle;
    }
  }
  pthread_mutex_lock(&fz_storage_kv_lock);
  int32_t kv_handle = fz_storage_kv_alloc();
  fz_storage_kv_state* kv = fz_storage_kv_get(kv_handle);
  if (kv != NULL) {
    kv->path_id = path_id;
    kv->map_handle = map_handle;
  }
  pthread_mutex_unlock(&fz_storage_kv_lock);
  return kv == NULL ? -1 : kv_handle;
}

int32_t fz_native_storage_kv_close(int32_t kv_handle) {
  pthread_mutex_lock(&fz_storage_kv_lock);
  fz_storage_kv_state* kv = fz_storage_kv_get(kv_handle);
  if (kv == NULL) {
    pthread_mutex_unlock(&fz_storage_kv_lock);
    return -1;
  }
  memset(kv, 0, sizeof(*kv));
  pthread_mutex_unlock(&fz_storage_kv_lock);
  return 0;
}

int32_t fz_native_storage_kv_get(int32_t kv_handle, int32_t key_id) {
  pthread_mutex_lock(&fz_storage_kv_lock);
  fz_storage_kv_state* kv = fz_storage_kv_get(kv_handle);
  if (kv == NULL) {
    pthread_mutex_unlock(&fz_storage_kv_lock);
    return fz_intern_slice("", 0);
  }
  int32_t map_handle = kv->map_handle;
  pthread_mutex_unlock(&fz_storage_kv_lock);
  return fz_runtime_map_get(map_handle, key_id);
}

int32_t fz_native_storage_kv_put(int32_t kv_handle, int32_t key_id, int32_t value_id) {
  pthread_mutex_lock(&fz_storage_kv_lock);
  fz_storage_kv_state* kv = fz_storage_kv_get(kv_handle);
  if (kv == NULL) {
    pthread_mutex_unlock(&fz_storage_kv_lock);
    return -1;
  }
  int32_t path_id = kv->path_id;
  int32_t map_handle = kv->map_handle;
  pthread_mutex_unlock(&fz_storage_kv_lock);
  int rc = fz_runtime_map_set(map_handle, key_id, value_id);
  if (rc != 0) {
    return -1;
  }
  int32_t json_id = fz_native_json_from_map(map_handle);
  const char* path = fz_lookup_string(path_id);
  const char* content = fz_lookup_string(json_id);
  return fz_storage_write_atomic_path(path, content) == 0 ? 0 : -1;
}

static int fz_fs_read_lstat(const char* path, struct stat* st, const char* context) {
  if (path == NULL || path[0] == '\0' || st == NULL) {
    errno = EINVAL;
    fz_set_last_error(EINVAL, 3, context);
    return -1;
  }
  if (lstat(path, st) == 0) {
    return 0;
  }
  fz_set_last_error(errno, 3, context);
  return -1;
}

static char* fz_fs_join_owned(const char* left, const char* right) {
  if (left == NULL) left = "";
  if (right == NULL) right = "";
  size_t left_len = strlen(left);
  size_t right_len = strlen(right);
  int need_sep = left_len > 0 && left[left_len - 1] != '/';
  char* out = (char*)malloc(left_len + right_len + (need_sep ? 2 : 1));
  if (out == NULL) {
    errno = ENOMEM;
    return NULL;
  }
  strcpy(out, left);
  if (need_sep) strcat(out, "/");
  strcat(out, right);
  return out;
}

static int fz_fs_mkdirs_owned(char* path) {
  if (path == NULL || path[0] == '\0') {
    errno = EINVAL;
    return -1;
  }
  size_t len = strlen(path);
  if (len == 0) {
    errno = EINVAL;
    return -1;
  }
  for (size_t i = 1; i < len; i++) {
    if (path[i] != '/') continue;
    path[i] = '\0';
    if (path[0] != '\0' && mkdir(path, 0755) != 0 && errno != EEXIST) {
      path[i] = '/';
      return -1;
    }
    path[i] = '/';
  }
  if (mkdir(path, 0755) != 0 && errno != EEXIST) {
    return -1;
  }
  return 0;
}

static int fz_fs_ensure_parent_dirs(const char* path, const char* context) {
  if (path == NULL || path[0] == '\0') {
    fz_set_last_error(EINVAL, 3, context);
    return -1;
  }
  const char* slash = strrchr(path, '/');
  if (slash == NULL) {
    return 0;
  }
  size_t len = (size_t)(slash - path);
  if (len == 0) {
    return 0;
  }
  char* parent = (char*)malloc(len + 1);
  if (parent == NULL) {
    fz_set_last_error(ENOMEM, 3, context);
    return -1;
  }
  memcpy(parent, path, len);
  parent[len] = '\0';
  int rc = fz_fs_mkdirs_owned(parent);
  if (rc != 0) {
    fz_set_last_error(errno, 3, context);
  }
  free(parent);
  return rc;
}

static int fz_fs_copy_file_path(const char* src, const char* dst, const char* context) {
  struct stat st;
  if (fz_fs_read_lstat(src, &st, context) != 0) {
    return -1;
  }
  if (!S_ISREG(st.st_mode)) {
    fz_set_last_error(EINVAL, 3, context);
    return -1;
  }
  if (fz_fs_ensure_parent_dirs(dst, context) != 0) {
    return -1;
  }
  int in_fd = open(src, O_RDONLY);
  if (in_fd < 0) {
    fz_set_last_error(errno, 3, context);
    return -1;
  }
  int out_fd = open(dst, O_CREAT | O_TRUNC | O_WRONLY, st.st_mode & 0777 ? st.st_mode & 0777 : 0644);
  if (out_fd < 0) {
    close(in_fd);
    fz_set_last_error(errno, 3, context);
    return -1;
  }
  char buf[8192];
  int rc = 0;
  for (;;) {
    ssize_t got = read(in_fd, buf, sizeof(buf));
    if (got == 0) {
      break;
    }
    if (got < 0) {
      if (errno == EINTR) continue;
      rc = -1;
      break;
    }
    char* p = buf;
    ssize_t left = got;
    while (left > 0) {
      ssize_t wrote = write(out_fd, p, (size_t)left);
      if (wrote < 0) {
        if (errno == EINTR) continue;
        rc = -1;
        left = 0;
        break;
      }
      p += wrote;
      left -= wrote;
    }
    if (rc != 0) {
      break;
    }
  }
  if (rc == 0 && fsync(out_fd) != 0) {
    rc = -1;
  }
  int saved_errno = errno;
  close(in_fd);
  close(out_fd);
  if (rc != 0) {
    errno = saved_errno;
    fz_set_last_error(errno, 3, context);
    return -1;
  }
  return 0;
}

static int fz_fs_remove_path(const char* path, const char* context) {
  struct stat st;
  if (fz_fs_read_lstat(path, &st, context) != 0) {
    return -1;
  }
  if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
    DIR* dir = opendir(path);
    if (dir == NULL) {
      fz_set_last_error(errno, 3, context);
      return -1;
    }
    int rc = 0;
    struct dirent* ent = NULL;
    while ((ent = readdir(dir)) != NULL) {
      if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
      char* child = fz_fs_join_owned(path, ent->d_name);
      if (child == NULL) {
        rc = -1;
        break;
      }
      if (fz_fs_remove_path(child, context) != 0) {
        free(child);
        rc = -1;
        break;
      }
      free(child);
    }
    int saved_errno = errno;
    closedir(dir);
    if (rc != 0) {
      errno = saved_errno;
      return -1;
    }
    if (rmdir(path) != 0) {
      fz_set_last_error(errno, 3, context);
      return -1;
    }
    return 0;
  }
  if (unlink(path) != 0) {
    fz_set_last_error(errno, 3, context);
    return -1;
  }
  return 0;
}

static int fz_fs_copy_tree_path(const char* src, const char* dst, const char* context) {
  struct stat st;
  if (fz_fs_read_lstat(src, &st, context) != 0) {
    return -1;
  }
  if (S_ISLNK(st.st_mode)) {
    fz_set_last_error(EINVAL, 3, context);
    return -1;
  }
  if (S_ISREG(st.st_mode)) {
    return fz_fs_copy_file_path(src, dst, context);
  }
  if (!S_ISDIR(st.st_mode)) {
    fz_set_last_error(EINVAL, 3, context);
    return -1;
  }
  char* dst_owned = strdup(dst);
  if (dst_owned == NULL) {
    fz_set_last_error(ENOMEM, 3, context);
    return -1;
  }
  if (fz_fs_mkdirs_owned(dst_owned) != 0) {
    free(dst_owned);
    fz_set_last_error(errno, 3, context);
    return -1;
  }
  free(dst_owned);
  DIR* dir = opendir(src);
  if (dir == NULL) {
    fz_set_last_error(errno, 3, context);
    return -1;
  }
  int rc = 0;
  struct dirent* ent = NULL;
  while ((ent = readdir(dir)) != NULL) {
    if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
    char* src_child = fz_fs_join_owned(src, ent->d_name);
    char* dst_child = fz_fs_join_owned(dst, ent->d_name);
    if (src_child == NULL || dst_child == NULL) {
      free(src_child);
      free(dst_child);
      errno = ENOMEM;
      rc = -1;
      break;
    }
    if (fz_fs_copy_tree_path(src_child, dst_child, context) != 0) {
      free(src_child);
      free(dst_child);
      rc = -1;
      break;
    }
    free(src_child);
    free(dst_child);
  }
  int saved_errno = errno;
  closedir(dir);
  if (rc != 0) {
    errno = saved_errno;
    return -1;
  }
  return 0;
}

static int fz_compare_cstr_ptrs(const void* left, const void* right) {
  const char* const* a = (const char* const*)left;
  const char* const* b = (const char* const*)right;
  const char* av = (a != NULL && *a != NULL) ? *a : "";
  const char* bv = (b != NULL && *b != NULL) ? *b : "";
  return strcmp(av, bv);
}

"#
}
