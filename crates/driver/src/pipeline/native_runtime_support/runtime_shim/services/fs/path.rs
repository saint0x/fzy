pub(super) fn section() -> &'static str {
    r#"
int32_t fz_native_fs_mkdir(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') return -1;
  if (mkdir(path, 0755) == 0 || errno == EEXIST) return 0;
  return -1;
}

int32_t fz_native_fs_exists(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') return 0;
  struct stat st;
  return lstat(path, &st) == 0 ? 1 : 0;
}

int32_t fz_native_fs_is_file(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  struct stat st;
  if (fz_fs_read_lstat(path, &st, "fs.is_file failed") != 0) return 0;
  return S_ISREG(st.st_mode) ? 1 : 0;
}

int32_t fz_native_fs_is_dir(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  struct stat st;
  if (fz_fs_read_lstat(path, &st, "fs.is_dir failed") != 0) return 0;
  return S_ISDIR(st.st_mode) ? 1 : 0;
}

int32_t fz_native_fs_is_symlink(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  struct stat st;
  if (fz_fs_read_lstat(path, &st, "fs.is_symlink failed") != 0) return 0;
  return S_ISLNK(st.st_mode) ? 1 : 0;
}

int32_t fz_native_fs_stat_size(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  struct stat st;
  if (fz_fs_read_lstat(path, &st, "fs.stat_size failed") != 0) return -1;
  return (int32_t)st.st_size;
}

int32_t fz_native_fs_stat_mtime(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  struct stat st;
  if (fz_fs_read_lstat(path, &st, "fs.stat_mtime failed") != 0) return -1;
  return (int32_t)st.st_mtime;
}

int32_t fz_native_fs_listdir(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') return -1;
  DIR* dir = opendir(path);
  if (dir == NULL) {
    fz_set_last_error(errno, 3, "fs.listdir failed");
    return -1;
  }
  pthread_mutex_lock(&fz_list_lock);
  int32_t list_handle = fz_list_alloc();
  fz_list_state* list = fz_list_get(list_handle);
  if (list != NULL) {
    struct dirent* ent = NULL;
    while ((ent = readdir(dir)) != NULL) {
      if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
      (void)fz_list_push_cstr(list, ent->d_name);
    }
    if (list->count > 1) {
      qsort(list->items, (size_t)list->count, sizeof(char*), fz_compare_cstr_ptrs);
    }
  }
  pthread_mutex_unlock(&fz_list_lock);
  closedir(dir);
  return list_handle;
}

int32_t fz_native_fs_remove_file(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') return -1;
  return unlink(path) == 0 ? 0 : -1;
}

int32_t fz_native_fs_remove(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  return fz_fs_remove_path(path, "fs.remove failed");
}

int32_t fz_native_fs_temp_file(int32_t prefix_id) {
  const char* prefix = fz_lookup_string(prefix_id);
  if (prefix == NULL || prefix[0] == '\0') prefix = "fz";
  char tmpl[512];
  snprintf(tmpl, sizeof(tmpl), "/tmp/%s-XXXXXX", prefix);
  int fd = mkstemp(tmpl);
  if (fd < 0) return fz_intern_slice("", 0);
  close(fd);
  return fz_intern_slice(tmpl, strlen(tmpl));
}

int32_t fz_native_fs_copy_file(int32_t src_id, int32_t dst_id) {
  const char* src = fz_lookup_string(src_id);
  const char* dst = fz_lookup_string(dst_id);
  return fz_fs_copy_file_path(src, dst, "fs.copy_file failed");
}

int32_t fz_native_fs_copy_tree(int32_t src_id, int32_t dst_id) {
  const char* src = fz_lookup_string(src_id);
  const char* dst = fz_lookup_string(dst_id);
  return fz_fs_copy_tree_path(src, dst, "fs.copy_tree failed");
}

int32_t fz_native_path_join(int32_t left_id, int32_t right_id) {
  const char* left = fz_lookup_string(left_id);
  const char* right = fz_lookup_string(right_id);
  if (left == NULL) left = "";
  if (right == NULL) right = "";
  size_t left_len = strlen(left);
  size_t right_len = strlen(right);
  int need_sep = left_len > 0 && left[left_len - 1] != '/';
  char* out = (char*)malloc(left_len + right_len + (need_sep ? 2 : 1));
  if (out == NULL) return 0;
  strcpy(out, left);
  if (need_sep) strcat(out, "/");
  strcat(out, right);
  return fz_intern_owned(out);
}

int32_t fz_native_path_normalize(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL) path = "";
  char* out = strdup(path);
  if (out == NULL) return 0;
  size_t w = 0;
  for (size_t r = 0; out[r] != '\0'; r++) {
    if (out[r] == '/' && w > 0 && out[w - 1] == '/') continue;
    out[w++] = out[r];
  }
  if (w > 1 && out[w - 1] == '/') w--;
  out[w] = '\0';
  return fz_intern_owned(out);
}

static const char* fz_path_last_segment(const char* path) {
  const char* last = strrchr(path, '/');
  if (last == NULL) return path;
  if (last[1] == '\0') return last;
  return last + 1;
}

int32_t fz_native_path_basename(int32_t path_id) {
  int32_t normalized_id = fz_native_path_normalize(path_id);
  const char* normalized = fz_lookup_string(normalized_id);
  if (normalized == NULL || normalized[0] == '\0') return fz_intern_slice(".", 1);
  if (strcmp(normalized, "/") == 0) return fz_intern_slice("/", 1);
  const char* base = fz_path_last_segment(normalized);
  if (base[0] == '\0') return fz_intern_slice(".", 1);
  return fz_intern_slice(base, strlen(base));
}

int32_t fz_native_path_dirname(int32_t path_id) {
  int32_t normalized_id = fz_native_path_normalize(path_id);
  const char* normalized = fz_lookup_string(normalized_id);
  if (normalized == NULL || normalized[0] == '\0') return fz_intern_slice(".", 1);
  if (strcmp(normalized, "/") == 0) return fz_intern_slice("/", 1);
  const char* last = strrchr(normalized, '/');
  if (last == NULL) return fz_intern_slice(".", 1);
  if (last == normalized) return fz_intern_slice("/", 1);
  return fz_intern_slice(normalized, (size_t)(last - normalized));
}

int32_t fz_native_path_stem(int32_t path_id) {
  int32_t base_id = fz_native_path_basename(path_id);
  const char* base = fz_lookup_string(base_id);
  if (base == NULL || base[0] == '\0' || strcmp(base, "/") == 0 || strcmp(base, ".") == 0) {
    return fz_intern_slice(base == NULL ? "" : base, base == NULL ? 0 : strlen(base));
  }
  const char* dot = strrchr(base, '.');
  if (dot == NULL || dot == base) return fz_intern_slice(base, strlen(base));
  return fz_intern_slice(base, (size_t)(dot - base));
}

int32_t fz_native_path_extension(int32_t path_id) {
  int32_t base_id = fz_native_path_basename(path_id);
  const char* base = fz_lookup_string(base_id);
  if (base == NULL || base[0] == '\0' || strcmp(base, "/") == 0 || strcmp(base, ".") == 0) {
    return fz_intern_slice("", 0);
  }
  const char* dot = strrchr(base, '.');
  if (dot == NULL || dot == base || dot[1] == '\0') return fz_intern_slice("", 0);
  return fz_intern_slice(dot + 1, strlen(dot + 1));
}

"#
}
