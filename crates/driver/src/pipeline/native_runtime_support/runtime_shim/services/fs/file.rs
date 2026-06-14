pub(super) fn section() -> &'static str {
    r#"
int32_t fz_native_fs_open(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') {
    fz_set_last_error(EINVAL, 3, "fs.open failed: path must not be empty");
    return -1;
  }
  int fd = open(path, O_CREAT | O_RDWR, 0644);
  if (fd < 0) {
    fz_set_last_error(errno, 3, "fs.open failed");
    return -1;
  }
  (void)fz_mark_cloexec(fd);
  return fd;
}

int32_t fz_native_fs_close(int32_t handle) {
  if (handle < 0) {
    fz_set_last_error(EINVAL, 3, "fs.close failed: invalid handle");
    return -1;
  }
  if (close(handle) != 0) {
    fz_set_last_error(errno, 3, "fs.close failed");
    return -1;
  }
  return 0;
}

int32_t fz_native_fs_write(int32_t handle, int32_t content_id) {
  const char* content = fz_lookup_string(content_id);
  if (handle < 0) {
    fz_set_last_error(EINVAL, 3, "fs.write failed: invalid handle");
    return -1;
  }
  if (content == NULL) content = "";
  if (lseek(handle, 0, SEEK_END) < 0) {
    fz_set_last_error(errno, 3, "fs.write failed: seek failed");
    return -1;
  }
  size_t left = strlen(content);
  const char* p = content;
  while (left > 0) {
    ssize_t wrote = write(handle, p, left);
    if (wrote < 0) {
      if (errno == EINTR) continue;
      fz_set_last_error(errno, 3, "fs.write failed");
      return -1;
    }
    if (wrote == 0) {
      break;
    }
    p += wrote;
    left -= (size_t)wrote;
  }
  return 0;
}

int32_t fz_native_fs_read(int32_t handle, int32_t limit) {
  if (handle < 0) {
    fz_set_last_error(EINVAL, 3, "fs.read failed: invalid handle");
    return fz_intern_slice("", 0);
  }
  if (limit < 0) {
    fz_set_last_error(EINVAL, 3, "fs.read failed: limit must be >= 0");
    return fz_intern_slice("", 0);
  }
  if (lseek(handle, 0, SEEK_SET) < 0) {
    fz_set_last_error(errno, 3, "fs.read failed: seek failed");
    return fz_intern_slice("", 0);
  }
  size_t cap = (size_t)limit;
  if (cap > 1048576) cap = 1048576;
  fz_bytes_buf buf;
  fz_bytes_buf_init(&buf);
  char tmp[4096];
  while (buf.len < cap) {
    size_t chunk = sizeof(tmp);
    if (cap - buf.len < chunk) {
      chunk = cap - buf.len;
    }
    if (chunk == 0) {
      break;
    }
    ssize_t got = read(handle, tmp, chunk);
    if (got > 0) {
      if (fz_bytes_buf_append(&buf, tmp, (size_t)got) != 0) {
        fz_set_last_error(ENOMEM, 3, "fs.read failed: buffer alloc failed");
        break;
      }
      continue;
    }
    if (got == 0) break;
    if (errno == EINTR) continue;
    fz_set_last_error(errno, 3, "fs.read failed");
    break;
  }
  int32_t out = fz_intern_slice(buf.data == NULL ? "" : buf.data, buf.len);
  fz_bytes_buf_free(&buf);
  return out;
}

int32_t fz_native_fs_flush(int32_t handle) {
  if (handle < 0) {
    fz_set_last_error(EINVAL, 3, "fs.flush failed: invalid handle");
    return -1;
  }
  return fsync(handle) == 0 ? 0 : -1;
}

int32_t fz_native_fs_fsync(int32_t handle) {
  if (handle < 0) {
    fz_set_last_error(EINVAL, 3, "fs.fsync failed: invalid handle");
    return -1;
  }
  if (fsync(handle) != 0) {
    fz_set_last_error(errno, 3, "fs.fsync failed");
    return -1;
  }
  return 0;
}

int32_t fz_native_fs_lock(int32_t handle) {
  if (handle < 0) {
    fz_set_last_error(EINVAL, 3, "fs.lock failed: invalid handle");
    return -1;
  }
  if (lockf(handle, F_LOCK, 0) != 0) {
    fz_set_last_error(errno, 3, "fs.lock failed");
    return -1;
  }
  return 0;
}

int32_t fz_native_fs_atomic_write(int32_t path_id, int32_t body_id) {
  const char* path = fz_lookup_string(path_id);
  const char* payload = fz_lookup_string(body_id);
  if (path == NULL || path[0] == '\0') {
    fz_set_last_error(EINVAL, 3, "fs.atomic_write failed: invalid path");
    return -1;
  }
  if (payload == NULL) {
    payload = "";
  }
  char tmp_path[2048];
  int written = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
  if (written <= 0 || (size_t)written >= sizeof(tmp_path)) {
    fz_set_last_error(ENAMETOOLONG, 3, "fs.atomic_write failed: temp path too long");
    return -1;
  }
  int fd = open(tmp_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
  if (fd < 0) {
    fz_set_last_error(errno, 3, "fs.atomic_write failed: open temp file");
    return -1;
  }
  size_t left = strlen(payload);
  const char* cursor = payload;
  while (left > 0) {
    ssize_t n = write(fd, cursor, left);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      close(fd);
      fz_set_last_error(errno, 3, "fs.atomic_write failed: write temp file");
      return -1;
    }
    if (n == 0) {
      break;
    }
    cursor += n;
    left -= (size_t)n;
  }
  if (fsync(fd) != 0) {
    int err = errno;
    close(fd);
    fz_set_last_error(err, 3, "fs.atomic_write failed: fsync temp file");
    return -1;
  }
  close(fd);
  if (rename(tmp_path, path) != 0) {
    fz_set_last_error(errno, 3, "fs.atomic_write failed: rename temp file");
    return -1;
  }
  return 0;
}

int32_t fz_native_fs_read_file(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') {
    return fz_intern_slice("", 0);
  }
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    fz_set_last_error(errno, 3, "fs.read_file failed");
    return fz_intern_slice("", 0);
  }
  fz_bytes_buf buf;
  fz_bytes_buf_init(&buf);
  char tmp[4096];
  for (;;) {
    ssize_t got = read(fd, tmp, sizeof(tmp));
    if (got > 0) {
      if (fz_bytes_buf_append(&buf, tmp, (size_t)got) != 0) {
        break;
      }
      continue;
    }
    if (got == 0) break;
    if (errno == EINTR) continue;
    break;
  }
  close(fd);
  int32_t out = fz_intern_slice(buf.data == NULL ? "" : buf.data, buf.len);
  fz_bytes_buf_free(&buf);
  return out;
}

int32_t fz_native_fs_write_file(int32_t path_id, int32_t content_id) {
  const char* path = fz_lookup_string(path_id);
  const char* content = fz_lookup_string(content_id);
  if (path == NULL || path[0] == '\0') {
    return -1;
  }
  if (content == NULL) content = "";
  int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
  if (fd < 0) {
    fz_set_last_error(errno, 3, "fs.write_file open failed");
    return -1;
  }
  size_t left = strlen(content);
  const char* p = content;
  while (left > 0) {
    ssize_t wrote = write(fd, p, left);
    if (wrote < 0) {
      if (errno == EINTR) continue;
      close(fd);
      fz_set_last_error(errno, 3, "fs.write_file write failed");
      return -1;
    }
    if (wrote == 0) break;
    p += wrote;
    left -= (size_t)wrote;
  }
  close(fd);
  return 0;
}

"#
}
