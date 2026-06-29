pub(super) fn section() -> &'static str {
    r#"
int32_t fz_native_fs_read_bytes(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') {
    fz_set_last_error(EINVAL, 3, "fs.read_bytes failed: invalid path");
    return -1;
  }
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    fz_set_last_error(errno, 3, "fs.read_bytes failed");
    return -1;
  }
  fz_bytes_buf buf;
  fz_bytes_buf_init(&buf);
  char tmp[4096];
  for (;;) {
    ssize_t got = read(fd, tmp, sizeof(tmp));
    if (got > 0) {
      if (fz_bytes_buf_append(&buf, tmp, (size_t)got) != 0) {
        close(fd);
        fz_bytes_buf_free(&buf);
        fz_set_last_error(ENOMEM, 3, "fs.read_bytes failed: buffer alloc failed");
        return -1;
      }
      continue;
    }
    if (got == 0) {
      break;
    }
    if (errno == EINTR) {
      continue;
    }
    close(fd);
    fz_bytes_buf_free(&buf);
    fz_set_last_error(errno, 3, "fs.read_bytes failed");
    return -1;
  }
  close(fd);
  int32_t out = fz_runtime_bytes_new_from_slice((const uint8_t*)buf.data, buf.len);
  fz_bytes_buf_free(&buf);
  return out;
}

int32_t fz_native_fs_write_bytes(int32_t path_id, int32_t bytes_handle) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') {
    fz_set_last_error(EINVAL, 3, "fs.write_bytes failed: invalid path");
    return -1;
  }
  int32_t logical_len = fz_runtime_bytes_len(bytes_handle);
  if (logical_len < 0) {
    fz_set_last_error(EINVAL, 3, "fs.write_bytes failed: invalid bytes handle");
    return -1;
  }
  size_t len = 0;
  const uint8_t* data = fz_runtime_bytes_data_ptr(bytes_handle, &len);
  int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
  if (fd < 0) {
    fz_set_last_error(errno, 3, "fs.write_bytes failed: open failed");
    return -1;
  }
  size_t left = len;
  const uint8_t* cursor = data == NULL ? (const uint8_t*)"" : data;
  while (left > 0) {
    ssize_t wrote = write(fd, cursor, left);
    if (wrote < 0) {
      if (errno == EINTR) {
        continue;
      }
      close(fd);
      fz_set_last_error(errno, 3, "fs.write_bytes failed: write failed");
      return -1;
    }
    if (wrote == 0) {
      break;
    }
    cursor += wrote;
    left -= (size_t)wrote;
  }
  close(fd);
  fz_set_last_error(0, 0, "");
  return 0;
}

int32_t fz_native_bytes_len(int32_t bytes_handle) {
  int32_t len = fz_runtime_bytes_len(bytes_handle);
  if (len < 0) {
    fz_set_last_error(EINVAL, 3, "bytes.len failed: invalid bytes handle");
  } else {
    fz_set_last_error(0, 0, "");
  }
  return len;
}

int32_t fz_native_bytes_slice(int32_t bytes_handle, int32_t start, int32_t end) {
  if (fz_runtime_bytes_len(bytes_handle) < 0) {
    fz_set_last_error(EINVAL, 3, "bytes.slice failed: invalid bytes handle");
    return -1;
  }
  size_t len = 0;
  const uint8_t* data = fz_runtime_bytes_data_ptr(bytes_handle, &len);
  if (start < 0 || end < start) {
    fz_set_last_error(EINVAL, 3, "bytes.slice failed: invalid range");
    return -1;
  }
  if (!fz_runtime_bytes_bounds_ok(len, start, end - start, "bytes.slice failed: range out of bounds")) {
    return -1;
  }
  return fz_runtime_bytes_new_from_slice(data == NULL ? (const uint8_t*)"" : data + start, (size_t)(end - start));
}

int32_t fz_native_bytes_at(int32_t bytes_handle, int32_t index) {
  if (fz_runtime_bytes_len(bytes_handle) < 0) {
    fz_set_last_error(EINVAL, 3, "bytes.at failed: invalid bytes handle");
    return -1;
  }
  size_t len = 0;
  const uint8_t* data = fz_runtime_bytes_data_ptr(bytes_handle, &len);
  if (!fz_runtime_bytes_bounds_ok(len, index, 1, "bytes.at failed: index out of bounds")) {
    return -1;
  }
  fz_set_last_error(0, 0, "");
  return (int32_t)data[index];
}

int32_t fz_native_bytes_read_u16_le(int32_t bytes_handle, int32_t index) {
  if (fz_runtime_bytes_len(bytes_handle) < 0) {
    fz_set_last_error(EINVAL, 3, "bytes.read_u16_le failed: invalid bytes handle");
    return 0;
  }
  size_t len = 0;
  const uint8_t* data = fz_runtime_bytes_data_ptr(bytes_handle, &len);
  if (!fz_runtime_bytes_bounds_ok(len, index, 2, "bytes.read_u16_le failed: index out of bounds")) {
    return 0;
  }
  fz_set_last_error(0, 0, "");
  return (int32_t)((uint32_t)data[index] | ((uint32_t)data[index + 1] << 8));
}

int32_t fz_native_bytes_read_u32_le(int32_t bytes_handle, int32_t index) {
  if (fz_runtime_bytes_len(bytes_handle) < 0) {
    fz_set_last_error(EINVAL, 3, "bytes.read_u32_le failed: invalid bytes handle");
    return 0;
  }
  size_t len = 0;
  const uint8_t* data = fz_runtime_bytes_data_ptr(bytes_handle, &len);
  if (!fz_runtime_bytes_bounds_ok(len, index, 4, "bytes.read_u32_le failed: index out of bounds")) {
    return 0;
  }
  fz_set_last_error(0, 0, "");
  return (int32_t)(
      (uint32_t)data[index]
      | ((uint32_t)data[index + 1] << 8)
      | ((uint32_t)data[index + 2] << 16)
      | ((uint32_t)data[index + 3] << 24));
}

int64_t fz_native_bytes_read_u64_le(int32_t bytes_handle, int32_t index) {
  if (fz_runtime_bytes_len(bytes_handle) < 0) {
    fz_set_last_error(EINVAL, 3, "bytes.read_u64_le failed: invalid bytes handle");
    return 0;
  }
  size_t len = 0;
  const uint8_t* data = fz_runtime_bytes_data_ptr(bytes_handle, &len);
  if (!fz_runtime_bytes_bounds_ok(len, index, 8, "bytes.read_u64_le failed: index out of bounds")) {
    return 0;
  }
  uint64_t value = 0;
  for (int i = 0; i < 8; i++) {
    value |= ((uint64_t)data[index + i]) << (8 * i);
  }
  fz_set_last_error(0, 0, "");
  return (int64_t)value;
}

float fz_native_bytes_read_f32_le(int32_t bytes_handle, int32_t index) {
  if (fz_runtime_bytes_len(bytes_handle) < 0) {
    fz_set_last_error(EINVAL, 3, "bytes.read_f32_le failed: invalid bytes handle");
    return 0.0f;
  }
  size_t len = 0;
  const uint8_t* data = fz_runtime_bytes_data_ptr(bytes_handle, &len);
  if (!fz_runtime_bytes_bounds_ok(len, index, 4, "bytes.read_f32_le failed: index out of bounds")) {
    return 0.0f;
  }
  union {
    uint32_t bits;
    float value;
  } out;
  out.bits =
      (uint32_t)data[index]
      | ((uint32_t)data[index + 1] << 8)
      | ((uint32_t)data[index + 2] << 16)
      | ((uint32_t)data[index + 3] << 24);
  fz_set_last_error(0, 0, "");
  return out.value;
}

float fz_native_bytes_read_f16_le(int32_t bytes_handle, int32_t index) {
  if (fz_runtime_bytes_len(bytes_handle) < 0) {
    fz_set_last_error(EINVAL, 3, "bytes.read_f16_le failed: invalid bytes handle");
    return 0.0f;
  }
  size_t len = 0;
  const uint8_t* data = fz_runtime_bytes_data_ptr(bytes_handle, &len);
  if (!fz_runtime_bytes_bounds_ok(len, index, 2, "bytes.read_f16_le failed: index out of bounds")) {
    return 0.0f;
  }
  uint16_t bits = (uint16_t)((uint16_t)data[index] | ((uint16_t)data[index + 1] << 8));
  fz_set_last_error(0, 0, "");
  return fz_runtime_bytes_f16_to_f32(bits);
}

int32_t fz_native_bytes_as_str(int32_t bytes_handle) {
  if (fz_runtime_bytes_len(bytes_handle) < 0) {
    fz_set_last_error(EINVAL, 3, "bytes.as_str failed: invalid bytes handle");
    return fz_intern_slice("", 0);
  }
  size_t len = 0;
  const uint8_t* data = fz_runtime_bytes_data_ptr(bytes_handle, &len);
  if (!fz_runtime_bytes_utf8_ok(data, len)) {
    fz_set_last_error(EINVAL, 3, "bytes.as_str failed: bytes are not UTF-8 text-safe");
    return fz_intern_slice("", 0);
  }
  fz_set_last_error(0, 0, "");
  return fz_intern_slice((const char*)(data == NULL ? (const uint8_t*)"" : data), len);
}

"#
}
