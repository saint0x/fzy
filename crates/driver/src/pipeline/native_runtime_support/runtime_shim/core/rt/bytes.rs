pub(super) fn section() -> &'static str {
    r#"
static void fz_bytes_reset(fz_bytes_state* bytes) {
  if (bytes == NULL) {
    return;
  }
  free(bytes->data);
  bytes->data = NULL;
  bytes->len = 0;
}

static int32_t fz_runtime_bytes_new_from_slice(const uint8_t* data, size_t len) {
  pthread_mutex_lock(&fz_bytes_lock);
  int32_t handle = fz_bytes_alloc();
  fz_bytes_state* bytes = fz_bytes_get(handle);
  if (bytes == NULL) {
    pthread_mutex_unlock(&fz_bytes_lock);
    fz_set_last_error(ENOMEM, 3, "bytes alloc failed: no free slots");
    return -1;
  }
  if (len > 0) {
    bytes->data = (uint8_t*)malloc(len);
    if (bytes->data == NULL) {
      memset(bytes, 0, sizeof(*bytes));
      pthread_mutex_unlock(&fz_bytes_lock);
      fz_set_last_error(ENOMEM, 3, "bytes alloc failed: buffer alloc failed");
      return -1;
    }
    memcpy(bytes->data, data, len);
  }
  bytes->len = len;
  pthread_mutex_unlock(&fz_bytes_lock);
  fz_set_last_error(0, 0, "");
  return handle;
}

static int32_t fz_runtime_bytes_len(int32_t handle) {
  pthread_mutex_lock(&fz_bytes_lock);
  fz_bytes_state* bytes = fz_bytes_get(handle);
  int32_t out = bytes == NULL ? -1 : (bytes->len > (size_t)INT32_MAX ? INT32_MAX : (int32_t)bytes->len);
  pthread_mutex_unlock(&fz_bytes_lock);
  return out;
}

static const uint8_t* fz_runtime_bytes_data_ptr(int32_t handle, size_t* out_len) {
  const uint8_t* out = NULL;
  size_t len = 0;
  pthread_mutex_lock(&fz_bytes_lock);
  fz_bytes_state* bytes = fz_bytes_get(handle);
  if (bytes != NULL) {
    out = bytes->data;
    len = bytes->len;
  }
  pthread_mutex_unlock(&fz_bytes_lock);
  if (out_len != NULL) {
    *out_len = len;
  }
  return out;
}

static int fz_runtime_bytes_bounds_ok(size_t len, int32_t start, int32_t width, const char* context) {
  if (start < 0 || width < 0) {
    fz_set_last_error(EINVAL, 3, context);
    return 0;
  }
  size_t offset = (size_t)start;
  size_t needed = (size_t)width;
  if (offset > len || needed > len - offset) {
    fz_set_last_error(ERANGE, 3, context);
    return 0;
  }
  return 1;
}

static int fz_runtime_bytes_utf8_ok(const uint8_t* data, size_t len) {
  size_t i = 0;
  while (i < len) {
    uint8_t byte = data[i];
    if (byte == 0) {
      return 0;
    }
    if ((byte & 0x80) == 0) {
      i++;
      continue;
    }
    size_t need = 0;
    uint32_t codepoint = 0;
    if ((byte & 0xE0) == 0xC0) {
      need = 1;
      codepoint = (uint32_t)(byte & 0x1F);
      if (codepoint < 0x2) {
        return 0;
      }
    } else if ((byte & 0xF0) == 0xE0) {
      need = 2;
      codepoint = (uint32_t)(byte & 0x0F);
    } else if ((byte & 0xF8) == 0xF0) {
      need = 3;
      codepoint = (uint32_t)(byte & 0x07);
      if (codepoint > 0x4) {
        return 0;
      }
    } else {
      return 0;
    }
    if (i + need >= len) {
      return 0;
    }
    for (size_t j = 1; j <= need; j++) {
      uint8_t cont = data[i + j];
      if ((cont & 0xC0) != 0x80) {
        return 0;
      }
      codepoint = (codepoint << 6) | (uint32_t)(cont & 0x3F);
    }
    if ((need == 2 && codepoint < 0x800)
        || (need == 3 && codepoint < 0x10000)
        || (codepoint >= 0xD800 && codepoint <= 0xDFFF)
        || codepoint > 0x10FFFF) {
      return 0;
    }
    i += need + 1;
  }
  return 1;
}

static float fz_runtime_bytes_f16_to_f32(uint16_t bits) {
  uint32_t sign = (uint32_t)(bits & 0x8000) << 16;
  uint32_t exp = (uint32_t)(bits >> 10) & 0x1F;
  uint32_t frac = (uint32_t)bits & 0x03FF;
  uint32_t out_bits;
  if (exp == 0) {
    if (frac == 0) {
      out_bits = sign;
    } else {
      exp = 1;
      while ((frac & 0x0400) == 0) {
        frac <<= 1;
        exp--;
      }
      frac &= 0x03FF;
      out_bits = sign | ((exp + 112) << 23) | (frac << 13);
    }
  } else if (exp == 0x1F) {
    out_bits = sign | 0x7F800000u | (frac << 13);
  } else {
    out_bits = sign | ((exp + 112) << 23) | (frac << 13);
  }
  union {
    uint32_t bits;
    float value;
  } out;
  out.bits = out_bits;
  return out.value;
}

"#
}
