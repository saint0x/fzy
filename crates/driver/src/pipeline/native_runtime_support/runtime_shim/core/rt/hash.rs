pub(super) fn section() -> &'static str {
    r#"
static void fz_sha1_compute(const uint8_t* data, size_t len, uint8_t out[20]) {
  uint32_t h0 = 0x67452301u;
  uint32_t h1 = 0xEFCDAB89u;
  uint32_t h2 = 0x98BADCFEu;
  uint32_t h3 = 0x10325476u;
  uint32_t h4 = 0xC3D2E1F0u;
  uint64_t bit_len = (uint64_t)len * 8u;
  size_t padded_len = len + 1 + 8;
  size_t rem = padded_len % 64;
  if (rem != 0) {
    padded_len += 64 - rem;
  }
  uint8_t* buf = (uint8_t*)calloc(padded_len, 1);
  if (buf == NULL) {
    memset(out, 0, 20);
    return;
  }
  memcpy(buf, data, len);
  buf[len] = 0x80u;
  for (int i = 0; i < 8; i++) {
    buf[padded_len - 1 - i] = (uint8_t)(bit_len >> (i * 8));
  }
  for (size_t offset = 0; offset < padded_len; offset += 64) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++) {
      size_t at = offset + (size_t)i * 4;
      w[i] = ((uint32_t)buf[at] << 24) | ((uint32_t)buf[at + 1] << 16)
          | ((uint32_t)buf[at + 2] << 8) | (uint32_t)buf[at + 3];
    }
    for (int i = 16; i < 80; i++) {
      uint32_t x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
      w[i] = (x << 1) | (x >> 31);
    }
    uint32_t a = h0;
    uint32_t b = h1;
    uint32_t c = h2;
    uint32_t d = h3;
    uint32_t e = h4;
    for (int i = 0; i < 80; i++) {
      uint32_t f;
      uint32_t k;
      if (i < 20) {
        f = (b & c) | ((~b) & d);
        k = 0x5A827999u;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1u;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDCu;
      } else {
        f = b ^ c ^ d;
        k = 0xCA62C1D6u;
      }
      uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
      e = d;
      d = c;
      c = (b << 30) | (b >> 2);
      b = a;
      a = temp;
    }
    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
  }
  free(buf);
  uint32_t words[5] = {h0, h1, h2, h3, h4};
  for (int i = 0; i < 5; i++) {
    out[i * 4] = (uint8_t)(words[i] >> 24);
    out[i * 4 + 1] = (uint8_t)(words[i] >> 16);
    out[i * 4 + 2] = (uint8_t)(words[i] >> 8);
    out[i * 4 + 3] = (uint8_t)(words[i]);
  }
}

static char* fz_base64_encode(const uint8_t* data, size_t len) {
  static const char table[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t out_len = ((len + 2) / 3) * 4;
  char* out = (char*)malloc(out_len + 1);
  if (out == NULL) {
    return NULL;
  }
  size_t j = 0;
  for (size_t i = 0; i < len; i += 3) {
    uint32_t octet_a = data[i];
    uint32_t octet_b = i + 1 < len ? data[i + 1] : 0;
    uint32_t octet_c = i + 2 < len ? data[i + 2] : 0;
    uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;
    out[j++] = table[(triple >> 18) & 0x3F];
    out[j++] = table[(triple >> 12) & 0x3F];
    out[j++] = i + 1 < len ? table[(triple >> 6) & 0x3F] : '=';
    out[j++] = i + 2 < len ? table[triple & 0x3F] : '=';
  }
  out[j] = '\0';
  return out;
}

static int fz_websocket_recv_exact(int fd, uint8_t* buf, size_t len) {
  size_t used = 0;
  while (used < len) {
    ssize_t got = recv(fd, buf + used, len - used, 0);
    if (got < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        if (fz_wait_for_fd_event(fd, POLLIN, 2500) == 0) {
          continue;
        }
      }
      return -1;
    }
    if (got == 0) {
      return -1;
    }
    used += (size_t)got;
  }
  return 0;
}

static int fz_websocket_write_frame(int fd, uint8_t opcode, const char* payload, size_t payload_len) {
  if (fd < 0) {
    return -1;
  }
  uint8_t header[10];
  size_t header_len = 0;
  header[header_len++] = (uint8_t)(0x80u | (opcode & 0x0Fu));
  if (payload_len < 126) {
    header[header_len++] = (uint8_t)payload_len;
  } else if (payload_len <= 0xFFFFu) {
    header[header_len++] = 126;
    header[header_len++] = (uint8_t)((payload_len >> 8) & 0xFFu);
    header[header_len++] = (uint8_t)(payload_len & 0xFFu);
  } else {
    header[header_len++] = 127;
    for (int i = 7; i >= 0; i--) {
      header[header_len++] = (uint8_t)((payload_len >> (i * 8)) & 0xFFu);
    }
  }
  if (fz_send_all(fd, (const char*)header, header_len) != 0) {
    return -1;
  }
  if (payload_len > 0 && payload != NULL && fz_send_all(fd, payload, payload_len) != 0) {
    return -1;
  }
  return 0;
}

static int fz_websocket_read_frame(
    fz_websocket_state* ws,
    int32_t max_bytes,
    int32_t* out_kind_id,
    int32_t* out_close_code,
    int32_t* out_error_id) {
  if (ws == NULL || ws->fd < 0 || out_kind_id == NULL || out_close_code == NULL || out_error_id == NULL) {
    return fz_intern_slice("", 0);
  }
  *out_close_code = 0;
  *out_error_id = fz_intern_slice("", 0);
  uint8_t hdr[2];
  if (fz_websocket_recv_exact(ws->fd, hdr, 2) != 0) {
    *out_kind_id = fz_intern_slice("error", 5);
    *out_error_id = fz_intern_slice("websocket read failed", 21);
    return fz_intern_slice("", 0);
  }
  uint8_t opcode = hdr[0] & 0x0Fu;
  int fin = (hdr[0] & 0x80u) != 0;
  int masked = (hdr[1] & 0x80u) != 0;
  uint64_t payload_len = hdr[1] & 0x7Fu;
  if (payload_len == 126) {
    uint8_t ext[2];
    if (fz_websocket_recv_exact(ws->fd, ext, 2) != 0) {
      *out_kind_id = fz_intern_slice("error", 5);
      *out_error_id = fz_intern_slice("websocket extended length read failed", 37);
      return fz_intern_slice("", 0);
    }
    payload_len = ((uint64_t)ext[0] << 8) | (uint64_t)ext[1];
  } else if (payload_len == 127) {
    uint8_t ext[8];
    if (fz_websocket_recv_exact(ws->fd, ext, 8) != 0) {
      *out_kind_id = fz_intern_slice("error", 5);
      *out_error_id = fz_intern_slice("websocket 64-bit length read failed", 35);
      return fz_intern_slice("", 0);
    }
    payload_len = 0;
    for (int i = 0; i < 8; i++) {
      payload_len = (payload_len << 8) | (uint64_t)ext[i];
    }
  }
  uint8_t mask[4] = {0};
  if (masked) {
    if (fz_websocket_recv_exact(ws->fd, mask, 4) != 0) {
      *out_kind_id = fz_intern_slice("error", 5);
      *out_error_id = fz_intern_slice("websocket mask read failed", 26);
      return fz_intern_slice("", 0);
    }
  }
  if (max_bytes > 0 && payload_len > (uint64_t)max_bytes) {
    *out_kind_id = fz_intern_slice("error", 5);
    *out_error_id = fz_intern_slice("websocket frame exceeds max_bytes", 33);
    return fz_intern_slice("", 0);
  }
  uint8_t* payload = NULL;
  if (payload_len > 0) {
    payload = (uint8_t*)malloc((size_t)payload_len);
    if (payload == NULL) {
      *out_kind_id = fz_intern_slice("error", 5);
      *out_error_id = fz_intern_slice("websocket payload alloc failed", 30);
      return fz_intern_slice("", 0);
    }
    if (fz_websocket_recv_exact(ws->fd, payload, (size_t)payload_len) != 0) {
      free(payload);
      *out_kind_id = fz_intern_slice("error", 5);
      *out_error_id = fz_intern_slice("websocket payload read failed", 29);
      return fz_intern_slice("", 0);
    }
    if (masked) {
      for (uint64_t i = 0; i < payload_len; i++) {
        payload[i] ^= mask[i % 4];
      }
    }
  }
  if (!fin) {
    free(payload);
    *out_kind_id = fz_intern_slice("error", 5);
    *out_error_id = fz_intern_slice("fragmented websocket frames unsupported", 39);
    return fz_intern_slice("", 0);
  }
  if (opcode == 0x8u) {
    *out_kind_id = fz_intern_slice("close", 5);
    if (payload_len >= 2) {
      *out_close_code = ((int32_t)payload[0] << 8) | (int32_t)payload[1];
    }
    free(payload);
    ws->closed = 1;
    return fz_intern_slice("", 0);
  }
  if (opcode == 0x9u) {
    *out_kind_id = fz_intern_slice("ping", 4);
  } else if (opcode == 0xAu) {
    *out_kind_id = fz_intern_slice("pong", 4);
  } else if (opcode == 0x2u) {
    *out_kind_id = fz_intern_slice("binary", 6);
  } else {
    *out_kind_id = fz_intern_slice("text", 4);
  }
  int32_t out = fz_intern_slice((const char*)(payload == NULL ? (uint8_t*)"" : payload), (size_t)payload_len);
  free(payload);
  return out;
}

"#
}
