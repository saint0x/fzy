pub(super) fn section() -> &'static str {
    r#"
typedef struct {
  uint32_t state[8];
  uint64_t bitlen;
  uint8_t data[64];
  size_t datalen;
} fz_sha256_ctx;

static uint32_t fz_sha256_rotr(uint32_t value, uint32_t bits) {
  return (value >> bits) | (value << (32 - bits));
}

static uint32_t fz_sha256_ch(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ (~x & z);
}

static uint32_t fz_sha256_maj(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

static uint32_t fz_sha256_ep0(uint32_t x) {
  return fz_sha256_rotr(x, 2) ^ fz_sha256_rotr(x, 13) ^ fz_sha256_rotr(x, 22);
}

static uint32_t fz_sha256_ep1(uint32_t x) {
  return fz_sha256_rotr(x, 6) ^ fz_sha256_rotr(x, 11) ^ fz_sha256_rotr(x, 25);
}

static uint32_t fz_sha256_sig0(uint32_t x) {
  return fz_sha256_rotr(x, 7) ^ fz_sha256_rotr(x, 18) ^ (x >> 3);
}

static uint32_t fz_sha256_sig1(uint32_t x) {
  return fz_sha256_rotr(x, 17) ^ fz_sha256_rotr(x, 19) ^ (x >> 10);
}

static const uint32_t fz_sha256_k[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

static void fz_sha256_transform(fz_sha256_ctx* ctx, const uint8_t data[64]) {
  uint32_t m[64];
  for (int i = 0; i < 16; i++) {
    m[i] = ((uint32_t)data[i * 4] << 24) | ((uint32_t)data[(i * 4) + 1] << 16)
        | ((uint32_t)data[(i * 4) + 2] << 8) | (uint32_t)data[(i * 4) + 3];
  }
  for (int i = 16; i < 64; i++) {
    m[i] = fz_sha256_sig1(m[i - 2]) + m[i - 7] + fz_sha256_sig0(m[i - 15]) + m[i - 16];
  }
  uint32_t a = ctx->state[0];
  uint32_t b = ctx->state[1];
  uint32_t c = ctx->state[2];
  uint32_t d = ctx->state[3];
  uint32_t e = ctx->state[4];
  uint32_t f = ctx->state[5];
  uint32_t g = ctx->state[6];
  uint32_t h = ctx->state[7];
  for (int i = 0; i < 64; i++) {
    uint32_t t1 = h + fz_sha256_ep1(e) + fz_sha256_ch(e, f, g) + fz_sha256_k[i] + m[i];
    uint32_t t2 = fz_sha256_ep0(a) + fz_sha256_maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

static void fz_sha256_init(fz_sha256_ctx* ctx) {
  memset(ctx, 0, sizeof(*ctx));
  ctx->state[0] = 0x6a09e667u;
  ctx->state[1] = 0xbb67ae85u;
  ctx->state[2] = 0x3c6ef372u;
  ctx->state[3] = 0xa54ff53au;
  ctx->state[4] = 0x510e527fu;
  ctx->state[5] = 0x9b05688cu;
  ctx->state[6] = 0x1f83d9abu;
  ctx->state[7] = 0x5be0cd19u;
}

static void fz_sha256_update(fz_sha256_ctx* ctx, const uint8_t* data, size_t len) {
  if (ctx == NULL || (data == NULL && len != 0)) {
    return;
  }
  for (size_t i = 0; i < len; i++) {
    ctx->data[ctx->datalen++] = data[i];
    if (ctx->datalen == 64) {
      fz_sha256_transform(ctx, ctx->data);
      ctx->bitlen += 512;
      ctx->datalen = 0;
    }
  }
}

static void fz_sha256_final(fz_sha256_ctx* ctx, uint8_t hash[32]) {
  size_t i = ctx->datalen;
  if (i < 56) {
    ctx->data[i++] = 0x80;
    while (i < 56) {
      ctx->data[i++] = 0x00;
    }
  } else {
    ctx->data[i++] = 0x80;
    while (i < 64) {
      ctx->data[i++] = 0x00;
    }
    fz_sha256_transform(ctx, ctx->data);
    memset(ctx->data, 0, 56);
  }
  ctx->bitlen += (uint64_t)ctx->datalen * 8u;
  ctx->data[63] = (uint8_t)(ctx->bitlen);
  ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
  ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
  ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
  ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
  ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
  ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
  ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
  fz_sha256_transform(ctx, ctx->data);
  for (i = 0; i < 4; i++) {
    hash[i] = (uint8_t)((ctx->state[0] >> (24 - i * 8)) & 0xff);
    hash[i + 4] = (uint8_t)((ctx->state[1] >> (24 - i * 8)) & 0xff);
    hash[i + 8] = (uint8_t)((ctx->state[2] >> (24 - i * 8)) & 0xff);
    hash[i + 12] = (uint8_t)((ctx->state[3] >> (24 - i * 8)) & 0xff);
    hash[i + 16] = (uint8_t)((ctx->state[4] >> (24 - i * 8)) & 0xff);
    hash[i + 20] = (uint8_t)((ctx->state[5] >> (24 - i * 8)) & 0xff);
    hash[i + 24] = (uint8_t)((ctx->state[6] >> (24 - i * 8)) & 0xff);
    hash[i + 28] = (uint8_t)((ctx->state[7] >> (24 - i * 8)) & 0xff);
  }
}

static void fz_sha256_hash(const uint8_t* data, size_t len, uint8_t out[32]) {
  fz_sha256_ctx ctx;
  fz_sha256_init(&ctx);
  fz_sha256_update(&ctx, data, len);
  fz_sha256_final(&ctx, out);
}

static void fz_hmac_sha256_hash(
    const uint8_t* key,
    size_t key_len,
    const uint8_t* data,
    size_t data_len,
    uint8_t out[32]) {
  uint8_t key_block[64];
  memset(key_block, 0, sizeof(key_block));
  if (key_len > 64) {
    fz_sha256_hash(key, key_len, key_block);
  } else if (key_len > 0 && key != NULL) {
    memcpy(key_block, key, key_len);
  }
  uint8_t ipad[64];
  uint8_t opad[64];
  for (size_t i = 0; i < 64; i++) {
    ipad[i] = (uint8_t)(key_block[i] ^ 0x36u);
    opad[i] = (uint8_t)(key_block[i] ^ 0x5cu);
  }
  uint8_t inner[32];
  fz_sha256_ctx ctx;
  fz_sha256_init(&ctx);
  fz_sha256_update(&ctx, ipad, sizeof(ipad));
  fz_sha256_update(&ctx, data, data_len);
  fz_sha256_final(&ctx, inner);
  fz_sha256_init(&ctx);
  fz_sha256_update(&ctx, opad, sizeof(opad));
  fz_sha256_update(&ctx, inner, sizeof(inner));
  fz_sha256_final(&ctx, out);
  fz_crypto_memzero(key_block, sizeof(key_block));
  fz_crypto_memzero(ipad, sizeof(ipad));
  fz_crypto_memzero(opad, sizeof(opad));
  fz_crypto_memzero(inner, sizeof(inner));
}

static int fz_crypto_fill_random(void* out, size_t len) {
  if (len == 0) {
    return 0;
  }
  if (out == NULL) {
    errno = EINVAL;
    return -1;
  }
#if defined(__APPLE__)
  arc4random_buf(out, len);
  return 0;
#elif defined(__linux__)
  uint8_t* cursor = (uint8_t*)out;
  size_t remaining = len;
  while (remaining > 0) {
    size_t chunk = remaining > 256 ? 256 : remaining;
    if (getentropy(cursor, chunk) == 0) {
      cursor += chunk;
      remaining -= chunk;
      continue;
    }
    if (errno == EINTR) {
      continue;
    }
    if (errno != ENOSYS) {
      return -1;
    }
    break;
  }
  if (remaining == 0) {
    return 0;
  }
#endif
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0) {
    return -1;
  }
#if !defined(__linux__)
  uint8_t* cursor = (uint8_t*)out;
  size_t remaining = len;
#endif
  while (remaining > 0) {
    ssize_t got = read(fd, cursor, remaining);
    if (got < 0) {
      if (errno == EINTR) {
        continue;
      }
      close(fd);
      return -1;
    }
    if (got == 0) {
      close(fd);
      return -1;
    }
    cursor += (size_t)got;
    remaining -= (size_t)got;
  }
  close(fd);
  return 0;
}

static char* fz_crypto_hex_encode(const uint8_t* data, size_t len) {
  static const char* hex = "0123456789abcdef";
  char* out = (char*)malloc((len * 2) + 1);
  if (out == NULL) {
    return NULL;
  }
  for (size_t i = 0; i < len; i++) {
    out[i * 2] = hex[(data[i] >> 4) & 0x0f];
    out[(i * 2) + 1] = hex[data[i] & 0x0f];
  }
  out[len * 2] = '\0';
  return out;
}

static char* fz_crypto_base64_encode_alloc(const uint8_t* data, size_t len) {
  static const char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t out_len = ((len + 2) / 3) * 4;
  char* out = (char*)malloc(out_len + 1);
  if (out == NULL) {
    return NULL;
  }
  size_t in_index = 0;
  size_t out_index = 0;
  while (in_index < len) {
    size_t remaining = len - in_index;
    uint32_t octet_a = data[in_index++];
    uint32_t octet_b = remaining > 1 ? data[in_index++] : 0;
    uint32_t octet_c = remaining > 2 ? data[in_index++] : 0;
    uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;
    out[out_index++] = alphabet[(triple >> 18) & 0x3f];
    out[out_index++] = alphabet[(triple >> 12) & 0x3f];
    out[out_index++] = remaining > 1 ? alphabet[(triple >> 6) & 0x3f] : '=';
    out[out_index++] = remaining > 2 ? alphabet[triple & 0x3f] : '=';
  }
  out[out_len] = '\0';
  return out;
}

static char* fz_crypto_base64_url_encode_alloc(const uint8_t* data, size_t len) {
  char* out = fz_crypto_base64_encode_alloc(data, len);
  if (out == NULL) {
    return NULL;
  }
  size_t write_index = 0;
  for (size_t read_index = 0; out[read_index] != '\0'; read_index++) {
    char ch = out[read_index];
    if (ch == '=') {
      continue;
    }
    if (ch == '+') {
      ch = '-';
    } else if (ch == '/') {
      ch = '_';
    }
    out[write_index++] = ch;
  }
  out[write_index] = '\0';
  return out;
}

static int fz_crypto_base64_value(int ch) {
  if (ch >= 'A' && ch <= 'Z') return ch - 'A';
  if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
  if (ch >= '0' && ch <= '9') return ch - '0' + 52;
  if (ch == '+') return 62;
  if (ch == '/') return 63;
  return -1;
}

static int fz_crypto_base64_decode_alloc(const char* input, uint8_t** out, size_t* out_len) {
  if (out == NULL || out_len == NULL) {
    errno = EINVAL;
    return -1;
  }
  *out = NULL;
  *out_len = 0;
  if (input == NULL) {
    return 0;
  }
  size_t len = strlen(input);
  if (len == 0) {
    *out = (uint8_t*)calloc(1, 1);
    return *out == NULL ? -1 : 0;
  }
  if ((len % 4) != 0) {
    errno = EINVAL;
    return -1;
  }
  size_t padding = 0;
  if (len >= 1 && input[len - 1] == '=') padding++;
  if (len >= 2 && input[len - 2] == '=') padding++;
  size_t decoded_len = (len / 4) * 3 - padding;
  uint8_t* buf = (uint8_t*)malloc(decoded_len == 0 ? 1 : decoded_len);
  if (buf == NULL) {
    return -1;
  }
  size_t out_index = 0;
  for (size_t i = 0; i < len; i += 4) {
    int is_last_block = (i + 4) == len ? 1 : 0;
    int vals[4];
    for (int j = 0; j < 4; j++) {
      int ch = (unsigned char)input[i + (size_t)j];
      if (ch == '=') {
        if (!is_last_block || j < 2) {
          free(buf);
          errno = EINVAL;
          return -1;
        }
        if (j == 2 && input[i + 3] != '=') {
          free(buf);
          errno = EINVAL;
          return -1;
        }
        vals[j] = 0;
        continue;
      }
      vals[j] = fz_crypto_base64_value(ch);
      if (vals[j] < 0) {
        free(buf);
        errno = EINVAL;
        return -1;
      }
    }
    if (input[i + 2] == '=' && input[i + 3] != '=') {
      free(buf);
      errno = EINVAL;
      return -1;
    }
    uint32_t triple =
        ((uint32_t)vals[0] << 18) | ((uint32_t)vals[1] << 12) | ((uint32_t)vals[2] << 6)
        | (uint32_t)vals[3];
    if (out_index < decoded_len) buf[out_index++] = (uint8_t)((triple >> 16) & 0xff);
    if (out_index < decoded_len) buf[out_index++] = (uint8_t)((triple >> 8) & 0xff);
    if (out_index < decoded_len) buf[out_index++] = (uint8_t)(triple & 0xff);
  }
  *out = buf;
  *out_len = decoded_len;
  return 0;
}

static int fz_crypto_base64_url_decode_alloc(const char* input, uint8_t** out, size_t* out_len) {
  if (out == NULL || out_len == NULL) {
    errno = EINVAL;
    return -1;
  }
  *out = NULL;
  *out_len = 0;
  if (input == NULL) {
    return 0;
  }
  size_t len = strlen(input);
  if (len == 0) {
    return fz_crypto_base64_decode_alloc("", out, out_len);
  }
  int saw_padding = 0;
  for (size_t i = 0; i < len; i++) {
    char ch = input[i];
    if (ch == '=') {
      saw_padding = 1;
      continue;
    }
    if (saw_padding) {
      errno = EINVAL;
      return -1;
    }
    if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
          || ch == '-' || ch == '_')) {
      errno = EINVAL;
      return -1;
    }
  }

  size_t rem = len % 4;
  size_t padded_len = len;
  if (!saw_padding) {
    if (rem == 1) {
      errno = EINVAL;
      return -1;
    }
    if (rem != 0) {
      padded_len += 4 - rem;
    }
  } else if (rem != 0) {
    errno = EINVAL;
    return -1;
  }

  char* standard = (char*)malloc(padded_len + 1);
  if (standard == NULL) {
    errno = ENOMEM;
    return -1;
  }
  for (size_t i = 0; i < len; i++) {
    char ch = input[i];
    if (ch == '-') {
      standard[i] = '+';
    } else if (ch == '_') {
      standard[i] = '/';
    } else {
      standard[i] = ch;
    }
  }
  for (size_t i = len; i < padded_len; i++) {
    standard[i] = '=';
  }
  standard[padded_len] = '\0';
  int rc = fz_crypto_base64_decode_alloc(standard, out, out_len);
  fz_crypto_memzero(standard, padded_len);
  free(standard);
  return rc;
}


"#
}
