pub(super) fn section() -> &'static str {
    r#"
static char* fz_trim_ascii(char* text) {
  if (text == NULL) {
    return NULL;
  }
  while (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n') {
    text++;
  }
  size_t len = strlen(text);
  while (len > 0 && (text[len - 1] == ' ' || text[len - 1] == '\t' || text[len - 1] == '\r' || text[len - 1] == '\n')) {
    text[--len] = '\0';
  }
  return text;
}

static void fz_unquote_env_value(char* value) {
  if (value == NULL) {
    return;
  }
  size_t len = strlen(value);
  if (len < 2) {
    return;
  }
  char quote = value[0];
  if ((quote != '\'' && quote != '\"') || value[len - 1] != quote) {
    return;
  }
  value[len - 1] = '\0';
  memmove(value, value + 1, len - 1);
  if (quote == '\"') {
    char* src = value;
    char* dst = value;
    while (*src != '\0') {
      if (*src == '\\' && src[1] != '\0') {
        src++;
        switch (*src) {
          case 'n': *dst++ = '\n'; break;
          case 'r': *dst++ = '\r'; break;
          case 't': *dst++ = '\t'; break;
          case '\\': *dst++ = '\\'; break;
          case '\"': *dst++ = '\"'; break;
          default: *dst++ = *src; break;
        }
        src++;
        continue;
      }
      *dst++ = *src++;
    }
    *dst = '\0';
  }
}

static void fz_dotenv_load(void) {
  const char* path = getenv("FZ_DOTENV_PATH");
  if (path == NULL || path[0] == '\0') {
    path = ".env";
  }
  FILE* file = fopen(path, "r");
  if (file == NULL) {
    return;
  }
  char line[4096];
  while (fgets(line, sizeof(line), file) != NULL) {
    char* entry = fz_trim_ascii(line);
    if (entry == NULL || entry[0] == '\0' || entry[0] == '#') {
      continue;
    }
    if (strncmp(entry, "export ", 7) == 0) {
      entry = fz_trim_ascii(entry + 7);
      if (entry == NULL || entry[0] == '\0') {
        continue;
      }
    }
    char* eq = strchr(entry, '=');
    if (eq == NULL) {
      continue;
    }
    *eq = '\0';
    char* key = fz_trim_ascii(entry);
    char* value = fz_trim_ascii(eq + 1);
    if (key == NULL || key[0] == '\0' || value == NULL) {
      continue;
    }
    fz_unquote_env_value(value);
    if (getenv(key) == NULL) {
      (void)setenv(key, value, 0);
    }
  }
  fclose(file);
}

static void fz_env_bootstrap(void) {
  fz_dotenv_load();
}

static const char* fz_env_get_bootstrapped(const char* key) {
  if (key == NULL || key[0] == '\0') {
    return NULL;
  }
  (void)pthread_once(&fz_env_bootstrap_once, fz_env_bootstrap);
  return getenv(key);
}

static int fz_has_env_value(const char* key) {
  const char* value = fz_env_get_bootstrapped(key);
  return value != NULL && value[0] != '\0';
}

static int fz_parse_port_from_env(const char* key, int fallback) {
  const char* raw = fz_env_get_bootstrapped(key);
  if (raw == NULL || raw[0] == '\0') {
    return fallback;
  }
  char* end = NULL;
  long parsed = strtol(raw, &end, 10);
  if (end == raw || parsed <= 0 || parsed > 65535) {
    return fallback;
  }
  return (int)parsed;
}

static int fz_default_port(void) {
  int port = 8787;
  port = fz_parse_port_from_env("PORT", port);
  port = fz_parse_port_from_env("AGENT_PORT", port);
  port = fz_parse_port_from_env("FZ_PORT", port);
  return port;
}

static const char* fz_default_host_name(void) {
  const char* host = fz_env_get_bootstrapped("FZ_HOST");
  if (host == NULL || host[0] == '\0') {
    host = fz_env_get_bootstrapped("AGENT_HOST");
  }
  if (host == NULL || host[0] == '\0') {
    host = "127.0.0.1";
  }
  return host;
}

static uint32_t fz_default_addr(void) {
  const char* host = fz_default_host_name();
  struct in_addr addr;
  if (inet_pton(AF_INET, host, &addr) == 1) {
    return addr.s_addr;
  }
  if (strcmp(host, "localhost") == 0) {
    return htonl(INADDR_LOOPBACK);
  }
  return htonl(INADDR_LOOPBACK);
}

static void fz_log_bind_target(int listener_fd) {
  struct sockaddr_in addr;
  socklen_t addr_len = sizeof(addr);
  memset(&addr, 0, sizeof(addr));
  if (getsockname(listener_fd, (struct sockaddr*)&addr, &addr_len) != 0) {
    return;
  }
  char host[64];
  const char* rendered = inet_ntop(AF_INET, &addr.sin_addr, host, sizeof(host));
  if (rendered == NULL) {
    rendered = "127.0.0.1";
  }
  int port = (int)ntohs(addr.sin_port);
  const char* host_source = fz_has_env_value("FZ_HOST")
      ? "FZ_HOST"
      : (fz_has_env_value("AGENT_HOST") ? "AGENT_HOST" : "default");
  const char* port_source = fz_has_env_value("FZ_PORT")
      ? "FZ_PORT"
      : (fz_has_env_value("AGENT_PORT")
            ? "AGENT_PORT"
            : (fz_has_env_value("PORT") ? "PORT" : "default"));
  fprintf(
      stderr,
      "[fz-runtime] listen active addr=%s port=%d (host_source=%s port_source=%s)\n",
      rendered,
      port,
      host_source,
      port_source);
  fflush(stderr);
}

static int64_t fz_now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + (ts.tv_nsec / 1000000);
}

static int fz_async_current_task_cancelled(void) {
  if (fz_tls_async_cancelled) {
    return 1;
  }
  if (fz_tls_task_handle <= 0) {
    return 0;
  }
  int cancelled = 0;
  pthread_mutex_lock(&fz_spawn_lock);
  fz_spawn_state* state = fz_spawn_state_by_handle_locked(fz_tls_task_handle);
  if (state != NULL && state->cancelled) {
    cancelled = 1;
  }
  pthread_mutex_unlock(&fz_spawn_lock);
  if (cancelled) {
    fz_tls_async_cancelled = 1;
  }
  return cancelled;
}

static int fz_async_deadline_expired(void) {
  return fz_tls_async_deadline_ms > 0 && fz_now_ms() >= fz_tls_async_deadline_ms;
}

static int fz_async_effective_timeout_ms(int timeout_ms) {
  if (fz_async_current_task_cancelled()) {
    return 0;
  }
  if (fz_tls_async_deadline_ms <= 0) {
    return timeout_ms;
  }
  int64_t remaining = fz_tls_async_deadline_ms - fz_now_ms();
  if (remaining <= 0) {
    return 0;
  }
  if (timeout_ms < 0 || remaining < (int64_t)timeout_ms) {
    return remaining > INT32_MAX ? INT32_MAX : (int)remaining;
  }
  return timeout_ms;
}

"#
}
