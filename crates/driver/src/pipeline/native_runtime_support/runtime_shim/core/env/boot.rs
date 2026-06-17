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

static void fz_log_bind_target(int listener_fd) {
  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);
  memset(&addr, 0, sizeof(addr));
  if (getsockname(listener_fd, (struct sockaddr*)&addr, &addr_len) != 0) {
    return;
  }
  char host[NI_MAXHOST];
  char service[NI_MAXSERV];
  int rc = getnameinfo(
      (struct sockaddr*)&addr,
      addr_len,
      host,
      sizeof(host),
      service,
      sizeof(service),
      NI_NUMERICHOST | NI_NUMERICSERV);
  if (rc != 0) {
    return;
  }
  fprintf(
      stderr,
      "[fz-runtime] listen active addr=%s port=%s\n",
      host,
      service);
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
