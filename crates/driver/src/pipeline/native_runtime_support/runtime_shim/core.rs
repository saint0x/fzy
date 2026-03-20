pub(super) fn runtime_shim_section_core() -> &'static str {
    r#"
#define FZ_MAX_DYNAMIC_STRINGS 16384
#define FZ_MAX_CONN_STATES 2048
#define FZ_MAX_HTTP_READ 262144
#define FZ_MAX_PROC_STATES 1024
#define FZ_MAX_HTTP_HEADERS 128
#define FZ_MAX_SPAWN_THREADS 4096
#define FZ_MAX_CONN_META 128
#define FZ_MAX_ROUTE_PARAMS 64
#define FZ_MAX_LISTS 2048
#define FZ_MAX_LIST_ITEMS 4096
#define FZ_MAX_MAPS 2048
#define FZ_MAX_MAP_ENTRIES 4096
#define FZ_MAX_INTERVALS 512
#define FZ_MAX_JSON_VALUES 16384
#define FZ_MAX_STORAGE_KV 1024

static char* fz_dynamic_strings[FZ_MAX_DYNAMIC_STRINGS];
static int fz_dynamic_string_count = 0;
static pthread_mutex_t fz_string_lock = PTHREAD_MUTEX_INITIALIZER;

static int fz_listener_fd = -1;
static pthread_mutex_t fz_listener_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
  int in_use;
  int fd;
  int32_t method_id;
  int32_t path_id;
  int32_t body_id;
  int32_t request_id;
  int32_t remote_addr_id;
  int keep_alive;
  int header_count;
  int32_t header_key_ids[FZ_MAX_CONN_META];
  int32_t header_value_ids[FZ_MAX_CONN_META];
  int query_count;
  int32_t query_key_ids[FZ_MAX_CONN_META];
  int32_t query_value_ids[FZ_MAX_CONN_META];
  int param_count;
  int32_t param_key_ids[FZ_MAX_ROUTE_PARAMS];
  int32_t param_value_ids[FZ_MAX_ROUTE_PARAMS];
} fz_conn_state;

static fz_conn_state fz_conn_states[FZ_MAX_CONN_STATES];
static pthread_mutex_t fz_conn_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
  char* data;
  size_t len;
  size_t cap;
} fz_bytes_buf;

typedef struct {
  int in_use;
  pid_t pid;
  int stdout_fd;
  int stderr_fd;
  int done;
  int exit_notified;
  int exit_code;
  size_t stdout_read_pos;
  size_t stderr_read_pos;
  int32_t stdout_id;
  int32_t stderr_id;
  fz_bytes_buf stdout_buf;
  fz_bytes_buf stderr_buf;
} fz_proc_state;

typedef struct {
  int in_use;
  int count;
  char* items[FZ_MAX_LIST_ITEMS];
} fz_list_state;

typedef struct {
  int in_use;
  int count;
  int32_t items[FZ_MAX_LIST_ITEMS];
} fz_array_state;

typedef struct {
  int in_use;
  int count;
  char* keys[FZ_MAX_MAP_ENTRIES];
  char* values[FZ_MAX_MAP_ENTRIES];
} fz_map_state;

typedef struct {
  int in_use;
  int32_t period_ms;
  int64_t next_ms;
} fz_interval_state;

typedef struct {
  int in_use;
  int32_t value_id;
} fz_json_value_state;

typedef struct {
  int in_use;
  int32_t path_id;
  int32_t map_handle;
} fz_storage_kv_state;

static fz_proc_state fz_proc_states[FZ_MAX_PROC_STATES];
static pthread_mutex_t fz_proc_lock = PTHREAD_MUTEX_INITIALIZER;
static int32_t fz_proc_default_timeout_ms = 30000;
static int32_t fz_proc_last_error_id = 0;
static int32_t fz_last_exit_class = 0;
static fz_list_state fz_lists[FZ_MAX_LISTS];
static fz_array_state fz_arrays[FZ_MAX_LISTS];
static fz_map_state fz_maps[FZ_MAX_MAPS];
static fz_interval_state fz_intervals[FZ_MAX_INTERVALS];
static fz_json_value_state fz_json_values[FZ_MAX_JSON_VALUES];
static fz_storage_kv_state fz_storage_kv[FZ_MAX_STORAGE_KV];
static pthread_mutex_t fz_collections_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t fz_time_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t fz_json_lock = PTHREAD_MUTEX_INITIALIZER;
static int32_t fz_conn_request_counter = 0;
static int32_t fz_last_error_code = 0;
static int32_t fz_last_error_class = 0;
static int32_t fz_last_error_message_id = 0;
static int fz_log_json = 0;

typedef struct {
  int32_t key_id;
  int32_t value_id;
} fz_http_header_pair;

static fz_http_header_pair fz_http_headers[FZ_MAX_HTTP_HEADERS];
static int fz_http_header_count = 0;
static pthread_mutex_t fz_http_lock = PTHREAD_MUTEX_INITIALIZER;
static int32_t fz_http_last_status = 0;
static int32_t fz_http_last_body_id = 0;
static int32_t fz_http_last_error_id = 0;
static int fz_fs_fd = -1;
static char fz_fs_base_path[512] = {0};
static char fz_fs_tmp_path[544] = {0};
static pthread_mutex_t fz_fs_lock = PTHREAD_MUTEX_INITIALIZER;
typedef struct {
  int in_use;
  int32_t handle;
  int32_t task_ref;
  int32_t context_id;
  int32_t group_id;
  pthread_t thread;
  int started;
  int finished;
  int detached;
  int joined;
  int cancelled;
  int32_t result;
} fz_spawn_state;

typedef struct {
  int in_use;
  int32_t id;
  int32_t active_count;
} fz_task_group_state;

static fz_spawn_state fz_spawn_states[FZ_MAX_SPAWN_THREADS];
static fz_task_group_state fz_task_groups[256];
static int32_t fz_next_spawn_handle = 1;
static int32_t fz_next_task_group_id = 1;
static int32_t fz_spawn_active_count = 0;
static int32_t fz_spawn_max_active = 1024;
static pthread_mutex_t fz_spawn_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t fz_spawn_atexit_once = PTHREAD_ONCE_INIT;
static __thread int32_t fz_tls_task_context = 0;
static int64_t fz_async_deadline_ms = 0;
static int32_t fz_async_cancelled = 0;
static fz_callback_i32_v0 fz_host_callbacks[64];
static int fz_host_initialized = 0;
static pthread_mutex_t fz_host_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t fz_env_bootstrap_once = PTHREAD_ONCE_INIT;

typedef struct {
  int32_t handle;
} fz_spawn_ctx;

static int fz_mark_cloexec(int fd);
static void fz_proc_set_last_error(const char* msg);
static void fz_dotenv_load(void);
static void fz_env_bootstrap(void);
static const char* fz_env_get_bootstrapped(const char* key);
static int fz_has_env_value(const char* key);
static void fz_log_bind_target(int listener_fd);
static int fz_json_parse_string(const char** cursor, char** out);
static int fz_parse_json_string_array(const char* raw, char*** out_items, int* out_count);
static int fz_parse_json_env_object(const char* raw, char*** out_items, int* out_count);
static void fz_free_string_list(char** items, int count);
static int fz_json_parse_value_slice(const char* raw, const char** out_start, const char** out_end);
int32_t fz_native_net_request_id(int32_t conn_fd);
int32_t fz_native_net_write(int32_t conn_fd, int32_t status_code, int32_t body_id);


static const char* fz_lookup_string(int32_t id) {
  if (id <= 0) {
    return "";
  }
  if (id <= fz_string_literal_count) {
    const char* literal = fz_string_literals[id - 1];
    return literal == NULL ? "" : literal;
  }
  int dynamic_index = id - fz_string_literal_count - 1;
  if (dynamic_index < 0 || dynamic_index >= fz_dynamic_string_count) {
    return "";
  }
  const char* value = fz_dynamic_strings[dynamic_index];
  return value == NULL ? "" : value;
}

static int32_t fz_intern_owned(char* owned) {
  if (owned == NULL) {
    return 0;
  }
  pthread_mutex_lock(&fz_string_lock);
  for (int i = 0; i < fz_string_literal_count; i++) {
    const char* literal = fz_string_literals[i];
    if (literal != NULL && strcmp(literal, owned) == 0) {
      pthread_mutex_unlock(&fz_string_lock);
      free(owned);
      return i + 1;
    }
  }
  for (int i = 0; i < fz_dynamic_string_count; i++) {
    const char* existing = fz_dynamic_strings[i];
    if (existing != NULL && strcmp(existing, owned) == 0) {
      pthread_mutex_unlock(&fz_string_lock);
      free(owned);
      return fz_string_literal_count + i + 1;
    }
  }
  if (fz_dynamic_string_count >= FZ_MAX_DYNAMIC_STRINGS) {
    pthread_mutex_unlock(&fz_string_lock);
    free(owned);
    return 0;
  }
  int index = fz_dynamic_string_count++;
  fz_dynamic_strings[index] = owned;
  pthread_mutex_unlock(&fz_string_lock);
  return fz_string_literal_count + index + 1;
}

static int32_t fz_intern_slice(const char* data, size_t len) {
  char* owned = (char*)malloc(len + 1);
  if (owned == NULL) {
    return 0;
  }
  if (len > 0) {
    memcpy(owned, data, len);
  }
  owned[len] = '\0';
  return fz_intern_owned(owned);
}

static void fz_set_last_error(int32_t code, int32_t class_id, const char* message) {
  if (message == NULL) {
    message = "";
  }
  fz_last_error_code = code;
  fz_last_error_class = class_id;
  fz_last_error_message_id = fz_intern_slice(message, strlen(message));
}

static int32_t fz_list_alloc(void) {
  for (int i = 0; i < FZ_MAX_LISTS; i++) {
    if (!fz_lists[i].in_use) {
      memset(&fz_lists[i], 0, sizeof(fz_lists[i]));
      fz_lists[i].in_use = 1;
      return i + 1;
    }
  }
  return -1;
}

static fz_list_state* fz_list_get(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_LISTS) {
    return NULL;
  }
  fz_list_state* list = &fz_lists[handle - 1];
  return list->in_use ? list : NULL;
}

static int fz_list_push_cstr(fz_list_state* list, const char* value) {
  if (list == NULL || list->count >= FZ_MAX_LIST_ITEMS) {
    return -1;
  }
  if (value == NULL) {
    value = "";
  }
  char* dup = strdup(value);
  if (dup == NULL) {
    return -1;
  }
  list->items[list->count++] = dup;
  return 0;
}

static int32_t fz_array_alloc(void) {
  for (int i = 0; i < FZ_MAX_LISTS; i++) {
    if (!fz_arrays[i].in_use) {
      memset(&fz_arrays[i], 0, sizeof(fz_arrays[i]));
      fz_arrays[i].in_use = 1;
      return i + 1;
    }
  }
  return -1;
}

static fz_array_state* fz_array_get(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_LISTS) {
    return NULL;
  }
  fz_array_state* array = &fz_arrays[handle - 1];
  return array->in_use ? array : NULL;
}

static int fz_array_push_i32(fz_array_state* array, int32_t value) {
  if (array == NULL || array->count >= FZ_MAX_LIST_ITEMS) {
    return -1;
  }
  array->items[array->count++] = value;
  return 0;
}

static int32_t fz_map_alloc(void) {
  for (int i = 0; i < FZ_MAX_MAPS; i++) {
    if (!fz_maps[i].in_use) {
      memset(&fz_maps[i], 0, sizeof(fz_maps[i]));
      fz_maps[i].in_use = 1;
      return i + 1;
    }
  }
  return -1;
}

static fz_map_state* fz_map_get(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_MAPS) {
    return NULL;
  }
  fz_map_state* map = &fz_maps[handle - 1];
  return map->in_use ? map : NULL;
}

static int fz_map_find_index(fz_map_state* map, const char* key) {
  if (map == NULL || key == NULL) {
    return -1;
  }
  for (int i = 0; i < map->count; i++) {
    if (map->keys[i] != NULL && strcmp(map->keys[i], key) == 0) {
      return i;
    }
  }
  return -1;
}

static int32_t fz_storage_kv_alloc(void) {
  for (int i = 0; i < FZ_MAX_STORAGE_KV; i++) {
    if (!fz_storage_kv[i].in_use) {
      memset(&fz_storage_kv[i], 0, sizeof(fz_storage_kv[i]));
      fz_storage_kv[i].in_use = 1;
      return i + 1;
    }
  }
  return -1;
}

static fz_storage_kv_state* fz_storage_kv_get(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_STORAGE_KV) {
    return NULL;
  }
  fz_storage_kv_state* kv = &fz_storage_kv[handle - 1];
  return kv->in_use ? kv : NULL;
}

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

static int32_t fz_exit_class_from_status(int timed_out, int status, int spawn_error) {
  if (spawn_error) {
    return 3;
  }
  if (timed_out) {
    return 2;
  }
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status) == 0 ? 0 : 1;
  }
  if (WIFSIGNALED(status)) {
    return 1;
  }
  return 1;
}

static const char* fz_fs_path(void) {
  if (fz_fs_base_path[0] != '\0') {
    return fz_fs_base_path;
  }
  const char* from_env = getenv("FZ_FS_PATH");
  if (from_env == NULL || from_env[0] == '\0') {
    from_env = "/tmp/fozzy_native_store.dat";
  }
  snprintf(fz_fs_base_path, sizeof(fz_fs_base_path), "%s", from_env);
  snprintf(fz_fs_tmp_path, sizeof(fz_fs_tmp_path), "%s.tmp", from_env);
  return fz_fs_base_path;
}

static int fz_fs_ensure_open(void) {
  if (fz_fs_fd >= 0) {
    return fz_fs_fd;
  }
  const char* path = fz_fs_path();
  int fd = open(path, O_CREAT | O_RDWR, 0644);
  if (fd < 0) {
    return -1;
  }
  (void)fz_mark_cloexec(fd);
  fz_fs_fd = fd;
  return fd;
}

static void fz_http_headers_clear(void) {
  pthread_mutex_lock(&fz_http_lock);
  fz_http_header_count = 0;
  pthread_mutex_unlock(&fz_http_lock);
}

static char* fz_json_escape_owned(const char* input) {
  if (input == NULL) {
    input = "";
  }
  size_t in_len = strlen(input);
  size_t cap = (in_len * 6) + 1;
  char* out = (char*)malloc(cap);
  if (out == NULL) {
    return NULL;
  }
  size_t j = 0;
  for (size_t i = 0; i < in_len; i++) {
    unsigned char ch = (unsigned char)input[i];
    switch (ch) {
      case '\"': out[j++] = '\\'; out[j++] = '\"'; break;
      case '\\': out[j++] = '\\'; out[j++] = '\\'; break;
      case '\b': out[j++] = '\\'; out[j++] = 'b'; break;
      case '\f': out[j++] = '\\'; out[j++] = 'f'; break;
      case '\n': out[j++] = '\\'; out[j++] = 'n'; break;
      case '\r': out[j++] = '\\'; out[j++] = 'r'; break;
      case '\t': out[j++] = '\\'; out[j++] = 't'; break;
      default:
        if (ch < 0x20) {
          static const char* hex = "0123456789abcdef";
          out[j++] = '\\';
          out[j++] = 'u';
          out[j++] = '0';
          out[j++] = '0';
          out[j++] = hex[(ch >> 4) & 0xF];
          out[j++] = hex[ch & 0xF];
        } else {
          out[j++] = (char)ch;
        }
        break;
    }
  }
  out[j] = '\0';
  return out;
}

static int32_t fz_json_value_alloc(int32_t value_id) {
  if (value_id <= 0) {
    return -1;
  }
  pthread_mutex_lock(&fz_json_lock);
  for (int i = 0; i < FZ_MAX_JSON_VALUES; i++) {
    if (!fz_json_values[i].in_use) {
      fz_json_values[i].in_use = 1;
      fz_json_values[i].value_id = value_id;
      pthread_mutex_unlock(&fz_json_lock);
      return i + 1;
    }
  }
  pthread_mutex_unlock(&fz_json_lock);
  return -1;
}

static int32_t fz_json_value_get_id(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_JSON_VALUES) {
    return 0;
  }
  pthread_mutex_lock(&fz_json_lock);
  fz_json_value_state* slot = &fz_json_values[handle - 1];
  int32_t value_id = slot->in_use ? slot->value_id : 0;
  pthread_mutex_unlock(&fz_json_lock);
  return value_id;
}

static int32_t fz_json_value_alloc_from_slice(const char* start, const char* end) {
  if (start == NULL || end == NULL || end < start) {
    return -1;
  }
  int32_t value_id = fz_intern_slice(start, (size_t)(end - start));
  if (value_id <= 0) {
    return -1;
  }
  return fz_json_value_alloc(value_id);
}

static const char* fz_json_ws(const char* p) {
  while (p != NULL && (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')) {
    p++;
  }
  return p;
}

static int fz_json_match_lit(const char** cursor, const char* lit) {
  const char* p = fz_json_ws(*cursor);
  size_t n = strlen(lit);
  if (strncmp(p, lit, n) != 0) {
    return -1;
  }
  *cursor = p + n;
  return 0;
}

static int fz_json_skip_string_token(const char** cursor) {
  const char* p = fz_json_ws(*cursor);
  if (p == NULL || *p != '\"') {
    return -1;
  }
  p++;
  while (*p != '\0') {
    if (*p == '\"') {
      *cursor = p + 1;
      return 0;
    }
    if (*p == '\\') {
      p++;
      if (*p == '\0') {
        return -1;
      }
      if (*p == 'u') {
        p++;
        for (int i = 0; i < 4; i++) {
          if (!isxdigit((unsigned char)p[i])) {
            return -1;
          }
        }
        p += 4;
        continue;
      }
      p++;
      continue;
    }
    p++;
  }
  return -1;
}

static int fz_json_skip_number_token(const char** cursor) {
  const char* p = fz_json_ws(*cursor);
  if (p == NULL) {
    return -1;
  }
  if (*p == '-') {
    p++;
  }
  if (*p == '0') {
    p++;
  } else if (isdigit((unsigned char)*p)) {
    while (isdigit((unsigned char)*p)) p++;
  } else {
    return -1;
  }
  if (*p == '.') {
    p++;
    if (!isdigit((unsigned char)*p)) {
      return -1;
    }
    while (isdigit((unsigned char)*p)) p++;
  }
  if (*p == 'e' || *p == 'E') {
    p++;
    if (*p == '+' || *p == '-') {
      p++;
    }
    if (!isdigit((unsigned char)*p)) {
      return -1;
    }
    while (isdigit((unsigned char)*p)) p++;
  }
  *cursor = p;
  return 0;
}

static int fz_json_skip_value_token(const char** cursor, int depth);

static int fz_json_skip_array_token(const char** cursor, int depth) {
  if (depth > 256) {
    return -1;
  }
  const char* p = fz_json_ws(*cursor);
  if (p == NULL || *p != '[') {
    return -1;
  }
  p = fz_json_ws(p + 1);
  if (*p == ']') {
    *cursor = p + 1;
    return 0;
  }
  for (;;) {
    if (fz_json_skip_value_token(&p, depth + 1) != 0) {
      return -1;
    }
    p = fz_json_ws(p);
    if (*p == ',') {
      p = fz_json_ws(p + 1);
      continue;
    }
    if (*p == ']') {
      *cursor = p + 1;
      return 0;
    }
    return -1;
  }
}

static int fz_json_skip_object_token(const char** cursor, int depth) {
  if (depth > 256) {
    return -1;
  }
  const char* p = fz_json_ws(*cursor);
  if (p == NULL || *p != '{') {
    return -1;
  }
  p = fz_json_ws(p + 1);
  if (*p == '}') {
    *cursor = p + 1;
    return 0;
  }
  for (;;) {
    if (fz_json_skip_string_token(&p) != 0) {
      return -1;
    }
    p = fz_json_ws(p);
    if (*p != ':') {
      return -1;
    }
    p = fz_json_ws(p + 1);
    if (fz_json_skip_value_token(&p, depth + 1) != 0) {
      return -1;
    }
    p = fz_json_ws(p);
    if (*p == ',') {
      p = fz_json_ws(p + 1);
      continue;
    }
    if (*p == '}') {
      *cursor = p + 1;
      return 0;
    }
    return -1;
  }
}

static int fz_json_skip_value_token(const char** cursor, int depth) {
  const char* p = fz_json_ws(*cursor);
  if (p == NULL || *p == '\0') {
    return -1;
  }
  int rc = -1;
  switch (*p) {
    case '\"': rc = fz_json_skip_string_token(&p); break;
    case '{': rc = fz_json_skip_object_token(&p, depth); break;
    case '[': rc = fz_json_skip_array_token(&p, depth); break;
    case 't': rc = fz_json_match_lit(&p, "true"); break;
    case 'f': rc = fz_json_match_lit(&p, "false"); break;
    case 'n': rc = fz_json_match_lit(&p, "null"); break;
    default: rc = fz_json_skip_number_token(&p); break;
  }
  if (rc == 0) {
    *cursor = p;
  }
  return rc;
}

static int fz_json_parse_value_slice(const char* raw, const char** out_start, const char** out_end) {
  if (raw == NULL || out_start == NULL || out_end == NULL) {
    return -1;
  }
  const char* start = fz_json_ws(raw);
  const char* p = start;
  if (fz_json_skip_value_token(&p, 0) != 0) {
    return -1;
  }
  p = fz_json_ws(p);
  if (*p != '\0') {
    return -1;
  }
  *out_start = start;
  *out_end = p;
  return 0;
}

static int fz_json_object_lookup(const char* raw, const char* key, const char** out_start, const char** out_end) {
  if (raw == NULL || key == NULL || out_start == NULL || out_end == NULL) {
    return -1;
  }
  const char* p = fz_json_ws(raw);
  if (*p != '{') {
    return -1;
  }
  p = fz_json_ws(p + 1);
  if (*p == '}') {
    return 0;
  }
  for (;;) {
    char* candidate = NULL;
    if (fz_json_parse_string(&p, &candidate) != 0) {
      return -1;
    }
    p = fz_json_ws(p);
    if (*p != ':') {
      free(candidate);
      return -1;
    }
    p = fz_json_ws(p + 1);
    const char* value_start = p;
    if (fz_json_skip_value_token(&p, 0) != 0) {
      free(candidate);
      return -1;
    }
    const char* value_end = p;
    int matches = strcmp(candidate == NULL ? "" : candidate, key) == 0;
    free(candidate);
    if (matches) {
      *out_start = value_start;
      *out_end = value_end;
      return 1;
    }
    p = fz_json_ws(p);
    if (*p == ',') {
      p = fz_json_ws(p + 1);
      continue;
    }
    if (*p == '}') {
      return 0;
    }
    return -1;
  }
}

static int fz_json_array_lookup(const char* raw, int index, const char** out_start, const char** out_end) {
  if (raw == NULL || index < 0 || out_start == NULL || out_end == NULL) {
    return -1;
  }
  const char* p = fz_json_ws(raw);
  if (*p != '[') {
    return -1;
  }
  p = fz_json_ws(p + 1);
  if (*p == ']') {
    return 0;
  }
  int at = 0;
  for (;;) {
    const char* value_start = p;
    if (fz_json_skip_value_token(&p, 0) != 0) {
      return -1;
    }
    const char* value_end = p;
    if (at == index) {
      *out_start = value_start;
      *out_end = value_end;
      return 1;
    }
    at++;
    p = fz_json_ws(p);
    if (*p == ',') {
      p = fz_json_ws(p + 1);
      continue;
    }
    if (*p == ']') {
      return 0;
    }
    return -1;
  }
}


static int fz_send_all(int fd, const char* data, size_t len) {
  size_t sent = 0;
  while (sent < len) {
    ssize_t wrote = send(fd, data + sent, len - sent, 0);
    if (wrote < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (wrote == 0) {
      return -1;
    }
    sent += (size_t)wrote;
  }
  return 0;
}

static const char* fz_http_reason(int status_code) {
  switch (status_code) {
    case 200: return "OK";
    case 201: return "Created";
    case 202: return "Accepted";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 409: return "Conflict";
    case 422: return "Unprocessable Entity";
    case 429: return "Too Many Requests";
    case 500: return "Internal Server Error";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    default: return "OK";
  }
}

static fz_conn_state* fz_conn_state_for(int fd, int create_if_missing) {
  fz_conn_state* free_slot = NULL;
  for (int i = 0; i < FZ_MAX_CONN_STATES; i++) {
    if (fz_conn_states[i].in_use && fz_conn_states[i].fd == fd) {
      return &fz_conn_states[i];
    }
    if (!fz_conn_states[i].in_use && free_slot == NULL) {
      free_slot = &fz_conn_states[i];
    }
  }
  if (!create_if_missing || free_slot == NULL) {
    return NULL;
  }
  memset(free_slot, 0, sizeof(*free_slot));
  free_slot->in_use = 1;
  free_slot->fd = fd;
  return free_slot;
}

static void fz_conn_state_drop(int fd) {
  pthread_mutex_lock(&fz_conn_lock);
  for (int i = 0; i < FZ_MAX_CONN_STATES; i++) {
    if (fz_conn_states[i].in_use && fz_conn_states[i].fd == fd) {
      memset(&fz_conn_states[i], 0, sizeof(fz_conn_states[i]));
      break;
    }
  }
  pthread_mutex_unlock(&fz_conn_lock);
}

static int fz_find_header_end(const char* buf, int len) {
  for (int i = 0; i + 3 < len; i++) {
    if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
      return i + 4;
    }
  }
  return -1;
}

static int fz_contains_ci(const char* hay, size_t hay_len, const char* needle) {
  size_t needle_len = strlen(needle);
  if (needle_len == 0 || hay_len < needle_len) {
    return 0;
  }
  for (size_t i = 0; i + needle_len <= hay_len; i++) {
    size_t j = 0;
    while (j < needle_len) {
      char a = (char)tolower((unsigned char)hay[i + j]);
      char b = (char)tolower((unsigned char)needle[j]);
      if (a != b) {
        break;
      }
      j++;
    }
    if (j == needle_len) {
      return 1;
    }
  }
  return 0;
}

static int64_t fz_parse_content_length(const char* headers, int header_len) {
  const char* cursor = headers;
  const char* end = headers + header_len;
  while (cursor < end) {
    const char* line_end = strstr(cursor, "\r\n");
    if (line_end == NULL || line_end > end) {
      break;
    }
    if (line_end == cursor) {
      break;
    }
    size_t line_len = (size_t)(line_end - cursor);
    if (line_len >= 15 && strncasecmp(cursor, "Content-Length:", 15) == 0) {
      const char* value = cursor + 15;
      while (value < line_end && (*value == ' ' || *value == '\t')) {
        value++;
      }
      char tmp[32];
      size_t max = (size_t)(line_end - value);
      if (max >= sizeof(tmp)) {
        max = sizeof(tmp) - 1;
      }
      memcpy(tmp, value, max);
      tmp[max] = '\0';
      char* parse_end = NULL;
      long long parsed = strtoll(tmp, &parse_end, 10);
      if (parse_end != tmp && parsed >= 0) {
        return parsed;
      }
    }
    cursor = line_end + 2;
  }
  return -1;
}

static int fz_parse_keep_alive(const char* headers, int header_len, const char* version, int version_len) {
  int keep_alive = (version_len >= 8 && strncasecmp(version, "HTTP/1.1", 8) == 0) ? 1 : 0;
  const char* cursor = headers;
  const char* end = headers + header_len;
  while (cursor < end) {
    const char* line_end = strstr(cursor, "\r\n");
    if (line_end == NULL || line_end > end) {
      break;
    }
    if (line_end == cursor) {
      break;
    }
    size_t line_len = (size_t)(line_end - cursor);
    if (line_len >= 11 && strncasecmp(cursor, "Connection:", 11) == 0) {
      const char* value = cursor + 11;
      while (value < line_end && (*value == ' ' || *value == '\t')) {
        value++;
      }
      size_t value_len = (size_t)(line_end - value);
      if (fz_contains_ci(value, value_len, "close")) {
        keep_alive = 0;
      } else if (fz_contains_ci(value, value_len, "keep-alive")) {
        keep_alive = 1;
      }
      break;
    }
    cursor = line_end + 2;
  }
  return keep_alive;
}

static int fz_send_http_response(int conn_fd, int status_code, const char* content_type, const char* body, int close_after) {
  if (conn_fd < 0) {
    return -1;
  }
  if (content_type == NULL || content_type[0] == '\0') {
    content_type = "text/plain; charset=utf-8";
  }
  if (body == NULL) {
    body = "";
  }
  int body_len = (int)strlen(body);
  const char* reason = fz_http_reason(status_code);
  char header[512];
  int header_len = snprintf(
      header,
      sizeof(header),
      "HTTP/1.1 %d %s\r\n"
      "Content-Type: %s\r\n"
      "Content-Length: %d\r\n"
      "Connection: %s\r\n"
      "\r\n",
      status_code,
      reason,
      content_type,
      body_len,
      close_after ? "close" : "keep-alive");
  if (header_len <= 0 || header_len >= (int)sizeof(header)) {
    return -1;
  }
  if (fz_send_all(conn_fd, header, (size_t)header_len) != 0) {
    return -1;
  }
  if (body_len > 0 && fz_send_all(conn_fd, body, (size_t)body_len) != 0) {
    return -1;
  }
  if (close_after) {
    shutdown(conn_fd, SHUT_RDWR);
    close(conn_fd);
    fz_conn_state_drop(conn_fd);
  }
  return 0;
}

static void fz_bytes_buf_init(fz_bytes_buf* buf) {
  buf->data = NULL;
  buf->len = 0;
  buf->cap = 0;
}

static void fz_bytes_buf_free(fz_bytes_buf* buf) {
  if (buf->data != NULL) {
    free(buf->data);
  }
  buf->data = NULL;
  buf->len = 0;
  buf->cap = 0;
}

static int fz_bytes_buf_append(fz_bytes_buf* buf, const char* data, size_t len) {
  if (len == 0) {
    return 0;
  }
  size_t needed = buf->len + len + 1;
  if (needed > buf->cap) {
    size_t next_cap = buf->cap == 0 ? 4096 : buf->cap;
    while (next_cap < needed) {
      next_cap *= 2;
    }
    char* next = (char*)realloc(buf->data, next_cap);
    if (next == NULL) {
      return -1;
    }
    buf->data = next;
    buf->cap = next_cap;
  }
  memcpy(buf->data + buf->len, data, len);
  buf->len += len;
  buf->data[buf->len] = '\0';
  return 0;
}

static int fz_drain_fd(int fd, fz_bytes_buf* buf) {
  if (fd < 0) {
    return 0;
  }
  char tmp[4096];
  for (;;) {
    ssize_t got = read(fd, tmp, sizeof(tmp));
    if (got > 0) {
      if (fz_bytes_buf_append(buf, tmp, (size_t)got) != 0) {
        return -1;
      }
      continue;
    }
    if (got == 0) {
      return 1;
    }
    if (errno == EINTR) {
      continue;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return 0;
    }
    return -1;
  }
}

static int fz_set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int fz_mark_cloexec(int fd) {
  int flags = fcntl(fd, F_GETFD, 0);
  if (flags < 0) {
    return -1;
  }
  return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static fz_proc_state* fz_proc_state_get(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_PROC_STATES) {
    return NULL;
  }
  fz_proc_state* state = &fz_proc_states[handle - 1];
  if (!state->in_use) {
    return NULL;
  }
  return state;
}

static void fz_proc_set_last_error(const char* msg) {
  if (msg == NULL) {
    msg = "proc error";
  }
  fz_proc_last_error_id = fz_intern_slice(msg, strlen(msg));
}

static int32_t fz_proc_state_alloc(pid_t pid, int stdout_fd, int stderr_fd) {
  for (int i = 0; i < FZ_MAX_PROC_STATES; i++) {
    if (!fz_proc_states[i].in_use) {
      fz_proc_states[i].in_use = 1;
      fz_proc_states[i].pid = pid;
      fz_proc_states[i].stdout_fd = stdout_fd;
      fz_proc_states[i].stderr_fd = stderr_fd;
      fz_proc_states[i].done = 0;
      fz_proc_states[i].exit_notified = 0;
      fz_proc_states[i].exit_code = -1;
      fz_proc_states[i].stdout_read_pos = 0;
      fz_proc_states[i].stderr_read_pos = 0;
      fz_proc_states[i].stdout_id = 0;
      fz_proc_states[i].stderr_id = 0;
      fz_bytes_buf_init(&fz_proc_states[i].stdout_buf);
      fz_bytes_buf_init(&fz_proc_states[i].stderr_buf);
      return i + 1;
    }
  }
  return -1;
}

static void fz_proc_finalize(fz_proc_state* state, int exit_code) {
  if (state->stdout_fd >= 0) {
    (void)fz_drain_fd(state->stdout_fd, &state->stdout_buf);
    close(state->stdout_fd);
    state->stdout_fd = -1;
  }
  if (state->stderr_fd >= 0) {
    (void)fz_drain_fd(state->stderr_fd, &state->stderr_buf);
    close(state->stderr_fd);
    state->stderr_fd = -1;
  }
  state->stdout_id = fz_intern_slice(
      state->stdout_buf.data == NULL ? "" : state->stdout_buf.data,
      state->stdout_buf.data == NULL ? 0 : state->stdout_buf.len);
  state->stderr_id = fz_intern_slice(
      state->stderr_buf.data == NULL ? "" : state->stderr_buf.data,
      state->stderr_buf.data == NULL ? 0 : state->stderr_buf.len);
  state->exit_code = exit_code;
  state->done = 1;
}

static void fz_spawn_join_all(void) {
  for (int i = 0; i < FZ_MAX_SPAWN_THREADS; i++) {
    pthread_t thread;
    int should_join = 0;
    pthread_mutex_lock(&fz_spawn_lock);
    fz_spawn_state* state = &fz_spawn_states[i];
    if (state->in_use && !state->detached && !state->joined) {
      state->joined = 1;
      thread = state->thread;
      should_join = 1;
    }
    pthread_mutex_unlock(&fz_spawn_lock);
    if (should_join) {
      (void)pthread_join(thread, NULL);
    }
  }
}

static void fz_spawn_register_atexit(void) {
  const char* max_active = fz_env_get_bootstrapped("FZ_SPAWN_MAX_ACTIVE");
  if (max_active != NULL && max_active[0] != '\0') {
    int parsed = atoi(max_active);
    if (parsed > 0 && parsed <= FZ_MAX_SPAWN_THREADS) {
      fz_spawn_max_active = parsed;
    }
  }
  (void)atexit(fz_spawn_join_all);
}

static fz_spawn_state* fz_spawn_state_by_handle_locked(int32_t handle) {
  for (int i = 0; i < FZ_MAX_SPAWN_THREADS; i++) {
    if (fz_spawn_states[i].in_use && fz_spawn_states[i].handle == handle) {
      return &fz_spawn_states[i];
    }
  }
  return NULL;
}

static fz_spawn_state* fz_spawn_state_alloc_locked(void) {
  for (int i = 0; i < FZ_MAX_SPAWN_THREADS; i++) {
    if (!fz_spawn_states[i].in_use) {
      return &fz_spawn_states[i];
    }
  }
  return NULL;
}

static fz_task_group_state* fz_task_group_by_id_locked(int32_t group_id) {
  for (int i = 0; i < 256; i++) {
    if (fz_task_groups[i].in_use && fz_task_groups[i].id == group_id) {
      return &fz_task_groups[i];
    }
  }
  return NULL;
}

static fz_task_group_state* fz_task_group_alloc_locked(void) {
  for (int i = 0; i < 256; i++) {
    if (!fz_task_groups[i].in_use) {
      return &fz_task_groups[i];
    }
  }
  return NULL;
}

static void* fz_spawn_thread_main(void* arg) {
  fz_spawn_ctx* ctx = (fz_spawn_ctx*)arg;
  if (ctx == NULL) {
    return NULL;
  }
  int32_t handle = ctx->handle;
  free(ctx);

  fz_task_entry_fn entry = NULL;
  int32_t context_id = 0;
  int32_t group_id = 0;
  int cancelled = 0;
  pthread_mutex_lock(&fz_spawn_lock);
  fz_spawn_state* state = fz_spawn_state_by_handle_locked(handle);
  if (state != NULL) {
    state->started = 1;
    entry = fz_task_entries[state->task_ref - 1];
    context_id = state->context_id;
    group_id = state->group_id;
    cancelled = state->cancelled;
  }
  pthread_mutex_unlock(&fz_spawn_lock);

  int32_t result = -1;
  fz_tls_task_context = context_id;
  if (!cancelled && entry != NULL) {
    result = entry();
  } else if (cancelled) {
    result = -2;
  }

  pthread_mutex_lock(&fz_spawn_lock);
  state = fz_spawn_state_by_handle_locked(handle);
  if (state != NULL) {
    state->finished = 1;
    state->result = result;
    if (fz_spawn_active_count > 0) {
      fz_spawn_active_count--;
    }
    if (group_id > 0) {
      fz_task_group_state* group = fz_task_group_by_id_locked(group_id);
      if (group != NULL && group->active_count > 0) {
        group->active_count--;
      }
    }
    if (state->detached) {
      memset(state, 0, sizeof(*state));
    }
  }
  pthread_mutex_unlock(&fz_spawn_lock);
  return NULL;
}

static int32_t fz_native_spawn_impl(int32_t task_ref, int32_t context_id, int32_t group_id) {
  if (task_ref <= 0 || task_ref > fz_task_entry_count) {
    return -1;
  }
  if (fz_task_entries[task_ref - 1] == NULL) {
    return -1;
  }

  pthread_once(&fz_spawn_atexit_once, fz_spawn_register_atexit);
  pthread_mutex_lock(&fz_spawn_lock);
  if (fz_spawn_active_count >= fz_spawn_max_active) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  if (group_id > 0 && fz_task_group_by_id_locked(group_id) == NULL) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  fz_spawn_state* state = fz_spawn_state_alloc_locked();
  if (state == NULL) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  memset(state, 0, sizeof(*state));
  state->in_use = 1;
  state->handle = fz_next_spawn_handle++;
  state->task_ref = task_ref;
  state->context_id = context_id;
  state->group_id = group_id;
  if (group_id > 0) {
    fz_task_group_state* group = fz_task_group_by_id_locked(group_id);
    if (group != NULL) {
      group->active_count++;
    }
  }
  fz_spawn_active_count++;
  int32_t handle = state->handle;
  pthread_mutex_unlock(&fz_spawn_lock);

  fz_spawn_ctx* ctx = (fz_spawn_ctx*)malloc(sizeof(fz_spawn_ctx));
  if (ctx == NULL) {
    pthread_mutex_lock(&fz_spawn_lock);
    state = fz_spawn_state_by_handle_locked(handle);
    if (state != NULL) {
      if (state->group_id > 0) {
        fz_task_group_state* group = fz_task_group_by_id_locked(state->group_id);
        if (group != NULL && group->active_count > 0) {
          group->active_count--;
        }
      }
      memset(state, 0, sizeof(*state));
    }
    if (fz_spawn_active_count > 0) {
      fz_spawn_active_count--;
    }
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  ctx->handle = handle;

  pthread_t thread;
  if (pthread_create(&thread, NULL, fz_spawn_thread_main, ctx) != 0) {
    free(ctx);
    pthread_mutex_lock(&fz_spawn_lock);
    state = fz_spawn_state_by_handle_locked(handle);
    if (state != NULL) {
      if (state->group_id > 0) {
        fz_task_group_state* group = fz_task_group_by_id_locked(state->group_id);
        if (group != NULL && group->active_count > 0) {
          group->active_count--;
        }
      }
      memset(state, 0, sizeof(*state));
    }
    if (fz_spawn_active_count > 0) {
      fz_spawn_active_count--;
    }
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }

  pthread_mutex_lock(&fz_spawn_lock);
  state = fz_spawn_state_by_handle_locked(handle);
  if (state != NULL) {
    state->thread = thread;
  }
  pthread_mutex_unlock(&fz_spawn_lock);
  return handle;
}

int32_t fz_native_env_get(int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  if (key == NULL || key[0] == '\0') {
    return 0;
  }
  const char* value = fz_env_get_bootstrapped(key);
  if (value == NULL) {
    value = "";
  }
  return fz_intern_slice(value, strlen(value));
}

int32_t fz_native_time_now(void) {
  return (int32_t)fz_now_ms();
}

int32_t fz_native_http_header(int32_t key_id, int32_t value_id) {
  if (key_id <= 0 || value_id <= 0) {
    return -1;
  }
  pthread_mutex_lock(&fz_http_lock);
  if (fz_http_header_count >= FZ_MAX_HTTP_HEADERS) {
    pthread_mutex_unlock(&fz_http_lock);
    return -1;
  }
  fz_http_headers[fz_http_header_count].key_id = key_id;
  fz_http_headers[fz_http_header_count].value_id = value_id;
  fz_http_header_count++;
  pthread_mutex_unlock(&fz_http_lock);
  return 0;
}

int32_t fz_native_json_escape(int32_t input_id) {
  const char* input = fz_lookup_string(input_id);
  char* escaped = fz_json_escape_owned(input);
  if (escaped == NULL) {
    return 0;
  }
  return fz_intern_owned(escaped);
}

int32_t fz_native_json_str(int32_t input_id) {
  const char* input = fz_lookup_string(input_id);
  char* escaped = fz_json_escape_owned(input);
  if (escaped == NULL) {
    return 0;
  }
  size_t len = strlen(escaped);
  char* wrapped = (char*)malloc(len + 3);
  if (wrapped == NULL) {
    free(escaped);
    return 0;
  }
  wrapped[0] = '\"';
  if (len > 0) {
    memcpy(wrapped + 1, escaped, len);
  }
  wrapped[len + 1] = '\"';
  wrapped[len + 2] = '\0';
  free(escaped);
  return fz_intern_owned(wrapped);
}

int32_t fz_native_json_raw(int32_t input_id) {
  const char* input = fz_lookup_string(input_id);
  if (input == NULL || input[0] == '\0') {
    return fz_intern_slice("null", 4);
  }
  return fz_intern_slice(input, strlen(input));
}

static int32_t fz_native_json_array_from_values(const int32_t* ids, int value_count) {
  if (ids == NULL || value_count <= 0) {
    return fz_intern_slice("[]", 2);
  }
  size_t total = 3;
  for (int i = 0; i < value_count; i++) {
    const char* value = fz_lookup_string(ids[i]);
    total += strlen(value == NULL || value[0] == '\0' ? "null" : value) + 1;
  }
  char* out = (char*)malloc(total);
  if (out == NULL) {
    return 0;
  }
  size_t used = 0;
  out[used++] = '[';
  for (int i = 0; i < value_count; i++) {
    if (i > 0) {
      out[used++] = ',';
    }
    const char* value = fz_lookup_string(ids[i]);
    if (value == NULL || value[0] == '\0') {
      value = "null";
    }
    size_t len = strlen(value);
    if (len > 0) {
      memcpy(out + used, value, len);
      used += len;
    }
  }
  out[used++] = ']';
  out[used] = '\0';
  return fz_intern_owned(out);
}

static int32_t fz_native_json_object_from_pairs(const int32_t* ids, int pair_count) {
  if (ids == NULL || pair_count <= 0) {
    return fz_intern_slice("{}", 2);
  }
  char** escaped_keys = (char**)calloc((size_t)pair_count, sizeof(char*));
  if (escaped_keys == NULL) {
    return 0;
  }
  size_t total = 3;
  for (int i = 0; i < pair_count; i++) {
    const char* key = fz_lookup_string(ids[i * 2]);
    const char* raw_value = fz_lookup_string(ids[(i * 2) + 1]);
    if (raw_value == NULL || raw_value[0] == '\0') {
      raw_value = "null";
    }
    escaped_keys[i] = fz_json_escape_owned(key);
    if (escaped_keys[i] == NULL) {
      for (int j = 0; j <= i; j++) {
        free(escaped_keys[j]);
      }
      free(escaped_keys);
      return 0;
    }
    total += strlen(escaped_keys[i]) + strlen(raw_value) + 5;
  }
  char* body = (char*)malloc(total);
  if (body == NULL) {
    for (int i = 0; i < pair_count; i++) {
      free(escaped_keys[i]);
    }
    free(escaped_keys);
    return 0;
  }
  size_t used = 0;
  body[used++] = '{';
  for (int i = 0; i < pair_count; i++) {
    if (i > 0) {
      body[used++] = ',';
    }
    body[used++] = '\"';
    size_t key_len = strlen(escaped_keys[i]);
    memcpy(body + used, escaped_keys[i], key_len);
    used += key_len;
    body[used++] = '\"';
    body[used++] = ':';
    const char* raw_value = fz_lookup_string(ids[(i * 2) + 1]);
    if (raw_value == NULL || raw_value[0] == '\0') {
      raw_value = "null";
    }
    size_t value_len = strlen(raw_value);
    memcpy(body + used, raw_value, value_len);
    used += value_len;
  }
  body[used++] = '}';
  body[used] = '\0';
  for (int i = 0; i < pair_count; i++) {
    free(escaped_keys[i]);
  }
  free(escaped_keys);
  return fz_intern_owned(body);
}

static int32_t fz_runtime_list_new(void) {
  pthread_mutex_lock(&fz_collections_lock);
  int32_t handle = fz_list_alloc();
  pthread_mutex_unlock(&fz_collections_lock);
  return handle;
}

static int32_t fz_runtime_list_push(int32_t handle, int32_t value_id) {
  const char* value = fz_lookup_string(value_id);
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(handle);
  int ok = list != NULL && fz_list_push_cstr(list, value) == 0 ? 0 : -1;
  pthread_mutex_unlock(&fz_collections_lock);
  return ok;
}

static int32_t fz_runtime_list_pop(int32_t handle) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(handle);
  if (list == NULL || list->count <= 0) {
    pthread_mutex_unlock(&fz_collections_lock);
    return fz_intern_slice("", 0);
  }
  char* item = list->items[list->count - 1];
  list->items[list->count - 1] = NULL;
  list->count--;
  int32_t id = fz_intern_slice(item == NULL ? "" : item, item == NULL ? 0 : strlen(item));
  free(item);
  pthread_mutex_unlock(&fz_collections_lock);
  return id;
}

static int32_t fz_runtime_list_len(int32_t handle) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(handle);
  int32_t len = list == NULL ? -1 : list->count;
  pthread_mutex_unlock(&fz_collections_lock);
  return len;
}

static int32_t fz_runtime_list_get(int32_t handle, int32_t index) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(handle);
  if (list == NULL || index < 0 || index >= list->count) {
    pthread_mutex_unlock(&fz_collections_lock);
    return fz_intern_slice("", 0);
  }
  const char* item = list->items[index] == NULL ? "" : list->items[index];
  int32_t id = fz_intern_slice(item, strlen(item));
  pthread_mutex_unlock(&fz_collections_lock);
  return id;
}

static int32_t fz_runtime_list_set(int32_t handle, int32_t index, int32_t value_id) {
  const char* value = fz_lookup_string(value_id);
  if (value == NULL) value = "";
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(handle);
  if (list == NULL || index < 0 || index >= list->count) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  char* dup = strdup(value);
  if (dup == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  free(list->items[index]);
  list->items[index] = dup;
  pthread_mutex_unlock(&fz_collections_lock);
  return 0;
}

static int32_t fz_runtime_list_clear(int32_t handle) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(handle);
  if (list == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  for (int i = 0; i < list->count; i++) {
    free(list->items[i]);
    list->items[i] = NULL;
  }
  list->count = 0;
  pthread_mutex_unlock(&fz_collections_lock);
  return 0;
}

static int32_t fz_runtime_list_join(int32_t handle, int32_t sep_id) {
  const char* sep = fz_lookup_string(sep_id);
  if (sep == NULL) sep = "";
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(handle);
  if (list == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return fz_intern_slice("", 0);
  }
  size_t sep_len = strlen(sep);
  size_t total = 1;
  for (int i = 0; i < list->count; i++) {
    total += strlen(list->items[i] == NULL ? "" : list->items[i]);
    if (i > 0) total += sep_len;
  }
  char* out = (char*)malloc(total);
  if (out == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return 0;
  }
  size_t used = 0;
  for (int i = 0; i < list->count; i++) {
    if (i > 0 && sep_len > 0) {
      memcpy(out + used, sep, sep_len);
      used += sep_len;
    }
    const char* item = list->items[i] == NULL ? "" : list->items[i];
    size_t len = strlen(item);
    if (len > 0) {
      memcpy(out + used, item, len);
      used += len;
    }
  }
  out[used] = '\0';
  pthread_mutex_unlock(&fz_collections_lock);
  return fz_intern_owned(out);
}

static int32_t fz_runtime_map_new(void) {
  pthread_mutex_lock(&fz_collections_lock);
  int32_t handle = fz_map_alloc();
  pthread_mutex_unlock(&fz_collections_lock);
  return handle;
}

static int32_t fz_runtime_map_set(int32_t handle, int32_t key_id, int32_t value_id) {
  const char* key = fz_lookup_string(key_id);
  const char* value = fz_lookup_string(value_id);
  if (key == NULL || key[0] == '\0') {
    return -1;
  }
  if (value == NULL) value = "";
  pthread_mutex_lock(&fz_collections_lock);
  fz_map_state* map = fz_map_get(handle);
  if (map == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  int idx = fz_map_find_index(map, key);
  if (idx >= 0) {
    char* dup = strdup(value);
    if (dup == NULL) {
      pthread_mutex_unlock(&fz_collections_lock);
      return -1;
    }
    free(map->values[idx]);
    map->values[idx] = dup;
    pthread_mutex_unlock(&fz_collections_lock);
    return 0;
  }
  if (map->count >= FZ_MAX_MAP_ENTRIES) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  map->keys[map->count] = strdup(key);
  map->values[map->count] = strdup(value);
  if (map->keys[map->count] == NULL || map->values[map->count] == NULL) {
    free(map->keys[map->count]);
    free(map->values[map->count]);
    map->keys[map->count] = NULL;
    map->values[map->count] = NULL;
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  map->count++;
  pthread_mutex_unlock(&fz_collections_lock);
  return 0;
}

static int32_t fz_runtime_map_get(int32_t handle, int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  pthread_mutex_lock(&fz_collections_lock);
  fz_map_state* map = fz_map_get(handle);
  if (map == NULL || key == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return fz_intern_slice("", 0);
  }
  int idx = fz_map_find_index(map, key);
  const char* value = (idx >= 0 && map->values[idx] != NULL) ? map->values[idx] : "";
  int32_t out = fz_intern_slice(value, strlen(value));
  pthread_mutex_unlock(&fz_collections_lock);
  return out;
}

static int32_t fz_runtime_map_has(int32_t handle, int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  pthread_mutex_lock(&fz_collections_lock);
  fz_map_state* map = fz_map_get(handle);
  int ok = (map != NULL && key != NULL && fz_map_find_index(map, key) >= 0) ? 1 : 0;
  pthread_mutex_unlock(&fz_collections_lock);
  return ok;
}

static int32_t fz_runtime_map_delete(int32_t handle, int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  pthread_mutex_lock(&fz_collections_lock);
  fz_map_state* map = fz_map_get(handle);
  if (map == NULL || key == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  int idx = fz_map_find_index(map, key);
  if (idx < 0) {
    pthread_mutex_unlock(&fz_collections_lock);
    return 0;
  }
  free(map->keys[idx]);
  free(map->values[idx]);
  for (int i = idx; i + 1 < map->count; i++) {
    map->keys[i] = map->keys[i + 1];
    map->values[i] = map->values[i + 1];
  }
  map->count--;
  map->keys[map->count] = NULL;
  map->values[map->count] = NULL;
  pthread_mutex_unlock(&fz_collections_lock);
  return 1;
}

static int32_t fz_runtime_map_keys(int32_t handle) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_map_state* map = fz_map_get(handle);
  if (map == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  int32_t list_handle = fz_list_alloc();
  fz_list_state* list = fz_list_get(list_handle);
  if (list == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  for (int i = 0; i < map->count; i++) {
    (void)fz_list_push_cstr(list, map->keys[i] == NULL ? "" : map->keys[i]);
  }
  pthread_mutex_unlock(&fz_collections_lock);
  return list_handle;
}

static int32_t fz_runtime_map_len(int32_t handle) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_map_state* map = fz_map_get(handle);
  int32_t len = map == NULL ? -1 : map->count;
  pthread_mutex_unlock(&fz_collections_lock);
  return len;
}

"#
}
