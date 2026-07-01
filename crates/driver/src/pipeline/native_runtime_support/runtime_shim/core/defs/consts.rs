pub(super) fn section() -> &'static str {
    r#"

#define FZ_INITIAL_DYNAMIC_STRING_CAPACITY 16384
#define FZ_MAX_CONN_STATES 2048
#define FZ_MAX_HTTP_READ 262144
#define FZ_MAX_PROC_STATES 1024
#define FZ_MAX_HTTP_HEADERS 128
#define FZ_MAX_HTTP_STREAMS 256
#define FZ_MAX_WEBSOCKETS 256
#define FZ_MAX_SPAWN_THREADS 4096
#define FZ_MAX_CONN_META 128
#define FZ_MAX_ROUTE_PARAMS 64
#define FZ_INITIAL_LIST_CAPACITY 2048
#define FZ_INITIAL_LIST_ITEM_CAPACITY 16
#define FZ_INITIAL_ARRAY_CAPACITY 2048
#define FZ_INITIAL_ARRAY_ITEM_CAPACITY 16
#define FZ_INITIAL_NUMERIC_VEC_CAPACITY 2048
#define FZ_INITIAL_MAP_CAPACITY 2048
#define FZ_INITIAL_MAP_ENTRY_CAPACITY 16
#define FZ_INITIAL_AGGREGATE_CAPACITY 4096
#define FZ_MAX_AGGREGATE_ITEMS 64
#define FZ_INITIAL_INTERVAL_CAPACITY 512
#define FZ_INITIAL_JSON_VALUE_CAPACITY 16384
#define FZ_INITIAL_STORAGE_KV_CAPACITY 1024
#define FZ_INITIAL_BYTES_CAPACITY 8192
#define FZ_MAX_NET_POLL_WATCHES 256
#define FZ_INITIAL_STRING_INDEX_CAPACITY 65536

static char** fz_dynamic_strings = NULL;
static int32_t fz_dynamic_string_count = 0;
static int32_t fz_dynamic_string_capacity = 0;
static int32_t* fz_string_index_ids = NULL;
static uint32_t* fz_string_index_hashes = NULL;
static int32_t fz_string_index_capacity = 0;
static pthread_rwlock_t fz_string_lock = PTHREAD_RWLOCK_INITIALIZER;
static pthread_once_t fz_string_index_once = PTHREAD_ONCE_INIT;

static int fz_listener_fd = -1;
static pthread_mutex_t fz_listener_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
  int in_use;
  int fd;
  short events;
} fz_net_poll_watch;

static fz_net_poll_watch fz_net_poll_watches[FZ_MAX_NET_POLL_WATCHES];
static pthread_mutex_t fz_net_poll_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
  int in_use;
  int fd;
  int32_t method_id;
  int32_t path_id;
  int32_t body_id;
  int32_t request_id;
  int32_t remote_addr_id;
  int keep_alive;
  int request_headers_ready;
  int request_body_mode;
  int request_body_eof;
  int request_body_fully_buffered;
  int request_body_active;
  int64_t request_body_remaining;
  int64_t request_chunk_remaining;
  char* request_meta_buf;
  size_t request_meta_len;
  char* request_body_buf;
  size_t request_body_buf_len;
  size_t request_body_buf_pos;
  int header_count;
  uint32_t header_key_offsets[FZ_MAX_CONN_META];
  uint32_t header_key_lens[FZ_MAX_CONN_META];
  uint32_t header_value_offsets[FZ_MAX_CONN_META];
  uint32_t header_value_lens[FZ_MAX_CONN_META];
  int response_header_count;
  int32_t response_header_key_ids[FZ_MAX_CONN_META];
  int32_t response_header_value_ids[FZ_MAX_CONN_META];
  int query_count;
  uint32_t query_key_offsets[FZ_MAX_CONN_META];
  uint32_t query_key_lens[FZ_MAX_CONN_META];
  uint32_t query_value_offsets[FZ_MAX_CONN_META];
  uint32_t query_value_lens[FZ_MAX_CONN_META];
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
  int32_t count;
  int32_t cap;
  char** items;
} fz_list_state;

typedef struct {
  int in_use;
  int32_t count;
  int32_t cap;
  int32_t* items;
} fz_array_state;

typedef struct {
  int in_use;
  int32_t element_kind;
  int32_t count;
  int32_t cap;
  uint32_t* items;
} fz_numeric_vec_state;

typedef struct {
  int in_use;
  int32_t count;
  int32_t cap;
  char** keys;
  char** values;
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

typedef struct {
  int in_use;
  size_t len;
  uint8_t* data;
} fz_bytes_state;

typedef struct {
  int in_use;
  int32_t tag;
  int32_t count;
  uint64_t* items;
} fz_aggregate_state;

static fz_proc_state fz_proc_states[FZ_MAX_PROC_STATES];
static pthread_mutex_t fz_proc_lock = PTHREAD_MUTEX_INITIALIZER;
static int32_t fz_proc_default_timeout_ms = 30000;
static int32_t fz_proc_last_error_id = 0;
static int32_t fz_last_exit_class = 0;
static fz_list_state* fz_lists = NULL;
static int32_t fz_list_capacity = 0;
static fz_array_state* fz_arrays = NULL;
static int32_t fz_array_capacity = 0;
static fz_numeric_vec_state* fz_numeric_vecs = NULL;
static int32_t fz_numeric_vec_capacity = 0;
static fz_map_state* fz_maps = NULL;
static int32_t fz_map_capacity = 0;
static fz_aggregate_state* fz_aggregates = NULL;
static int32_t fz_aggregate_capacity = 0;
static fz_interval_state* fz_intervals = NULL;
static int32_t fz_interval_capacity = 0;
static fz_json_value_state* fz_json_values = NULL;
static int32_t fz_json_value_capacity = 0;
static fz_storage_kv_state* fz_storage_kv = NULL;
static int32_t fz_storage_kv_capacity = 0;
static fz_bytes_state* fz_bytes = NULL;
static int32_t fz_bytes_capacity = 0;
static pthread_mutex_t fz_collections_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t fz_list_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t fz_array_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t fz_map_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t fz_aggregate_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t fz_storage_kv_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t fz_bytes_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t fz_time_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t fz_json_lock = PTHREAD_MUTEX_INITIALIZER;
static int32_t fz_conn_request_counter = 0;
static int32_t fz_last_error_code = 0;
static int32_t fz_last_error_class = 0;
static int32_t fz_last_error_message_id = 0;
static int fz_log_json = 0;
static int fz_log_enabled = 1;
static int32_t fz_log_min_level = 0;
static int32_t fz_log_sink = 0;

typedef struct {
  int32_t key_id;
  int32_t value_id;
} fz_http_header_pair;

typedef struct {
  int in_use;
  pid_t pid;
  int stdout_fd;
  int stderr_fd;
  int done;
  int eof;
  int closed;
  int exit_code;
  int32_t status_code;
  int32_t error_id;
  size_t stdout_read_pos;
  fz_bytes_buf stdout_buf;
  fz_bytes_buf stderr_buf;
} fz_http_stream_state;

typedef struct {
  int in_use;
  int fd;
  int closed;
  int32_t last_kind_id;
  int32_t last_error_id;
  int32_t close_code;
} fz_websocket_state;

static fz_http_header_pair fz_http_headers[FZ_MAX_HTTP_HEADERS];
static int fz_http_header_count = 0;
static pthread_mutex_t fz_http_lock = PTHREAD_MUTEX_INITIALIZER;
static int32_t fz_http_last_status = 0;
static int32_t fz_http_last_body_id = 0;
static int32_t fz_http_last_error_id = 0;
static fz_http_stream_state fz_http_stream_states[FZ_MAX_HTTP_STREAMS];
static fz_websocket_state fz_websocket_states[FZ_MAX_WEBSOCKETS];
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
static __thread int32_t fz_tls_task_handle = 0;
static __thread int64_t fz_tls_async_deadline_ms = 0;
static __thread int32_t fz_tls_async_cancelled = 0;
static fz_callback_i32_v0 fz_host_callbacks[64];
static int fz_host_initialized = 0;
static pthread_mutex_t fz_host_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t fz_env_bootstrap_once = PTHREAD_ONCE_INIT;

typedef struct {
  int32_t handle;
} fz_spawn_ctx;

static int fz_mark_cloexec(int fd);
static void fz_proc_set_last_error(const char* msg);
static void fz_bytes_buf_init(fz_bytes_buf* buf);
static void fz_bytes_buf_free(fz_bytes_buf* buf);
static int fz_bytes_buf_append(fz_bytes_buf* buf, const char* data, size_t len);
static int fz_wait_for_fd_event(int fd, short events, int timeout_ms);
static void fz_conn_state_reset_request_body(fz_conn_state* state);
static void fz_conn_state_reset_response_headers(fz_conn_state* state);
static int fz_parse_chunked_flag(const char* headers, int header_len);
static int fz_conn_recv_into_body_buffer(fz_conn_state* state, size_t want, int timeout_ms);
static int fz_conn_read_body_chunk(fz_conn_state* state, char** out_ptr, size_t* out_len, int32_t max_bytes);
static int fz_conn_discard_body(fz_conn_state* state);
static int32_t fz_conn_state_intern_meta_slice(fz_conn_state* state, uint32_t offset, uint32_t len);
static const char* fz_conn_state_meta_slice_ptr(fz_conn_state* state, uint32_t offset, uint32_t len, size_t* out_len);
static int fz_conn_state_meta_key_eq(fz_conn_state* state, uint32_t offset, uint32_t len, const char* key, int case_insensitive);
static int fz_send_http_response_state(
    fz_conn_state* state,
    int status_code,
    const char* content_type,
    const char* body,
    int close_after);
static fz_websocket_state* fz_websocket_state_get(int32_t handle);
static int32_t fz_websocket_state_alloc(int fd);
static int fz_websocket_write_frame(int fd, uint8_t opcode, const char* payload, size_t payload_len);
static int fz_websocket_read_frame(
    fz_websocket_state* ws,
    int32_t max_bytes,
    int32_t* out_kind_id,
    int32_t* out_close_code,
    int32_t* out_error_id);
static void fz_dotenv_load(void);
static void fz_env_bootstrap(void);
static const char* fz_env_get_bootstrapped(const char* key);
static void fz_log_bind_target(int listener_fd);
static void fz_crypto_memzero(void* ptr, size_t len);
static int fz_crypto_fill_random(void* out, size_t len);
static char* fz_crypto_hex_encode(const uint8_t* data, size_t len);
static char* fz_crypto_base64_encode_alloc(const uint8_t* data, size_t len);
static char* fz_crypto_base64_url_encode_alloc(const uint8_t* data, size_t len);
static int fz_crypto_base64_decode_alloc(const char* input, uint8_t** out, size_t* out_len);
static int fz_crypto_base64_url_decode_alloc(const char* input, uint8_t** out, size_t* out_len);
static int fz_json_parse_string(const char** cursor, char** out);
static int fz_parse_json_string_array(const char* raw, char*** out_items, int* out_count);
static int fz_parse_json_env_object(const char* raw, char*** out_items, int* out_count);
static void fz_free_string_list(char** items, int count);
static int fz_json_parse_value_slice(const char* raw, const char** out_start, const char** out_end);
static fz_spawn_state* fz_spawn_state_by_handle_locked(int32_t handle);
static const char* fz_lookup_string_unlocked(int32_t id);
static uint32_t fz_string_hash_bytes(const char* data, size_t len);
static int32_t fz_find_string_slice_unlocked(const char* value, size_t len, uint32_t hash);
static int32_t fz_find_string_cstr_unlocked(const char* value, uint32_t hash);
static void fz_string_index_insert_unlocked(int32_t id, const char* value, uint32_t hash);
static void fz_string_index_bootstrap(void);
static int32_t fz_bytes_alloc(void);
static fz_bytes_state* fz_bytes_get(int32_t handle);
static void fz_bytes_reset(fz_bytes_state* bytes);
static int32_t fz_runtime_bytes_new_from_slice(const uint8_t* data, size_t len);
static int32_t fz_runtime_bytes_len(int32_t handle);
static const uint8_t* fz_runtime_bytes_data_ptr(int32_t handle, size_t* out_len);
static int fz_runtime_bytes_bounds_ok(size_t len, int32_t start, int32_t width, const char* context);
static int fz_runtime_bytes_utf8_ok(const uint8_t* data, size_t len);
static float fz_runtime_bytes_f16_to_f32(uint16_t bits);
static void fz_list_reset(fz_list_state* list);
static int fz_list_reserve(fz_list_state* list, int32_t need);
static void fz_array_reset(fz_array_state* array);
static int fz_array_reserve(fz_array_state* array, int32_t need);
static void fz_map_reset(fz_map_state* map);
static int fz_map_reserve(fz_map_state* map, int32_t need);
static void fz_numeric_vec_reset(fz_numeric_vec_state* vec);
static int fz_numeric_vec_reserve(fz_numeric_vec_state* vec, int32_t need);
int32_t fz_native_net_request_id(int32_t conn_fd);
int32_t fz_native_net_write(int32_t conn_fd, int32_t status_code, int32_t body_id);


"#
}
