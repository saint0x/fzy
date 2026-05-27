pub(super) fn runtime_shim_section_term() -> &'static str {
    r#"
#define FZ_MAX_PROC_ARGS 512

static pthread_once_t fz_proc_args_once = PTHREAD_ONCE_INIT;
static int32_t fz_proc_arg_count = 0;
static int32_t fz_proc_arg_ids[FZ_MAX_PROC_ARGS];
static pthread_mutex_t fz_term_lock = PTHREAD_MUTEX_INITIALIZER;
static int32_t fz_term_last_stdin_eof = 0;

static void fz_proc_capture_args(void) {
  fz_proc_arg_count = 0;
#ifdef __APPLE__
  int* argc_ptr = _NSGetArgc();
  char*** argv_ptr = _NSGetArgv();
  int argc = argc_ptr == NULL ? 0 : *argc_ptr;
  char** argv = argv_ptr == NULL ? NULL : *argv_ptr;
  if (argc <= 0 || argv == NULL) {
    return;
  }
  if (argc > FZ_MAX_PROC_ARGS) {
    argc = FZ_MAX_PROC_ARGS;
  }
  for (int i = 0; i < argc; i++) {
    const char* item = argv[i] == NULL ? "" : argv[i];
    fz_proc_arg_ids[i] = fz_intern_slice(item, strlen(item));
  }
  fz_proc_arg_count = argc;
#elif defined(__linux__)
  FILE* file = fopen("/proc/self/cmdline", "rb");
  if (file == NULL) {
    return;
  }
  size_t cap = 4096;
  size_t len = 0;
  char* raw = (char*)malloc(cap);
  if (raw == NULL) {
    fclose(file);
    return;
  }
  for (;;) {
    if (len == cap) {
      size_t next_cap = cap * 2;
      char* next = (char*)realloc(raw, next_cap);
      if (next == NULL) {
        free(raw);
        fclose(file);
        return;
      }
      raw = next;
      cap = next_cap;
    }
    size_t got = fread(raw + len, 1, cap - len, file);
    len += got;
    if (got == 0) {
      break;
    }
  }
  fclose(file);
  size_t start = 0;
  int count = 0;
  while (start < len && count < FZ_MAX_PROC_ARGS) {
    size_t end = start;
    while (end < len && raw[end] != '\0') {
      end++;
    }
    fz_proc_arg_ids[count++] = fz_intern_slice(raw + start, end - start);
    start = end + 1;
  }
  fz_proc_arg_count = count;
  free(raw);
#endif
}

int32_t fz_native_proc_argv_count(void) {
  pthread_once(&fz_proc_args_once, fz_proc_capture_args);
  return fz_proc_arg_count;
}

int32_t fz_native_proc_argv_get(int32_t index) {
  pthread_once(&fz_proc_args_once, fz_proc_capture_args);
  if (index < 0 || index >= fz_proc_arg_count || index >= FZ_MAX_PROC_ARGS) {
    return fz_intern_slice("", 0);
  }
  return fz_proc_arg_ids[index];
}

int32_t fz_native_term_read_line(void) {
  pthread_mutex_lock(&fz_term_lock);
  fz_term_last_stdin_eof = 0;
  size_t cap = 256;
  size_t len = 0;
  char* buffer = (char*)malloc(cap);
  if (buffer == NULL) {
    pthread_mutex_unlock(&fz_term_lock);
    return 0;
  }
  int ch = 0;
  while ((ch = fgetc(stdin)) != EOF) {
    if (ch == '\n') {
      break;
    }
    if (len + 1 >= cap) {
      size_t next_cap = cap * 2;
      char* next = (char*)realloc(buffer, next_cap);
      if (next == NULL) {
        free(buffer);
        pthread_mutex_unlock(&fz_term_lock);
        return 0;
      }
      buffer = next;
      cap = next_cap;
    }
    buffer[len++] = (char)ch;
  }
  if (ch == EOF) {
    fz_term_last_stdin_eof = 1;
  }
  if (len > 0 && buffer[len - 1] == '\r') {
    len--;
  }
  buffer[len] = '\0';
  int32_t out = fz_intern_owned(buffer);
  if (out == 0) {
    out = fz_intern_slice("", 0);
  }
  pthread_mutex_unlock(&fz_term_lock);
  return out;
}

int32_t fz_native_term_stdin_eof(void) {
  pthread_mutex_lock(&fz_term_lock);
  int32_t eof = fz_term_last_stdin_eof;
  pthread_mutex_unlock(&fz_term_lock);
  return eof;
}

int32_t fz_native_term_write(int32_t text_id) {
  const char* text = fz_lookup_string(text_id);
  if (text == NULL) {
    text = "";
  }
  if (fputs(text, stdout) == EOF) {
    return -1;
  }
  return fflush(stdout) == 0 ? 0 : -1;
}

int32_t fz_native_term_write_err(int32_t text_id) {
  const char* text = fz_lookup_string(text_id);
  if (text == NULL) {
    text = "";
  }
  if (fputs(text, stderr) == EOF) {
    return -1;
  }
  return fflush(stderr) == 0 ? 0 : -1;
}

int32_t fz_native_term_stdin_is_tty(void) {
  return isatty(STDIN_FILENO) ? 1 : 0;
}

int32_t fz_native_term_stdout_is_tty(void) {
  return isatty(STDOUT_FILENO) ? 1 : 0;
}
"#
}
