pub(super) fn section() -> &'static str {
    r#"
int32_t fz_native_net_bind(void) {
  (void)pthread_once(&fz_env_bootstrap_once, fz_env_bootstrap);
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    char msg[256];
    snprintf(msg, sizeof(msg), "http.bind failed: socket() errno=%d (%s)", errno, strerror(errno));
    fz_set_last_error(errno, 3, msg);
    return -1;
  }
  (void)fz_mark_cloexec(fd);
  int yes = 1;
  (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = fz_default_addr();
  addr.sin_port = htons((uint16_t)fz_default_port());
  if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
    char host[64];
    const char* rendered = inet_ntop(AF_INET, &addr.sin_addr, host, sizeof(host));
    if (rendered == NULL) {
      rendered = fz_default_host_name();
    }
    int bind_port = (int)ntohs(addr.sin_port);
    char msg[320];
    snprintf(
        msg,
        sizeof(msg),
        "http.bind failed on %s:%d errno=%d (%s); set FZ_HOST/FZ_PORT or AGENT_HOST/AGENT_PORT",
        rendered,
        bind_port,
        errno,
        strerror(errno));
    fz_set_last_error(errno, 3, msg);
    close(fd);
    return -1;
  }
  pthread_mutex_lock(&fz_listener_lock);
  fz_listener_fd = fd;
  pthread_mutex_unlock(&fz_listener_lock);
  fz_set_last_error(0, 0, "");
  return fd;
}

int32_t fz_native_net_listen(int32_t fd) {
  int listener = fd;
  if (listener < 0) {
    pthread_mutex_lock(&fz_listener_lock);
    listener = fz_listener_fd;
    pthread_mutex_unlock(&fz_listener_lock);
  }
  if (listener < 0) {
    fz_set_last_error(EINVAL, 3, "http.listen failed: no listener fd (call http.bind first)");
    return -1;
  }
  if (listen(listener, 128) != 0) {
    char msg[256];
    snprintf(
        msg,
        sizeof(msg),
        "http.listen failed fd=%d backlog=128 errno=%d (%s)",
        listener,
        errno,
        strerror(errno));
    fz_set_last_error(errno, 3, msg);
    return -1;
  }
  fz_log_bind_target(listener);
  fz_set_last_error(0, 0, "");
  return 0;
}

int32_t fz_native_net_accept(void) {
  int listener = -1;
  pthread_mutex_lock(&fz_listener_lock);
  listener = fz_listener_fd;
  pthread_mutex_unlock(&fz_listener_lock);
  if (listener < 0) {
    fz_set_last_error(EINVAL, 3, "http.accept failed: listener not initialized");
    return -1;
  }
  struct sockaddr_in peer;
  socklen_t peer_len = sizeof(peer);
  int conn_fd = accept(listener, (struct sockaddr*)&peer, &peer_len);
  if (conn_fd < 0) {
    if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
      char msg[256];
      snprintf(
          msg,
          sizeof(msg),
          "http.accept failed listener=%d errno=%d (%s)",
          listener,
          errno,
          strerror(errno));
      fz_set_last_error(errno, 3, msg);
    }
    return -1;
  }
  (void)fz_mark_cloexec(conn_fd);
  char peer_addr[64];
  const char* rendered = inet_ntop(AF_INET, &peer.sin_addr, peer_addr, sizeof(peer_addr));
  if (rendered == NULL) {
    rendered = "";
  }
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 1);
  if (state != NULL) {
    fz_conn_state_reset_request_body(state);
    fz_conn_state_reset_response_headers(state);
    state->remote_addr_id = fz_intern_slice(rendered, strlen(rendered));
    state->request_id = 0;
    state->header_count = 0;
    state->query_count = 0;
    state->param_count = 0;
  }
  pthread_mutex_unlock(&fz_conn_lock);
  fz_set_last_error(0, 0, "");
  return conn_fd;
}

static int fz_wait_for_fd_event(int fd, short events, int timeout_ms) {
  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = events;
  pfd.revents = 0;
  for (;;) {
    if (fz_async_current_task_cancelled()) {
      errno = ECANCELED;
      return -1;
    }
    if (fz_async_deadline_expired()) {
      errno = ETIMEDOUT;
      return -1;
    }
    int effective_timeout_ms = fz_async_effective_timeout_ms(timeout_ms);
    int ready = poll(&pfd, 1, effective_timeout_ms);
    if (ready > 0) {
      return 0;
    }
    if (ready == 0) {
      errno = ETIMEDOUT;
      return -1;
    }
    if (errno == EINTR) {
      continue;
    }
    return -1;
  }
}

int32_t fz_native_net_poll_register(int32_t fd) {
  if (fd < 0) {
    fz_set_last_error(EINVAL, 3, "http.poll_register failed: invalid handle");
    return -1;
  }
  pthread_mutex_lock(&fz_net_poll_lock);
  for (int i = 0; i < FZ_MAX_NET_POLL_WATCHES; i++) {
    if (fz_net_poll_watches[i].in_use && fz_net_poll_watches[i].fd == fd) {
      fz_net_poll_watches[i].events = POLLIN;
      pthread_mutex_unlock(&fz_net_poll_lock);
      fz_set_last_error(0, 0, "");
      return 0;
    }
  }
  for (int i = 0; i < FZ_MAX_NET_POLL_WATCHES; i++) {
    if (!fz_net_poll_watches[i].in_use) {
      fz_net_poll_watches[i].in_use = 1;
      fz_net_poll_watches[i].fd = fd;
      fz_net_poll_watches[i].events = POLLIN;
      pthread_mutex_unlock(&fz_net_poll_lock);
      fz_set_last_error(0, 0, "");
      return 0;
    }
  }
  pthread_mutex_unlock(&fz_net_poll_lock);
  fz_set_last_error(ENOSPC, 3, "http.poll_register failed: poll watch queue full");
  return -1;
}

"#
}
