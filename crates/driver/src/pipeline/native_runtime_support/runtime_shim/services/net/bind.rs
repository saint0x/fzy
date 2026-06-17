pub(super) fn section() -> &'static str {
    r#"
static int fz_split_bind_addr(
    const char* addr,
    char* host,
    size_t host_cap,
    char* service,
    size_t service_cap) {
  if (addr == NULL || addr[0] == '\0') {
    return -1;
  }
  if (addr[0] == '[') {
    const char* end = strchr(addr, ']');
    if (end == NULL || end[1] != ':' || end == addr + 1) {
      return -1;
    }
    size_t host_len = (size_t)(end - addr - 1);
    const char* port = end + 2;
    size_t port_len = strlen(port);
    if (host_len + 1 > host_cap || port_len == 0 || port_len + 1 > service_cap) {
      return -1;
    }
    memcpy(host, addr + 1, host_len);
    host[host_len] = '\0';
    memcpy(service, port, port_len + 1);
    return 0;
  }
  const char* colon = strrchr(addr, ':');
  if (colon == NULL || colon == addr || colon[1] == '\0' || strchr(colon + 1, ':') != NULL) {
    return -1;
  }
  if (strchr(addr, ':') != colon) {
    return -1;
  }
  size_t host_len = (size_t)(colon - addr);
  size_t port_len = strlen(colon + 1);
  if (host_len + 1 > host_cap || port_len + 1 > service_cap) {
    return -1;
  }
  memcpy(host, addr, host_len);
  host[host_len] = '\0';
  memcpy(service, colon + 1, port_len + 1);
  return 0;
}

int32_t fz_native_net_bind(int32_t addr_id) {
  (void)pthread_once(&fz_env_bootstrap_once, fz_env_bootstrap);
  const char* addr = fz_lookup_string(addr_id);
  char host[NI_MAXHOST];
  char service[NI_MAXSERV];
  if (fz_split_bind_addr(addr, host, sizeof(host), service, sizeof(service)) != 0) {
    char msg[320];
    snprintf(
        msg,
        sizeof(msg),
        "http.bind failed: invalid addr `%s` (expected host:port or [ipv6]:port)",
        addr == NULL ? "" : addr);
    fz_set_last_error(EINVAL, 3, msg);
    return -1;
  }

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICSERV;

  struct addrinfo* results = NULL;
  int gai = getaddrinfo(host, service, &hints, &results);
  if (gai != 0) {
    char msg[320];
    snprintf(
        msg,
        sizeof(msg),
        "http.bind failed for %s:%s: %s",
        host,
        service,
        gai_strerror(gai));
    fz_set_last_error(EINVAL, 3, msg);
    return -1;
  }

  int fd = -1;
  int last_errno = EADDRNOTAVAIL;
  for (struct addrinfo* it = results; it != NULL; it = it->ai_next) {
    fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (fd < 0) {
      last_errno = errno;
      continue;
    }
    (void)fz_mark_cloexec(fd);
    int yes = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef IPV6_V6ONLY
    if (it->ai_family == AF_INET6) {
      (void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes));
    }
#endif
    if (bind(fd, it->ai_addr, it->ai_addrlen) == 0) {
      break;
    }
    last_errno = errno;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(results);

  if (fd < 0) {
    char msg[320];
    snprintf(
        msg,
        sizeof(msg),
        "http.bind failed on %s:%s errno=%d (%s)",
        host,
        service,
        last_errno,
        strerror(last_errno));
    fz_set_last_error(last_errno, 3, msg);
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
  struct sockaddr_storage peer;
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
  char peer_addr[NI_MAXHOST];
  if (getnameinfo(
          (struct sockaddr*)&peer,
          peer_len,
          peer_addr,
          sizeof(peer_addr),
          NULL,
          0,
          NI_NUMERICHOST)
      != 0) {
    peer_addr[0] = '\0';
  }
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 1);
  if (state != NULL) {
    fz_conn_state_reset_request_body(state);
    fz_conn_state_reset_response_headers(state);
    state->remote_addr_id = fz_intern_slice(peer_addr, strlen(peer_addr));
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
