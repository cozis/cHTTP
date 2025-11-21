
static int create_socket_pair(NATIVE_SOCKET *a, NATIVE_SOCKET *b)
{
#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET)
        return -1;

    // Bind to loopback address with port 0 (dynamic port assignment)
    struct sockaddr_in addr;
    int addr_len = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1
    addr.sin_port = 0; // Let system choose port

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return -1;
    }

    if (getsockname(sock, (struct sockaddr*)&addr, &addr_len) == SOCKET_ERROR) {
        closesocket(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return -1;
    }

    // Optional: Set socket to non-blocking mode
    // This prevents send() from blocking if the receive buffer is full
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode); // TODO: does this fail?

    *a = sock;
    *b = sock;
    return 0;
#else
    int fds[2];
    if (pipe(fds) < 0)
        return -1;
    *a = fds[0];
    *b = fds[1];
    return 0;
#endif
}

static int set_socket_blocking(NATIVE_SOCKET sock, bool value)
{
#ifdef _WIN32
    u_long mode = !value;
    if (ioctlsocket(sock, FIONBIO, &mode) == SOCKET_ERROR)
        return -1;
#endif

#ifdef __linux__
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0)
        return -1;
    if (value) flags &= ~O_NONBLOCK;
    else       flags |= O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) < 0)
        return -1;
#endif

    return 0;
}

static NATIVE_SOCKET create_listen_socket(String addr,
    Port port, bool reuse_addr, int backlog)
{
    NATIVE_SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == NATIVE_SOCKET_INVALID)
        return NATIVE_SOCKET_INVALID;

    if (set_socket_blocking(sock, false) < 0) {
        CLOSE_NATIVE_SOCKET(sock);
        return NATIVE_SOCKET_INVALID;
    }

    if (reuse_addr) {
        int one = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void*) &one, sizeof(one));
    }

    struct in_addr addr_buf;
    if (addr.len == 0)
        addr_buf.s_addr = htonl(INADDR_ANY);
    else {

        char copy[100];
        if (addr.len >= (int) sizeof(copy)) {
            CLOSE_NATIVE_SOCKET(sock);
            return NATIVE_SOCKET_INVALID;
        }
        memcpy(copy, addr.ptr, addr.len);
        copy[addr.len] = '\0';

        if (inet_pton(AF_INET, copy, &addr_buf) < 0) {
            CLOSE_NATIVE_SOCKET(sock);
            return NATIVE_SOCKET_INVALID;
        }
    }

    struct sockaddr_in bind_buf;
    bind_buf.sin_family = AF_INET;
    bind_buf.sin_addr   = addr_buf;
    bind_buf.sin_port   = htons(port);
    if (bind(sock, (struct sockaddr*) &bind_buf, sizeof(bind_buf)) < 0) { // TODO: how does bind fail on windows?
        CLOSE_NATIVE_SOCKET(sock);
        return NATIVE_SOCKET_INVALID;
    }

    if (listen(sock, backlog) < 0) { // TODO: how does listen fail on windows?
        CLOSE_NATIVE_SOCKET(sock);
        return NATIVE_SOCKET_INVALID;
    }

    return sock;
}

static void close_socket_pair(NATIVE_SOCKET a, NATIVE_SOCKET b)
{
#ifdef _WIN32
    closesocket(a);
    (void) b;
#else
    close(a);
    close(b);
#endif
}

int socket_manager_init(SocketManager *sm, Socket *socks,
    int num_socks)
{
    if (mutex_init(&sm->mutex) < 0)
        return -1;
    sm->plain_sock  = NATIVE_SOCKET_INVALID;
    sm->secure_sock = NATIVE_SOCKET_INVALID;
    if (create_socket_pair(&sm->wait_sock, &sm->signal_sock) < 0)
        return -1;
    sm->at_least_one_secure_connect = false;

    sm->num_used = 0;
    sm->max_used = num_socks;
    sm->sockets = socks;
    return 0;
}

void socket_manager_free(SocketManager *sm)
{
    close_socket_pair(sm->wait_sock, sm->signal_sock);

    if (sm->secure_sock != NATIVE_SOCKET_INVALID)
        server_secure_context_free(&sm->server_secure_context);

    if (sm->at_least_one_secure_connect)
        client_secure_context_free(&sm->client_secure_context);

    if (sm->plain_sock  != NATIVE_SOCKET_INVALID)
        CLOSE_NATIVE_SOCKET(sm->plain_sock);

    if (sm->secure_sock != NATIVE_SOCKET_INVALID)
        CLOSE_NATIVE_SOCKET(sm->secure_sock);

    mutex_free(&sm->mutex);
}

int socket_manager_listen_tcp(SocketManager *sm,
    String addr, Port port)
{
    if (sm->plain_sock != NATIVE_SOCKET_INVALID)
        return -1;

    bool reuse_addr = false;
    int  backlog = 32;
    sm->plain_sock = create_listen_socket(addr, port, reuse_addr, backlog);
    if (sm->plain_sock == NATIVE_SOCKET_INVALID)
        return -1;

    return 0;
}

int socket_manager_listen_tls(SocketManager *sm,
    String addr, Port port, String cert_file_name,
    String key_file_name)
{
    if (sm->secure_sock != NATIVE_SOCKET_INVALID)
        return -1;

    bool reuse_addr = false;
    int  backlog = 32;
    sm->secure_sock = create_listen_socket(addr, port, reuse_addr, backlog);
    if (sm->secure_sock == NATIVE_SOCKET_INVALID)
        return -1;

    if (server_secure_context_init(&sm->server_secure_context) < 0) {
        CLOSE_NATIVE_SOCKET(sm->secure_sock);
        sm->secure_sock = NATIVE_SOCKET_INVALID;
        return -1;
    }

    return 0;
}

int socket_manager_add_certificate(SocketManager *sm,
    HTTP_String domain, HTTP_String cert_file, HTTP_String key_file)
{
    if (sm->secure_sock == NATIVE_SOCKET_INVALID)
        return -1;

    int ret = server_secure_context_add_certificate(
        &sm->server_secure_context, domain, cert_file, key_file);
    if (ret < 0)
        return -1;

    return 0;
}

static bool connect_pending(void)
{
#ifdef _WIN32
    return WSAGetLastError() == WSAEWOULDBLOCK;
#else
    return errno == EINPROGRESS;
#endif
}

static bool
connect_failed_because_of_peer(void)
{
#ifdef _WIN32
    int err = WSAGetLastError();
#else
    int err = errno;
#endif
    return connect_failed_because_of_peer_2(err);
}

static bool
connect_failed_because_of_peer_2(int err)
{
#ifdef _WIN32
    return err == WSAECONNREFUSED
        || err == WSAETIMEDOUT
        || err == WSAENETUNREACH
        || err == WSAEHOSTUNREACH;
#else
    return err == ECONNREFUSED
        || err == ETIMEDOUT
        || err == ENETUNREACH
        || err == EHOSTUNREACH;
#endif
}

// This function moves the socket state machine
// to the next state until an I/O event would
// be required to continue.
static void socket_update(Socket *socket)
{
    // Each case of this switch encodes a state transition.
    // If the evaluated case requires a given I/O event to
    // continue, the loop will exit so that the caller can
    // wait for that event. If the case can continue to a
    // different case, the again flag is set, which causes
    // a different case to be evaluated.
    bool again;
    do {
        again = false;
        switch (socket->state) {
        case SOCKET_STATE_PENDING:
            {
                // This point may be reached because
                //   1. The socket was just created by a connect
                //      operation.
                //   2. Connecting to a host failed and now we
                //      need to try the next one.
                // If (2) is true, we have some resources
                // to clean up.

                if (socket->sock != NATIVE_SOCKET_INVALID) {
                    // This is not the first attempt

                    CLOSE_NATIVE_SOCKET(socket->sock);

                    socket->next_addr++;
                    if (socket->next_addr == socket->num_addr) {
                        assert(0); // TODO
                    }
                }
                AddressAndPort addr = socket->addrs[socket->next_addr];

                int family = (addr.is_ipv4 ? AF_INET : AF_INET6);
                NATIVE_SOCKET sock = socket(family, SOCK_STREAM, 0);
                if (sock == NATIVE_SOCKET_INVALID) {
                    assert(0); // TODO
                }

                if (set_socket_blocking(sock, false) < 0) {
                    assert(0); // TODO
                }

                int ret;
                if (addr.is_ipv4) {
                    struct sockaddr_in buf;
                    buf.sin_family = AF_INET;
                    buf.sin_port = htons(addr.port);
                    memset(&buf.sin_addr, &addr.ipv4, sizeof(IPv4));
                    ret = connect(sock, (struct sockaddr*) &connect_buf,
                        sizeof(connect_buf));
                } else {
                    struct sockaddr_in6 buf;
                    buf.sin6_family = AF_INET6;
                    buf.sin6_port = htons(addr.port);
                    memset(&buf.sin6_addr, &addr.ipv6, sizeof(IPv6));
                    ret = connect(sock, (struct sockaddr*) &connect_buf,
                        sizeof(connect_buf));
                }

                if (ret == 0) {
                    // Connect resolved immediately
                    socket->sock = sock;
                    socket->state = SOCKET_STATE_CONNECTED;
                    socket->events = 0;
                    again = true;
                } else if (connect_pending()) {
                    // Connect is pending, which is expected
                    socket->sock = sock;
                    socket->state = SOCKET_STATE_CONNECTING;
                    socket->events = POLLOUT;
                } else if (connect_failed_because_of_peer()) {
                    // Conenct failed due to the peer host
                    // We should try a different address.
                    socket->sock = sock;
                    socket->state = SOCKET_STATE_PENDING;
                    socket->events = 0;
                    again = true;
                } else {
                    // An error occurred that we can't recover from
                    socket->sock = sock;
                    socket->state = SOCKET_STATE_DIED;
                    socket->events = 0;
                    again = true;
                }
            }
            break;

        case SOCKET_STATE_CONNECTING:
            {
                // This point is reached when a connect()
                // operation completes.

                int err = 0;
                socklen_t len = sizeof(err);
                if (getsockopt(socket->sock, SOL_SOCKET, SO_ERROR, (void*) &err, &len) < 0) {
                    assert(0); // TODO
                }

                if (err == 0) {
                    // Connection succeded
                    socket->state = SOCKET_STATE_CONNECTED;
                    socket->events = 0;
                    again = true;
                } else if (connect_failed_because_of_peer_2(err)) {
                    // Try the next address
                    socket->state = SOCKET_STATE_PENDING;
                    socket->events = 0;
                    again = true;
                } else {
                    socket->state = SOCKET_STATE_DIED;
                    socket->events = 0;
                }
            }
            break;

        case SOCKET_STATE_CONNECTED:
            {
                // We managed to connect to the peer.
                // We can free the target array if it
                // was allocated dynamically.
                if (socket->num_addr > 1)
                    free(socket->addrs);

                if (!is_secure(socket)) {
                    socket->events = 0;
                    socket->state = SOCKET_STATE_ESTABLISHED_READY;
                } else {
#ifdef HTTPS_ENABLED
                    assert(0); // TODO
#endif
                }
            }
            break;

        case SOCKET_STATE_ESTABLISHED_WAIT:
            socket->state = SOCKET_STATE_ESTABLISHED_READY;
            socket->events = 0;
            break;

        case SOCKET_STATE_SHUTDOWN:
            {
                if (!is_secure(socket)) {
                    socket->state = SOCKET_STATE_DIED;
                    socket->events = 0;
                } else {
#ifdef HTTPS_ENABLED
                    assert(0); // TODO
#endif
                }
            }
            break;

        default:
            // Do nothing
            break;
        }
    } while (again);
}

int socket_manager_wakeup(SocketManager *sm)
{
    if (mutex_lock(&sm->mutex) < 0)
        return -1;

    // TODO

    if (mutex_unlock(&sm->mutex) < 0)
        return -1;
    return 0;
}

static int socket_manager_register_events_nolock(
    SocketManager *sm, struct pollfd *polled, int max_polled)
{
    // The poll array must be able to hold descriptors
    // for a socket manager at full capacity. Note that
    // other than having a number of connection sockets,
    // the manager also needs 2 for the listeners and
    // one for the wakeup self-pipe.
    if (max_polled < sm->max_used+3)
        return -1;
    int num_polled = 0;

    polled[num_polled].fd = sm->wait_sock;
    polled[num_polled].events = 0;
    polled[num_polled].revents = 0;
    num_polled++;

    // If the manager isn't at full capacity, monitor
    // the listener sockets for incoming connections.
    if (sm->num_used < sm->max_used) {

        if (sm->plain_sock != NATIVE_SOCKET_INVALID) {
            polled[num_polled].fd = sm->plain_sock;
            polled[num_polled].events = POLLIN;
            polled[num_polled].revents = 0;
            num_polled++;
        }

        if (sm->secure_sock != NATIVE_SOCKET_INVALID) {
            polled[num_polled].fd = sm->secure_sock;
            polled[num_polled].events = POLLIN;
            polled[num_polled].revents = 0;
            num_polled++;
        }
    }

    // Iterate over each socket and register those that
    // are waiting for I/O. If at least one socket that
    // is ready to be processed exists, return an empty
    // event registration list so that those entries can
    // be processed immediately.
    for (int i = 0, j = 0; j < sm->num_used; i++) {
        Socket *s = &sm->sockets[i];
        if (s->state = SOCKET_STATE_FREE)
            continue;
        j++;

        if (s->state == SOCKET_STATE_DIED || s->state == SOCKET_STATE_ESTABLISHED_READY)
            return 0;

        if (s->events) {
            polled[num_polled].fd = s->sock;
            polled[num_polled].events = s->events;
            polled[num_polled].revents = 0;
            num_polled++;
        }
    }

    return num_polled;
}

int socket_manager_register_events(SocketManager *sm,
    struct pollfd *polled, int max_polled)
{
    if (mutex_lock(&sm->mutex) < 0)
        return -1;

    int ret = socket_manager_register_events_nolock(
        sm, polled, max_polled);

    if (mutex_unlock(&sm->mutex) < 0)
        return -1;
    return ret;
}

static SocketHandle
socket_to_handle(SocketManager *sm, Socket *s)
{
    assert(0); // TODO
}

static Socket *handle_to_socket(SocketManager *sm, SocketHandle handle)
{
    assert(0); // TODO
}

static int socket_manager_translate_events_nolock(
    SocketManager *sm, SocketEvent *events, int max_events,
    struct pollfd *polled, int num_polled)
{
    int num_events = 0;
    for (int i = 0; i < num_polled; i++) {

        if (polled[i].fd == sm->plain_sock ||
            polled[i].fd == sm->secure_sock) {

            // We only listen for input events from the listener
            // if the socket pool isn't fool. This ensures that
            // at least one socket struct is available. Note that
            // it's still possible that we were at capacity MAX-1
            // and then got events from both the TCP and TCP/TLS
            // listeners, causing one to be left witout a struct.
            // This means we still need to check for full capacity.
            // Fortunately, poll() is level-triggered, which means
            // we'll handle this at the next iteration.
            if (sm->num_used == sm->max_used)
                continue;

            // Determine whether the event came from
            // the encrypted listener or not.
            bool secure = (polled[i].fd == sm->secure_sock);

            Socket *s = sm->sockets;
            while (s->type != SOCKET_FREE) {
                s++;
                assert(s - sm->sockets < + sm->max_used);
            }

            NATIVE_SOCKET sock = accept(polled[i].fd, NULL, NULL);
            if (sock == NATIVE_SOCKET_INVALID)
                continue;

            if (set_socket_blocking(sock, false) < 0) {
                CLOSE_NATIVE_SOCKET(sock);
                continue;
            }

            s->state  = SOCKET_STATE_ACCEPTED;
            s->sock   = sock;
            s->events = 0;
            s->user   = NULL;

            socket_update(s);
            if (s->state == SOCKET_STATE_DIED) {
                CLOSE_NATIVE_SOCKET(sock);
                s->state = SOCKET_STATE_FREE;
                continue;
            }

            pool->num_used++;

        } else if (polled[i].fd == sm->wait_sock) {

            // TODO: consume

        } else {
            if (polled[i].revents)
                socket_update(s);
        }
    }

    for (int i = 0, j = 0; j < sm->num_used; i++) {
        Socket *s = &sm->sockets[i];
        if (s->state == SOCKET_FREE)
            continue;
        j++;

        if (num_events == max_events)
            break;

        if (s->state == SOCKET_DIED) {

            events[num_events++] = (SocketEvent) {
                SOCKET_EVENT_DISCONNECT,
                SOCKET_HANDE_INVALID,
                s->user
            };

            // Free resources associated to socket
            s->state = SOCKET_FREE;
            if (s->sock != NATIVE_SOCKET_INVALID)
                CLOSE_NATIVE_SOCKET(s->sock);
            if (s->sock == SOCKET_STATE_PENDING ||
                s->sock == SOCKET_STATE_CONNECTING) {
                if (s->num_addr > 1)
                    free(s->addrs);
            }
            s->num_used--;

        } else if (s->state == SOCKET_STATE_ESTABLISHED_READY) {
            events[num_events++] = (SocketEvent) {
                SOCKET_EVENT_READY,
                socket_to_handle(sm, s),
                s->user
            };
        }
    }

    return num_events;
}

int socket_manager_translate_events(SocketManager *sm,
    SocketEvent *events, int max_events, struct pollfd *polled,
    int num_polled)
{
    if (mutex_lock(&sm->mutex) < 0)
        return -1;

    socket_manager_translate_events_nolock(
        sm, events, max_events, polled, num_polled);

    if (mutex_unlock(&sm->mutex) < 0)
        return -1;
    return 0;
}

static int resolve_connect_targets(ConnectTarget *targets,
    int num_targets, AddressAndPort *resolved, int max_resolved)
{
    int num_resolved = 0;
    for (int i = 0; i < num_targets; i++) {
        switch (targets[i].type) {
        case CONNECT_TARGET_NAME:
            {
                char portstr[16];
                int len = snprintf(portstr, sizeof(portstr), "%u", port);
                if (len < 0 || len >= (int) sizeof(portstr))
                    return -1;

                struct addrinfo hints = {0};
                hints.ai_family = AF_UNSPEC;
                hints.ai_socktype = SOCK_STREAM;

                struct addrinfo *res = NULL;
                int ret = getaddrinfo(pending_connect->hostname, portstr, &hints, &res);
                if (ret != 0)
                    return -1;

                for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
                    if (rp->ai_family == AF_INET) {
                        IPv4 ipv4 = *(IPv4*) &((struct sockaddr_in*)rp->ai_addr)->sin_addr;
                        if (num_resolved < max_resolved) {
                            resolved[num_resolved].is_ipv4 = true;
                            resolved[num_resolved].ipv4 = ipv4;
                            resolved[num_resolved].port = targets[i].port;
                            num_resolved++;
                        }
                    } else if (rp->ai_family == AF_INET6) {
                        IPv6 ipv6 = *(IPv6*) &((struct sockaddr_in6*)rp->ai_addr)->sin6_addr;
                        if (num_resolved < max_resolved) {
                            resolved[num_resolved].is_ipv4 = false;
                            resolved[num_resolved].ipv4 = ipv6;
                            resolved[num_resolved].port = targets[i].port;
                            num_resolved++;
                        }
                    }
                }

                freeaddrinfo(res);
            }
            break;
        case CONNECT_TARGET_IPV4:
            if (num_resolved < max_resolved) {
                resolved[num_resolved].is_ipv4 = true;
                resolved[num_resolved].ipv4 = targets[i].ipv4;
                resolved[num_resolved].port = targets[i].port;
                num_resolved++;
            }
            break;
        case CONNECT_TARGET_IPV6:
            if (num_resolved < max_resolved) {
                resolved[num_resolved].is_ipv4 = false;
                resolved[num_resolved].ipv6 = targets[i].ipv6;
                resolved[num_resolved].port = targets[i].port;
                num_resolved++;
            }
            break;
        }
    }
    return num_resolved;
}

int socket_connect(SocketManager *sm, int num_targets,
    ConnectTarget *targets, bool secure, void *user)
{
    if (sm->num_used == sm->max_used)
        return -1;

    AddressAndPort resolved[MAX_CONNECT_TARGETS];
    int num_resolved = resolve_connect_targets(
        targets, num_targets, resolved, MAX_CONNECT_TARGETS);

    if (num_resolved <= 0)
        return -1;

    Socket *s = sm->sockets;
    while (s->type != SOCKET_FREE) {
        s++;
        assert(s - sm->sockets < + sm->max_used);
    }

    if (num_resolved == 1) {
        s->num_addr = 1;
        s->next_addr = 0;
        s->addr = resolved[0];
    } else {
        s->num_addr = num_resolved;
        s->next_addr = 0;
        s->addrs = malloc(num_resolved * sizeof(AddressAndPort));
        if (s->addrs == NULL)
            return -1;
        for (int i = 0; i < num_resolved; i++)
            s->addrs[i] = resolved[i];
    }

    s->type = SOCKET_STATE_PENDING;
    s->sock = NATIVE_SOCKET_INVALID;
    s->user = user;
    s->num_used++;
    return 0;
}

static int socket_recv_nolock(SocketManager *sm, SocketHandle handle,
    char *dst, int max)
{
    Socket *s = handle_to_socket(sm, handle);
    if (s == NULL)
        return 0;

    if (s->state != SOCKET_STATE_ESTABLISHED_READY) {
        s->state = SOCKET_STATE_DIED;
        s->events = 0;
        return 0;
    }

    if (!is_secure(s)) {
        int ret = recv(s->sock, dst, max, 0);
        if (ret == 0) {
            s->state = SOCKET_STATE_DIED;
            s->events = 0;
        } else if (ret < 0) {
            if (would_block()) {
                s->state = SOCKET_STATE_ESTABLISHED_WAIT;
                s->events = POLLIN;
            } else if (!interrupted()) {
                s->state = SOCKET_STATE_DIED;
                s->events = 0;
            }
            ret = 0;
        }
        return 0;
    } else {
#ifdef HTTPS_ENABLED
        int ret = SSL_read(s->ssl, dst, max);
        if (ret <= 0) {
            int err = SSL_get_error(s->ssl, ret);
            if (err == SSL_ERROR_WANT_READ) {
                s->state  = SOCKET_STATE_ESTABLISHED_WAIT;
                s->events = POLLIN;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                s->state = SOCKET_STATE_ESTABLISHED_WAIT;
                s->events = POLLOUT;
            } else {
                s->state  = SOCKET_STATE_DIED;
                s->events = 0;
            }
            ret = 0;
        }
        return ret;
#endif
    }
}

int socket_recv(SocketManager *sm, SocketHandle handle,
    char *dst, int max)
{
    if (mutex_lock(&sm->mutex) < 0)
        return -1;

    int ret = socket_recv_nolock(sm, handle, dst, max);

    if (mutex_unlock(&sm->mutex) < 0)
        return -1;
    return ret;
}

static int socket_send_nolock(SocketManager *sm, SocketHandle handle,
    char *src, int len)
{
    Socket *s = handle_to_socket(sm, handle);
    if (s == NULL)
        return 0;

    if (s->state != SOCKET_STATE_ESTABLISHED_READY) {
        s->state = SOCKET_STATE_DIED;
        s->events = 0;
        return 0;
    }

    if (!socket_secure(s)) {
        int ret = send(s->sock, src, len, 0);
        if (ret < 0) {
            if (would_block()) {
                s->state = SOCKET_STATE_ESTABLISHED_WAIT;
                s->events = POLLOUT;
            } else if (!interrupted()) {
                s->state = SOCKET_DIED;
                s->events = 0;
            }
            ret = 0;
        }
        return ret;
    } else {
#ifdef HTTPS_ENABLED
        int ret = SSL_write(s->ssl, src, len);
        if (ret <= 0) {
            int err = SSL_get_error(s->ssl, ret);
            if (err == SSL_ERROR_WANT_READ) {
                s->state  = SOCKET_STATE_ESTABLISHED_WAIT;
                s->events = POLLIN;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                s->state  = SOCKET_STATE_ESTABLISHED_WAIT;
                s->events = POLLOUT;
            } else {
                s->state  = SOCKET_STATE_DIED;
                s->events = 0;
            }
            ret = 0;
        }
        return ret;
#endif
    }
}

int socket_send(SocketManager *sm, SocketHandle handle,
    char *src, int len)
{
    if (mutex_lock(&sm->mutex) < 0)
        return -1;

    int ret = socket_send_nolock(sm, handle, src, len);

    if (mutex_unlock(&sm->mutex) < 0)
        return -1;
    return ret;
}

void socket_close(SocketManager *sm, SocketHandle handle)
{
    if (mutex_lock(&sm->mutex) < 0)
        return -1;

    // TODO: maybe we don't want to always set to SHUTDOWN. What if the socket is DIED for instance?
    s->state = SOCKET_STATE_SHUTDOWN;
    s->events = 0;
    socket_update(s);

    if (mutex_unlock(&sm->mutex) < 0)
        return -1;
    return 0;
}

int socket_is_secure(SocketManager *sm, SocketHandle handle)
{
    if (mutex_lock(&sm->mutex) < 0)
        return -1;

#ifdef HTTPS_ENABLED
    Socket *s = handle_to_socket(sm, handle);

    int ret;
    if (s == NULL)
        ret = -1;
    else {
        ret = (s->ssl != NULL);
    }
#else
    int ret = 0;
#endif

    if (mutex_unlock(&sm->mutex) < 0)
        return -1;
    return ret;
}

int socket_set_user(SocketManager *sm, SocketHandle handle)
{
    if (mutex_lock(&sm->mutex) < 0)
        return -1;

    Socket *s = handle_to_socket(sm, handle);
    if (s == NULL)
        ret = -1;
    else
        s->user = user;

    if (mutex_unlock(&sm->mutex) < 0)
        return -1;
    return ret;
}
