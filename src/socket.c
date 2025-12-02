
//#define TRACE_STATE_CHANGES

#ifndef TRACE_STATE_CHANGES
#define UPDATE_STATE(a, b) a = b
#else
static char *state_to_str(SocketState state)
{
    switch (state) {
    case SOCKET_STATE_FREE      : return "FREE";
    case SOCKET_STATE_PENDING   : return "PENDING";
    case SOCKET_STATE_CONNECTING: return "CONNECTING";
    case SOCKET_STATE_CONNECTED : return "CONNECTED";
    case SOCKET_STATE_ACCEPTED  : return "ACCEPTED";
    case SOCKET_STATE_ESTABLISHED_WAIT : return "ESTABLISHED_WAIT";
    case SOCKET_STATE_ESTABLISHED_READY: return "ESTABLISHED_READY";
    case SOCKET_STATE_SHUTDOWN  : return "SHUTDOWN";
    case SOCKET_STATE_DIED      : return "DIED";
    }
    return "???";
}
#define UPDATE_STATE(a, b) {    \
    printf("%s -> %s  %s:%d\n", \
        state_to_str(a),        \
        state_to_str(b),        \
        __FILE__, __LINE__);    \
    a = b;                      \
}
#endif

static int create_socket_pair(NATIVE_SOCKET *a, NATIVE_SOCKET *b, bool *global_cleanup)
{
#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    *global_cleanup = false;
    if (sock == INVALID_SOCKET && WSAGetLastError() == WSANOTINITIALISED) {

        WSADATA wsaData;
        WORD wVersionRequested = MAKEWORD(2, 2);
        if (WSAStartup(wVersionRequested, &wsaData))
            return HTTP_ERROR_UNSPECIFIED;

        sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET && *global_cleanup)
            WSACleanup();
    }

    if (sock == INVALID_SOCKET) {
        if (*global_cleanup)
            WSACleanup();
        return HTTP_ERROR_UNSPECIFIED;
    }

    // Bind to loopback address with port 0 (dynamic port assignment)
    struct sockaddr_in addr;
    int addr_len = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1
    addr.sin_port = 0; // Let system choose port

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        if (*global_cleanup)
            WSACleanup();
        return HTTP_ERROR_UNSPECIFIED;
    }

    if (getsockname(sock, (struct sockaddr*)&addr, &addr_len) == SOCKET_ERROR) {
        closesocket(sock);
        if (*global_cleanup)
            WSACleanup();
        return HTTP_ERROR_UNSPECIFIED;
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        if (*global_cleanup)
            WSACleanup();
        return HTTP_ERROR_UNSPECIFIED;
    }

    // Optional: Set socket to non-blocking mode
    // This prevents send() from blocking if the receive buffer is full
    u_long mode = 1;
    if (ioctlsocket(sock, FIONBIO, &mode) == SOCKET_ERROR) {
        closesocket(sock);
        if (*global_cleanup)
            WSACleanup();
        return HTTP_ERROR_UNSPECIFIED;
    }

    *a = sock;
    *b = sock;
    return HTTP_OK;
#else
    *global_cleanup = false;
    int fds[2];
    if (pipe(fds) < 0)
        return HTTP_ERROR_UNSPECIFIED;
    *a = fds[0];
    *b = fds[1];
    return HTTP_OK;
#endif
}

static int set_socket_blocking(NATIVE_SOCKET sock, bool value)
{
#ifdef _WIN32
    u_long mode = !value;
    if (ioctlsocket(sock, FIONBIO, &mode) == SOCKET_ERROR)
        return HTTP_ERROR_UNSPECIFIED;
    return HTTP_OK;
#endif

#ifdef __linux__
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0)
        return HTTP_ERROR_UNSPECIFIED;
    if (value) flags &= ~O_NONBLOCK;
    else       flags |= O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) < 0)
        return HTTP_ERROR_UNSPECIFIED;
    return HTTP_OK;
#endif
}

static NATIVE_SOCKET create_listen_socket(HTTP_String addr,
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
    if (bind(sock, (struct sockaddr*) &bind_buf, sizeof(bind_buf)) < 0) {
        CLOSE_NATIVE_SOCKET(sock);
        return NATIVE_SOCKET_INVALID;
    }

    if (listen(sock, backlog) < 0) {
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
    sm->plain_sock  = NATIVE_SOCKET_INVALID;
    sm->secure_sock = NATIVE_SOCKET_INVALID;

    int ret = create_socket_pair(
        &sm->wait_sock,
        &sm->signal_sock,
        &sm->global_cleanup);
    if (ret < 0) return ret;

    sm->at_least_one_secure_connect = false;

    sm->num_used = 0;
    sm->max_used = num_socks;
    sm->sockets = socks;

    for (int i = 0; i < num_socks; i++) {
        socks[i].state = SOCKET_STATE_FREE;
        socks[i].gen = 1;
    }
    return HTTP_OK;
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

#ifdef _WIN32
    if (sm->global_cleanup)
        WSACleanup();
#endif
}

int socket_manager_listen_tcp(SocketManager *sm,
    HTTP_String addr, Port port, int backlog,
    bool reuse_addr)
{
    if (sm->plain_sock != NATIVE_SOCKET_INVALID)
        return HTTP_ERROR_UNSPECIFIED;

    sm->plain_sock = create_listen_socket(addr, port, reuse_addr, backlog);
    if (sm->plain_sock == NATIVE_SOCKET_INVALID)
        return HTTP_ERROR_UNSPECIFIED;

    return HTTP_OK;
}

int socket_manager_listen_tls(SocketManager *sm,
    HTTP_String addr, Port port, int backlog,
    bool reuse_addr, HTTP_String cert_file,
    HTTP_String key_file)
{
#ifndef HTTPS_ENABLED
    return HTTP_ERROR_NOTLS;
#endif

    if (sm->secure_sock != NATIVE_SOCKET_INVALID)
        return HTTP_ERROR_UNSPECIFIED;

    sm->secure_sock = create_listen_socket(addr, port, reuse_addr, backlog);
    if (sm->secure_sock == NATIVE_SOCKET_INVALID)
        return HTTP_ERROR_UNSPECIFIED;

    if (server_secure_context_init(&sm->server_secure_context,
        cert_file, key_file) < 0) {
        CLOSE_NATIVE_SOCKET(sm->secure_sock);
        sm->secure_sock = NATIVE_SOCKET_INVALID;
        return HTTP_ERROR_UNSPECIFIED;
    }

    return HTTP_OK;
}

int socket_manager_add_certificate(SocketManager *sm,
    HTTP_String domain, HTTP_String cert_file, HTTP_String key_file)
{
    if (sm->secure_sock == NATIVE_SOCKET_INVALID)
        return HTTP_ERROR_UNSPECIFIED;

    int ret = server_secure_context_add_certificate(
        &sm->server_secure_context, domain, cert_file, key_file);
    if (ret < 0)
        return ret;

    return HTTP_OK;
}

static bool is_secure(Socket *s)
{
#ifdef HTTPS_ENABLED
    return s->server_secure_context != NULL
        || s->client_secure_context != NULL;
#else
    (void) s;
    return false;
#endif
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

static void free_addr_list(AddressAndPort *addrs, int num_addr)
{
#ifdef HTTPS_ENABLED
    for (int i = 0; i < num_addr; i++) {
        RegisteredName *name = addrs[i].name;
        if (name) {
            assert(name->refs > 0);
            name->refs--;
            if (name->refs == 0)
                free(name);
        }
    }
#else
    (void) addrs;
    (void) num_addr;
#endif
}

// This function moves the socket state machine
// to the next state until an I/O event would
// be required to continue.
static void socket_update(Socket *s)
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
        switch (s->state) {
        case SOCKET_STATE_PENDING:
            {
                // This point may be reached because
                //   1. The socket was just created by a connect
                //      operation.
                //   2. Connecting to a host failed and now we
                //      need to try the next one.
                // If (2) is true, we have some resources
                // to clean up.

                if (s->sock != NATIVE_SOCKET_INVALID) {
                    // This is not the first attempt

#ifdef HTTPS_ENABLED
                    if (s->ssl) {
                        SSL_free(s->ssl);
                        s->ssl = NULL;
                    }
#endif

                    CLOSE_NATIVE_SOCKET(s->sock);

                    s->next_addr++;
                    if (s->next_addr == s->num_addr) {
                        // All addresses have been tried and failed
                        UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                        s->events = 0;
                        continue;
                    }
                }

                AddressAndPort addr;
                if (s->num_addr == 1)
                    addr = s->addr;
                else
                    addr = s->addrs[s->next_addr];

                int family = (addr.is_ipv4 ? AF_INET : AF_INET6);
                NATIVE_SOCKET sock = socket(family, SOCK_STREAM, 0);
                if (sock == NATIVE_SOCKET_INVALID) {
                    UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                    s->events = 0;
                    continue;
                }

                if (set_socket_blocking(sock, false) < 0) {
                    CLOSE_NATIVE_SOCKET(sock);
                    UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                    s->events = 0;
                    continue;
                }

                int ret;
                if (addr.is_ipv4) {
                    struct sockaddr_in buf;
                    buf.sin_family = AF_INET;
                    buf.sin_port = htons(addr.port);
                    memcpy(&buf.sin_addr, &addr.ipv4, sizeof(HTTP_IPv4));
                    ret = connect(sock, (struct sockaddr*) &buf, sizeof(buf));
                } else {
                    struct sockaddr_in6 buf;
                    buf.sin6_family = AF_INET6;
                    buf.sin6_port = htons(addr.port);
                    memcpy(&buf.sin6_addr, &addr.ipv6, sizeof(HTTP_IPv6));
                    ret = connect(sock, (struct sockaddr*) &buf, sizeof(buf));
                }

                if (ret == 0) {
                    // Connect resolved immediately
                    s->sock = sock;
                    UPDATE_STATE(s->state, SOCKET_STATE_CONNECTED);
                    s->events = 0;
                    again = true;
                } else if (connect_pending()) {
                    // Connect is pending, which is expected
                    s->sock = sock;
                    UPDATE_STATE(s->state, SOCKET_STATE_CONNECTING);
                    s->events = POLLOUT;
                } else if (connect_failed_because_of_peer()) {
                    // Conenct failed due to the peer host
                    // We should try a different address.
                    s->sock = sock;
                    UPDATE_STATE(s->state, SOCKET_STATE_PENDING);
                    s->events = 0;
                    again = true;
                } else {
                    // An error occurred that we can't recover from
                    s->sock = sock;
                    UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                    s->events = 0;
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
                if (getsockopt(s->sock, SOL_SOCKET, SO_ERROR, (void*) &err, &len) < 0) {
                    // Failed to get socket error status
                    UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                    s->events = 0;
                    continue;
                }

                if (err == 0) {
                    // Connection succeded
                    UPDATE_STATE(s->state, SOCKET_STATE_CONNECTED);
                    s->events = 0;
                    again = true;
                } else if (connect_failed_because_of_peer_2(err)) {
                    // Try the next address
                    UPDATE_STATE(s->state, SOCKET_STATE_PENDING);
                    s->events = 0;
                    again = true;
                } else {
                    UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                    s->events = 0;
                }
            }
            break;

        case SOCKET_STATE_CONNECTED:
            {
                if (!is_secure(s)) {

                    // We managed to connect to the peer.
                    // We can free the target array if it
                    // was allocated dynamically.
                    if (s->num_addr > 1)
                        free(s->addrs);

                    s->events = 0;
                    UPDATE_STATE(s->state, SOCKET_STATE_ESTABLISHED_READY);
                } else {
#ifdef HTTPS_ENABLED
                    if (s->ssl == NULL) {
                        s->ssl = SSL_new(s->client_secure_context->p);
                        if (s->ssl == NULL) {
                            UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                            s->events = 0;
                            break;
                        }

                        if (SSL_set_fd(s->ssl, s->sock) != 1) {
                            UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                            s->events = 0;
                            break;
                        }

                        SSL_set_verify(s->ssl, s->dont_verify_cert
                            ? SSL_VERIFY_NONE : SSL_VERIFY_PEER, NULL);

                        AddressAndPort addr;
                        if (s->num_addr > 1)
                            addr = s->addrs[s->next_addr];
                        else
                            addr = s->addr;

                        if (addr.name) {

                            // Set expected hostname for verification
                            if (SSL_set1_host(s->ssl, addr.name->data) != 1) {
                                UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                                s->events = 0;
                                break;
                            }

                            // Optional but recommended: be strict about wildcards
                            SSL_set_hostflags(s->ssl,
                                X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

                            // Also set for SNI (Server Name Indication)
                            SSL_set_tlsext_host_name(s->ssl, addr.name->data);
                        }
                    }

                    int ret = SSL_connect(s->ssl);
                    if (ret == 1) {
                        // Handshake done

                        // We managed to connect to the peer.
                        // We can free the target array if it
                        // was allocated dynamically.
                        if (s->num_addr == 1)
                            free_addr_list(&s->addr, 1);
                        else {
                            assert(s->num_addr > 1);
                            free_addr_list(s->addrs, s->num_addr);
                            free(s->addrs);
                        }

                        UPDATE_STATE(s->state, SOCKET_STATE_ESTABLISHED_READY);
                        s->events = 0;
                        break;
                    }

                    int err = SSL_get_error(s->ssl, ret);
                    if (err == SSL_ERROR_WANT_READ) {
                        s->events = POLLIN;
                        break;
                    }

                    if (err == SSL_ERROR_WANT_WRITE) {
                        s->events = POLLOUT;
                        break;
                    }

                    UPDATE_STATE(s->state, SOCKET_STATE_PENDING);
                    s->events = 0;
                    again = true;
#endif
                }
            }
            break;

        case SOCKET_STATE_ACCEPTED:
            {
                if (!is_secure(s)) {
                    UPDATE_STATE(s->state, SOCKET_STATE_ESTABLISHED_READY);
                    s->events = 0;
                } else {
#ifdef HTTPS_ENABLED
                    // Start server-side SSL handshake
                    if (!s->ssl) {

                        s->ssl = SSL_new(s->server_secure_context->p);
                        if (s->ssl == NULL) {
                            UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                            s->events = 0;
                            break;
                        }

                        if (SSL_set_fd(s->ssl, s->sock) != 1) {
                            UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                            s->events = 0;
                            break;
                        }
                    }

                    int ret = SSL_accept(s->ssl);
                    if (ret == 1) {
                        // Handshake done
                        UPDATE_STATE(s->state, SOCKET_STATE_ESTABLISHED_READY);
                        s->events = 0;
                        break;
                    }

                    int err = SSL_get_error(s->ssl, ret);
                    if (err == SSL_ERROR_WANT_READ) {
                        s->events = POLLIN;
                        break;
                    }

                    if (err == SSL_ERROR_WANT_WRITE) {
                        s->events = POLLOUT;
                        break;
                    }

                    // Server socket error - close the connection
                    UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                    s->events = 0;
#endif
                }
            }
            break;

        case SOCKET_STATE_ESTABLISHED_WAIT:
            UPDATE_STATE(s->state, SOCKET_STATE_ESTABLISHED_READY);
            s->events = 0;
            break;

        case SOCKET_STATE_SHUTDOWN:
            {
                if (!is_secure(s)) {
                    UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                    s->events = 0;
                } else {
#ifdef HTTPS_ENABLED
                    int ret = SSL_shutdown(s->ssl);
                    if (ret == 1) {
                        UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                        s->events = 0;
                        break;
                    }

                    int err = SSL_get_error(s->ssl, ret);
                    if (err == SSL_ERROR_WANT_READ) {
                        s->events = POLLIN;
                        break;
                    }

                    if (err == SSL_ERROR_WANT_WRITE) {
                        s->events = POLLOUT;
                        break;
                    }

                    UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                    s->events = 0;
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
    // NOTE: It's assumed send/write operate atomically
    //       on The descriptor.
    char byte = 1;
#ifdef _WIN32
    if (send(sm->signal_sock, &byte, 1, 0) < 0)
        return HTTP_ERROR_UNSPECIFIED;
#else
    if (write(sm->signal_sock, &byte, 1) < 0)
        return HTTP_ERROR_UNSPECIFIED;
#endif
    return HTTP_OK;
}

void socket_manager_register_events(
    SocketManager *sm, EventRegister *reg)
{
    reg->num_polled = 0;

    reg->polled[reg->num_polled].fd = sm->wait_sock;
    reg->polled[reg->num_polled].events = POLLIN;
    reg->polled[reg->num_polled].revents = 0;
    reg->ptrs[reg->num_polled] = NULL;
    reg->num_polled++;

    // If the manager isn't at full capacity, monitor
    // the listener sockets for incoming connections.
    if (sm->num_used < sm->max_used) {

        if (sm->plain_sock != NATIVE_SOCKET_INVALID) {
            reg->polled[reg->num_polled].fd = sm->plain_sock;
            reg->polled[reg->num_polled].events = POLLIN;
            reg->polled[reg->num_polled].revents = 0;
            reg->ptrs[reg->num_polled] = NULL;
            reg->num_polled++;
        }

        if (sm->secure_sock != NATIVE_SOCKET_INVALID) {
            reg->polled[reg->num_polled].fd = sm->secure_sock;
            reg->polled[reg->num_polled].events = POLLIN;
            reg->polled[reg->num_polled].revents = 0;
            reg->ptrs[reg->num_polled] = NULL;
            reg->num_polled++;
        }
    }

    // Iterate over each socket and register those that
    // are waiting for I/O. If at least one socket that
    // is ready to be processed exists, return an empty
    // event registration list so that those entries can
    // be processed immediately.
    for (int i = 0, j = 0; j < sm->num_used; i++) {
        Socket *s = &sm->sockets[i];
        if (s->state == SOCKET_STATE_FREE)
            continue;
        j++;

        // If at least one socket can be processed, return an
        // empty list.
        if (s->state == SOCKET_STATE_DIED || s->state == SOCKET_STATE_ESTABLISHED_READY) {
            reg->num_polled = 0;
            return;
        }

        if (s->events) {
            reg->polled[reg->num_polled].fd = s->sock;
            reg->polled[reg->num_polled].events = s->events;
            reg->polled[reg->num_polled].revents = 0;
            reg->ptrs[reg->num_polled] = s;
            reg->num_polled++;
        }
    }
}

static SocketHandle
socket_to_handle(SocketManager *sm, Socket *s)
{
    return ((uint32_t) (s - sm->sockets) << 16) | s->gen;
}

static Socket *handle_to_socket(SocketManager *sm, SocketHandle handle)
{
    uint16_t gen = handle & 0xFFFF;
    uint16_t idx = handle >> 16;
    if (idx >= sm->max_used)
        return NULL;
    if (sm->sockets[idx].gen != gen)
        return NULL;
    return &sm->sockets[idx];
}

int socket_manager_translate_events(
    SocketManager *sm, SocketEvent *events,
    EventRegister reg)
{
    int num_events = 0;
    for (int i = 0; i < reg.num_polled; i++) {

        if (!reg.polled[i].revents)
            continue;

        if (reg.polled[i].fd == sm->plain_sock ||
            reg.polled[i].fd == sm->secure_sock) {

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

            Socket *s = sm->sockets;
            while (s->state != SOCKET_STATE_FREE) {
                s++;
                assert(s - sm->sockets < + sm->max_used);
            }

            NATIVE_SOCKET sock = accept(reg.polled[i].fd, NULL, NULL);
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
#ifdef HTTPS_ENABLED
            // Determine whether the event came from
            // the encrypted listener or not.
            bool secure = (reg.polled[i].fd == sm->secure_sock);

            s->ssl = NULL;
            s->server_secure_context = NULL;
            s->client_secure_context = NULL;
            if (secure)
                s->server_secure_context = &sm->server_secure_context;
#endif

            socket_update(s);
            if (s->state == SOCKET_STATE_DIED) {
                CLOSE_NATIVE_SOCKET(sock);
                UPDATE_STATE(s->state, SOCKET_STATE_FREE);
                s->gen++;
                if (s->gen == 0)
                    s->gen = 1;
                continue;
            }

            sm->num_used++;

        } else if (reg.polled[i].fd == sm->wait_sock) {

            // Consume one byte from the wakeup signal
            char byte;
#ifdef _WIN32
            recv(sm->wait_sock, &byte, 1, 0);
#else
            read(sm->wait_sock, &byte, 1);
#endif

        } else {
            Socket *s = reg.ptrs[i];
            socket_update(s);
        }
    }

    for (int i = 0, j = 0; j < sm->num_used; i++) {
        Socket *s = &sm->sockets[i];
        if (s->state == SOCKET_STATE_FREE)
            continue;
        j++;

        if (s->state == SOCKET_STATE_DIED) {

            events[num_events++] = (SocketEvent) {
                SOCKET_EVENT_DISCONNECT,
                SOCKET_HANDLE_INVALID,
                s->user
            };

            // Free resources associated to socket
            UPDATE_STATE(s->state, SOCKET_STATE_FREE);
            if (s->sock != NATIVE_SOCKET_INVALID)
                CLOSE_NATIVE_SOCKET(s->sock);
            if (s->sock == SOCKET_STATE_PENDING ||
                s->sock == SOCKET_STATE_CONNECTING) {
                if (s->num_addr > 1)
                    free(s->addrs);
            }
            sm->num_used--;

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

static int resolve_connect_targets(ConnectTarget *targets,
    int num_targets, AddressAndPort *resolved, int max_resolved)
{
    int num_resolved = 0;
    for (int i = 0; i < num_targets; i++) {
        switch (targets[i].type) {
        case CONNECT_TARGET_NAME:
            {
                char portstr[16];
                int len = snprintf(portstr, sizeof(portstr), "%u", targets[i].port);
                assert(len > 1 && len < (int) sizeof(portstr));

                struct addrinfo hints = {0};
                hints.ai_family = AF_UNSPEC;
                hints.ai_socktype = SOCK_STREAM;

#ifdef HTTPS_ENABLED
                RegisteredName *name = malloc(sizeof(RegisteredName) + targets[i].name.len + 1);
                if (name == NULL) {
                    free_addr_list(resolved, num_resolved);
                    return HTTP_ERROR_OOM;
                }
                name->refs = 0;
                memcpy(name->data, targets[i].name.ptr, targets[i].name.len);
                name->data[targets[i].name.len] = '\0';
                char *hostname = name->data;
#else
                // 512 bytes is more than enough for a DNS hostname (max 253 chars)
                char hostname[1<<9];
                if (targets[i].name.len >= (int) sizeof(hostname))
                    return HTTP_ERROR_OOM;
                memcpy(hostname, targets[i].name.ptr, targets[i].name.len);
                hostname[targets[i].name.len] = '\0';
#endif
                struct addrinfo *res = NULL;
                int ret = getaddrinfo(hostname, portstr, &hints, &res);
                if (ret != 0) {
#ifdef HTTPS_ENABLED
                    // Free the name allocated for this target
                    free(name);
#endif
                    free_addr_list(resolved, num_resolved);
                    return HTTP_ERROR_UNSPECIFIED;
                }

                for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
                    if (rp->ai_family == AF_INET) {
                        HTTP_IPv4 ipv4 = *(HTTP_IPv4*) &((struct sockaddr_in*)rp->ai_addr)->sin_addr;
                        if (num_resolved < max_resolved) {
                            resolved[num_resolved].is_ipv4 = true;
                            resolved[num_resolved].ipv4 = ipv4;
                            resolved[num_resolved].port = targets[i].port;
#ifdef HTTPS_ENABLED
                            resolved[num_resolved].name = name;
                            name->refs++;
#endif
                            num_resolved++;
                        }
                    } else if (rp->ai_family == AF_INET6) {
                        HTTP_IPv6 ipv6 = *(HTTP_IPv6*) &((struct sockaddr_in6*)rp->ai_addr)->sin6_addr;
                        if (num_resolved < max_resolved) {
                            resolved[num_resolved].is_ipv4 = false;
                            resolved[num_resolved].ipv6 = ipv6;
                            resolved[num_resolved].port = targets[i].port;
#ifdef HTTPS_ENABLED
                            resolved[num_resolved].name = name;
                            name->refs++;
#endif
                            num_resolved++;
                        }
                    }
                }

#ifdef HTTPS_ENABLED
                if (name->refs == 0)
                    free(name);
#endif

                freeaddrinfo(res);
            }
            break;
        case CONNECT_TARGET_IPV4:
            if (num_resolved < max_resolved) {
                resolved[num_resolved].is_ipv4 = true;
                resolved[num_resolved].ipv4 = targets[i].ipv4;
                resolved[num_resolved].port = targets[i].port;
#ifdef HTTPS_ENABLED
                resolved[num_resolved].name = NULL;
#endif
                num_resolved++;
            }
            break;
        case CONNECT_TARGET_IPV6:
            if (num_resolved < max_resolved) {
                resolved[num_resolved].is_ipv4 = false;
                resolved[num_resolved].ipv6 = targets[i].ipv6;
                resolved[num_resolved].port = targets[i].port;
#ifdef HTTPS_ENABLED
                resolved[num_resolved].name = NULL;
#endif
                num_resolved++;
            }
            break;
        }
    }
    return num_resolved;
}

#define MAX_CONNECT_TARGETS 16

int socket_connect(SocketManager *sm, int num_targets,
    ConnectTarget *targets, bool secure, bool dont_verify_cert,
    void *user)
{
    if (sm->num_used == sm->max_used)
        return HTTP_ERROR_UNSPECIFIED;

#ifdef HTTPS_ENABLED
    if (!sm->at_least_one_secure_connect) {
        if (client_secure_context_init(&sm->client_secure_context) < 0)
            return HTTP_ERROR_UNSPECIFIED;
        sm->at_least_one_secure_connect = true;
    }
#else
    if (secure)
        return HTTP_ERROR_NOTLS;
#endif

    AddressAndPort resolved[MAX_CONNECT_TARGETS];
    int num_resolved = resolve_connect_targets(
        targets, num_targets, resolved, MAX_CONNECT_TARGETS);

    if (num_resolved <= 0)
        return HTTP_ERROR_UNSPECIFIED;

    Socket *s = sm->sockets;
    while (s->state != SOCKET_STATE_FREE) {
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
            return HTTP_ERROR_OOM;
        for (int i = 0; i < num_resolved; i++)
            s->addrs[i] = resolved[i];
    }

    UPDATE_STATE(s->state, SOCKET_STATE_PENDING);
    s->sock = NATIVE_SOCKET_INVALID;
    s->user = user;
#ifdef HTTPS_ENABLED
    s->server_secure_context = NULL;
    s->client_secure_context = NULL;
    s->ssl = NULL;
    s->dont_verify_cert = false;
    if (secure) {
        s->client_secure_context = &sm->client_secure_context;
        s->dont_verify_cert = dont_verify_cert;
    }
#else
    (void) dont_verify_cert;
#endif
    sm->num_used++;

    socket_update(s);
    return HTTP_OK;
}

static bool would_block(void)
{
#ifdef _WIN32
    int err = WSAGetLastError();
    return err == WSAEWOULDBLOCK;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK;
#endif
}

static bool interrupted(void)
{
#ifdef _WIN32
    return false;
#else
    return errno == EINTR;
#endif
}

int socket_recv(SocketManager *sm, SocketHandle handle,
    char *dst, int max)
{
    Socket *s = handle_to_socket(sm, handle);
    if (s == NULL)
        return 0;

    if (s->state != SOCKET_STATE_ESTABLISHED_READY) {
        UPDATE_STATE(s->state, SOCKET_STATE_DIED);
        s->events = 0;
        return 0;
    }

    if (!is_secure(s)) {
        int ret = recv(s->sock, dst, max, 0);
        if (ret == 0) {
            UPDATE_STATE(s->state, SOCKET_STATE_DIED);
            s->events = 0;
        } else if (ret < 0) {
            if (would_block()) {
                UPDATE_STATE(s->state, SOCKET_STATE_ESTABLISHED_WAIT);
                s->events = POLLIN;
            } else if (!interrupted()) {
                UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                s->events = 0;
            }
            ret = 0;
        }
        return ret;
    } else {
#ifdef HTTPS_ENABLED
        int ret = SSL_read(s->ssl, dst, max);
        if (ret <= 0) {
            int err = SSL_get_error(s->ssl, ret);
            if (err == SSL_ERROR_WANT_READ) {
                s->state  = SOCKET_STATE_ESTABLISHED_WAIT;
                s->events = POLLIN;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                UPDATE_STATE(s->state, SOCKET_STATE_ESTABLISHED_WAIT);
                s->events = POLLOUT;
            } else {
                s->state  = SOCKET_STATE_DIED;
                s->events = 0;
            }
            ret = 0;
        }
        return ret;
#else
        // Unreachable
        return 0;
#endif
    }
}

int socket_send(SocketManager *sm, SocketHandle handle,
    char *src, int len)
{
    Socket *s = handle_to_socket(sm, handle);
    if (s == NULL)
        return 0;

    if (s->state != SOCKET_STATE_ESTABLISHED_READY) {
        UPDATE_STATE(s->state, SOCKET_STATE_DIED);
        s->events = 0;
        return 0;
    }

    if (!is_secure(s)) {
        int ret = send(s->sock, src, len, 0);
        if (ret < 0) {
            if (would_block()) {
                UPDATE_STATE(s->state, SOCKET_STATE_ESTABLISHED_WAIT);
                s->events = POLLOUT;
            } else if (!interrupted()) {
                UPDATE_STATE(s->state, SOCKET_STATE_DIED);
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
#else
        // Unreachable
        return 0;
#endif
    }
}

void socket_close(SocketManager *sm, SocketHandle handle)
{
    Socket *s = handle_to_socket(sm, handle);
    if (s == NULL)
        return;

    if (s->state != SOCKET_STATE_DIED) {
        UPDATE_STATE(s->state, SOCKET_STATE_SHUTDOWN);
        s->events = 0;
        socket_update(s);
    }
}

bool socket_is_secure(SocketManager *sm, SocketHandle handle)
{
    Socket *s = handle_to_socket(sm, handle);
    if (s == NULL)
        return false;
    return is_secure(s);
}

void socket_set_user(SocketManager *sm, SocketHandle handle, void *user)
{
    Socket *s = handle_to_socket(sm, handle);
    if (s == NULL)
        return;

    s->user = user;
}

bool socket_ready(SocketManager *sm, SocketHandle handle)
{
    Socket *s = handle_to_socket(sm, handle);
    if (s == NULL)
       return false;

   if (s->events == 0 && s->state != SOCKET_STATE_DIED)
        return true;

    return false;
}
