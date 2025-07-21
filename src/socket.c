#include <stdio.h> // snprintf
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <ws2tcpip.h>
#endif

#ifdef __linux__
#include <netdb.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#ifdef HTTPS_ENABLED
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#ifndef HTTP_AMALGAMATION
#include "basic.h"
#include "socket.h"
#endif

typedef struct {
    bool is_ipv4;
    union {
        HTTP_IPv4 ipv4;
        HTTP_IPv6 ipv6;
    };
} PendingConnectAddr;

struct PendingConnect {
    uint16_t port;
    int      cursor;
    int      num_addrs;
    int      max_addrs;
    PendingConnectAddr *addrs;
    char*    hostname; // null-terminated
    int      hostname_len;
};

static PendingConnect*
pending_connect_init(HTTP_String hostname, uint16_t port, int max_addrs)
{
    PendingConnect *pending_connect = malloc(sizeof(PendingConnect) + max_addrs * sizeof(PendingConnectAddr) + hostname.len + 1);
    if (pending_connect == NULL)
        return NULL;
    pending_connect->port = port;
    pending_connect->cursor = 0;
    pending_connect->num_addrs = 0;
    pending_connect->max_addrs = max_addrs;
    pending_connect->addrs = (PendingConnectAddr*) (pending_connect + 1);
    pending_connect->hostname = (char*) (pending_connect->addrs + max_addrs);
    memcpy(pending_connect->hostname, hostname.ptr, hostname.len);
    pending_connect->hostname[hostname.len] = '\0';
    pending_connect->hostname_len = hostname.len;
    return pending_connect;
}

static void
pending_connect_free(PendingConnect *pending_connect)
{
    free(pending_connect);
}

static void
pending_connect_add_ipv4(PendingConnect *pending_connect, HTTP_IPv4 ipv4)
{
    if (pending_connect->num_addrs == pending_connect->max_addrs)
        return;
    pending_connect->addrs[pending_connect->num_addrs++] = (PendingConnectAddr) { .is_ipv4=true, .ipv4=ipv4 };
}

static void
pending_connect_add_ipv6(PendingConnect *pending_connect, HTTP_IPv6 ipv6)
{
    if (pending_connect->num_addrs == pending_connect->max_addrs)
        return;
    pending_connect->addrs[pending_connect->num_addrs++] = (PendingConnectAddr) { .is_ipv4=false, .ipv6=ipv6 };
}

static int
next_connect_addr(PendingConnect *pending_connect, PendingConnectAddr *addr)
{
    if (pending_connect->cursor == pending_connect->num_addrs)
        return -1;
    *addr = pending_connect->addrs[pending_connect->cursor++];
    return 0;
}

// Initializes a FREE socket with the information required to
// connect to specified host name. The resulting socket state
// is DIED if an error occurred or PENDING.
void socket_connect(Socket *sock, SecureContext *sec,
    HTTP_String hostname, uint16_t port, void *user_data)
{
    PendingConnect *pending_connect;

    int max_addrs = 30;
    pending_connect = pending_connect_init(hostname, port, max_addrs);
    if (pending_connect == NULL) {
        sock->state = SOCKET_STATE_DIED;
        sock->events = 0;
        return;
    }

    char portstr[16];
    int len = snprintf(portstr, sizeof(portstr), "%u", port);
    if (len < 0 || len >= (int) sizeof(portstr)) {
        pending_connect_free(pending_connect);
        sock->state = SOCKET_STATE_DIED;
        sock->events = 0;
        return;
    }

    // DNS query
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int ret = getaddrinfo(pending_connect->hostname, portstr, &hints, &res);
    if (ret != 0) {
        printf("ret=%d\n", ret); // TODO: remove
        pending_connect_free(pending_connect);
        sock->state = SOCKET_STATE_DIED;
        sock->events = 0;
        return;
    }

    for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET) {
            HTTP_IPv4 *ipv4 = (void*) &((struct sockaddr_in*)rp->ai_addr)->sin_addr;
            pending_connect_add_ipv4(pending_connect, *ipv4);
        } else if (rp->ai_family == AF_INET6) {
            HTTP_IPv6 *ipv6 = (void*) &((struct sockaddr_in6*)rp->ai_addr)->sin6_addr;
            pending_connect_add_ipv6(pending_connect, *ipv6);
        }
    }

    freeaddrinfo(res);

    sock->state = SOCKET_STATE_PENDING;
    sock->events = 0;

    sock->raw = BAD_SOCKET;
    sock->user_data = user_data;
    sock->pending_connect = pending_connect;
    sock->sec = sec;

#ifdef HTTPS_ENABLED
    sock->ssl = NULL;
#endif

    socket_update(sock);
}

// Just like socket_connect, but the raw IPv4 address is specified
void socket_connect_ipv4(Socket *sock, SecureContext *sec,
    HTTP_IPv4 addr, uint16_t port, void *user_data)
{
    PendingConnect *pending_connect;
    
    pending_connect = pending_connect_init(HTTP_STR(""), port, 1);
    if (pending_connect == NULL) {
        sock->state = SOCKET_STATE_DIED;
        sock->events = 0;
        return;
    }

    pending_connect_add_ipv4(pending_connect, addr);

    sock->state = SOCKET_STATE_PENDING;
    sock->events = 0;

    sock->raw = BAD_SOCKET;
    sock->user_data = user_data;
    sock->pending_connect = pending_connect;
    sock->sec = sec;

#ifdef HTTPS_ENABLED
    sock->ssl = NULL;
#endif

    socket_update(sock);
}

// Just like socket_connect, but the raw IPv6 address is specified
void socket_connect_ipv6(Socket *sock, SecureContext *sec,
    HTTP_IPv6 addr, uint16_t port, void *user_data)
{
    PendingConnect *pending_connect;
    
    pending_connect = pending_connect_init(HTTP_STR(""), port, 1);
    if (pending_connect == NULL) {
        sock->state = SOCKET_STATE_DIED;
        sock->events = 0;
        return;
    }

    pending_connect_add_ipv6(pending_connect, addr);

    sock->state = SOCKET_STATE_PENDING;
    sock->events = 0;

    sock->raw = BAD_SOCKET;
    sock->user_data = user_data;
    sock->pending_connect = pending_connect;
    sock->sec = sec;

#ifdef HTTPS_ENABLED
    sock->ssl = NULL;
#endif

    socket_update(sock);
}

void socket_accept(Socket *sock, SecureContext *sec, RAW_SOCKET raw)
{
    sock->state = SOCKET_STATE_ACCEPTED;
    sock->raw = raw;
    sock->events = 0;
    sock->user_data = NULL;
    sock->pending_connect = NULL;
    sock->sec = sec;

#ifdef HTTPS_ENABLED
    sock->ssl = NULL;
#endif

    if (set_socket_blocking(raw, false) < 0) {
        sock->state  = SOCKET_STATE_DIED;
        sock->events = 0;
        return;
    }

    socket_update(sock);
}

void socket_close(Socket *sock)
{
    // TODO: maybe we don't want to always set to SHUTDOWN. What if the socket is DIED for instance?
    sock->state  = SOCKET_STATE_SHUTDOWN;
    sock->events = 0;
    socket_update(sock);
}

bool socket_ready(Socket *sock)
{
    return sock->state == SOCKET_STATE_ESTABLISHED_READY;
}

bool socket_died(Socket *sock)
{
    return sock->state == SOCKET_STATE_DIED;
}

// TODO: when is the pending_connect data freed?

static bool connect_pending(void)
{
#ifdef _WIN32
    return WSAGetLastError() == WSAEWOULDBLOCK;
#else
    return errno == EINPROGRESS;
#endif
}

static bool
connect_failed_because_or_peer_2(int err)
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
connect_failed_because_or_peer(void)
{
#ifdef _WIN32
    int err = WSAGetLastError();
#else
    int err = errno;
#endif
    return connect_failed_because_or_peer_2(err);
}

// Processes the socket until it's either ready, died, or would block
void socket_update(Socket *sock)
{
    sock->events = 0;

    bool again;
    do {

        again = false;

        switch (sock->state) {
        case SOCKET_STATE_PENDING:
        {
            // In this state we need to pop an address from the pending connect
            // data and try connect to it. This state is reached when a socket
            // is initialized using one of the socket_connect functions or by
            // failing to connect before the established state is reached.

            // If this isn't the first connection attempt we may have old
            // descriptors that need freeing before trying again.
            {
#ifdef HTTPS_ENABLED
                if (sock->ssl) {
                    SSL_free(sock->ssl);
                    sock->ssl = NULL;
                }
#endif
                if (sock->raw != BAD_SOCKET)
                    CLOSE_SOCKET(sock->raw);
            }

            // Pop the next address from the pending connect data
            PendingConnectAddr addr;
            if (next_connect_addr(sock->pending_connect, &addr) < 0) {
                sock->state  = SOCKET_STATE_DIED;
                sock->events = 0;
                break;
            }
            uint16_t port = sock->pending_connect->port;

            // Create a kernel socket object
            int family = addr.is_ipv4 ? AF_INET : AF_INET6;
            RAW_SOCKET raw = socket(family, SOCK_STREAM, 0);
            if (raw == BAD_SOCKET) {
                sock->state  = SOCKET_STATE_PENDING;
                sock->events = 0;
                again = true;
                break;
            }

            // Configure it
            if (set_socket_blocking(raw, false) < 0) {
                CLOSE_SOCKET(raw);
                sock->state  = SOCKET_STATE_DIED;
                sock->events = 0;
                break;
            }

            // Now perform the connect

            struct sockaddr_in  connect_buf_4;
            struct sockaddr_in6 connect_buf_6;
            struct sockaddr*    connect_buf;
            int    connect_buf_len;

            if (addr.is_ipv4) {

                connect_buf = (struct sockaddr*) &connect_buf_4;
                connect_buf_len = sizeof(connect_buf_4);

                connect_buf_4.sin_family = AF_INET;
                connect_buf_4.sin_port = htons(port);
                memcpy(&connect_buf_4.sin_addr, &addr.ipv4, sizeof(HTTP_IPv4));

            } else {

                connect_buf = (struct sockaddr*) &connect_buf_6;
                connect_buf_len = sizeof(connect_buf_6);

                connect_buf_6.sin6_family = AF_INET6;
                connect_buf_6.sin6_port = htons(port);
                memcpy(&connect_buf_6.sin6_addr, &addr.ipv6, sizeof(HTTP_IPv6));
            }

            int ret = connect(raw, connect_buf, connect_buf_len);

            // We divide the connect() results in four categories:
            //
            //   1) The connect resolved immediately. I'm not sure how this can happen,
            //      but we may as well handle it. This allows us to skip a step.
            //
            //   2) The connect operation is pending. This is what we expect most of the time.
            //
            //   3) The connect operation failed because the target address wasn't good
            //      for some reason. It make sense to try connecting to a different address
            //
            //   4) The connect operation failed for unknown reasons. There isn't much we
            //      can do at this point.

            if (ret == 0) {
                // Connected immediately
                sock->raw    = raw;
                sock->state  = SOCKET_STATE_CONNECTED;
                sock->events = 0;
                again = true;
                break;
            }

            if (connect_pending()) { // TODO: I'm pretty sure all the error numbers need to be changed for windows
                // Connection pending
                sock->raw = raw;
                sock->state = SOCKET_STATE_CONNECTING;
                sock->events = POLLOUT;
                break;
            }

            // Connect failed

            // If remote peer not working, try next address
            if (connect_failed_because_or_peer()) {
                sock->state = SOCKET_STATE_PENDING;
                sock->events = 0;
                again = true;
            } else {
                sock->state = SOCKET_STATE_DIED;
                sock->events = 0;
            }
        }
        break;

        case SOCKET_STATE_CONNECTING:
        {
            // We reach this point when a connect() operation on the
            // socket started and then the descriptor was marked as
            // ready for output. This means the operation is complete.

            int err = 0;
            socklen_t len = sizeof(err);

            if (getsockopt(sock->raw, SOL_SOCKET, SO_ERROR, (void*) &err, &len) < 0 || err != 0) {

                // If remote peer not working, try next address
                if (connect_failed_because_or_peer_2(err)) {
                    sock->state = SOCKET_STATE_PENDING;
                    sock->events = 0;
                    again = true;
                    break;
                }

                sock->state = SOCKET_STATE_DIED;
                sock->events = 0;
                break;
            }

            // Connect succeeded
            sock->state = SOCKET_STATE_CONNECTED;
            sock->events = 0;
            again = true;
        }
        break;

        case SOCKET_STATE_CONNECTED:
        {
            if (!socket_secure(sock)) {

                pending_connect_free(sock->pending_connect);
                sock->pending_connect = NULL;

                sock->events = 0;
                sock->state = SOCKET_STATE_ESTABLISHED_READY;

            } else {
#ifdef HTTPS_ENABLED
                // Start SSL handshake

                if (!sock->ssl) {
                    sock->ssl = SSL_new(sock->sec->ctx);
                    if (sock->ssl == NULL) {
                        sock->state  = SOCKET_STATE_DIED;
                        sock->events = 0;
                        break;
                    }

                    if (SSL_set_fd(sock->ssl, sock->raw) != 1) {
                        sock->state  = SOCKET_STATE_DIED;
                        sock->events = 0;
                        break;
                    }

                    char *hostname = NULL;
                    if (sock->pending_connect->hostname[0])
                        hostname = sock->pending_connect->hostname;

                    if (hostname)
                        SSL_set_tlsext_host_name(sock->ssl, hostname);
                }

                int ret = SSL_connect(sock->ssl);
                if (ret == 1) {
                    // Handshake done

                    pending_connect_free(sock->pending_connect);
                    sock->pending_connect = NULL;

                    sock->state  = SOCKET_STATE_ESTABLISHED_READY;
                    sock->events = 0;
                    break;
                }

                int err = SSL_get_error(sock->ssl, ret);
                if (err == SSL_ERROR_WANT_READ) {
                    sock->events = POLLIN;
                    break;
                }

                if (err == SSL_ERROR_WANT_WRITE) {
                    sock->events = POLLOUT;
                    break;
                }

                sock->state  = SOCKET_STATE_PENDING;
                sock->events = 0;
                again = true;
#else
                assert(0);
#endif
            }
        }
        break;

        case SOCKET_STATE_ACCEPTED:
        {
            if (!socket_secure(sock)) {
                sock->state  = SOCKET_STATE_ESTABLISHED_READY;
                sock->events = 0;
            } else {
#ifdef HTTPS_ENABLED
                // Start server-side SSL handshake
                if (!sock->ssl) {

                    sock->ssl = SSL_new(sock->sec->ctx);
                    if (sock->ssl == NULL) {
                        sock->state  = SOCKET_STATE_DIED;
                        sock->events = 0;
                        break;
                    }

                    if (SSL_set_fd(sock->ssl, sock->raw) != 1) {
                        sock->state  = SOCKET_STATE_DIED;
                        sock->events = 0;
                        break;
                    }
                }

                int ret = SSL_accept(sock->ssl);
                if (ret == 1) {
                    // Handshake done
                    sock->state = SOCKET_STATE_ESTABLISHED_READY;
                    sock->events = 0;
                    break;
                }

                int err = SSL_get_error(sock->ssl, ret);
                if (err == SSL_ERROR_WANT_READ) {
                    sock->events = POLLIN;
                    break;
                }

                if (err == SSL_ERROR_WANT_WRITE) {
                    sock->events = POLLOUT;
                    break;
                }

                // Server socket error - close the connection
                sock->state  = SOCKET_STATE_DIED;
                sock->events = 0;
#else
               assert(0);
#endif
            }
        }
        break;

        case SOCKET_STATE_ESTABLISHED_WAIT:
        {
            sock->state = SOCKET_STATE_ESTABLISHED_READY;
            sock->events = 0;
        }
        break;

        case SOCKET_STATE_SHUTDOWN:
        {
            if (!socket_secure(sock)) {
                sock->state = SOCKET_STATE_DIED;
                sock->events = 0;
            } else {
#ifdef HTTPS_ENABLED
                int ret = SSL_shutdown(sock->ssl);
                if (ret == 1) {
                    sock->state  = SOCKET_STATE_DIED;
                    sock->events = 0;
                    break;
                }

                int err = SSL_get_error(sock->ssl, ret);
                if (err == SSL_ERROR_WANT_READ) {
                    sock->events = POLLIN;
                    break;
                }
                
                if (err == SSL_ERROR_WANT_WRITE) {
                    sock->events = POLLOUT;
                    break;
                }

                sock->state  = SOCKET_STATE_DIED;
                sock->events = 0;
#else
                assert(0);
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

int socket_read(Socket *sock, char *dst, int max)
{
    // If not ESTABLISHED, set state to DIED and return
    if (sock->state != SOCKET_STATE_ESTABLISHED_READY) {
        sock->state = SOCKET_STATE_DIED;
        sock->events = 0;
        return 0;
    }

    if (!socket_secure(sock)) {
        int ret = recv(sock->raw, dst, max, 0);
        if (ret == 0) {
            sock->state  = SOCKET_STATE_DIED;
            sock->events = 0;
        } else {
            if (ret < 0) {
                if (would_block()) {
                    sock->state  = SOCKET_STATE_ESTABLISHED_WAIT;
                    sock->events = POLLIN;
                } else {
                    if (!interrupted()) {
                        sock->state  = SOCKET_STATE_DIED;
                        sock->events = 0;
                    }
                }
                ret = 0;
            }
        }
        return ret;
    } else {
#ifdef HTTPS_ENABLED
        int ret = SSL_read(sock->ssl, dst, max);
        if (ret <= 0) {
            int err = SSL_get_error(sock->ssl, ret);
            if (err == SSL_ERROR_WANT_READ) {
                sock->state  = SOCKET_STATE_ESTABLISHED_WAIT;
                sock->events = POLLIN;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                sock->state = SOCKET_STATE_ESTABLISHED_WAIT;
                sock->events = POLLOUT;
            } else {
                fprintf(stderr, "OpenSSL error in socket_read: ");
                ERR_print_errors_fp(stderr);
                sock->state  = SOCKET_STATE_DIED;
                sock->events = 0;
            }
            ret = 0;
        }
        return ret;
#else
        assert(0);
        return -1;
#endif
    }
}

int socket_write(Socket *sock, char *src, int len)
{
    // If not ESTABLISHED, set state to DIED and return
    if (sock->state != SOCKET_STATE_ESTABLISHED_READY) {
        sock->state  = SOCKET_STATE_DIED;
        sock->events = 0;
        return 0;
    }

    if (!socket_secure(sock)) {
        int ret = send(sock->raw, src, len, 0);
        if (ret < 0) {
            if (would_block()) {
                sock->state  = SOCKET_STATE_ESTABLISHED_WAIT;
                sock->events = POLLOUT;
            } else {
                if (!interrupted()) {
                    sock->state = SOCKET_STATE_DIED;
                    sock->events = 0;
                }
            }
            ret = 0;
        }
        return ret;
    } else {
#ifdef HTTPS_ENABLED
        int ret = SSL_write(sock->ssl, src, len);
        if (ret <= 0) {
            int err = SSL_get_error(sock->ssl, ret);
            if (err == SSL_ERROR_WANT_READ) {
                sock->state  = SOCKET_STATE_ESTABLISHED_WAIT;
                sock->events = POLLIN;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                sock->state  = SOCKET_STATE_ESTABLISHED_WAIT;
                sock->events = POLLOUT;
            } else {
                fprintf(stderr, "OpenSSL error in socket_write: ");
                ERR_print_errors_fp(stderr);
                sock->state  = SOCKET_STATE_DIED;
                sock->events = 0;
            }
            ret = 0;
        }
        return ret;
#else
        assert(0);
#endif
    }
}

bool socket_secure(Socket *sock)
{
#ifdef HTTPS_ENABLED
    return sock->sec != NULL;
#else
    (void) sock;
    return false;
#endif
}

void socket_free(Socket *sock)
{
    if (sock->pending_connect != NULL)
        pending_connect_free(sock->pending_connect);

    if (sock->raw != BAD_SOCKET)
        CLOSE_SOCKET(sock->raw);

#ifdef HTTPS_ENABLED
    if (sock->ssl)
        SSL_free(sock->ssl);
#endif

    sock->state = SOCKET_STATE_FREE;
}

void socket_set_user_data(Socket *sock, void *user_data)
{
    sock->user_data = user_data;
}

void *socket_get_user_data(Socket *sock)
{
    return sock->user_data;
}