#include <assert.h>
#include <stdlib.h>

#ifdef __linux__
#include <errno.h>
#include <sys/socket.h>
#endif

#ifndef HTTP_AMALGAMATION
#include "socket_pool.h"
#endif

#define SOCKET_HARD_LIMIT (1<<10)
#define MAX_CERTS 10

struct SocketPool {

    SecureContext sec;

    RAW_SOCKET listen_sock;
    RAW_SOCKET secure_sock;

    int num_socks;
    int max_socks;
    Socket socks[];
};

int socket_pool_global_init(void)
{
    int ret = socket_raw_global_init();
    if (ret < 0)
        return -1;

    secure_context_global_init();
    return 0;
}

void socket_pool_global_free(void)
{
    secure_context_global_free();
    socket_raw_global_free();
}

SocketPool *socket_pool_init(HTTP_String addr,
    uint16_t port, uint16_t secure_port, int max_socks,
    bool reuse_addr, int backlog, HTTP_String cert_file,
    HTTP_String key_file)
{
    if (max_socks > SOCKET_HARD_LIMIT)
        return NULL;

    SocketPool *pool = malloc(sizeof(SocketPool) + max_socks * sizeof(Socket));
    if (pool == NULL)
        return NULL;

    pool->num_socks = 0;
    pool->max_socks = max_socks;

    for (int i = 0; i < pool->max_socks; i++)
        pool->socks[i].state = SOCKET_STATE_FREE;

    if (port == 0)
        pool->listen_sock = BAD_SOCKET;
    else {
        pool->listen_sock = listen_socket(addr, port, reuse_addr, backlog);
        if (pool->listen_sock == BAD_SOCKET) {
            free(pool);
            return NULL;
        }
    }

    if (secure_port == 0)
        pool->secure_sock = BAD_SOCKET;
    else {
#ifndef HTTPS_ENABLED
        (void) cert_file;
        (void) key_file;
        if (pool->listen_sock != BAD_SOCKET)
            CLOSE_SOCKET(pool->listen_sock);
        free(pool);
        return NULL;
#else
        if (secure_context_init_as_server(&pool->sec, cert_file, key_file) < 0) {
            if (pool->listen_sock != BAD_SOCKET)
                CLOSE_SOCKET(pool->listen_sock);
            free(pool);
            return NULL;
        }

        pool->secure_sock = listen_socket(addr, secure_port, reuse_addr, backlog);
        if (pool->secure_sock == BAD_SOCKET) {
            if (pool->listen_sock != BAD_SOCKET) CLOSE_SOCKET(pool->listen_sock);
            free(pool);
            return NULL;
        }
#endif
    }

#ifdef HTTPS_ENABLED
    if (port == 0 && secure_port == 0) {
        if (secure_context_init_as_client(&pool->sec) < 0) {
            if (pool->listen_sock != BAD_SOCKET) CLOSE_SOCKET(pool->listen_sock);
            if (pool->secure_sock != BAD_SOCKET) CLOSE_SOCKET(pool->secure_sock);
            free(pool);
            return NULL;
        }
    }
#endif

    for (int i = 0; i < max_socks; i++)
        pool->socks[i].state = SOCKET_STATE_FREE;

    return pool;
}

void socket_pool_free(SocketPool *pool)
{
    for (int i = 0, j = 0; j < pool->num_socks; i++) {

        Socket *sock = &pool->socks[i];

        if (sock->state == SOCKET_STATE_FREE)
            continue;
        j++;

        socket_free(sock);
    }

    secure_context_free(&pool->sec);

    if (pool->secure_sock != BAD_SOCKET) CLOSE_SOCKET(pool->secure_sock);
    if (pool->listen_sock != BAD_SOCKET) CLOSE_SOCKET(pool->listen_sock);
}

int socket_pool_add_cert(SocketPool *pool, HTTP_String domain, HTTP_String cert_file, HTTP_String key_file)
{
    return secure_context_add_cert(&pool->sec, domain, cert_file, key_file);
}

void socket_pool_set_user_data(SocketPool *pool, SocketHandle handle, void *user_data)
{
    Socket *sock = &pool->socks[handle];
    socket_set_user_data(sock, user_data);
}

void socket_pool_close(SocketPool *pool, SocketHandle handle)
{
    Socket *sock = &pool->socks[handle];
    socket_close(sock);
}

static Socket *find_free_socket(SocketPool *pool)
{
    if (pool->num_socks == pool->max_socks)
        return NULL;

    int i = 0;
    while (pool->socks[i].state != SOCKET_STATE_FREE)
        i++;

    return &pool->socks[i];
}

int socket_pool_connect(SocketPool *pool, bool secure,
    HTTP_String addr, uint16_t port, void *user_data)
{
    Socket *sock = find_free_socket(pool);
    if (sock == NULL)
        return -1;

    socket_connect(sock, secure ? &pool->sec : NULL, addr, port, user_data);

    if (socket_died(sock)) {
        socket_free(sock);
        return -1;
    }

    pool->num_socks++;
    return 0;
}

int socket_pool_connect_ipv4(SocketPool *pool, bool secure,
    HTTP_IPv4 addr, uint16_t port, void *user_data)
{
    Socket *sock = find_free_socket(pool);
    if (sock == NULL)
        return -1;

    socket_connect_ipv4(sock, secure ? &pool->sec : NULL, addr, port, user_data);

    if (socket_died(sock)) {
        socket_free(sock);
        return -1;
    }

    pool->num_socks++;
    return 0;
}

int socket_pool_connect_ipv6(SocketPool *pool, bool secure,
    HTTP_IPv6 addr, uint16_t port, void *user_data)
{
    Socket *sock = find_free_socket(pool);
    if (sock == NULL)
        return -1;

    socket_connect_ipv6(sock, secure ? &pool->sec : NULL, addr, port, user_data);

    if (socket_died(sock)) {
        socket_free(sock);
        return -1;
    }

    pool->num_socks++;
    return 0;
}

#include <stdio.h> // TODO: remove

SocketEvent socket_pool_wait(SocketPool *pool)
{
    for (;;) {

        // First, iterate over all sockets to find one that
        // died or is ready.

        for (int i = 0, j = 0; j < pool->num_socks; i++) {

            Socket *sock = &pool->socks[i];

            if (sock->state == SOCKET_STATE_FREE)
                continue;
            j++;

            if (socket_died(sock)) {
                void *user_data = socket_get_user_data(sock);
                socket_free(sock);
                pool->num_socks--;
                return (SocketEvent) { SOCKET_EVENT_DIED, -1, user_data };
            }

            if (socket_ready(sock))
                return (SocketEvent) { SOCKET_EVENT_READY, i, socket_get_user_data(sock) };

            assert(sock->events);
        }

        // If we reached this point, we either have no sockets
        // or all sockets need to wait for some event. Waiting
        // when no sockets are available is only allowed when
        // the pool is in server mode.

        int indices[SOCKET_HARD_LIMIT+2];
        struct pollfd polled[SOCKET_HARD_LIMIT+2];
        int num_polled = 0;

        if (pool->num_socks < pool->max_socks) {

            if (pool->listen_sock != BAD_SOCKET) {
                indices[num_polled] = -1;
                polled[num_polled].fd = pool->listen_sock;
                polled[num_polled].events = POLLIN;
                polled[num_polled].revents = 0;
                num_polled++;
            }

            if (pool->secure_sock != BAD_SOCKET) {
                indices[num_polled] = -1;
                polled[num_polled].fd = pool->secure_sock;
                polled[num_polled].events = POLLIN;
                polled[num_polled].revents = 0;
                num_polled++;
            }
        }

        for (int i = 0, j = 0; j < pool->num_socks; i++) {

            Socket *sock = &pool->socks[i];

            if (sock->state == SOCKET_STATE_FREE)
                continue;
            j++;

            indices[num_polled] = i;
            polled[num_polled].fd = sock->raw;
            polled[num_polled].events = sock->events;
            polled[num_polled].revents = 0;
            num_polled++;
        }

        if (num_polled == 0)
            return (SocketEvent) { SOCKET_EVENT_ERROR, -1, NULL };

        int ret = POLL(polled, num_polled, -1);
        if (ret < 0) {

            if (errno == EINTR)
                return (SocketEvent) { SOCKET_EVENT_SIGNAL, -1, NULL };

            return (SocketEvent) { SOCKET_EVENT_ERROR, -1, NULL };
        }

        for (int i = 0; i < num_polled; i++) {

            Socket *sock;
            
            if (polled[i].fd == pool->listen_sock || polled[i].fd == pool->secure_sock) {

                bool secure = false;
                if (polled[i].fd == pool->secure_sock)
                    secure = true;

                Socket *sock = find_free_socket(pool);
                if (sock == NULL)
                    continue;

                RAW_SOCKET raw = accept(polled[i].fd, NULL, NULL);
                if (raw == BAD_SOCKET)
                    continue;

                socket_accept(sock, secure ? &pool->sec : NULL, raw);

                if (socket_died(sock)) {
                    socket_free(sock);
                    continue;
                }

                pool->num_socks++;

            } else {
                int j = indices[i];
                sock = &pool->socks[j];

                if (polled[i].revents)
                    socket_update(sock);
            }
        }
    }

    // This branch is unreachable
    return (SocketEvent) { SOCKET_EVENT_ERROR, -1, NULL };
}

int socket_pool_read(SocketPool *pool, SocketHandle handle, char *dst, int len)
{
    return socket_read(&pool->socks[handle], dst, len);
}

int socket_pool_write(SocketPool *pool, SocketHandle handle, char *src, int len)
{
    return socket_write(&pool->socks[handle], src, len);
}

bool socket_pool_secure(SocketPool *pool, SocketHandle handle)
{
    return socket_secure(&pool->socks[handle]);
}