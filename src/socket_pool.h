#ifndef SOCKET_POOL_INCLUDED
#define SOCKET_POOL_INCLUDED

#ifndef HTTP_AMALGAMATION
#include "basic.h"
#include "socket.h"
#include "socket_raw.h"
#endif

typedef struct SocketPool SocketPool;

typedef int SocketHandle;

typedef enum {
    SOCKET_EVENT_DIED,
    SOCKET_EVENT_READY,
    SOCKET_EVENT_ERROR,
    SOCKET_EVENT_SIGNAL,
} SocketEventType;

typedef struct {
    SocketEventType type;
    SocketHandle handle;
    void *user_data;
} SocketEvent;

int  socket_pool_global_init(void);
void socket_pool_global_free(void);

SocketPool *socket_pool_init(HTTP_String addr,
    uint16_t port, uint16_t secure_port, int max_socks,
    bool reuse_addr, int backlog, HTTP_String cert_file,
    HTTP_String key_file);

void socket_pool_free(SocketPool *pool);

int socket_pool_add_cert(SocketPool *pool, char *domain, int domain_len, char *cert_file, int cert_file_len, char *key_file, int key_file_len);

SocketEvent socket_pool_wait(SocketPool *pool);

void socket_pool_set_user_data(SocketPool *pool, SocketHandle handle, void *user_data);

void socket_pool_close(SocketPool *pool, SocketHandle handle);

int socket_pool_connect(SocketPool *pool, bool secure,
    HTTP_String addr, uint16_t port, void *user_data);

int socket_pool_connect_ipv4(SocketPool *pool, bool secure,
    HTTP_IPv4 addr, uint16_t port, void *user_data);

int socket_pool_connect_ipv6(SocketPool *pool, bool secure,
    HTTP_IPv6 addr, uint16_t port, void *user_data);

int socket_pool_read(SocketPool *pool, SocketHandle handle, char *dst, int len);

int socket_pool_write(SocketPool *pool, SocketHandle handle, char *src, int len);

#endif // SOCKET_POOL_INCLUDED