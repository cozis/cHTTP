#ifndef SOCKET_INCLUDED
#define SOCKET_INCLUDED
// This is a socket abstraction module for non-blocking TCP and TLS sockets.
//
// Sockets may be in a number of states based on if they are plain TCP or TLS
// sockets. Users generally only care about when the connection is established
// or is terminated.
//
// Sockets can be created by connecting to a server using one of these:
//
//   socket_connect
//   socket_connect_ipv4
//   socket_connect_ipv6
//
// They allow connecting to a remote host by specifying its name, of IP address.
// Or by interning a socket accepted by a listening socket:
//
//   socket_accept
//
// after creation, the event field will hold one of the values:
//
//   SOCKET_WANT_READ
//   SOCKET_WANT_WRITE
//
// Which respectively mean that the socket object needs to read or write
// from the underlying socket, and to do so non-blockingly, the caller needs
// to wait for the socket being ready for that operation. This is one way
// to do it:
//
//   // Translate the socket event field to poll() flags
//   int events;
//   if (sock.event == SOCKET_WANT_READ)
//     events = POLLIN;
//   else if (sock.event == SOCKET_WANT_WRITE)
//     events = POLLOUT;
//
//   // block until the socket is ready
//   struct pollfd buf;
//   buf.fd = sock.fd;
//   buf.events = events;
//   buf.revents = 0;
//   poll(&buf, 1, -1);
//
// whenever a socket is ready, the user must call the socket_update
// function. Then, if the socket is in the SOCKET_STATE_ESTABLISHED_READY
// state, the user can call one of
//
//   socket_close
//   socket_read
//   socket_write
//
// At any point the socket could reach the SOCKET_STATE_DIED state,
// which means the user needs to call socket_free to free the socket
// as it's not unusable.

#include <stdint.h>

#ifdef HTTPS_ENABLED
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#endif

#ifndef HTTP_AMALGAMATION
#include "parse.h"
#endif

typedef struct {
    int is_ipv6;
    union {
        HTTP_IPv4 ipv4;
        HTTP_IPv6 ipv6;
    } addr;
} AddrInfo;

typedef enum {
    SOCKET_STATE_PENDING,
    SOCKET_STATE_CONNECTING,
    SOCKET_STATE_CONNECTED,
    SOCKET_STATE_ACCEPTED,
    SOCKET_STATE_ESTABLISHED_WAIT,
    SOCKET_STATE_ESTABLISHED_READY,
    SOCKET_STATE_SHUTDOWN,
    SOCKET_STATE_DIED
} SocketState;

typedef enum {
    SOCKET_WANT_NONE,
    SOCKET_WANT_READ,
    SOCKET_WANT_WRITE,
} SocketWantEvent;

typedef struct {
    SocketState state;
    SocketWantEvent event;
    int fd;
#if HTTPS_ENABLED
    SSL *ssl;
    SSL_CTX *ssl_ctx;
#endif
    AddrInfo *addr_list;
    int addr_count;
    int addr_cursor;
    char *hostname;
    uint16_t port;
} Socket;

#ifdef HTTPS_ENABLED
typedef struct {
    char name[128];
    SSL_CTX *ssl_ctx;
} Domain;
#endif

typedef struct {
#ifdef HTTPS_ENABLED
    SSL_CTX *ssl_ctx;
    int num_domains;
    int max_domains;
    Domain *domains;
#endif
} SocketGroup;

void        socket_global_init  (void);
void        socket_global_free  (void);
int         socket_group_init   (SocketGroup *group);
int         socket_group_init_server(SocketGroup *group, HTTP_String cert_file, HTTP_String key_file);
int         socket_group_add_domain(SocketGroup *group, HTTP_String domain, HTTP_String cert_key, HTTP_String private_key);
void        socket_group_free   (SocketGroup *group);
SocketState socket_state        (Socket *sock);
void        socket_accept       (Socket *sock, SocketGroup *group, int fd);
void        socket_connect      (Socket *sock, SocketGroup *group, HTTP_String host, uint16_t port);
void        socket_connect_ipv4 (Socket *sock, SocketGroup *group, HTTP_IPv4   addr, uint16_t port);
void        socket_connect_ipv6 (Socket *sock, SocketGroup *group, HTTP_IPv6   addr, uint16_t port);
void        socket_update       (Socket *sock);
int         socket_read         (Socket *sock, char *dst, int max);
int         socket_write        (Socket *sock, char *src, int len);
void        socket_close        (Socket *sock);
void        socket_free         (Socket *sock);
int         socket_wait         (Socket **socks, int num_socks);

#endif // SOCKET_INCLUDED