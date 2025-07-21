#ifndef SOCKET_INCLUDED
#define SOCKET_INCLUDED

// This module implements the socket state machine to encapsulate
// the complexity of non-blocking TCP and TLS sockets.
//
// A socket is represented by the "Socket" structure, which may
// be in a number of states. As far as an user of the interface
// is concerned, the socket may be DIED, READY, or in an internal
// state that requires waiting for an event. Therefore, if the
// socket is not DIED or READY, the user needs to wait for the
// events specified in the [socket->events] field, then call the
// socket_update function. At some point the socket will become
// either READY or DIED.
//
// When the socket reaches the DIED state, the user must call
// socket_free.
//
// If the socket is ESTABLISHED_READY, the user may call socket_read,
// socket_write, or socket_close on it.

#ifndef HTTP_AMALGAMATION
#include "sec.h"
#include "parse.h"
#include "socket_raw.h"
#endif

typedef struct PendingConnect PendingConnect;

// These should only be relevant to socket.c
typedef enum {
    SOCKET_STATE_FREE,
    SOCKET_STATE_DIED,
    SOCKET_STATE_ESTABLISHED_WAIT,
    SOCKET_STATE_ESTABLISHED_READY,
    SOCKET_STATE_PENDING,
    SOCKET_STATE_ACCEPTED,
    SOCKET_STATE_CONNECTED,
    SOCKET_STATE_CONNECTING,
    SOCKET_STATE_SHUTDOWN,
} SocketState;

typedef struct {
    SocketState state;

    RAW_SOCKET raw;
    int events;

    void *user_data;
    PendingConnect *pending_connect;

#ifdef HTTPS_ENABLED
    SSL *ssl;
#endif

    SecureContext *sec;

} Socket;

void  socket_connect(Socket *sock, SecureContext *sec, HTTP_String hostname, uint16_t port, void *user_data);
void  socket_connect_ipv4(Socket *sock, SecureContext *sec, HTTP_IPv4 addr, uint16_t port, void *user_data);
void  socket_connect_ipv6(Socket *sock, SecureContext *sec, HTTP_IPv6 addr, uint16_t port, void *user_data);
void  socket_accept(Socket *sock, SecureContext *sec, RAW_SOCKET raw);
void  socket_update(Socket *sock);
void  socket_close(Socket *sock);
bool  socket_ready(Socket *sock);
bool  socket_died(Socket *sock);
int   socket_read(Socket *sock, char *dst, int max);
int   socket_write(Socket *sock, char *src, int len);
void  socket_free(Socket *sock);
bool  socket_secure(Socket *sock);
void  socket_set_user_data(Socket *sock, void *user_data);
void* socket_get_user_data(Socket *sock);

#endif // SOCKET_INCLUDED