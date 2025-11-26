// This file (and its relative .c file) implements an asynchronous TCP/TLS
// server and client abstraction.
//
// It introduces the concept of a "socket manager", which is a pool of
// connection sockets and a listener socket. The listener is managed
// internally, which means the manager automatically accepts sockets
// from it and adds them to the pool.
//
// If the listener is configured using the function:
//
//   socket_manager_listen_tcp
//
// the resulting connections will not use TLS. If instead the listener
// is configured using:
//
//   socket_manager_listen_tls
//
// the listener will use TLS. Note that both functions can be used on
// the same manager to allow both plaintext and encrypted connections.
// Users may enable zero listeners, in which case only outgoing
// connections are allowed (more on this later).
//
// Once the manager is set up, one can wait for events by following
// this pattern:
//
//   struct pollfd polled[...];
//   int num_polled = socket_manager_register_events(sm, polled, max_polled);
//   poll(polled, num_polled, -1);
//
//   #define MAX_EVENTS ...
//   SocketEvent events[MAX_EVENTS];
//   int num_events = socket_manager_translate_events(sm, events, MAX_EVENTS, polled, num_polled);
//   for (int i = 0; i < num_events; i++) {
//     ... Here call socket_recv, socket_send, socket_close, ...
//   }
//
// Note that from the user's perspective, there is no difference
// between connections that use plain TCP and those that use TCP/TLS.
//
// Users can also establish outgoing connections by calling the
// function:
//
//   socket_connect
//
// Which allows the creation of a connection towards an host given
// its domain, IPv4, IPv6, or an array of them. This can be done both
// for TCP and TCP/TLS connection. Note that users that only intend
// to establish outgoing connection may omit the configuration of
// listeners entirely.

#ifdef _WIN32
#define NATIVE_SOCKET         SOCKET
#define NATIVE_SOCKET_INVALID SOCKET_ERROR
#define CLOSE_NATIVE_SOCKET   closesocket
#else
#define NATIVE_SOCKET         int
#define NATIVE_SOCKET_INVALID -1
#define CLOSE_NATIVE_SOCKET   close
#endif

typedef uint32_t SocketHandle;
#define SOCKET_HANDLE_INVALID ((SocketHandle) 0)

typedef uint16_t Port;

typedef enum {
    SOCKET_EVENT_READY,
    SOCKET_EVENT_DISCONNECT,
} SocketEventType;

typedef struct {
    SocketEventType type;
    SocketHandle    handle;
    void*           user;
} SocketEvent;

// Internal use only
typedef enum {

    // The Socket struct is unused
    SOCKET_STATE_FREE,

    // The state associated to a socket created
    // by a connect operation that hasn't been
    // processed yet.
    SOCKET_STATE_PENDING,

    // A connect() operation was started but is
    // still pending.
    SOCKET_STATE_CONNECTING,

    // Outgoing connection was established, but
    // a TLS handshake may need to be performed.
    SOCKET_STATE_CONNECTED,

    // Incoming connection was established, but
    // a TLS handshake may need to be performed.
    SOCKET_STATE_ACCEPTED,

    // The connection was esablished, but the user
    // wants to perform a read or write operation that
    // would block.
    SOCKET_STATE_ESTABLISHED_WAIT,

    // The connection was established and it's possible
    // to perform read or write operations on it without
    // blocking.
    SOCKET_STATE_ESTABLISHED_READY,

    // The socket was marked to be closed.
    SOCKET_STATE_SHUTDOWN,

    // The current socket is was closed. The only
    // valid thing to do here is free its resources.
    SOCKET_STATE_DIED,
} SocketState;

typedef struct {
    int  refs;
    char data[];
} RegisteredName;

// Internal use only
typedef struct {
    union {
        HTTP_IPv4 ipv4;
        HTTP_IPv6 ipv6;
    };
    bool is_ipv4;
    Port port;

#ifdef HTTPS_ENABLED
    // When connecting to a peer using TLS, if the address
    // was resolved from a registered name, that name is
    // used to request the correct certificate once the TCP
    // handshake is established, and therefore need to
    // store it somewhere until that happens.
    RegisteredName *name;
#endif
} AddressAndPort;

// Internal use only
typedef struct {
    SocketState state;

    // OS-specific socket type
    NATIVE_SOCKET sock;

    // Native socket events that need to be monitored
    int events;

    // Generation counter to invalidate any SocketHandle
    // referring to this socket when it is freed.
    // Note that this counter may wrap but always skips
    // the 0 value to ensure the 0 SocketHandle is always
    // invalid.
    uint16_t gen;

    // User-provided context pointer
    void *user;

    // A single connect operation may involve
    // trying to establish a connection towards
    // one of a set of addresses.
    int num_addr;
    int next_addr;
    union {
        AddressAndPort addr; // When num_addr=1
        AddressAndPort *addrs; // Dynamically allocated when num_addr>1
    };

#ifdef HTTPS_ENABLED
    ClientSecureContext *client_secure_context;
    ServerSecureContext *server_secure_context;
    SSL *ssl;
#endif

} Socket;

// Glorified array of sockets. This structure
// is private to the .c file associated to this
// header.
typedef struct {

    // This guards access to the main thread using
    // the manager from other threads calling the
    // wakeup function.
    Mutex mutex;

    // TCP listener sockets. The first is intended
    // for plaintext, while the second is for TLS.
    // The socket manager will accept and add new
    // sockets to the pool automatically. Note that
    // either may be unset. If both are unset, users
    // can only create outgoing connections.
    NATIVE_SOCKET plain_sock;
    NATIVE_SOCKET secure_sock;

    // Handles for the self-pipe trick necessary for
    // other threads to wake up sockets blocked on
    // poll().
    NATIVE_SOCKET wait_sock;
    NATIVE_SOCKET signal_sock;

    // TLS contexts. One is used for outgoing connections
    // (the client context) and one for incoming
    // connections (server). If the secure_sock is
    // set, the server context is initialized. If at
    // least one connect was performed using TLS
    // (and the flag is set), the client context is
    // initialized.
    bool at_least_one_secure_connect;
    ClientSecureContext client_secure_context;
    ServerSecureContext server_secure_context;

    // Array of sockets. Structs with state FREE
    // are unused.
    int num_used;
    int max_used;
    Socket *sockets;

} SocketManager;

// Instanciate a socket manager. Returns 0 on
// success and -1 on error.
int socket_manager_init(SocketManager *sm, Socket *socks,
    int num_socks);

// Deinitialize a socket manager
void socket_manager_free(SocketManager *sm);

// Configure the socket manager to listen on
// the specified interface for TCP connections.
// Incoming connections will be automatically
// added to the internal pool. This function
// can only be used once per manager.
// Returns 0 on success, -1 on error.
int socket_manager_listen_tcp(SocketManager *sm,
    HTTP_String addr, Port port, int backlog,
    bool reuse_addr);

// Same as the previous function, but incoming
// connections will be interpreted as TLS. You
// can only call this function once per manager,
// but you can call this and the plaintext variant
// on the same manager to accept both plaintext
// and secure connections.
// Returns 0 on success, -1 on error.
int socket_manager_listen_tls(SocketManager *sm,
    HTTP_String addr, Port port, int backlog,
    bool reuse_addr, HTTP_String cert_file,
    HTTP_String key_file);

// If the socket manager was configures to accept
// TLS connections, this adds additional certificates
// the client can use to verify the server's
// authenticity.
// Returns 0 on success, -1 on error.
int socket_manager_add_certificate(SocketManager *sm,
    HTTP_String domain, HTTP_String cert_file, HTTP_String key_file);

// When a thread is blocked on a poll() call for
// descriptors associated to this socket manager,
// other threads can call this function to wake
// up that blocked thread.
// Returns 0 on success, -1 on error.
int socket_manager_wakeup(SocketManager *sm);

typedef struct {
    void **ptrs;
    struct pollfd *polled;
    int num_polled;
    int max_polled;
} EventRegister;

// Resets the event register with the list of descriptors
// the socket manager wants monitored. Returns 0 on
// success, -1 if the event register's capacity isn't
// large enough.
int socket_manager_register_events(SocketManager *sm,
    EventRegister *reg);

// After poll() is called on the previously registered
// pollfd array and the revents fields are set, this
// function processes those events to produce higher-level
// socket events. Returns the number of socket events
// written to the output array, or -1 on error.
//
// The maximum number of events this will write
// to the events array is equal to the numero of
// socket structs provided to the socket manager
// via the init function.
int socket_manager_translate_events(SocketManager *sm,
    SocketEvent *events, EventRegister *reg);

typedef enum {
    CONNECT_TARGET_NAME,
    CONNECT_TARGET_IPV4,
    CONNECT_TARGET_IPV6,
} ConnectTargetType;

typedef struct {
    ConnectTargetType type;
    Port port;
    union {
        HTTP_IPv4 ipv4;
        HTTP_IPv6 ipv6;
        HTTP_String name;
    };
} ConnectTarget;

// Connect to one of the given targets. The socket
// manager will try to connecting to addresses until
// one succedes. If secure=true, the socket uses TLS.
// Returns 0 on success, -1 on error.
int socket_connect(SocketManager *sm, int num_targets,
    ConnectTarget *targets, bool secure, void *user);

int socket_recv(SocketManager *sm, SocketHandle handle,
    char *dst, int max);

int socket_send(SocketManager *sm, SocketHandle handle,
    char *src, int len);

int socket_close(SocketManager *sm, SocketHandle handle);

// Returns -1 on error, 0 if the socket was accepted
// from the plaintext listener, or 1 if it was accepted
// by the secure listener.
int socket_is_secure(SocketManager *sm, SocketHandle handle);

// Set the user pointer of a socket
int socket_set_user(SocketManager *sm, SocketHandle handle, void *user);

// Returns true iff the socket is ready for reading or
// writing.
bool socket_ready(SocketManager *sm, SocketHandle handle);
