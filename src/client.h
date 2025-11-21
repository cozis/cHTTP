
#ifndef HTTP_CLIENT_CAPACITY
// The maximum ammount of requests that can be performed
// in parallel.
#define HTTP_CLIENT_CAPACITY (1<<7)
#endif

typedef enum {
    HTTP_CLIENT_CONN_FREE,
    HTTP_CLIENT_CONN_WAIT_LINE,
    HTTP_CLIENT_CONN_WAIT_HEADER,
    HTTP_CLIENT_CONN_WAIT_BODY,
    HTTP_CLIENT_CONN_FLUSHING,
    HTTP_CLIENT_CONN_BUFFERING,
    HTTP_CLIENT_CONN_COMPLETE,
} HTTP_ClientConnState;

// Fields of this struct are private
typedef struct {
    HTTP_ClientConnState state;
    ByteQueue input;
    ByteQueue output;
} HTTP_ClientConn;

// Fields of this struct are private
typedef struct {

    // Array of connections. The counter contains the
    // number of structs such that state=FREE.
    int num_conns;
    HTTP_ClientConn conns[HTTP_CLIENT_CAPACITY];

    // Queue of indices referring to connections that
    // are in the COMPLETE state.
    int num_ready;
    int ready_head;
    int ready[HTTP_CLIENT_CAPACITY];

    // Asynchronous TCP and TLS socket abstraction
    SocketManager sockets;

    // The server object doesn't interact with this
    // field directly, it just initializes the socket
    // manager with a pointer to it. This allows
    // allocating the exact number of sockets we
    // will need.
    Socket socket_pool[HTTP_CLIENT_CAPACITY];

} HTTP_Client;

// Initialize an HTTP client object. This allows one to
// perform a number of requests in parallel.
int http_client_init(HTTP_Client *client);

// Release resources associated to a client object.
void http_client_free(HTTP_Client *client);

// When a thread is blocked waiting for client events,
// other threads can call this function to wake it up.
int http_client_wakeup(HTTP_Client *client);

typedef struct {
    HTTP_Client *client;
    uint16_t index;
    uint16_t gen;
} HTTP_RequestBuilder;

// Create a new request builder object. If the response
// pointer is NULL, a brand new builder is created. If
// response isn't NULL (and http_free_response wasn't
// called on it yet), the connection associated to that
// previous exchange is reused. Note that it's up to the
// user to make sure the requests are targeting the same
// host. Returns 0 on success, -1 on error.
int http_client_get_builder(HTTP_Client *client,
    HTTP_Response *response, HTTP_RequestBuilder *builder);

// Set the URL of the current request. This is the first
// function of the request builder that the user must call.
void http_request_builder_url(HTTP_RequestBuilder builder, String url);

// After the URL, the user may set zero or more headers.
void http_request_builder_header(HTTP_RequestBuilder builder, String str);

// Append bytes to the request's body. You can call this
// any amount of times, as long as it's after having set
// the URL.
void http_request_builder_body(HTTP_RequestBuilder builder, String str);

// Mark this request as complete. This invalidates the
// builder.
void http_request_builder_send(HTTP_RequestBuilder builder);

// List all low-level socket events the client is
// waiting for such that the caller can call poll()
// with it.
int http_client_register_events(HTTP_Client *client,
    struct pollfd *polled, int max_polled);

// The caller has waited for poll() to return and some
// I/O events to be triggered, so now the HTTP client
// can continue its buffering and flushing operations.
int http_client_process_events(HTTP_Client *client,
    struct pollfd *polled, int num_polled);

// After some I/O events were processes, some responses
// may be availabe. This function returns one of the
// buffered responses. If a request was available, true
// is returned. If no more are avaiable, false is returned.
// The returned response must either be freed using the
// http_free_response function or reused by passing it
// to http_client_get_builder.
bool http_client_next_response(HTTP_Client *client,
    HTTP_Response **response);

// Free a response object. You can't access its fields
// again after this.
void http_free_response(HTTP_Response *res);
