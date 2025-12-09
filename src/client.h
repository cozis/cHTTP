
#ifndef CHTTP_CLIENT_CAPACITY
// The maximum ammount of requests that can be performed
// in parallel.
#define CHTTP_CLIENT_CAPACITY (1<<7)
#endif

// Maximum number of descriptors the client will want
// to wait on. It's one per connection plus the wakeup
// self-pipe.
#define CHTTP_CLIENT_POLL_CAPACITY (CHTTP_CLIENT_CAPACITY+1)

#ifndef CHTTP_COOKIE_JAR_CAPACITY
// Maximum number of cookies that can be associated to a
// single client.
#define CHTTP_COOKIE_JAR_CAPACITY 128
#endif

typedef struct {

    // Cookie name and value
    CHTTP_String name;
    CHTTP_String value;

    // If the "exact_domain" is true, the cookie
    // can only be sent to the exact domain referred
    // to by "domain" (which is never empty). If
    // "exact_domain" is false, then the cookie is
    // compatible with subdomains.
    bool exact_domain;
    CHTTP_String domain;

    // If "exact_path" is set, the cookie is only
    // compatible with requests to paths that match
    // "path" exactly. If "exact_path" is not set,
    // then any path that starts with "path" is
    // compatible with the cookie.
    bool exact_path;
    CHTTP_String path;

    // This cookie can only be sent over HTTPS
    bool secure;

} CHTTP_CookieJarEntry;

typedef struct {
    int count;
    CHTTP_CookieJarEntry items[CHTTP_COOKIE_JAR_CAPACITY];
} CHTTP_CookieJar;

typedef enum {
    CHTTP_CLIENT_CONN_FREE,
    CHTTP_CLIENT_CONN_WAIT_METHOD,
    CHTTP_CLIENT_CONN_WAIT_URL,
    CHTTP_CLIENT_CONN_WAIT_HEADER,
    CHTTP_CLIENT_CONN_WAIT_BODY,
    CHTTP_CLIENT_CONN_FLUSHING,
    CHTTP_CLIENT_CONN_BUFFERING,
    CHTTP_CLIENT_CONN_COMPLETE,
} CHTTP_ClientConnState;

// Fields of this struct are private
typedef struct CHTTP_Client CHTTP_Client;

typedef struct {
    CHTTP_ClientConnState state;

    // Handle to the socket
    SocketHandle handle;

    // Pointer back to the client
    CHTTP_Client *client;

    // Generation counter for request builder validation
    uint16_t gen;

    // Opaque pointer set by the user while building
    // the request. It's returned alongside the result.
    void *user;

    // TODO: comment
    bool trace_bytes;

    // TODO: comment
    bool dont_verify_cert;

    // Allocated copy of the URL string
    CHTTP_String url_buffer;

    // Parsed URL for connection establishment
    // All url.* pointers reference into url_buffer
    CHTTP_URL url;

    // Data received from the server
    ByteQueue input;

    // Data being sent to the server
    ByteQueue output;

    // If the request is COMPLETE, indicates
    // whether it completed with an error (-1)
    // or a success (0). If it was a success,
    // the response field is valid.
    int result;

    // Parsed response once complete
    CHTTP_Response response;

    // This offset points to the first byte that comes
    // after the string "Content-Length: ".
    ByteQueueOffset content_length_value_offset;

    // This one points to the first byte of the body.
    // This allows calculating the length of the request
    // content byte subtracting it from the offset reached
    // when the request is marked as done.
    ByteQueueOffset content_length_offset;
} CHTTP_ClientConn;

// Fields of this struct are private
struct CHTTP_Client {

    // Size limit of the input and output buffer of each
    // connection.
    uint32_t input_buffer_limit;
    uint32_t output_buffer_limit;

    // List of cookies created during this session
    CHTTP_CookieJar cookie_jar;

    // Array of connections. The counter contains the
    // number of structs such that state!=FREE.
    int num_conns;
    CHTTP_ClientConn conns[CHTTP_CLIENT_CAPACITY];

    // Queue of indices referring to connections that
    // are in the COMPLETE state.
    int num_ready;
    int ready_head;
    int ready[CHTTP_CLIENT_CAPACITY];

    // Asynchronous TCP and TLS socket abstraction
    SocketManager sockets;

    // The client object doesn't interact with this
    // field directly, it just initializes the socket
    // manager with a pointer to it. This allows
    // allocating the exact number of sockets we
    // will need.
    Socket socket_pool[CHTTP_CLIENT_CAPACITY];
};

// Initialize an HTTP client object. This allows one to
// perform a number of requests in parallel.
int chttp_client_init(CHTTP_Client *client);

// Release resources associated to a client object.
void chttp_client_free(CHTTP_Client *client);

// Set input and output buffer size limit for any
// given connection. The default value is 1MB
void chttp_client_set_input_limit(CHTTP_Client *client, uint32_t limit);
void chttp_client_set_output_limit(CHTTP_Client *client, uint32_t limit);

// When a thread is blocked waiting for client events,
// other threads can call this function to wake it up.
int chttp_client_wakeup(CHTTP_Client *client);

typedef struct {
    CHTTP_Client *client;
    uint16_t index;
    uint16_t gen;
} CHTTP_RequestBuilder;

// Create a new request builder object.
CHTTP_RequestBuilder chttp_client_get_builder(CHTTP_Client *client);

// TODO: comment
void chttp_request_builder_set_user(CHTTP_RequestBuilder builder,
    void *user);

// TODO: comment
void chttp_request_builder_trace(CHTTP_RequestBuilder builder,
    bool trace_bytes);

// TODO: comment
void chttp_request_builder_insecure(CHTTP_RequestBuilder builder,
    bool insecure);

// Set the method of the current request. This is the first
// function of the request builder that the user must call.
void chttp_request_builder_method(CHTTP_RequestBuilder builder,
    CHTTP_Method method);

// Set the URL of the current request. This must be set after
// the method and before any header/body
void chttp_request_builder_target(CHTTP_RequestBuilder builder,
    CHTTP_String url);

// After the URL, the user may set zero or more headers.
void chttp_request_builder_header(CHTTP_RequestBuilder builder,
    CHTTP_String str);

// Append bytes to the request's body. You can call this
// any amount of times, as long as it's after having set
// the URL.
void chttp_request_builder_body(CHTTP_RequestBuilder builder,
    CHTTP_String str);

// Mark this request as complete. This invalidates the
// builder.
// Returns 0 on success, -1 on error.
int chttp_request_builder_send(CHTTP_RequestBuilder builder);

// Resets the event register with the list of descriptors
// the client wants monitored.
void chttp_client_register_events(CHTTP_Client *client,
    EventRegister *reg);

// The caller has waited for poll() to return and some
// I/O events to be triggered, so now the HTTP client
// can continue its buffering and flushing operations.
void chttp_client_process_events(CHTTP_Client *client,
    EventRegister reg);

// After some I/O events were processes, some responses
// may be availabe. This function returns one of the
// buffered responses. If a request was available, true
// is returned. If no more are avaiable, false is returned.
// The returned response must be freed using the
// chttp_free_response function.
// TODO: Better comment talking about output arguments
bool chttp_client_next_response(CHTTP_Client *client,
    int *result, void **user, CHTTP_Response **response);

// TODO: comment
void chttp_client_wait_response(CHTTP_Client *client,
    int *result, void **user, CHTTP_Response **response);

// Free a response object. You can't access its fields
// again after this.
void chttp_free_response(CHTTP_Response *response);

// Perform a blocking GET request
int chttp_get(CHTTP_String url, CHTTP_String *headers,
    int num_headers, CHTTP_Response **response);

// Perform a blocking POST request
int chttp_post(CHTTP_String url, CHTTP_String *headers,
    int num_headers, CHTTP_String body,
    CHTTP_Response **response);

// Perform a blocking PUT request
int chttp_put(CHTTP_String url, CHTTP_String *headers,
    int num_headers, CHTTP_String body,
    CHTTP_Response **response);

// Perform a blocking DELETE request
int chttp_delete(CHTTP_String url, CHTTP_String *headers,
    int num_headers, CHTTP_Response **response);
