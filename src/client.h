
#ifndef HTTP_CLIENT_CAPACITY
// The maximum ammount of requests that can be performed
// in parallel.
#define HTTP_CLIENT_CAPACITY (1<<7)
#endif

// Maximum number of descriptors the client will want
// to wait on. It's one per connection plus the wakeup
// self-pipe.
#define HTTP_CLIENT_POLL_CAPACITY (HTTP_CLIENT_CAPACITY+1)

#ifndef HTTP_COOKIE_JAR_CAPACITY
// Maximum number of cookies that can be associated to a
// single client.
#define HTTP_COOKIE_JAR_CAPACITY 128
#endif

typedef struct {

    // Cookie name and value
    HTTP_String name;
    HTTP_String value;

    // If the "exact_domain" is true, the cookie
    // can only be sent to the exact domain referred
    // to by "domain" (which is never empty). If
    // "exact_domain" is false, then the cookie is
    // compatible with subdomains.
    bool exact_domain;
    HTTP_String domain;

    // If "exact_path" is set, the cookie is only
    // compatible with requests to paths that match
    // "path" exactly. If "exact_path" is not set,
    // then any path that starts with "path" is
    // compatible with the cookie.
    bool exact_path;
    HTTP_String path;

    // This cookie can only be sent over HTTPS
    bool secure;

} HTTP_CookieJarEntry;

typedef struct {
    int count;
    HTTP_CookieJarEntry items[HTTP_COOKIE_JAR_CAPACITY];
} HTTP_CookieJar;

typedef enum {
    HTTP_CLIENT_CONN_FREE,
    HTTP_CLIENT_CONN_WAIT_METHOD,
    HTTP_CLIENT_CONN_WAIT_URL,
    HTTP_CLIENT_CONN_WAIT_HEADER,
    HTTP_CLIENT_CONN_WAIT_BODY,
    HTTP_CLIENT_CONN_FLUSHING,
    HTTP_CLIENT_CONN_BUFFERING,
    HTTP_CLIENT_CONN_COMPLETE,
} HTTP_ClientConnState;

// Fields of this struct are private
typedef struct HTTP_Client HTTP_Client;

typedef struct {
    HTTP_ClientConnState state;

    // Handle to the socket
    SocketHandle handle;

    // Pointer back to the client
    HTTP_Client *client;

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
    HTTP_String url_buffer;

    // Parsed URL for connection establishment
    // All url.* pointers reference into url_buffer
    HTTP_URL url;

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
    HTTP_Response response;

    // This offset points to the first byte that comes
    // after the string "Content-Length: ".
    ByteQueueOffset content_length_value_offset;

    // This one points to the first byte of the body.
    // This allows calculating the length of the request
    // content byte subtracting it from the offset reached
    // when the request is marked as done.
    ByteQueueOffset content_length_offset;
} HTTP_ClientConn;

// Fields of this struct are private
struct HTTP_Client {

    // Size limit of the input and output buffer of each
    // connection.
    uint32_t input_buffer_limit;
    uint32_t output_buffer_limit;

    // List of cookies created during this session
    HTTP_CookieJar cookie_jar;

    // Array of connections. The counter contains the
    // number of structs such that state!=FREE.
    int num_conns;
    HTTP_ClientConn conns[HTTP_CLIENT_CAPACITY];

    // Queue of indices referring to connections that
    // are in the COMPLETE state.
    int num_ready;
    int ready_head;
    int ready[HTTP_CLIENT_CAPACITY];

    // Asynchronous TCP and TLS socket abstraction
    SocketManager sockets;

    // The client object doesn't interact with this
    // field directly, it just initializes the socket
    // manager with a pointer to it. This allows
    // allocating the exact number of sockets we
    // will need.
    Socket socket_pool[HTTP_CLIENT_CAPACITY];
};

// Initialize an HTTP client object. This allows one to
// perform a number of requests in parallel.
int http_client_init(HTTP_Client *client);

// Release resources associated to a client object.
void http_client_free(HTTP_Client *client);

// Set input and output buffer size limit for any
// given connection. The default value is 1MB
void http_client_set_input_limit(HTTP_Client *client, uint32_t limit);
void http_client_set_output_limit(HTTP_Client *client, uint32_t limit);

// When a thread is blocked waiting for client events,
// other threads can call this function to wake it up.
int http_client_wakeup(HTTP_Client *client);

typedef struct {
    HTTP_Client *client;
    uint16_t index;
    uint16_t gen;
} HTTP_RequestBuilder;

// Create a new request builder object.
HTTP_RequestBuilder http_client_get_builder(HTTP_Client *client);

// TODO: comment
void http_request_builder_set_user(HTTP_RequestBuilder builder,
    void *user);

// TODO: comment
void http_request_builder_trace(HTTP_RequestBuilder builder,
    bool trace_bytes);

// TODO: comment
void http_request_builder_insecure(HTTP_RequestBuilder builder,
    bool insecure);

// Set the method of the current request. This is the first
// function of the request builder that the user must call.
void http_request_builder_method(HTTP_RequestBuilder builder,
    HTTP_Method method);

// Set the URL of the current request. This must be set after
// the method and before any header/body
void http_request_builder_target(HTTP_RequestBuilder builder,
    HTTP_String url);

// After the URL, the user may set zero or more headers.
void http_request_builder_header(HTTP_RequestBuilder builder,
    HTTP_String str);

// Append bytes to the request's body. You can call this
// any amount of times, as long as it's after having set
// the URL.
void http_request_builder_body(HTTP_RequestBuilder builder,
    HTTP_String str);

// Mark this request as complete. This invalidates the
// builder.
// Returns 0 on success, -1 on error.
int http_request_builder_send(HTTP_RequestBuilder builder);

// Resets the event register with the list of descriptors
// the client wants monitored.
void http_client_register_events(HTTP_Client *client,
    EventRegister *reg);

// The caller has waited for poll() to return and some
// I/O events to be triggered, so now the HTTP client
// can continue its buffering and flushing operations.
void http_client_process_events(HTTP_Client *client,
    EventRegister reg);

// After some I/O events were processes, some responses
// may be availabe. This function returns one of the
// buffered responses. If a request was available, true
// is returned. If no more are avaiable, false is returned.
// The returned response must be freed using the
// http_free_response function.
// TODO: Better comment talking about output arguments
bool http_client_next_response(HTTP_Client *client,
    int *result, void **user, HTTP_Response **response);

// TODO: comment
void http_client_wait_response(HTTP_Client *client,
    int *result, void **user, HTTP_Response **response);

// Free a response object. You can't access its fields
// again after this.
void http_free_response(HTTP_Response *response);

// Perform a blocking GET request
int http_get(HTTP_String url, HTTP_String *headers,
    int num_headers, HTTP_Response **response);

// Perform a blocking POST request
int http_post(HTTP_String url, HTTP_String *headers,
    int num_headers, HTTP_String body,
    HTTP_Response **response);

// Perform a blocking PUT request
int http_put(HTTP_String url, HTTP_String *headers,
    int num_headers, HTTP_String body,
    HTTP_Response **response);

// Perform a blocking DELETE request
int http_delete(HTTP_String url, HTTP_String *headers,
    int num_headers, HTTP_Response **response);
