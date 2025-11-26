
#ifndef HTTP_SERVER_CAPACITY
// The maximum ammount of requests that can be handled
// in parallel.
#define HTTP_SERVER_CAPACITY (1<<9)
#endif

// Maximum number of descriptors the server will want
// to wait on. It's one per connection plus two for the
// TCP and TLS listener, plus one for the wakeup self-pipe.
#define HTTP_SERVER_POLL_CAPACITY (HTTP_SERVER_CAPACITY+3)

typedef enum {

    // This struct is unused
    HTTP_SERVER_CONN_FREE,

    // No request was buffered yet.
    HTTP_SERVER_CONN_BUFFERING,

    // A request was just buffered and is waiting for
    // the user to build a response. To be specific,
    // it's waiting for the user to set a response status.
    HTTP_SERVER_CONN_WAIT_STATUS,

    // A request is buffered and a status was set. Now
    // the user can set a header or append the first
    // bytes of the response body.
    HTTP_SERVER_CONN_WAIT_HEADER,

    // A request is buffered and some bytes were appended
    // to the response. Now the user can either append more
    // bytes or send out the response.
    HTTP_SERVER_CONN_WAIT_BODY,

    // A response has been produced and it's being flushed.
    HTTP_SERVER_CONN_FLUSHING,

} HTTP_ServerConnState;

// This structure represents the HTTP connection to
// a client.
typedef struct {

    // If false, this struct is unused
    HTTP_ServerConnState state;

    // Handle to the socket
    SocketHandle handle;

    // Data received by the client
    ByteQueue input;

    // Data being sent to the client
    ByteQueue output;

    // Generation counter. This is used to invalidate
    // response builders that refer to this connection.
    uint16_t gen;

    // This is set during the WAIT_XXX states or
    // the FLUSHING state. When the connection
    // completes flushing and no more bytes are
    // in the output buffer, it frees the connection
    // instead of turning it back to BUFFERING.
    bool closing;

    // When the state is WAIT_STATUS, WAIT_HEADER,
    // or WAIT_BODY, this contains the parsed version
    // of the buffered request.
    HTTP_Request request;

    // Length of the buffered request when the request
    // field is valid.
    int request_len;

    // Offset of the first response byte in the output
    // buffer. This is useful when the user wants to
    // undo the response it's building and start from
    // scratch.
    ByteQueueOffset response_offset;

    // When the first byte of the response content is
    // written, before it are prepended special headers,
    // including Content-Length and Connection. This
    // offset points to the first byte that comes after
    // the string "Content-Length: ".
    ByteQueueOffset content_length_value_offset;

    // Similarly to the previous field, this one points
    // to the first byte of the body. This allows calculating
    // the length of the response content byte subtracting
    // it from the offset reached when the response is marked
    // as done.
    ByteQueueOffset content_length_offset;
} HTTP_ServerConn;

typedef struct {

    // Size limit of the input and output buffer of each
    // connection.
    uint32_t input_buffer_limit;
    uint32_t output_buffer_limit;

    bool trace_bytes;
    bool reuse_addr;
    int backlog;

    // Array of connections. The counter contains the
    // number of structs such that state=FREE.
    int num_conns;
    HTTP_ServerConn conns[HTTP_SERVER_CAPACITY];

    // Queue of indices referring to connections that
    // are in the WAIT_STATUS state.
    int num_ready;
    int ready_head;
    int ready[HTTP_SERVER_CAPACITY];

    // Asynchronous TCP and TLS socket abstraction
    SocketManager sockets;

    // The server object doesn't interact with this
    // field directly, it just initializes the socket
    // manager with a pointer to it. This allows
    // allocating the exact number of sockets we
    // will need.
    Socket socket_pool[HTTP_SERVER_CAPACITY];

} HTTP_Server;

// Initialize the HTTP server object. By default, it won't
// listen for connections. You need to call
//
//   http_server_listen_tcp
//   http_server_listen_tls
//
// to listen for connection. Note that you can have a
// single server listening for HTTP and HTTPS requests
// by calling both.
int http_server_init(HTTP_Server *server);

// Release resources associated to the server.
void http_server_free(HTTP_Server *server);

// Set input and output buffer size limit for any
// given connection. The default value is 1MB
void http_server_set_input_limit(HTTP_Server *server, uint32_t limit);
void http_server_set_output_limit(HTTP_Server *server, uint32_t limit);

// TODO: Comment
void http_server_set_trace_bytes(HTTP_Server *server, bool value);

// TODO: Comment
void http_server_set_reuse_addr(HTTP_Server *server, bool reuse);

// TODO: comment
void http_server_set_backlog(HTTP_Server *server, int backlog);

// Enable listening for plain HTTP requests at the
// specified interface.
int http_server_listen_tcp(HTTP_Server *server,
    HTTP_String addr, Port port);

// Enable listening for HTTPS requests at the specified
// interfact, using the specified certificate and key
// to verify the connection.
int http_server_listen_tls(HTTP_Server *server, HTTP_String addr, Port port,
    HTTP_String cert_file_name, HTTP_String key_file_name);

// Add the certificate for an additional domain when
// the server is listening for HTTPS requests.
int http_server_add_certificate(HTTP_Server *server,
    HTTP_String domain, HTTP_String cert_file, HTTP_String key_file);

// When a thread is blocked waiting for server events,
// other threads can call this function to wake it up.
int http_server_wakeup(HTTP_Server *server);

// Resets the event register with the list of descriptors
// the server wants monitored.
void http_server_register_events(HTTP_Server *server,
    EventRegister *reg);

// The caller has waited for poll() to return and some
// I/O events to be triggered, so now the HTTP server
// can continue its buffering and flushing operations.
void http_server_process_events(HTTP_Server *server,
    EventRegister reg);

typedef struct {
    HTTP_Server *server;
    uint16_t     index;
    uint16_t     gen;
} HTTP_ResponseBuilder;

// After some I/O events were processes, some requests
// may be availabe. This function returns one of the
// buffered requests. If a request was available, true
// is returned. If no more are avaiable, false is returned.
// Note that It's possible to get multiple requests to
// respond in batches.
// For each request returned by this function, the user
// must build a response using the response builder API.
bool http_server_next_request(HTTP_Server *server,
    HTTP_Request **request, HTTP_ResponseBuilder *builder);

// TODO: comment
void http_server_wait_request(HTTP_Server *server,
    HTTP_Request **request, HTTP_ResponseBuilder *builder);

// This function is called to set the status code of
// a request's response. If this function is called
// after the other response builder functions, it will
// reset the response and set a new status.
void http_response_builder_status(HTTP_ResponseBuilder builder, int status);

// Append a header to the response. This can only be
// used after having set the status and before appending
// to the body.
void http_response_builder_header(HTTP_ResponseBuilder builder, HTTP_String str);

// Append some bytes to the response's body
void http_response_builder_body(HTTP_ResponseBuilder builder, HTTP_String str);

// TODO: comment
void  http_response_builder_body_cap(HTTP_ResponseBuilder builder, int cap);
char *http_response_builder_body_buf(HTTP_ResponseBuilder builder, int *cap);
void  http_response_builder_body_ack(HTTP_ResponseBuilder builder, int num);

// Mark the response as complete. This will invalidate
// the response builder handle.
void http_response_builder_send(HTTP_ResponseBuilder builder);
