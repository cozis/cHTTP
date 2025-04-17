#include <stddef.h>
#include <stdarg.h>

////////////////////////////////////////////////////////////////////////////
// OVERVIEW                                                               //
////////////////////////////////////////////////////////////////////////////
//
// TinyHTTP is the implementation of an HTTP sever.
//
// Users can use one of two interfaces:
//
//   1) Stream interface: This is the implementation of a single HTTP connection.
//      It abstracts the communication between the server and one client. The
//      advantage is it does not depend on specific I/O and can easily be embedded
//      in the user's I/O model.
//
//   2) Server interface: This is the full server implementation. It uses the
//      streaming interface by adding platform-specific I/O primitives. It uses
//      epoll on Linux and I/O completion ports on Windows. This can also serve
//      as reference for how to use the streaming interface to build a custom
//      server abstraction.
//
// A program using the server interface looks like this:
//
//   int main(void)
//   {
//     HTTPServerConfig config = {
//        // ... set config here ...
//     };
//     HTTPServer *s = http_server_init(config);
//     if (s == NULL) return -1;
//
//     for (;;) {
//       TinyHTTPRequest *req;
//       TinyHTTPResponse res;
//
//       int ret = http_server_wait(s, &req, &res, 1000);
//       if (ret == 1) continue; // Timeout
//       if (ret < 0) continue; // Error
//
//       // Respond
//
//       if (req->method == TINYHTTP_METHOD_POST) {
//         tinyhttp_response_status(res, 405);
//         tinyhttp_response_send(res);
//         continue;
//       }
//
//       tinyhttp_response_status(res, 200);
//       tinyhttp_response_header(res, "Server: TinyHTTP version %d", 0);
//       tinyhttp_response_body_setmincap(res, 1<<9);
//       ptrdiff_t cap;
//       char *dst = tinyhttp_response_body_buf(res, &cap);
//       int len = snprintf(dst, cap, "Hello, world!");
//       if (len < 0 || len > cap) {
//         tinyhttp_response_undo(res);
//         tinyhttp_response_status(res, 500);
//       }
//       tinyhttp_response_send(res);
//     }
//
//     http_server_free(s);
//     return 0;
//   }
//
// TODO: Make sure this example is up to date
//
// Note that this example does full error checking. The public API of tinyhttp
// tries very hard to handle any errors internally, keeping your routes as simple
// as possible.
//
// Once you get a response object from the wait function, you don't need to respond
// immediately. For instance if the response requires an operation to complete, you
// can store the response handle somewhere and accept new responses in the mean time.
//
// A program using the stream interface may look like this:
//
//   void respond(TinyHTTPStream *stream)
//   {
//     TinyHTTPRequest *req = tinyhttp_stream_request(stream);
//     if (req->method != TINYHTTP_METHOD_GET)
//       tinyhttp_stream_status(stream, 405);
//     else
//       tinyhttp_stream_status(stream, 200);
//     tinyhttp_stream_send(stream);
//   }
//
//   int main(void)
//   {
//     int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
//
//     struct sockaddr_in buf;
//     buf.sin_family = AF_INET;
//     buf.sin_port   = htons(port);
//     buf.sin_addr.s_addr = htonl(INADDR_ANY);
//     bind(listen_fd, (struct sockaddr*) &buf, sizeof(buf));
//
//     listen(listen_fd, 32);
//
//     int num_conns = 0;
//     int fds[1000];
//     TinyHTTPStream streams[1000];
//
//     for (int i = 0; i < 1000; i++)
//       fds[i] = -1;
//
//     for (;;) {
//       // TODO: timeouts
//
//       fd_set readset;
//       fd_set writeset;
//       FD_ZERO(&readset);
//       FD_ZERO(&writeset);
//
//       FD_SET(&readset);
//       int max_fd = listen_fd;
//       for (int i = 0; i < 1000; i++) {
//         if (fds[i] == -1) continue;
//         int state = tinyhttp_stream_state(&streams[i]);
//         if (state & TINYHTTP_STREAM_RECV)
//           FD_SET(fds[i], &readset);
//         if (state & TINYHTTP_STREAM_SEND)
//           FD_SET(fds[i], &writeset);
//         if (state & (TINYHTTP_STREAM_RECV | TINYHTTP_STREAM_SEND))
//           if (max_fd < fds[i]) max_fd = fds[i];
//       }
//
//       int num = select(max_fd+1, &readset, &writeset, NULL, NULL);
//
//       if (FD_ISSET(liste_fd, &readset)) {
//         // TODO
//       }
//
//       int ready_queue[1000];
//       int ready_head = 0;
//       int ready_count = 0;
//       for (int i = 0; i < 1000; i++) {
//         // TODO
//       }
//
//       while (ready_count > 0) {
//
//         int idx = ready_queue[ready_head];
//         TinyHTTPStream *stream = &streams[idx];
//
//         TinyHTTPRequest *req = tinyhttp_stream_request(stream);
//         assert(req);
//
//         respond(stream);
//
//         ready_head = (ready_head + 1) % 1000;
//         ready_count--;
//         if (tinyhttp_stream_request(stream)) {
//           ready_queue[(ready_head + ready_count) % 1000] = idx;
//           ready_count++;
//         }
//       }
//     }
//
//     close(listen_fd);
//     return 0;
//   }
//
// Note that this example does not keep track of timeouts.
//
// The recv_buf/recv_ack and send_buf/send_ack interface is very handy as it's
// compatible both with readyness-based event loops (epoll, poll, select) and
// completion-based event loops (iocp, io_uring). Since the stream object does
// not read from the socket directly, you can easily implement HTTPS by providing
// it with TLS-encoded data instead of data directly from the socket.

////////////////////////////////////////////////////////////////////////////
// CONFIGURATION                                                          //
////////////////////////////////////////////////////////////////////////////

#define TINYHTTP_SERVER_ENABLE
//#define TINYHTTP_ROUTER_ENABLE

#define TINYHTTP_ROUTER_MAX_PATH_COMPONENTS 32

#define TINYHTTP_HEADER_LIMIT 32
#define TINYHTTP_SERVER_CONN_LIMIT 3 // (1<<10)
#define TINYHTTP_SERVER_EPOLL_BATCH_SIZE (1<<10)

////////////////////////////////////////////////////////////////////////////
// HTTP SERVER INTEFACE                                                   //
////////////////////////////////////////////////////////////////////////////

typedef struct TinyHTTPServer TinyHTTPServer;

typedef enum {
	TINYHTTP_METHOD_GET,
	TINYHTTP_METHOD_POST,
} TinyHTTPMethod;

typedef struct {
	char     *name;
	ptrdiff_t name_len;
	char     *value;
	ptrdiff_t value_len;
} TinyHTTPHeader;

typedef struct {
	TinyHTTPMethod method;
	int            minor;
	char*          path;
	ptrdiff_t      path_len;
	int            num_headers;
	TinyHTTPHeader headers[TINYHTTP_HEADER_LIMIT];
	char*          body;
	ptrdiff_t      body_len;
} TinyHTTPRequest;

typedef struct {
	TinyHTTPServer *server;
	unsigned short idx;
	unsigned short gen;
} TinyHTTPResponse;

typedef struct {

	int reuse;

	// HTTP
	const char *plain_addr;
	int         plain_port;
	int         plain_backlog;

	// HTTPS
	int         secure;
	const char *secure_addr;
	int         secure_port;
	int         secure_backlog;
	const char *cert_file;
	const char *private_key_file;

} TinyHTTPServerConfig;

typedef enum {
	TINYHTTP_MEM_MALLOC,
	TINYHTTP_MEM_REALLOC,
	TINYHTTP_MEM_FREE,
} TinyHTTPMemoryFuncTag;

typedef void*(*TinyHTTPMemoryFunc)(TinyHTTPMemoryFuncTag tag,
	void *ptr, int len, void *data);

#ifdef TINYHTTP_SERVER_ENABLE

// TODO: Comment
TinyHTTPServer *tinyhttp_server_init(TinyHTTPServerConfig config,
	TinyHTTPMemoryFunc memfunc, void *memfuncdata);

// TODO: Comment
void tinyhttp_server_free(TinyHTTPServer *server);

// TODO: Comment
int tinyhttp_server_wait(TinyHTTPServer *server, TinyHTTPRequest **req,
	TinyHTTPResponse *res, int timeout);

// TODO: Comment
void tinyhttp_response_status(TinyHTTPResponse res, int status);

// TODO: Comment
void tinyhttp_response_header(TinyHTTPResponse res,
	const char *fmt, ...);

// TODO: Comment
void tinyhttp_response_header_fmt(TinyHTTPResponse res,
	const char *fmt, va_list args);

// TODO: Comment
void tinyhttp_response_body_setmincap(TinyHTTPResponse res,
	ptrdiff_t mincap);

// TODO: Comment
char *tinyhttp_response_body_buf(TinyHTTPResponse res, ptrdiff_t *cap);

// TODO: Comment
void tinyhttp_response_body_ack(TinyHTTPResponse res, ptrdiff_t num);

// TODO: Comment
void tinyhttp_response_send(TinyHTTPResponse res);

// TODO: Comment
void tinyhttp_response_undo(TinyHTTPResponse res);

#endif // TINYHTTP_SERVER_ENABLE

////////////////////////////////////////////////////////////////////////////
// HTTP STREAM INTEFACE                                                   //
////////////////////////////////////////////////////////////////////////////
//
// The TinyHTTPStream object abstracts the HTTP request/response
// state machine in a platorm-agnostic way.
//
// The connection is first initialized with [tinyhttp_stream_init].
// From this point on, the connection interacts with the network
// using the [tinyhttp_stream_net_{recv|send}_{buf|ack}] functions.
//
// The state of the connection can be queried using the
// [tinyhttp_stream_state] function. If the state is [TINYHTTP_STREAM_FREE],
// the connection was terminated and the caller must release
// any resources it allocated for it. If the connection is still
// active, zero or more of these flags may be set:
//
//   TINYHTTP_STREAM_READY
//     An HTTP request was completely buffered and its parsed
//     version can be accessed through the [tinyhttp_stream_request]
//     function.
//
//   TINYHTTP_STREAM_RECV
//     The connection expects some bytes from the network.
//
//   TINYHTTP_STREAM_SEND
//     The connection needs to send bytes on the network
//
// Any call to [tinyhttp_stream_*] functions may cause this state
// to change. When the HTTP-CONN_READY flag is set, the caller
// must create a response by calling these functions in
// sequence:
//
//   tinyhttp_stream_response_status
//   tinyhttp_stream_response_header (optional)
//   tinyhttp_stream_response_body_setmincap/buf/ack (optional)
//   tinyhttp_stream_response_send
//
// The header and body functions may be called any number
// of times.
//
// When [tinyhttp_stream_response_send] is called, the buffered
// request is removed and the following buffered requests
// is parsed. If no requests are left, the TINYHTTP_STREAM_READY
// state is unset.
//
// If at any point you want to change the response, you
// can undo all the calls by calling:
//
//   tinyhttp_stream_response_undo
//
// To start again from [tinyhttp_stream_response_status]
//
// Note that due to pipelining, the stream may still be reading
// after sending a response.

// See [tinyhttp_stream_state]
enum {
	TINYHTTP_STREAM_FREE  = 1 << 0,
	TINYHTTP_STREAM_READY = 1 << 1,
	TINYHTTP_STREAM_RECV  = 1 << 2,
	TINYHTTP_STREAM_SEND  = 1 << 3,
	TINYHTTP_STREAM_CLOSE = 1 << 4,
	TINYHTTP_STREAM_REUSE = 1 << 5,
	TINYHTTP_STREAM_SEND_STARTED = 1 << 6,
	TINYHTTP_STREAM_RECV_STARTED = 1 << 7,
};

// Internal use
typedef enum {
	TINYHTTP_OUTPUT_STATE_NONE,
	TINYHTTP_OUTPUT_STATE_STATUS,
	TINYHTTP_OUTPUT_STATE_HEADER,
	TINYHTTP_OUTPUT_STATE_BODY,
	TINYHTTP_OUTPUT_STATE_ERROR,
} TinyHTTPConnectionOutputState;

// Internal use
enum {
	BYTE_QUEUE_ERROR = 1 << 0,
	BYTE_QUEUE_LOCK  = 1 << 1,
	BYTE_QUEUE_READ  = 1 << 2,
	BYTE_QUEUE_WRITE = 1 << 3,
};

// Internal use
typedef struct {

	TinyHTTPMemoryFunc memfunc;
	void *memfuncdata;

	unsigned long long curs;
	unsigned int       lock; // TODO: Should this be u64?

	char*        data;
	unsigned int head;
	unsigned int size;
	unsigned int used;
	unsigned int limit;

	char*        read_target;
	unsigned int read_target_size;

	int flags;
} TinyHTTPByteQueue;

// Internal use
typedef unsigned long long TinyHTTPByteQueueOffset;

typedef struct {
	int state;
	int chunked;
	int keepalive;
	ptrdiff_t reqsize;
	unsigned long long bodylimit;
	TinyHTTPConnectionOutputState output_state;
	TinyHTTPByteQueueOffset content_length_value_offset;
	TinyHTTPByteQueueOffset content_length_offset;
	TinyHTTPByteQueue in;
	TinyHTTPByteQueue out;
	TinyHTTPRequest req;
} TinyHTTPStream;

// Initializes an HTTP stream
//
// TODO: Comment on memfunc
void
tinyhttp_stream_init(TinyHTTPStream *stream,
	TinyHTTPMemoryFunc memfunc, void *memfuncdata);

// Deinitializes an HTTP stream
//
// This function may be called at any time on a memory
// region where [tinyhttp_stream_init] was called at
// least once.
//
// From the moment this function is called until the
// next call to [tinyhttp_stream_init], all [tinyhttp_stream_*]
// calls become no-ops.
void tinyhttp_stream_free(TinyHTTPStream *stream);

// Returns the current state of the connection
//
// TODO: List the possible states
//
// Note:
//   - Calling this function is always valid on a
//     memory region where [tinyhttp_stream_init] was
//     called at least once.
int tinyhttp_stream_state(TinyHTTPStream *stream);

// Returns the pointer and capacity of a memory region
// where data should be read from the network.
// 
// You can write at least [*cap] bytes at the returned
// pointer, and need to call [tinyhttp_stream_net_recv_ack]
// when the write is complete.
//
// Note:
//   - Due to sticky errors, this function may return
//     the null pointer and a capacity of 0. The caller
//     must not write to the pointer but act as if
//     everything went okay.
char *tinyhttp_stream_recv_buf(TinyHTTPStream *stream, ptrdiff_t *cap);

// Acknowledge the bytes written from the network
//
// The write must have been initiated by calling
// [tinyhttp_stream_net_recv_buf].
void tinyhttp_stream_recv_ack(TinyHTTPStream *stream, ptrdiff_t num);

// Returns the pointer and capacity of a memory region
// where data should be written to the network.
//
// When the write is complete, [tinyhttp_stream_net_send_ack]
// should be called with the number of consumed bytes.
char *tinyhttp_stream_send_buf(TinyHTTPStream *stream, ptrdiff_t *len);

// See [tinyhttp_stream_net_send_buf]
void tinyhttp_stream_send_ack(TinyHTTPStream *stream, ptrdiff_t num);

// Enable/disable connection reuse for this HTTP
// connection. This change takes effect at the start
// of the next request.
//
// Note that even if the reuse option is set, the
// connection may still be closed due to errors or
// the client deciding otherwise.
//
// On the other hand, if this option is set the next
// request will definitely be the last.
void tinyhttp_stream_setreuse(TinyHTTPStream *stream, int value);

// TODO: Comment
void tinyhttp_stream_setbodylimit(TinyHTTPStream *stream, unsigned long long value);

// TODO: Comment
void tinyhttp_stream_setinbuflimit(TinyHTTPStream *stream, unsigned int value);

// TODO: Comment
void tinyhttp_stream_setoutbuflimit(TinyHTTPStream *stream, unsigned int value);

// TODO: Comment
TinyHTTPRequest *tinyhttp_stream_request(TinyHTTPStream *stream);

// TODO: Comment
void tinyhttp_stream_response_status(TinyHTTPStream *stream, int status);

// TODO: Comment
void tinyhttp_stream_response_header(TinyHTTPStream *stream, const char *fmt, ...);

// TODO: Comment
void tinyhttp_stream_response_header_fmt(TinyHTTPStream *stream, const char *fmt, va_list args);

// TODO: Comment
void tinyhttp_stream_response_body_setmincap(TinyHTTPStream *stream, ptrdiff_t mincap);

// TODO: Comment
char *tinyhttp_stream_response_body_buf(TinyHTTPStream *stream, ptrdiff_t *cap);

// TODO: Comment
void tinyhttp_stream_response_body_ack(TinyHTTPStream *stream, ptrdiff_t num);

// TODO: Comment
void tinyhttp_stream_response_send(TinyHTTPStream *stream);

// TODO: Comment
void tinyhttp_stream_response_undo(TinyHTTPStream *stream);

////////////////////////////////////////////////////////////////////////////
// HTTP ROUTER                                                            //
////////////////////////////////////////////////////////////////////////////

#ifdef TINYHTTP_ROUTER_ENABLE

typedef struct TinyHTTPRouter TinyHTTPRouter;

// TODO: Comment
TinyHTTPRouter *tinyhttp_router_init(void);

// TODO: Comment
void tinyhttp_router_free(TinyHTTPRouter *router);

// TODO: Comment
void tinyhttp_router_resolve(TinyHTTPRouter *router, TinyHTTPServer *server, TinyHTTPRequest *request, TinyHTTPResponse response);

// TODO: Comment
void tinyhttp_router_dir(TinyHTTPRouter *router, const char *endpoint, const char *path, int dir_listing);

#endif // TINYHTTP_ROUTER_ENABLE