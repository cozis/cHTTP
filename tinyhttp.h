////////////////////////////////////////////////////////////////////////////
// LICENSE                                                                //
////////////////////////////////////////////////////////////////////////////
//
// Copyright 2025 Francesco Cozzuto
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the “Software”),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.
//
////////////////////////////////////////////////////////////////////////////

#include <stddef.h>
#include <stdarg.h>

#ifdef TINYHTTP_CUSTOMCONFIG
#include "tinyhttp_config.h"
#else
#define TINYHTTP_SERVER_ENABLE 1
#define TINYHTTP_ROUTER_ENABLE 0
#define TINYHTTP_HTTPS_ENABLE  0
#define TINYHTTP_ROUTER_MAX_PATH_COMPONENTS 32
#define TINYHTTP_HEADER_LIMIT 32
#define TINYHTTP_SERVER_CONN_LIMIT (1<<10)
#define TINYHTTP_SERVER_EPOLL_BATCH_SIZE (1<<10)
#endif

#define TINYHTTP_LINESTR_HELPER1(X) #X
#define TINYHTTP_LINESTR_HELPER2(X) TINYHTTP_LINESTR_HELPER1(X)
#define TINYHTTP_LINESTR TINYHTTP_LINESTR_HELPER2(__LINE__)

// Opaque types
typedef struct TinyHTTPServer TinyHTTPServer;
typedef struct TinyHTTPRouter TinyHTTPRouter;

typedef struct {
	const char *ptr;
	ptrdiff_t   len;
} TinyHTTPString;

#define TINYHTTP_STRING(X) ((TinyHTTPString) {(X), sizeof(X)-1})

typedef enum {
	TINYHTTP_METHOD_GET,
	TINYHTTP_METHOD_POST,
} TinyHTTPMethod;

typedef struct {
	TinyHTTPString name;
	TinyHTTPString value;
} TinyHTTPHeader;

typedef struct {
	TinyHTTPMethod method;
	int            minor;
	TinyHTTPString path;
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
	TINYHTTP_MEM_FREE,
} TinyHTTPMemoryFuncTag;

typedef void*(*TinyHTTPMemoryFunc)(TinyHTTPMemoryFuncTag tag,
	void *ptr, int len, void *data);

// See [tinyhttp_stream_state]
enum {
	TINYHTTP_STREAM_DIED  = 1 << 0,
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
	int numexch;
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

// TODO: Comment
int tinyhttp_streq(TinyHTTPString s1, TinyHTTPString s2);

// TODO: Comment
int tinyhttp_streqcase(TinyHTTPString s1, TinyHTTPString s2);

// TODO: Comment
void tinyhttp_printbytes(char *prefix, const char *src, int len);

// TODO: Comment
void tinyhttp_printstate_(int state, const char *file, const char *line);

// TODO: Comment
#define tinyhttp_printstate(state) tinyhttp_printstate_(state, __FILE__, TINYHTTP_LINESTR)

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

// TODO: Comment
void tinyhttp_stream_kill(TinyHTTPStream *stream);

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
//
// NOTE: This is turned off by default
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
void tinyhttp_stream_response_body(TinyHTTPStream *stream, const char *src, int len);

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

// TODO: Comment
TinyHTTPServer *tinyhttp_server_init(TinyHTTPServerConfig config);

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
void tinyhttp_response_body(TinyHTTPResponse res, char *src, int len);

// TODO: Comment
void tinyhttp_response_send(TinyHTTPResponse res);

// TODO: Comment
void tinyhttp_response_undo(TinyHTTPResponse res);

// TODO: Comment
TinyHTTPRouter *tinyhttp_router_init(void);

// TODO: Comment
void tinyhttp_router_free(TinyHTTPRouter *router);

// TODO: Comment
void tinyhttp_router_resolve(TinyHTTPRouter *router, TinyHTTPServer *server, TinyHTTPRequest *request, TinyHTTPResponse response);

// TODO: Comment
void tinyhttp_router_dir(TinyHTTPRouter *router, const char *endpoint, const char *path, int dir_listing);
