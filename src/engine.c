#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h> // TODO: remove some of these headers
#include <stddef.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#ifndef HTTP_AMALGAMATION
#include "basic.h"
#include "engine.h"
#endif

// This is the implementation of a byte queue useful
// for systems that need to process engs of bytes.
//
// It features sticky errors, a zero-copy interface,
// and a safe mechanism to patch previously written
// bytes.
//
// Only up to 4GB of data can be stored at once.

enum {
	BYTE_QUEUE_ERROR = 1 << 0,
	BYTE_QUEUE_READ  = 1 << 1,
	BYTE_QUEUE_WRITE = 1 << 2,
};

static void*
callback_malloc(HTTP_ByteQueue *queue, int len)
{
	return queue->memfunc(HTTP_MEMFUNC_MALLOC, NULL, len, queue->memfuncdata);
}

static void
callback_free(HTTP_ByteQueue *queue, void *ptr, int len)
{
	queue->memfunc(HTTP_MEMFUNC_FREE, ptr, len, queue->memfuncdata);
}

// Initialize the queue
static void
byte_queue_init(HTTP_ByteQueue *queue, unsigned int limit, HTTP_MemoryFunc memfunc, void *memfuncdata)
{
	queue->flags = 0;
	queue->head = 0;
	queue->size = 0;
	queue->used = 0;
	queue->curs = 0;
	queue->limit = limit;
	queue->data = NULL;
	queue->read_target = NULL;
	queue->memfunc = memfunc;
	queue->memfuncdata = memfuncdata;
}

// Deinitialize the queue
static void
byte_queue_free(HTTP_ByteQueue *queue)
{
	if (queue->read_target) {
		if (queue->read_target != queue->data)
			callback_free(queue, queue->read_target, queue->read_target_size);
		queue->read_target = NULL;
		queue->read_target_size = 0;
	}

	callback_free(queue, queue->data, queue->size);
	queue->data = NULL;
}

static int
byte_queue_error(HTTP_ByteQueue *queue)
{
	return queue->flags & BYTE_QUEUE_ERROR;
}

static int
byte_queue_empty(HTTP_ByteQueue *queue)
{
	return queue->used == 0;
}

// Start a read operation on the queue.
//
// This function returnes the pointer to the memory region containing the bytes
// to read. Callers can't read more than [*len] bytes from it. To complete the
// read, the [byte_queue_read_ack] function must be called with the number of
// bytes that were acknowledged by the caller.
//
// Note:
//   - You can't have more than one pending read.
static char*
byte_queue_read_buf(HTTP_ByteQueue *queue, int *len)
{
	if (queue->flags & BYTE_QUEUE_ERROR) {
		*len = 0;
		return NULL;
	}

	HTTP_ASSERT((queue->flags & BYTE_QUEUE_READ) == 0);
	queue->flags |= BYTE_QUEUE_READ;
	queue->read_target      = queue->data;
	queue->read_target_size = queue->size;

	*len = queue->used;
	if (queue->data == NULL)
		return NULL;
	return queue->data + queue->head;
}

// Complete a previously started operation on the queue.
static void
byte_queue_read_ack(HTTP_ByteQueue *queue, int num)
{
	HTTP_ASSERT(num >= 0);

	if (queue->flags & BYTE_QUEUE_ERROR)
		return;

	if ((queue->flags & BYTE_QUEUE_READ) == 0)
		return;

	queue->flags &= ~BYTE_QUEUE_READ;

	HTTP_ASSERT((unsigned int) num <= queue->used);
	queue->head += (unsigned int) num;
	queue->used -= (unsigned int) num;
	queue->curs += (unsigned int) num;

	if (queue->read_target) {
		if (queue->read_target != queue->data)
			callback_free(queue, queue->read_target, queue->read_target_size);
		queue->read_target = NULL;
		queue->read_target_size = 0;
	}
}

static char*
byte_queue_write_buf(HTTP_ByteQueue *queue, int *cap)
{
	if ((queue->flags & BYTE_QUEUE_ERROR) || queue->data == NULL) {
		*cap = 0;
		return NULL;
	}

	HTTP_ASSERT((queue->flags & BYTE_QUEUE_WRITE) == 0);
	queue->flags |= BYTE_QUEUE_WRITE;

	unsigned int ucap = queue->size - (queue->head + queue->used);
	if (ucap > INT_MAX) ucap = INT_MAX;

	*cap = (int) ucap;
	return queue->data + (queue->head + queue->used);
}

static void
byte_queue_write_ack(HTTP_ByteQueue *queue, int num)
{
	HTTP_ASSERT(num >= 0);

	if (queue->flags & BYTE_QUEUE_ERROR)
		return;

	if ((queue->flags & BYTE_QUEUE_WRITE) == 0)
		return;

	queue->flags &= ~BYTE_QUEUE_WRITE;
	queue->used += (unsigned int) num;
}

// Sets the minimum capacity for the next write operation
// and returns 1 if the content of the queue was moved, else
// 0 is returned.
//
// You must not call this function while a write is pending.
// In other words, you must do this:
//
//   byte_queue_write_setmincap(queue, mincap);
//   dst = byte_queue_write_buf(queue, &cap);
//   ...
//   byte_queue_write_ack(num);
//
// And NOT this:
//
//   dst = byte_queue_write_buf(queue, &cap);
//   byte_queue_write_setmincap(queue, mincap); <-- BAD
//   ...
//   byte_queue_write_ack(num);
//
static int
byte_queue_write_setmincap(HTTP_ByteQueue *queue, int mincap)
{
	HTTP_ASSERT(mincap >= 0);
	unsigned int umincap = (unsigned int) mincap;

	// Sticky error
	if (queue->flags & BYTE_QUEUE_ERROR)
		return 0;

	// In general, the queue's contents look like this:
	//
	//                           size
	//                           v
	//   [___xxxxxxxxxxxx________]
	//   ^   ^           ^
	//   0   head        head + used
	//
	// This function needs to make sure that at least [mincap]
	// bytes are available on the right side of the content.
	//
	// We have 3 cases:
	//
	//   1) If there is enough memory already, this function doesn't
	//      need to do anything.
	//
	//   2) If there isn't enough memory on the right but there is
	//      enough free memory if we cound the left unused region,
	//      then the content is moved back to the
	//      start of the buffer.
	//
	//   3) If there isn't enough memory considering both sides, this
	//      function needs to allocate a new buffer.
	//
	// If there are pending read or write operations, the application
	// is holding pointers to the buffer, so we need to make sure
	// to not invalidate them. The only real problem is pending reads
	// since this function can only be called before starting a write
	// opearation.
	//
	// To avoid invalidating the read pointer when we allocate a new
	// buffer, we don't free the old buffer. Instead, we store the
	// pointer in the "old" field so that the read ack function can
	// free it.
	//
	// To avoid invalidating the pointer when we are moving back the
	// content since there is enough memory at the start of the buffer,
	// we just avoid that. Even if there is enough memory considering
	// left and right free regions, we allocate a new buffer.

	HTTP_ASSERT((queue->flags & BYTE_QUEUE_WRITE) == 0);

	unsigned int total_free_space = queue->size - queue->used;
	unsigned int free_space_after_data = queue->size - queue->used - queue->head;

	int moved = 0;
	if (free_space_after_data < umincap) {

		if (total_free_space < umincap || (queue->read_target == queue->data)) {
			// Resize required

			if (queue->used + umincap > queue->limit) {
				queue->flags |= BYTE_QUEUE_ERROR;
				return 0;
			}

			unsigned int size;
			if (queue->size > UINT32_MAX / 2)
				size = UINT32_MAX;
			else
				size = 2 * queue->size;

			if (size < queue->used + umincap)
				size = queue->used + umincap;

			if (size > queue->limit)
				size = queue->limit;

			char *data = callback_malloc(queue, size);
			if (!data) {
				queue->flags |= BYTE_QUEUE_ERROR;
				return 0;
			}

			if (queue->used > 0)
				memcpy(data, queue->data + queue->head, queue->used);

			if (queue->read_target != queue->data)
				callback_free(queue, queue->data, queue->size);

			queue->data = data;
			queue->head = 0;
			queue->size = size;

		} else {
			// Move required
			memmove(queue->data, queue->data + queue->head, queue->used);
			queue->head = 0;
		}

		moved = 1;
	}

	return moved;
}

static HTTP_ByteQueueOffset
byte_queue_offset(HTTP_ByteQueue *queue)
{
	if (queue->flags & BYTE_QUEUE_ERROR)
		return (HTTP_ByteQueueOffset) { 0 };
	return (HTTP_ByteQueueOffset) { queue->curs + queue->used };
}

static unsigned int
byte_queue_size_from_offset(HTTP_ByteQueue *queue, HTTP_ByteQueueOffset off)
{
	return queue->curs + queue->used - off;
}

static void
byte_queue_patch(HTTP_ByteQueue *queue, HTTP_ByteQueueOffset off,
	char *src, unsigned int len)
{
	if (queue->flags & BYTE_QUEUE_ERROR)
		return;

	// Check that the offset is in range
	HTTP_ASSERT(off >= queue->curs && off - queue->curs < queue->used);

	// Check that the length is in range
	HTTP_ASSERT(len <= queue->used - (off - queue->curs));

	// Perform the patch
	char *dst = queue->data + queue->head + (off - queue->curs);
	memcpy(dst, src, len);
}

static void
byte_queue_remove_from_offset(HTTP_ByteQueue *queue, HTTP_ByteQueueOffset offset)
{
	if (queue->flags & BYTE_QUEUE_ERROR)
		return;

	unsigned long long num = (queue->curs + queue->used) - offset;
	HTTP_ASSERT(num <= queue->used);

	queue->used -= num;
}

static void
byte_queue_write(HTTP_ByteQueue *queue, const char *str, int len)
{
    if (str == NULL) str = "";
	if (len < 0) len = strlen(str);

	int cap;
	byte_queue_write_setmincap(queue, len);
	char *dst = byte_queue_write_buf(queue, &cap);
	if (dst) memcpy(dst, str, len);
	byte_queue_write_ack(queue, len);
}

static void
byte_queue_write_fmt2(HTTP_ByteQueue *queue, const char *fmt, va_list args)
{
	if (queue->flags & BYTE_QUEUE_ERROR)
		return;

	va_list args2;
	va_copy(args2, args);

	int cap;
	byte_queue_write_setmincap(queue, 128);
	char *dst = byte_queue_write_buf(queue, &cap);

	int len = vsnprintf(dst, cap, fmt, args);
	if (len < 0) {
		queue->flags |= BYTE_QUEUE_ERROR;
		va_end(args2);
		va_end(args);
		return;
	}

	if (len > cap) {
		byte_queue_write_ack(queue, 0);
		byte_queue_write_setmincap(queue, len+1);
		dst = byte_queue_write_buf(queue, &cap);
		vsnprintf(dst, cap, fmt, args2);
	}

	byte_queue_write_ack(queue, len);

	va_end(args2);
	va_end(args);
}

static void
byte_queue_write_fmt(HTTP_ByteQueue *queue, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	byte_queue_write_fmt2(queue, fmt, args);
	va_end(args);
}

#define TEN_SPACES "          "

void http_engine_init(HTTP_Engine *eng, int client, HTTP_MemoryFunc memfunc, void *memfuncdata)
{
	if (client)
		eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_URL;
	else
		eng->state = HTTP_ENGINE_STATE_SERVER_RECV_BUF;

	eng->closing = 0;
	eng->numexch = 0;

	byte_queue_init(&eng->input,  1<<20, memfunc, memfuncdata);
	byte_queue_init(&eng->output, 1<<20, memfunc, memfuncdata);
}

void http_engine_free(HTTP_Engine *eng)
{
	byte_queue_free(&eng->input);
	byte_queue_free(&eng->output);
	eng->state = HTTP_ENGINE_STATE_NONE;
}

void http_engine_close(HTTP_Engine *eng)
{
	if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT)
		eng->state = HTTP_ENGINE_STATE_CLIENT_CLOSED;
	else
		eng->state = HTTP_ENGINE_STATE_SERVER_CLOSED;
}

HTTP_EngineState http_engine_state(HTTP_Engine *eng)
{
	return eng->state;
}

const char* http_engine_statestr(HTTP_EngineState state) { // TODO: remove
    switch (state) {
        case HTTP_ENGINE_STATE_NONE: return "NONE";
        case HTTP_ENGINE_STATE_CLIENT_PREP_URL: return "CLIENT_PREP_URL";
        case HTTP_ENGINE_STATE_CLIENT_PREP_HEADER: return "CLIENT_PREP_HEADER";
        case HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF: return "CLIENT_PREP_BODY_BUF";
        case HTTP_ENGINE_STATE_CLIENT_PREP_BODY_ACK: return "CLIENT_PREP_BODY_ACK";
        case HTTP_ENGINE_STATE_CLIENT_PREP_ERROR: return "CLIENT_PREP_ERROR";
        case HTTP_ENGINE_STATE_CLIENT_SEND_BUF: return "CLIENT_SEND_BUF";
        case HTTP_ENGINE_STATE_CLIENT_SEND_ACK: return "CLIENT_SEND_ACK";
        case HTTP_ENGINE_STATE_CLIENT_RECV_BUF: return "CLIENT_RECV_BUF";
        case HTTP_ENGINE_STATE_CLIENT_RECV_ACK: return "CLIENT_RECV_ACK";
        case HTTP_ENGINE_STATE_CLIENT_READY: return "CLIENT_READY";
        case HTTP_ENGINE_STATE_CLIENT_CLOSED: return "CLIENT_CLOSED";
        case HTTP_ENGINE_STATE_SERVER_RECV_BUF: return "SERVER_RECV_BUF";
        case HTTP_ENGINE_STATE_SERVER_RECV_ACK: return "SERVER_RECV_ACK";
        case HTTP_ENGINE_STATE_SERVER_PREP_STATUS: return "SERVER_PREP_STATUS";
        case HTTP_ENGINE_STATE_SERVER_PREP_HEADER: return "SERVER_PREP_HEADER";
        case HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF: return "SERVER_PREP_BODY_BUF";
        case HTTP_ENGINE_STATE_SERVER_PREP_BODY_ACK: return "SERVER_PREP_BODY_ACK";
        case HTTP_ENGINE_STATE_SERVER_PREP_ERROR: return "SERVER_PREP_ERROR";
        case HTTP_ENGINE_STATE_SERVER_SEND_BUF: return "SERVER_SEND_BUF";
        case HTTP_ENGINE_STATE_SERVER_SEND_ACK: return "SERVER_SEND_ACK";
        case HTTP_ENGINE_STATE_SERVER_CLOSED: return "SERVER_CLOSED";
        default: return "UNKNOWN";
    }
}

char *http_engine_recvbuf(HTTP_Engine *eng, int *cap)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_RECV_BUF) == 0) {
		*cap = 0;
		return NULL;
	}

	eng->state &= ~HTTP_ENGINE_STATEBIT_RECV_BUF;
	eng->state |=  HTTP_ENGINE_STATEBIT_RECV_ACK;

	byte_queue_write_setmincap(&eng->input, 1<<9);
	if (byte_queue_error(&eng->input)) {
		*cap = 0;
		if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT)
			eng->state = HTTP_ENGINE_STATE_CLIENT_CLOSED;
		else
			eng->state = HTTP_ENGINE_STATE_SERVER_CLOSED;
		return NULL;
	}

	return byte_queue_write_buf(&eng->input, cap);
}

static int
should_keep_alive(HTTP_Engine *eng)
{
	HTTP_ASSERT(eng->state & HTTP_ENGINE_STATEBIT_PREP);

#if 0
	// If the parent system doesn't want us to reuse
	// the connection, we certainly can't keep alive.
	if ((eng->state & TINYHTTP_STREAM_REUSE) == 0)
		return 0;
#endif

	if (eng->numexch >= 100) // TODO: Make this a parameter
		return 0;

	HTTP_Request *req = &eng->result.req;

	// If the client is using HTTP/1.0, we can't
	// keep alive.
	if (req->minor == 0)
		return 0;

	// TODO: This assumes "Connection" can only hold a single token,
	//       but this is not true.
	int i = http_find_header(req->headers, req->num_headers, HTTP_STR("Connection"));
	if (i >= 0 && http_streqcase(req->headers[i].value, HTTP_STR("Close")))
		return 0;

	return 1;
}

static void process_incoming_request(HTTP_Engine *eng)
{
	HTTP_ASSERT(eng->state == HTTP_ENGINE_STATE_SERVER_RECV_ACK
		|| eng->state == HTTP_ENGINE_STATE_SERVER_SEND_ACK
		|| eng->state == HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF
		|| eng->state == HTTP_ENGINE_STATE_SERVER_PREP_ERROR);

	char *src;
	int len;
	src = byte_queue_read_buf(&eng->input, &len);

	int ret = http_parse_request(src, len, &eng->result.req);

	if (ret == 0) {
		byte_queue_read_ack(&eng->input, 0);
		eng->state = HTTP_ENGINE_STATE_SERVER_RECV_BUF;
		return;
	}

	if (ret < 0) {
		byte_queue_read_ack(&eng->input, 0);
		byte_queue_write(&eng->output,
			"HTTP/1.1 400 Bad Request\r\n"
			"Connection: Close\r\n"
			"Content-Length: 0\r\n"
			"\r\n", -1
		);
		if (byte_queue_error(&eng->output))
			eng->state = HTTP_ENGINE_STATE_SERVER_CLOSED;
		else {
			eng->closing = 1;
			eng->state = HTTP_ENGINE_STATE_SERVER_SEND_BUF;
		}
		return;
	}

	HTTP_ASSERT(ret > 0);

	eng->state = HTTP_ENGINE_STATE_SERVER_PREP_STATUS;
	eng->reqsize = ret;
	eng->keepalive = should_keep_alive(eng);
	eng->response_offset = byte_queue_offset(&eng->output);
}

void http_engine_recvack(HTTP_Engine *eng, int num)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_RECV_ACK) == 0)
		return;

	byte_queue_write_ack(&eng->input, num);

	if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT) {
		
		char *src;
		int len;
		src = byte_queue_read_buf(&eng->input, &len);

		int ret = http_parse_response(src, len, &eng->result.res);

		if (ret == 0) {
			byte_queue_read_ack(&eng->input, 0);
			eng->state = HTTP_ENGINE_STATE_CLIENT_RECV_BUF;
			return;
		}

		if (ret < 0) {
			eng->state = HTTP_ENGINE_STATE_CLIENT_CLOSED;
			return;
		}

		HTTP_ASSERT(ret > 0);

		eng->state = HTTP_ENGINE_STATE_CLIENT_READY;

	} else {
		process_incoming_request(eng);
	}
}

char *http_engine_sendbuf(HTTP_Engine *eng, int *len)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_SEND_BUF) == 0) {
		*len = 0;
		return NULL;
	}

	eng->state &= ~HTTP_ENGINE_STATEBIT_SEND_BUF;
	eng->state |=  HTTP_ENGINE_STATEBIT_SEND_ACK;

	return byte_queue_read_buf(&eng->output, len);
}

void http_engine_sendack(HTTP_Engine *eng, int num)
{
	if (eng->state != HTTP_ENGINE_STATE_SERVER_SEND_ACK &&
		eng->state != HTTP_ENGINE_STATE_CLIENT_SEND_ACK)
		return;

	byte_queue_read_ack(&eng->output, num);

	if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT) {
		if (byte_queue_empty(&eng->output))
			eng->state = HTTP_ENGINE_STATE_CLIENT_RECV_BUF;
		else
			eng->state = HTTP_ENGINE_STATE_CLIENT_SEND_BUF;
	} else {
		if (byte_queue_empty(&eng->output)) {
			if (!eng->closing && eng->keepalive)
				process_incoming_request(eng);
			else
				eng->state = HTTP_ENGINE_STATE_SERVER_CLOSED;
		} else
			eng->state = HTTP_ENGINE_STATE_SERVER_SEND_BUF;
	}
}

HTTP_Request *http_engine_getreq(HTTP_Engine *eng)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_REQUEST) == 0)
		return NULL;
	return &eng->result.req;
}

HTTP_Response *http_engine_getres(HTTP_Engine *eng)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_RESPONSE) == 0)
		return NULL;
	return &eng->result.res;
}

void http_engine_url(HTTP_Engine *eng, HTTP_Method method, HTTP_String url, int minor)
{
	if (eng->state != HTTP_ENGINE_STATE_CLIENT_PREP_URL)
		return;

	eng->response_offset = byte_queue_offset(&eng->output); // TODO: rename response_offset to something that makes sense for clients

	HTTP_URL parsed_url;
	int ret = http_parse_url(url.ptr, url.len, &parsed_url);
	if (ret != url.len) {
		eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_ERROR;
		return;
	}

	HTTP_String method_and_space = HTTP_STR("???");
	switch (method) {
		case HTTP_METHOD_GET    : method_and_space = HTTP_STR("GET ");     break;
		case HTTP_METHOD_HEAD   : method_and_space = HTTP_STR("HEAD ");    break;
		case HTTP_METHOD_POST   : method_and_space = HTTP_STR("POST ");    break;
		case HTTP_METHOD_PUT    : method_and_space = HTTP_STR("PUT ");     break;
		case HTTP_METHOD_DELETE : method_and_space = HTTP_STR("DELETE ");  break;
		case HTTP_METHOD_CONNECT: method_and_space = HTTP_STR("CONNECT "); break;
		case HTTP_METHOD_OPTIONS: method_and_space = HTTP_STR("OPTIONS "); break;
		case HTTP_METHOD_TRACE  : method_and_space = HTTP_STR("TRACE ");   break;
		case HTTP_METHOD_PATCH  : method_and_space = HTTP_STR("PATCH ");   break;
	}

	HTTP_String path = parsed_url.path;
	if (path.len == 0)
		path = HTTP_STR("/");

	byte_queue_write(&eng->output, method_and_space.ptr, method_and_space.len);
	byte_queue_write(&eng->output, path.ptr, path.len);
	byte_queue_write(&eng->output, parsed_url.query.ptr, parsed_url.query.len);
	byte_queue_write(&eng->output, minor ? " HTTP/1.1\r\nHost: " : " HTTP/1.0\r\nHost: ", -1);
	byte_queue_write(&eng->output, parsed_url.authority.host.text.ptr, parsed_url.authority.host.text.len);
	if (parsed_url.authority.port > 0)
		byte_queue_write_fmt(&eng->output, "%d", parsed_url.authority.port);
	byte_queue_write(&eng->output, "\r\n", 2);

	eng->keepalive = 1; // TODO

	eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_HEADER;
}


static const char*
get_status_text(int code)
{
	switch(code) {

		case 100: return "Continue";
		case 101: return "Switching Protocols";
		case 102: return "Processing";

		case 200: return "OK";
		case 201: return "Created";
		case 202: return "Accepted";
		case 203: return "Non-Authoritative Information";
		case 204: return "No Content";
		case 205: return "Reset Content";
		case 206: return "Partial Content";
		case 207: return "Multi-Status";
		case 208: return "Already Reported";

		case 300: return "Multiple Choices";
		case 301: return "Moved Permanently";
		case 302: return "Found";
		case 303: return "See Other";
		case 304: return "Not Modified";
		case 305: return "Use Proxy";
		case 306: return "Switch Proxy";
		case 307: return "Temporary Redirect";
		case 308: return "Permanent Redirect";

		case 400: return "Bad Request";
		case 401: return "Unauthorized";
		case 402: return "Payment Required";
		case 403: return "Forbidden";
		case 404: return "Not Found";
		case 405: return "Method Not Allowed";
		case 406: return "Not Acceptable";
		case 407: return "Proxy Authentication Required";
		case 408: return "Request Timeout";
		case 409: return "Conflict";
		case 410: return "Gone";
		case 411: return "Length Required";
		case 412: return "Precondition Failed";
		case 413: return "Request Entity Too Large";
		case 414: return "Request-URI Too Long";
		case 415: return "Unsupported Media Type";
		case 416: return "Requested Range Not Satisfiable";
		case 417: return "Expectation Failed";
		case 418: return "I'm a teapot";
		case 420: return "Enhance your calm";
		case 422: return "Unprocessable Entity";
		case 426: return "Upgrade Required";
		case 429: return "Too many requests";
		case 431: return "Request Header Fields Too Large";
		case 449: return "Retry With";
		case 451: return "Unavailable For Legal Reasons";

		case 500: return "Internal Server Error";
		case 501: return "Not Implemented";
		case 502: return "Bad Gateway";
		case 503: return "Service Unavailable";
		case 504: return "Gateway Timeout";
		case 505: return "HTTP Version Not Supported";
		case 509: return "Bandwidth Limit Exceeded";
	}
	return "???";
}

void http_engine_status(HTTP_Engine *eng, int status)
{
	if (eng->state != HTTP_ENGINE_STATE_SERVER_PREP_STATUS)
		return;

	byte_queue_write_fmt(&eng->output,
		"HTTP/1.1 %d %s\r\n",
		status, get_status_text(status));

	eng->state = HTTP_ENGINE_STATE_SERVER_PREP_HEADER;
}

void http_engine_header(HTTP_Engine *eng, HTTP_String str)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_PREP_HEADER) == 0)
		return;

	// TODO: Check that the header is valid

	byte_queue_write(&eng->output, str.ptr, str.len);
	byte_queue_write(&eng->output, "\r\n", 2);
}

void http_engine_header_fmt2(HTTP_Engine *eng, const char *fmt, va_list args)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_PREP_HEADER) == 0)
		return;

	// TODO: Check that the header is valid

	byte_queue_write_fmt2(&eng->output, fmt, args);
	byte_queue_write(&eng->output, "\r\n", 2);
}

void http_engine_header_fmt(HTTP_Engine *eng, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	http_engine_header_fmt2(eng, fmt, args);
	va_end(args);
}

static void
complete_message_head(HTTP_Engine *eng)
{
	if (eng->keepalive) byte_queue_write(&eng->output, "Connection: Keep-Alive\r\n", -1);
	else                byte_queue_write(&eng->output, "Connection: Close\r\n", -1);

	byte_queue_write(&eng->output, "Content-Length: ", -1);
	eng->content_length_value_offset = byte_queue_offset(&eng->output);
	byte_queue_write(&eng->output, TEN_SPACES "\r\n", -1);

	byte_queue_write(&eng->output, "\r\n", -1);
	eng->content_length_offset = byte_queue_offset(&eng->output);
}

static void complete_message_body(HTTP_Engine *eng)
{
	unsigned int content_length = byte_queue_size_from_offset(&eng->output, eng->content_length_offset);

	if (content_length > UINT32_MAX) {
		// TODO
	}

	char tmp[10];

	tmp[0] = '0' + content_length / 1000000000; content_length %= 1000000000;
	tmp[1] = '0' + content_length / 100000000;  content_length %= 100000000;
	tmp[2] = '0' + content_length / 10000000;   content_length %= 10000000;
	tmp[3] = '0' + content_length / 1000000;    content_length %= 1000000;
	tmp[4] = '0' + content_length / 100000;     content_length %= 100000;
	tmp[5] = '0' + content_length / 10000;      content_length %= 10000;
	tmp[6] = '0' + content_length / 1000;       content_length %= 1000;
	tmp[7] = '0' + content_length / 100;        content_length %= 100;
	tmp[8] = '0' + content_length / 10;         content_length %= 10;
	tmp[9] = '0' + content_length;

	int i = 0;
	while (i < 9 && tmp[i] == '0')
		i++;

	byte_queue_patch(&eng->output, eng->content_length_value_offset, tmp + i, 10 - i);
}

void http_engine_body(HTTP_Engine *eng, HTTP_String str)
{
	http_engine_bodycap(eng, str.len);
	int cap;
	char *buf = http_engine_bodybuf(eng, &cap);
	if (buf) {
		memcpy(buf, str.ptr, str.len);
		http_engine_bodyack(eng, str.len);
	}
}

static void ensure_body_entered(HTTP_Engine *eng)
{
	if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT) {

		if (eng->state == HTTP_ENGINE_STATE_CLIENT_PREP_HEADER) {
			complete_message_head(eng);
			eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF;
		}

	} else {

		if (eng->state == HTTP_ENGINE_STATE_SERVER_PREP_HEADER) {
			complete_message_head(eng);
			eng->state = HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF;
		}
	}
}

void http_engine_bodycap(HTTP_Engine *eng, int mincap)
{
	ensure_body_entered(eng);
	if (eng->state != HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF &&
		eng->state != HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF)
		return;

	byte_queue_write_setmincap(&eng->output, mincap);
}

char *http_engine_bodybuf(HTTP_Engine *eng, int *cap)
{
	ensure_body_entered(eng);
	if (eng->state != HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF &&
		eng->state != HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF) {
		*cap = 0;
		return NULL;
	}

	if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT)
		eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_BODY_ACK;
	else
		eng->state = HTTP_ENGINE_STATE_SERVER_PREP_BODY_ACK;

	return byte_queue_write_buf(&eng->output, cap);
}

void http_engine_bodyack(HTTP_Engine *eng, int num)
{
	if (eng->state != HTTP_ENGINE_STATE_CLIENT_PREP_BODY_ACK &&
		eng->state != HTTP_ENGINE_STATE_SERVER_PREP_BODY_ACK)
		return;

	byte_queue_write_ack(&eng->output, num);

	if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT)
		eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF;
	else
		eng->state = HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF;
}

void http_engine_done(HTTP_Engine *eng)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_PREP) == 0)
		return;

	if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT) {

		if (eng->state == HTTP_ENGINE_STATE_CLIENT_PREP_URL) {
			eng->state = HTTP_ENGINE_STATE_CLIENT_CLOSED;
			return;
		}

		if (eng->state == HTTP_ENGINE_STATE_CLIENT_PREP_HEADER) {
			complete_message_head(eng);
			eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF;
		}

		if (eng->state == HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF)
			complete_message_body(eng);

		if (eng->state == HTTP_ENGINE_STATE_CLIENT_PREP_ERROR) {
			eng->state = HTTP_ENGINE_STATE_CLIENT_CLOSED;
			return;
		}

		if (byte_queue_error(&eng->output)) {
			eng->state = HTTP_ENGINE_STATE_CLIENT_CLOSED;
			return;
		}

		eng->state = HTTP_ENGINE_STATE_CLIENT_SEND_BUF;

	} else {

		if (eng->state == HTTP_ENGINE_STATE_SERVER_PREP_HEADER) {
			complete_message_head(eng);
			eng->state = HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF;
		}

		if (eng->state == HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF)
			complete_message_body(eng);

		if (eng->state == HTTP_ENGINE_STATE_SERVER_PREP_ERROR) {
			byte_queue_remove_from_offset(&eng->output, eng->response_offset);
			byte_queue_write(&eng->output,
				"HTTP/1.1 500 Internal Server Error\r\n"
				"Content-Length: 0\r\n"
				"Connection: Close\r\n"
				"\r\n",
				-1
			);
		}

		if (byte_queue_error(&eng->output)) {
			eng->state = HTTP_ENGINE_STATE_SERVER_CLOSED;
			return;
		}

		byte_queue_read_ack(&eng->input, eng->reqsize);
		eng->state = HTTP_ENGINE_STATE_SERVER_SEND_BUF;
	}
}

void http_engine_undo(HTTP_Engine *eng)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_PREP) == 0)
		return;

	byte_queue_write_ack(&eng->output, 0);
	byte_queue_remove_from_offset(&eng->output, eng->response_offset);

	if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT)
		eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_URL;
	else
		eng->state = HTTP_ENGINE_STATE_SERVER_PREP_STATUS;
}