#include "tinyhttp.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#ifdef TINYHTTP_SERVER_ENABLE
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#define CLOSESOCKET closesocket
#elif defined(__linux__)
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#define SOCKET int
#define CLOSESOCKET close
#define INVALID_SOCKET -1
#endif
#endif

#define MAX_U16 ((unsigned short) -1)
#define MAX_U32 ((unsigned int) -1)
#define MAX_U64 ((unsigned long long) -1ULL)

#define ASSERT(X) {if (!(X)) __builtin_trap();}
#define COUNTOF(X) (sizeof(X)/sizeof((X)[0]))

#define DUMP_IO 0

////////////////////////////////////////////////////////////////////////////////////
// DEBUG UTILITIES                                                                //
////////////////////////////////////////////////////////////////////////////////////

#if DUMP_IO
#include <stdio.h>
static void
print_bytes(char *prefix, char *src, int len)
{
	if (src == NULL) {
		printf("%s (null)\n", prefix);
		return;
	}

	int cur = 0;
	int newline = 1;
	while (cur < len) {
		int start = cur;
		while (cur < len && src[cur] != '\n' && src[cur] != '\r')
			cur++;
		if (newline) {
			printf("%s", prefix);
			newline = 0;
		}
		printf("%.*s", cur - start, src + start);
		if (cur < len) {
			if (src[cur] == '\r')
				printf("\\r");
			else {
				printf("\\n\n");
				newline = 1;
			}
			cur++;
		}
	}
	if (cur > 0 && src[cur-1] != '\n')
		printf("\n");
}
#endif

#if DUMP_IO
static void
dump_state(int state, const char *file, int line)
{
	printf("state = ");
	if (state == TINYHTTP_STREAM_FREE)
		printf("FREE ");

	if (state & TINYHTTP_STREAM_SEND)
		printf("SEND ");

	if (state & TINYHTTP_STREAM_RECV)
		printf("RECV ");

	if (state & TINYHTTP_STREAM_READY)
		printf("READY ");

	if (state & TINYHTTP_STREAM_CLOSE)
		printf("CLOSE ");

	if (state & TINYHTTP_STREAM_REUSE)
		printf("REUSE ");

	if (state & TINYHTTP_STREAM_SEND_STARTED)
		printf("SEND_STARTED ");

	if (state & TINYHTTP_STREAM_RECV_STARTED)
		printf("RECV_STARTED ");
	
	printf(" (in %s:%d)\n", file, line);
}
#define DUMP_STATE(state) dump_state(state, __FILE__, __LINE__);
#else
#define DUMP_STATE(...)
#endif

////////////////////////////////////////////////////////////////////////////////////
// HTTP REQUEST PARSER                                                            //
////////////////////////////////////////////////////////////////////////////////////

static ptrdiff_t
parse_request_head(char *src, ptrdiff_t len, TinyHTTPRequest *req)
{
	ptrdiff_t off;
	ptrdiff_t cur = 0;

	int found = 0;
	for (ptrdiff_t peek = 0; len - peek > 3; peek++) {
		if (src[peek+0] == '\r' &&
			src[peek+1] == '\n' && // Boyer-Moore?
			src[peek+2] == '\r' &&
			src[peek+3] == '\n') {
			found = 1;
			break;
		}
	}
	if (!found)
		return 0;

	if (len - cur > 3
		&& src[cur+0] == 'G'
		&& src[cur+1] == 'E'
		&& src[cur+2] == 'T'
		&& src[cur+3] == ' ') {
		cur += 4;
		req->method = TINYHTTP_METHOD_GET;
	} else if (len - cur > 4
		&& src[cur+0] == 'P'
		&& src[cur+1] == 'O'
		&& src[cur+2] == 'S'
		&& src[cur+3] == 'T'
		&& src[cur+4] == ' ') {
		cur += 5;
		req->method = TINYHTTP_METHOD_POST;
	} else
		return -405;

	off = cur;
	while (cur < len && src[cur] != ' ') // TODO: More robust
		cur++;
	req->path     = src + off;
	req->path_len = cur - off;

	if (len - cur <= 5
		|| src[cur+0] != ' '
		|| src[cur+1] != 'H'
		|| src[cur+2] != 'T'
		|| src[cur+3] != 'T'
		|| src[cur+4] != 'P'
		|| src[cur+5] != '/')
		return -400;
	cur += 6;

	if (3 < len - cur
		&& src[cur+0] == '1'
		&& src[cur+1] == '.'
		&& src[cur+2] == '1'
		&& src[cur+3] == '\r'
		&& src[cur+4] == '\n') {
		cur += 5;
		req->minor = 1;
	} else if (4 < len - cur
		&& src[cur+0] == '1'
		&& src[cur+1] == '.'
		&& src[cur+2] == '0'
		&& src[cur+3] == '\r'
		&& src[cur+4] == '\n') {
		cur += 5;
		req->minor = 0;
	} else if (2 < len - cur
		&& src[cur+0] == '1'
		&& src[cur+1] == '\r'
		&& src[cur+2] == '\n') {
		cur += 3;
		req->minor = 0;
	} else {
		return -505;
	}

	req->num_headers = 0;
	while (len - cur < 2 || src[cur+0] != '\r' || src[cur+1] != '\n') {

		ptrdiff_t name_off = cur;
		while (cur < len && src[cur] != ':') // TODO: robust
			cur++;
		ptrdiff_t name_len = cur - name_off;

		if (cur == len)
			return -400;
		cur++;

		ptrdiff_t value_off = cur;
		while (cur < len && src[cur] != '\r')
			cur++;
		ptrdiff_t value_len = cur - value_off;

		if (cur == len)
			return -400;
		cur++;

		if (cur == len || src[cur] != '\n')
			return -400;
		cur++;

		// TODO: Validate name and value:
		//   1) No spaces are allowed after the name
		//   2) Spaces should be trimmed from the value

		if (req->num_headers < TINYHTTP_HEADER_LIMIT) {
			TinyHTTPHeader *header = &req->headers[req->num_headers++];
			header->name      = src + name_off;
			header->name_len  = name_len;
			header->value     = src + value_off;
			header->value_len = value_len;
		}
	}
	cur += 2;

	return cur;
}

static char
to_lower(char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A' + 'a';
	return c;
}

static int
eqstrnocase(const char *s1, ptrdiff_t len1, const char *s2, ptrdiff_t len2)
{
	if (len1 != len2)
		return 0;
	for (int i = 0; i < len1; i++)
		if (to_lower(s1[i]) != to_lower(s2[i]))
			return 0;
	return 1;
}

static int
find_header(TinyHTTPRequest *req, const char *name)
{
	for (int i = 0; i < req->num_headers; i++) {
		TinyHTTPHeader *header = &req->headers[i];
		if (eqstrnocase(header->name, header->name_len, name, strlen(name)))
			return i;
	}
	return -1;
}

enum {
	TRANSFER_ENCODING_CHUNKED,
	TRANSFER_ENCODING_COMPRESS,
	TRANSFER_ENCODING_DEFLATE,
	TRANSFER_ENCODING_GZIP,
};

static int
parse_transfer_encoding(char *src, ptrdiff_t len, int *items, int max)
{
	int num = 0;
	ptrdiff_t cur = 0;
	for (;;) {

		while (cur < len && (src[cur] == ' ' || src[cur] == '\t'))
			cur++;

		if (6 < len - cur
			&& src[cur+0] == 'c'
			&& src[cur+1] == 'h'
			&& src[cur+2] == 'u'
			&& src[cur+3] == 'n'
			&& src[cur+4] == 'k'
			&& src[cur+5] == 'e'
			&& src[cur+6] == 'd') {
			if (num == max)
				return -1;
			items[num++] = TRANSFER_ENCODING_CHUNKED;
			cur += 7;
		} else if (7 < len - cur
			&& src[cur+0] == 'c'
			&& src[cur+1] == 'o'
			&& src[cur+2] == 'm'
			&& src[cur+3] == 'p'
			&& src[cur+4] == 'r'
			&& src[cur+5] == 'e'
			&& src[cur+6] == 's'
			&& src[cur+7] == 's') {
			if (num == max)
				return -1;
			items[num++] = TRANSFER_ENCODING_COMPRESS;
			cur += 8;
		} else if (6 < len - cur
			&& src[cur+0] == 'd'
			&& src[cur+1] == 'e'
			&& src[cur+2] == 'f'
			&& src[cur+3] == 'l'
			&& src[cur+4] == 'a'
			&& src[cur+5] == 't'
			&& src[cur+6] == 'e') {
			if (num == max)
				return -1;
			items[num++] = TRANSFER_ENCODING_DEFLATE;
			cur += 7;
		} else if (3 < len - cur
			&& src[cur+0] == 'g'
			&& src[cur+1] == 'z'
			&& src[cur+2] == 'i'
			&& src[cur+3] == 'p') {
			if (num == max)
				return -1;
			items[num++] = TRANSFER_ENCODING_GZIP;
			cur += 4;
		} else {
			return -1;
		}

		while (cur < len && (src[cur] == ' ' || src[cur]  == '\t'))
			cur++;

		if (cur == len)
			break;

		if (src[cur] != ',')
			return -1;
		cur++;
	}

	return num;
}

static int is_digit(char c)
{
	return c >= '0' && c <= '9';
}

static int
parse_content_length(char *src, ptrdiff_t len, unsigned long long *out)
{
	ptrdiff_t cur = 0;
	while (cur < len && (src[cur] == ' ' || src[cur] == '\t'))
		cur++;

	if (cur == len || !is_digit(src[cur]))
		return -1;

	unsigned long long buf = 0;
	do {
		int d = src[cur++] - '0';
		if (buf > (MAX_U64 - d) / 10)
			return -1;
		buf = buf * 10 + d;
	} while (cur < len && is_digit(src[cur]));

	*out = buf;
	return 0;
}

static int
parse_request(char *src, ptrdiff_t len, unsigned long long body_limit, TinyHTTPRequest *req)
{
	ptrdiff_t ret = parse_request_head(src, len, req);
	if (ret <= 0)
		return ret;
	ptrdiff_t head_len = ret;

	int transfer_encoding_index = find_header(req, "Transfer-Encoding");
	if (transfer_encoding_index >= 0) {

		TinyHTTPHeader *header = &req->headers[transfer_encoding_index];

		int items[8];
		int num = parse_transfer_encoding(header->value, header->value_len, items, COUNTOF(items));
		if (num < 0)
			return -400;

		for (;;) {

			return -501; // TODO: Parse chunks
		}

		return 1;
	}

	int content_length_index = find_header(req, "Content-Length");
	if (content_length_index >= 0) {

		TinyHTTPHeader *header = &req->headers[content_length_index];

		unsigned long long content_length;
		if (parse_content_length(header->value, header->value_len, &content_length) < 0)
			return -400;
		if (content_length > body_limit || content_length > MAX_U32)
			return -413;
		if (content_length < (unsigned long long) (len - head_len))
			return 0;

		req->body = src + head_len;
		req->body_len = content_length;
		return head_len + content_length;
	}

	req->body = NULL;
	req->body_len = 0;
	return head_len;
}

////////////////////////////////////////////////////////////////////////////////////
// BYTE QUEUE                                                                     //
////////////////////////////////////////////////////////////////////////////////////
//
// This is the implementation of a byte queue useful
// for systems that need to process streams of bytes.
//
// It features sticky errors, a zero-copy interface,
// and a safe mechanism to patch previously written
// bytes.
//
// Only up to 4GB of data can be stored at once.

static void*
callback_malloc(TinyHTTPByteQueue *queue, ptrdiff_t len)
{
	return queue->memfunc(TINYHTTP_MEM_MALLOC, NULL, len, queue->memfuncdata);
}

static void*
callback_realloc(TinyHTTPByteQueue *queue, void *ptr, ptrdiff_t len)
{
	return queue->memfunc(TINYHTTP_MEM_REALLOC, ptr, len, queue->memfuncdata);
}

static void
callback_free(TinyHTTPByteQueue *queue, void *ptr, ptrdiff_t len)
{
	queue->memfunc(TINYHTTP_MEM_FREE, ptr, len, queue->memfuncdata);
}

// Initialize the queue
static void
byte_queue_init(TinyHTTPByteQueue *queue, unsigned int limit, TinyHTTPMemoryFunc memfunc, void *memfuncdata)
{
	queue->flags = 0;
	queue->lock = 0;
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
byte_queue_free(TinyHTTPByteQueue *queue)
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
byte_queue_error(TinyHTTPByteQueue *queue)
{
	return queue->flags & BYTE_QUEUE_ERROR;
}

static void
byte_queue_setlimit(TinyHTTPByteQueue *queue, unsigned int value)
{
	queue->limit = value;
}

static char*
byte_queue_peek(TinyHTTPByteQueue *queue, ptrdiff_t *len)
{
	if ((queue->flags & (BYTE_QUEUE_ERROR)) || queue->data == NULL) {
		*len = 0;
		return NULL;
	}

	*len = queue->used;
	return queue->data + queue->head;
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
byte_queue_read_buf(TinyHTTPByteQueue *queue, ptrdiff_t *len)
{
	if ((queue->flags & (BYTE_QUEUE_ERROR)) || queue->data == NULL) {
		*len = 0;
		return NULL;
	}

	ASSERT((queue->flags & BYTE_QUEUE_READ) == 0);
	queue->flags |= BYTE_QUEUE_READ;
	queue->read_target      = queue->data;
	queue->read_target_size = queue->size;

	*len = queue->used;
	return queue->data + queue->head;
}

// Complete a previously started operation on the queue.
static void
byte_queue_read_ack(TinyHTTPByteQueue *queue, ptrdiff_t num)
{
	if (queue->flags & BYTE_QUEUE_ERROR)
		return;

	if ((queue->flags & BYTE_QUEUE_READ) == 0)
		return;

	queue->flags &= ~BYTE_QUEUE_READ;

	ASSERT(num <= queue->used);
	queue->head += num;
	queue->used -= num;
	queue->curs += num;

	if (queue->read_target) {
		if (queue->read_target != queue->data)
			callback_free(queue, queue->read_target, queue->read_target_size);
		queue->read_target = NULL;
		queue->read_target_size = 0;
	}
}

static int
byte_queue_read_started(TinyHTTPByteQueue *queue)
{
	return (queue->flags & BYTE_QUEUE_READ) == BYTE_QUEUE_READ;
}

static char*
byte_queue_write_buf(TinyHTTPByteQueue *queue, ptrdiff_t *cap)
{
	if ((queue->flags & BYTE_QUEUE_ERROR) || queue->data == NULL) {
		*cap = 0;
		return NULL;
	}

	ASSERT((queue->flags & BYTE_QUEUE_WRITE) == 0);
	queue->flags |= BYTE_QUEUE_WRITE;

	*cap = queue->size - (queue->head + queue->used);
	return queue->data + (queue->head + queue->used);
}

static void
byte_queue_write_ack(TinyHTTPByteQueue *queue, ptrdiff_t num)
{
	if (queue->flags & BYTE_QUEUE_ERROR)
		return;

	if ((queue->flags & BYTE_QUEUE_WRITE) == 0)
		return;

	queue->flags &= ~BYTE_QUEUE_WRITE;
	queue->used += num;
}

static int
byte_queue_write_started(TinyHTTPByteQueue *queue)
{
	return (queue->flags & BYTE_QUEUE_WRITE) == BYTE_QUEUE_WRITE;
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
byte_queue_write_setmincap(TinyHTTPByteQueue *queue, ptrdiff_t mincap)
{
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

	ASSERT((queue->flags & BYTE_QUEUE_WRITE) == 0);

	unsigned int total_free_space = queue->size - queue->used;
	unsigned int free_space_after_data = queue->size - queue->used - queue->head;

	int moved = 0;
	if (free_space_after_data < mincap) {

		if (total_free_space < mincap || (queue->read_target == queue->data)) {
			// Resize required

			if (queue->used + mincap > queue->limit) {
				queue->flags |= BYTE_QUEUE_ERROR;
				return 0;
			}

			unsigned int size;
			if (queue->size > MAX_U32 / 2)
				size = MAX_U32;
			else
				size = 2 * queue->size;

			if (size < queue->used + mincap)
				size = queue->used + mincap;

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

static TinyHTTPByteQueueOffset
byte_queue_offset(TinyHTTPByteQueue *queue)
{
	if (queue->flags & BYTE_QUEUE_ERROR)
		return (TinyHTTPByteQueueOffset) { 0 };
	return (TinyHTTPByteQueueOffset) { queue->curs + queue->used };
}

static unsigned int
byte_queue_size_from_offset(TinyHTTPByteQueue *queue, TinyHTTPByteQueueOffset off)
{
	return queue->curs + queue->used - off;
}

static void
byte_queue_patch(TinyHTTPByteQueue *queue, TinyHTTPByteQueueOffset off,
	char *src, unsigned int len)
{
	// Check that the offset is in range
	ASSERT(off >= queue->curs && off - queue->curs < queue->used);

	// Check that the length is in range
	ASSERT(len <= queue->used - (off - queue->curs));

	// Perform the patch
	char *dst = queue->data + queue->head + (off - queue->curs);
	memcpy(dst, src, len);
}

static void
byte_queue_remove_after_lock(TinyHTTPByteQueue *queue)
{
	ASSERT(queue->flags & BYTE_QUEUE_LOCK);

	unsigned long long num = (queue->curs + queue->head) - queue->lock;
	ASSERT(num <= queue->used);

	queue->used -= num;
}

static void
byte_queue_write(TinyHTTPByteQueue *queue, const char *str)
{
	ptrdiff_t cap;
	ptrdiff_t len = strlen(str);
	byte_queue_write_setmincap(queue, len);
	char *dst = byte_queue_write_buf(queue, &cap);
	if (dst) memcpy(dst, str, len);
	byte_queue_write_ack(queue, len);
}

static void
byte_queue_write_fmt2(TinyHTTPByteQueue *queue, const char *fmt, va_list args)
{
	if (queue->flags & BYTE_QUEUE_ERROR)
		return;

	va_list args2;
	va_copy(args2, args);

	ptrdiff_t cap;
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
byte_queue_write_fmt(TinyHTTPByteQueue *queue, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	byte_queue_write_fmt2(queue, fmt, args);
	va_end(args);
}

static unsigned int
byte_queue_read_size(TinyHTTPByteQueue *queue)
{
	if (queue->lock & BYTE_QUEUE_LOCK)
		return queue->curs + queue->used - queue->lock;
	return queue->used;
}

static void
byte_queue_read_lock(TinyHTTPByteQueue *queue)
{
	ASSERT((queue->flags & BYTE_QUEUE_LOCK) == 0);
	queue->lock = queue->curs + queue->used;
	queue->flags |= BYTE_QUEUE_LOCK;
}

static void
byte_queue_read_unlock(TinyHTTPByteQueue *queue)
{
	ASSERT(queue->flags & BYTE_QUEUE_LOCK);
	queue->flags &= ~BYTE_QUEUE_LOCK;
}

////////////////////////////////////////////////////////////////////////////////////
// HTTP STREAM                                                                    //
////////////////////////////////////////////////////////////////////////////////////

#define EIGHT_ZEROS "00000000"
#define TEN_SPACES "          "

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

// See tinyhttp.h
void tinyhttp_stream_init(TinyHTTPStream *stream, TinyHTTPMemoryFunc memfunc, void *memfuncdata)
{
	// Since we are the server, we are expecting
	// the client to send data first.
	stream->state = TINYHTTP_STREAM_RECV;

	// We only use the output state when a request
	// has been received.
	stream->output_state = TINYHTTP_OUTPUT_STATE_NONE;

	// Set the maximum content length
	stream->bodylimit = 1<<29; // 500MB

	byte_queue_init(&stream->in, 1<<29, memfunc, memfuncdata);
	byte_queue_init(&stream->out, 1<<29, memfunc, memfuncdata);
}

// See tinyhttp.h
void tinyhttp_stream_free(TinyHTTPStream *stream)
{
	if (stream->state == TINYHTTP_STREAM_FREE)
		return;
	byte_queue_free(&stream->out);
	byte_queue_free(&stream->in);
	stream->state = TINYHTTP_STREAM_FREE;
}

// See tinyhttp.h
int tinyhttp_stream_state(TinyHTTPStream *stream)
{
	// The state is stored in stream->state, but the
	// TINYHTTP_STREAM_SEND and TINYHTTP_STREAM_RECV are evaluated
	// lazily to avoid possible invalid states.

	int state = stream->state;

	// The TINYHTTP_STREAM_FREE state is exclusive
	if (state == TINYHTTP_STREAM_FREE)
		return state;

	// If there is data to read in the output buffer,
	// we are interested in sending data.
	if (byte_queue_read_size(&stream->out))
		state |= TINYHTTP_STREAM_SEND;

	if (stream->reqsize > 0)
		state |= TINYHTTP_STREAM_READY;

	// If we don't have a buffered request and the
	// connection is not closing, we are interested
	// in receiving data.
	if ((state & (TINYHTTP_STREAM_READY | TINYHTTP_STREAM_CLOSE)) == 0)
		state |= TINYHTTP_STREAM_RECV;

	if (byte_queue_write_started(&stream->in))
		state |= TINYHTTP_STREAM_RECV_STARTED;

	if (byte_queue_read_started(&stream->out))
		state |= TINYHTTP_STREAM_SEND_STARTED;

	return state;
}

// See tinyhttp.h
char *tinyhttp_stream_recv_buf(TinyHTTPStream *stream, ptrdiff_t *cap)
{
	// Sticky error
	if (stream->state == TINYHTTP_STREAM_FREE) {
		*cap = 0;
		return NULL;
	}

	// Make sure at least this free space is available
	ptrdiff_t minrecv = 1<<9;
	int resized = byte_queue_write_setmincap(&stream->in, minrecv);

	// If the input data was moved and a request was
	// buffered, we need to update the pointers of the
	// parsed request. We do this by parsing again.
	if (resized && (stream->state & TINYHTTP_STREAM_READY)) {

		char *src;
		ptrdiff_t len;

		// Get the new input data location
		src = byte_queue_peek(&stream->in, &len);

		// Parse again. We assume everything will go
		// well as it did the first time.
		parse_request(src, len, stream->bodylimit, &stream->req);
	}

	// Forward the write region from the input buffer
	return byte_queue_write_buf(&stream->in, cap);
}

static int
should_keep_alive(TinyHTTPStream *stream)
{
	ASSERT(stream->reqsize > 0);

	// If the parent system doesn't want us to reuse
	// the connection, we certainly can't keep alive.
	if ((stream->state & TINYHTTP_STREAM_REUSE) == 0)
		return 0;

	// If the client is using HTTP/1.0, we can't
	// keep alive.
	if (stream->req.minor == 0)
		return 0;

	return 1;
}

static void
process_next_request(TinyHTTPStream *stream)
{
	// Try parsing the request from the buffered bytes.

	ptrdiff_t len;
	char *src = byte_queue_read_buf(&stream->in, &len);
	int ret = parse_request(src, len, stream->bodylimit, &stream->req);

	// Request is incomplete
	if (ret == 0) {
		byte_queue_read_ack(&stream->in, 0);
		return;
	}

	// Invalid request
	if (ret < 0) {

		byte_queue_read_ack(&stream->in, 0);

		int status = -ret;
		byte_queue_write_fmt(&stream->out, "HTTP/1.1 %d %s\r\n", status, get_status_text(status));
		if (byte_queue_error(&stream->out)) {
			tinyhttp_stream_free(stream);
			return;
		}
		stream->state |= TINYHTTP_STREAM_CLOSE;
		return;
	}

	// Request buffered
	ASSERT(ret > 0);

	stream->reqsize = ret;

	// Start up the output state machine
	stream->output_state = TINYHTTP_OUTPUT_STATE_STATUS;

	// Configure chunked coding for this request
	stream->chunked = 0;

	// Determine whether this connection will be
	// kept alive after this request/response exchange;
	stream->keepalive = should_keep_alive(stream);

	// Don't allow bytes written to the output buffer
	// from this point on to be send over the network
	// until the response was completely buffered.
	//
	// This is because if an error occurs while responding,
	// we may want to reset everything and start from
	// scratch.
	byte_queue_read_lock(&stream->out);
}

// See tinyhttp.h
void tinyhttp_stream_recv_ack(TinyHTTPStream *stream, ptrdiff_t num)
{
	// Sticky error
	if (stream->state == TINYHTTP_STREAM_FREE)
		return;

	byte_queue_write_ack(&stream->in, num);

	// Since new data was ready, the state of the
	// connection may need to change.

	// If a request was already buffered, the state
	// won't change until a response is generated.
	if (stream->reqsize > 0)
		return;

	process_next_request(stream);
}

// See tinyhttp.h
char *tinyhttp_stream_send_buf(TinyHTTPStream *stream, ptrdiff_t *len)
{
	// Sticky error
	if (stream->state == TINYHTTP_STREAM_FREE)
		return NULL;

	return byte_queue_read_buf(&stream->out, len);
}

// See tinyhttp.h
void tinyhttp_stream_send_ack(TinyHTTPStream *stream, ptrdiff_t num)
{
	// Sticky error
	if (stream->state == TINYHTTP_STREAM_FREE)
		return;

	byte_queue_read_ack(&stream->out, num);

	if (byte_queue_read_size(&stream->out) == 0 && (stream->state & TINYHTTP_STREAM_CLOSE)) {
		tinyhttp_stream_free(stream);
		return;
	}
}

// See tinyhttp.h
void tinyhttp_stream_setreuse(TinyHTTPStream *stream, int value)
{
	// Sticky error
	if (stream->state == TINYHTTP_STREAM_FREE)
		return;

	if (value)
		stream->state |= TINYHTTP_STREAM_REUSE;
	else
		stream->state &= ~TINYHTTP_STREAM_REUSE;
}

// See tinyhttp.h
void tinyhttp_stream_setbodylimit(TinyHTTPStream *stream, unsigned long long value)
{
	stream->bodylimit = value;
}

// See tinyhttp.h
void tinyhttp_stream_setinbuflimit(TinyHTTPStream *stream, unsigned int value)
{
	byte_queue_setlimit(&stream->in, value);
}

// See tinyhttp.h
void tinyhttp_stream_setoutbuflimit(TinyHTTPStream *stream, unsigned int value)
{
	byte_queue_setlimit(&stream->out, value);
}

// See tinyhttp.h
TinyHTTPRequest *tinyhttp_stream_request(TinyHTTPStream *stream)
{
	if (stream->reqsize > 0)
		return &stream->req;
	return NULL;
}

// See tinyhttp.h
void tinyhttp_stream_response_status(TinyHTTPStream *stream, int status)
{
	// Sticky error
	if (stream->state == TINYHTTP_STREAM_FREE)
		return;

	if (stream->output_state != TINYHTTP_OUTPUT_STATE_STATUS) {
		if (stream->output_state != TINYHTTP_OUTPUT_STATE_NONE)
			stream->output_state = TINYHTTP_OUTPUT_STATE_ERROR;
		return;
	}

	byte_queue_write_fmt(&stream->out, "HTTP/1.1 %d %s\r\n", status, get_status_text(status));

	stream->output_state = TINYHTTP_OUTPUT_STATE_HEADER;
}

// See tinyhttp.h
void tinyhttp_stream_response_header(TinyHTTPStream *stream, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	tinyhttp_stream_response_header_fmt(stream, fmt, args);
	va_end(args);
}

// See tinyhttp.h
void tinyhttp_stream_response_header_fmt(TinyHTTPStream *stream, const char *fmt, va_list args)
{
	// Sticky error
	if (stream->state == TINYHTTP_STREAM_FREE)
		return;

	if (stream->output_state != TINYHTTP_OUTPUT_STATE_HEADER) {
		if (stream->output_state != TINYHTTP_OUTPUT_STATE_NONE)
			stream->output_state = TINYHTTP_OUTPUT_STATE_ERROR;
		return;
	}

	byte_queue_write_fmt2(&stream->out, fmt, args);
}

static void
append_special_headers(TinyHTTPStream *stream)
{
	if (stream->keepalive)
		byte_queue_write(&stream->out, "Connection: Keep-Alive\r\n");
	else {
		if (stream->req.minor > 0)
			byte_queue_write(&stream->out, "Connection: Close\r\n");
	}

	if (stream->chunked)
		byte_queue_write(&stream->out, "Transfer-Encoding: Chunked\r\n");
	else {
		byte_queue_write(&stream->out, "Content-Length: ");
		stream->content_length_value_offset = byte_queue_offset(&stream->out);
		byte_queue_write(&stream->out, TEN_SPACES "\r\n");
	}

	byte_queue_write(&stream->out, "\r\n");
	stream->content_length_offset = byte_queue_offset(&stream->out);
}

// See tinyhttp.h
void tinyhttp_stream_response_body_setmincap(TinyHTTPStream *stream, ptrdiff_t mincap)
{
	// Sticky error
	if (stream->state == TINYHTTP_STREAM_FREE)
		return;

	if (stream->output_state == TINYHTTP_OUTPUT_STATE_HEADER) {
		append_special_headers(stream);
		stream->output_state = TINYHTTP_OUTPUT_STATE_BODY;
	}

	if (stream->output_state != TINYHTTP_OUTPUT_STATE_BODY) {
		if (stream->output_state != TINYHTTP_OUTPUT_STATE_NONE)
			stream->output_state = TINYHTTP_OUTPUT_STATE_ERROR;
		return;
	}

	// Always add some extra padding in case we need
	// to append a chunk header.
	byte_queue_write_setmincap(&stream->out, mincap + 20);
}

// See tinyhttp.h
char *tinyhttp_stream_response_body_buf(TinyHTTPStream *stream, ptrdiff_t *cap)
{
	// Sticky error
	if (stream->state == TINYHTTP_STREAM_FREE)
		return NULL;

	if (stream->output_state == TINYHTTP_OUTPUT_STATE_HEADER) {
		append_special_headers(stream);
		stream->output_state = TINYHTTP_OUTPUT_STATE_BODY;
	}

	if (stream->output_state != TINYHTTP_OUTPUT_STATE_BODY) {
		if (stream->output_state != TINYHTTP_OUTPUT_STATE_NONE)
			stream->output_state = TINYHTTP_OUTPUT_STATE_ERROR;
		*cap = 0;
		return NULL;
	}

	if (stream->chunked)
		byte_queue_write(&stream->out, EIGHT_ZEROS "\r\n");

	return byte_queue_write_buf(&stream->out, cap);
}

// See tinyhttp.h
void tinyhttp_stream_response_body_ack(TinyHTTPStream *stream, ptrdiff_t num)
{
	// Sticky error
	if (stream->state == TINYHTTP_STREAM_FREE)
		return;

	if (stream->output_state != TINYHTTP_OUTPUT_STATE_BODY) {
		if (stream->output_state != TINYHTTP_OUTPUT_STATE_NONE)
			stream->output_state = TINYHTTP_OUTPUT_STATE_ERROR;
		return;
	}

	if (stream->chunked) {

		if ((num & 0xffffffff)) {
			stream->output_state = TINYHTTP_OUTPUT_STATE_ERROR;
			return;
		}

		char tmp[8];
		tmp[7] = (num >> 28) & 0xF;
		tmp[6] = (num >> 24) & 0xF;
		tmp[5] = (num >> 20) & 0xF;
		tmp[4] = (num >> 16) & 0xF;
		tmp[3] = (num >> 12) & 0xF;
		tmp[2] = (num >>  8) & 0xF;
		tmp[1] = (num >>  4) & 0xF;
		tmp[0] = (num >>  0) & 0xF;

		for (int i = 0; i < 8; i++) {
			if (tmp[i] < 10)
				tmp[i] += '0';
			else
				tmp[i] += 'a';
		}

		byte_queue_patch(&stream->out, byte_queue_offset(&stream->out) - 10, tmp, 8);
	}

	byte_queue_write_ack(&stream->out, num);

	if (stream->chunked)
		byte_queue_write(&stream->out, "\r\n");
}

// See tinyhttp.h
void tinyhttp_stream_response_send(TinyHTTPStream *stream)
{
	// Sticky error
	if (stream->state == TINYHTTP_STREAM_FREE)
		return;

	if (stream->output_state == TINYHTTP_OUTPUT_STATE_NONE)
		return;
	
	if (stream->output_state == TINYHTTP_OUTPUT_STATE_HEADER) {
		append_special_headers(stream);
		stream->output_state = TINYHTTP_OUTPUT_STATE_BODY;
	}

	DUMP_STATE(tinyhttp_stream_state(stream));

	if (stream->output_state == TINYHTTP_OUTPUT_STATE_BODY) {
		if (stream->chunked)
			byte_queue_write(&stream->out, "0\r\n\r\n");
		else {

			ptrdiff_t content_length = byte_queue_size_from_offset(&stream->out, stream->content_length_offset);
			ASSERT(content_length >= 0);

			if (content_length > MAX_U32) {
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
			while (i < 8 && tmp[i] == '0')
				i++;

			byte_queue_patch(&stream->out, stream->content_length_value_offset, tmp + i, 10 - i);
		}
	}

	DUMP_STATE(tinyhttp_stream_state(stream));

	if (stream->output_state == TINYHTTP_OUTPUT_STATE_ERROR) {
		byte_queue_remove_after_lock(&stream->out);
		byte_queue_write(&stream->out,
			"HTTP/1.1 500 Internal Server Error\r\n"
			"Content-Length: 0\r\n"
			"Connection: Close\r\n"
			"\r\n"
		);
	}

	DUMP_STATE(tinyhttp_stream_state(stream));

	if (byte_queue_error(&stream->out)) {
		tinyhttp_stream_free(stream);
		return;
	}

	DUMP_STATE(tinyhttp_stream_state(stream));

#if DUMP_IO
	ptrdiff_t ressize = (byte_queue_offset(&stream->out) - stream->out.lock);
	print_bytes("R << ", stream->out.data + stream->out.head, ressize);
#endif

	byte_queue_read_ack(&stream->in, stream->reqsize);
	byte_queue_read_unlock(&stream->out);
	stream->reqsize = 0;

	DUMP_STATE(tinyhttp_stream_state(stream));

	process_next_request(stream);

	DUMP_STATE(tinyhttp_stream_state(stream));
}

// See tinyhttp.h
void tinyhttp_stream_response_undo(TinyHTTPStream *stream)
{
	// Sticky error
	if (stream->state == TINYHTTP_STREAM_FREE)
		return;

	byte_queue_remove_after_lock(&stream->out);
	stream->output_state = TINYHTTP_OUTPUT_STATE_STATUS;
}

////////////////////////////////////////////////////////////////////////////////////
// HTTP SERVER                                                                    //
////////////////////////////////////////////////////////////////////////////////////

struct TinyHTTPServer {
#if defined(_WIN32)
	int deinit_winsock;
	HANDLE iocp;
	OVERLAPPED plain_accept_overlapped;
	OVERLAPPED secure_accept_overlapped;
	SOCKET plain_accept_target;
	SOCKET secure_accept_target;
	LPFN_ACCEPTEX accept_func;
	char plain_accept_buf[2 * (sizeof(struct sockaddr_in) + 16)];
	char secure_accept_buf[2 * (sizeof(struct sockaddr_in) + 16)];
	OVERLAPPED recv_overlapped[TINYHTTP_SERVER_CONN_LIMIT];
	OVERLAPPED send_overlapped[TINYHTTP_SERVER_CONN_LIMIT];
#elif defined(__linux__)
	int epoll_fd;
#endif
	TinyHTTPMemoryFunc memfunc;
	void *memfuncdata;
	SOCKET plain_listen_socket;
	SOCKET secure_listen_socket;
	int num_conns;
	int ready_head;
	int ready_count;
	int ready_queue[TINYHTTP_SERVER_CONN_LIMIT];
	unsigned short stream_gens[TINYHTTP_SERVER_CONN_LIMIT];
	TinyHTTPStream stream_state[TINYHTTP_SERVER_CONN_LIMIT];
	SOCKET         stream_sockets[TINYHTTP_SERVER_CONN_LIMIT];
};

static int
socket_set_block(SOCKET fd, int value)
{
#if defined(__linux__)
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return -1;

	if (value)
		flags &= ~O_NONBLOCK;
	else
		flags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) < 0)
		return -1;

	return 0;
#elif defined(_WIN32)
	u_long mode = !value;
	int ret = ioctlsocket(fd, FIONBIO, &mode);
	if (ret == SOCKET_ERROR)
		return -1;
	return 0;
#else
	return -1;
#endif
}

static SOCKET
socket_listen(const char *addr, int port, int backlog, int reuse)
{
	SOCKET fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == INVALID_SOCKET)
		return INVALID_SOCKET;

	if (socket_set_block(fd, 0) < 0) {
		CLOSESOCKET(fd);
		return INVALID_SOCKET;
	}

	if (reuse) {
		int one = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*) &one, sizeof(one)) < 0) {
			CLOSESOCKET(fd);
			return INVALID_SOCKET;
		}
	}

	struct in_addr bind_buf2;
	if (addr == NULL)
		bind_buf2.s_addr = htonl(INADDR_ANY);
	else if (inet_pton(AF_INET, addr, &bind_buf2) != 1) {
		CLOSESOCKET(fd);
		return INVALID_SOCKET;
	}

	struct sockaddr_in bind_buf;
	bind_buf.sin_family = AF_INET;
	bind_buf.sin_port = htons(port);
	bind_buf.sin_addr = bind_buf2;

	if (bind(fd, (struct sockaddr*) &bind_buf, sizeof(bind_buf)) < 0) {
		CLOSESOCKET(fd);
		return INVALID_SOCKET;
	}

	if (listen(fd, backlog) < 0) {
		CLOSESOCKET(fd);
		return INVALID_SOCKET;
	}

	return fd;
}

static TinyHTTPStream*
response_to_stream(TinyHTTPResponse res)
{
	if (res.server == NULL)
		return NULL;
	if (res.idx >= TINYHTTP_SERVER_CONN_LIMIT)
		return NULL;
	if (res.gen != res.server->stream_gens[res.idx])
		return NULL;
	return &res.server->stream_state[res.idx];
}

// TODO: The generation counters allow freeing streams while the user is still
//       holding a response handle that references them, but the user may still
//       be holding the pointer to the request structure. How to fix this? Should
//       callers only be allowed to access TinyHTTPRequest before the next call
//       to [tinyhttp_server_wait]? Or should connections be marked as pending
//       until [tinyhttp_server_send] is called?

static void
invalidate_handles_to_stream(TinyHTTPServer *server, TinyHTTPStream *stream)
{
	int idx = stream - server->stream_state;
	unsigned short *gen = &server->stream_gens[idx];
	(*gen)++;
	if (*gen == MAX_U16 || *gen == 0)
		*gen = 1;
}

#if defined(__linux__)

static void
server_free_platform(TinyHTTPServer *server)
{
	close(server->epoll_fd);
}

static int
server_init_platform(TinyHTTPServer *server,
	TinyHTTPServerConfig config)
{
	server->epoll_fd = epoll_create1(0);
	if (server->epoll_fd < 0)
		return -1;

	struct epoll_event epoll_buf;
	epoll_buf.data.fd = -1;
	epoll_buf.events = EPOLLIN;
	if (epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, server->plain_listen_socket, &epoll_buf) < 0) {
		close(server->epoll_fd);
		return -1;
	}

	if (config.secure) {

		epoll_buf.data.fd = -2;
		epoll_buf.events = EPOLLIN;
		if (epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, server->secure_listen_socket, &epoll_buf) < 0) {
			close(server->epoll_fd);
			return -1;
		}
	}

	return 0;
}

static unsigned long long
get_current_time_ms(void)
{
	struct timespec ts;
	int result = clock_gettime(CLOCK_REALTIME, &ts);
	if (result)
		return MAX_U64;
	return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int
accept_from_listen_socket(TinyHTTPServer *server, SOCKET listen_socket, int secure)
{
	int errors = 0;
	while (server->num_conns < TINYHTTP_SERVER_CONN_LIMIT) {
		SOCKET accepted_socket = accept(listen_socket, NULL, NULL);
		if (accepted_socket == INVALID_SOCKET) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			errors++;
			if (errors == 1000)
				break;
			continue;
		}
		errors = 0;

		if (socket_set_block(accepted_socket, 0)) {
			CLOSESOCKET(accepted_socket);
			continue;
		}

		int idx = 0;
		while (server->stream_sockets[idx] != INVALID_SOCKET)
			idx++;

		server->stream_sockets[idx] = accepted_socket;
		TinyHTTPStream *stream = &server->stream_state[idx];

		tinyhttp_stream_init(stream, server->memfunc, server->memfuncdata);
		int state = tinyhttp_stream_state(stream);

		struct epoll_event epoll_buf;
		epoll_buf.data.fd = idx;
		epoll_buf.events = 0;
		if (state & TINYHTTP_STREAM_RECV) epoll_buf.events |= EPOLLIN;
		if (state & TINYHTTP_STREAM_SEND) epoll_buf.events |= EPOLLOUT;
		if (epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, accepted_socket, &epoll_buf) < 0) {
			CLOSESOCKET(accepted_socket);
			tinyhttp_stream_free(stream);
			continue;
		}

		if (secure) {
			// TODO
		}

		server->num_conns++;
	}
	return 0;
}

static int
process_network_events(TinyHTTPServer *server, int timeout)
{
	// TODO: timeouts

	struct epoll_event batch[TINYHTTP_SERVER_EPOLL_BATCH_SIZE];

	int num;
	do
		num = epoll_wait(server->epoll_fd, batch, TINYHTTP_SERVER_EPOLL_BATCH_SIZE, timeout);
	while (num < 0 && errno == EINTR);

	for (int i = 0; i < num; i++) {

		int idx = batch[i].data.fd;
		int flags = batch[i].events;

		if (idx == -1) {
			// New plain connections
			if (accept_from_listen_socket(server, server->plain_listen_socket, 0) < 0)
				return -1;
		} else if (idx == -2) {
			// New secure connections
			if (accept_from_listen_socket(server, server->secure_listen_socket, 1) < 0)
				return -1;
		} else {

			SOCKET sock = server->stream_sockets[idx];
			TinyHTTPStream *stream = &server->stream_state[idx];

			if (flags & (EPOLLERR | EPOLLHUP))
				tinyhttp_stream_free(stream);

			int state = tinyhttp_stream_state(stream);
			if (flags & EPOLLIN) {
				while (state & TINYHTTP_STREAM_RECV) {
					ptrdiff_t cap;
					char *dst = tinyhttp_stream_recv_buf(stream, &cap);
					if (dst == NULL)
						continue;
					int ret = recv(sock, dst, cap, 0);
					if (ret < 0) {
						if (errno == EAGAIN || errno == EWOULDBLOCK)
							break;
						tinyhttp_stream_free(stream);
						break;
					}
					if (ret == 0) {
						tinyhttp_stream_free(stream);
						break;
					}
#if DUMP_IO
					print_bytes("N >> ", dst, ret);
#endif
					tinyhttp_stream_recv_ack(stream, ret);
					state = tinyhttp_stream_state(stream);
				}
				tinyhttp_stream_recv_ack(stream, 0);
			}

			if (flags & EPOLLOUT) {
				while (state & TINYHTTP_STREAM_SEND) {
					ptrdiff_t len;
					char *src = tinyhttp_stream_send_buf(stream, &len);
					if (src == NULL)
						continue;
					int ret = send(sock, src, len, 0);
					if (ret < 0) {
						if (errno == EAGAIN || errno == EWOULDBLOCK)
							break;
						tinyhttp_stream_free(stream);
						break;
					}
					if (ret == 0) {
						tinyhttp_stream_free(stream);
						break;
					}
#if DUMP_IO
					print_bytes("N << ", src, ret);
#endif
					tinyhttp_stream_send_ack(stream, ret);
					state = tinyhttp_stream_state(stream);
				}
				tinyhttp_stream_send_ack(stream, 0);
			}

			int new_state = tinyhttp_stream_state(&server->stream_state[idx]);
			if ((state & (TINYHTTP_STREAM_RECV | TINYHTTP_STREAM_SEND)) != (new_state & (TINYHTTP_STREAM_RECV | TINYHTTP_STREAM_SEND))) {
				struct epoll_event tmp;
				tmp.data.fd = idx;
				tmp.events = 0;
				if (new_state & TINYHTTP_STREAM_RECV) tmp.events |= EPOLLIN;
				if (new_state & TINYHTTP_STREAM_RECV) tmp.events |= EPOLLOUT;
				if (epoll_ctl(server->epoll_fd, EPOLL_CTL_MOD, sock, &tmp) < 0) {
					tinyhttp_stream_free(stream);
					new_state = tinyhttp_stream_state(stream);
				}
			}

			if (state & TINYHTTP_STREAM_READY) {
				int ready_idx = (server->ready_head + server->ready_count) % TINYHTTP_SERVER_CONN_LIMIT;
				server->ready_queue[ready_idx] = idx;
				server->ready_count++;
			}

			if (new_state == TINYHTTP_STREAM_FREE) {
				// TODO: Remove from the ready list
				CLOSESOCKET(sock);
				invalidate_handles_to_stream(server, stream);
				server->stream_sockets[idx] = INVALID_SOCKET;
				server->num_conns--;
			}
		}
	}

	return 0;
}
#elif defined(_WIN32)

static void
server_free_platform(TinyHTTPServer *server)
{
	CloseHandle(server->iocp);

	if (server->deinit_winsock)
		WSACleanup();
}

static SOCKET
start_accept_operation(LPFN_ACCEPTEX *accept_func,
	SOCKET listen_socket, OVERLAPPED *overlapped,
	char *buf, int buflen)
{
	if (*accept_func == NULL) {
		LPFN_ACCEPTEX lpfnAcceptEx = NULL;
		GUID GuidAcceptEx = WSAID_ACCEPTEX;
		unsigned long num;
		int ret = WSAIoctl(listen_socket,
			SIO_GET_EXTENSION_FUNCTION_POINTER,
			&GuidAcceptEx, sizeof(GuidAcceptEx),
			&lpfnAcceptEx, sizeof(lpfnAcceptEx),
			&num, NULL, NULL);
		if (ret == SOCKET_ERROR)
			return INVALID_SOCKET;
		*accept_func = lpfnAcceptEx;
	}

	SOCKET target_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (target_socket == INVALID_SOCKET)
		return INVALID_SOCKET;

	memset(overlapped, 0, sizeof(OVERLAPPED));

	DWORD num;
	int ok = (*accept_func)(
		(SOCKET) listen_socket, target_socket,
		buf, buflen - ((sizeof(struct sockaddr_in) + 16) * 2),
		sizeof(struct sockaddr_in) + 16,
		sizeof(struct sockaddr_in) + 16,
		&num, overlapped);
	if (!ok && WSAGetLastError() != ERROR_IO_PENDING) {
		CLOSESOCKET(target_socket);
		return INVALID_SOCKET;
	}

	return target_socket;
}

static int server_init_platform(TinyHTTPServer *server,
	TinyHTTPServerConfig config)
{
	server->iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
	if (server->iocp == INVALID_HANDLE_VALUE)
		return -1;

	if (CreateIoCompletionPort((HANDLE) server->plain_listen_socket, server->iocp, 0, 0) == NULL) {
		CloseHandle(server->iocp);
		return -1;
	}

	server->accept_func = NULL;

	server->plain_accept_target = start_accept_operation(
		&server->accept_func,
		server->plain_listen_socket,
		&server->plain_accept_overlapped,
		server->plain_accept_buf,
		sizeof(server->plain_accept_buf));
	if (server->plain_accept_target == INVALID_SOCKET)
		return -1;

	if (config.secure) {

		if (CreateIoCompletionPort((HANDLE) server->secure_listen_socket, server->iocp, 0, 0) == NULL) {
			CLOSESOCKET(server->plain_accept_target);
			CloseHandle(server->iocp);
			return -1;
		}

		server->secure_accept_target = start_accept_operation(
			&server->accept_func,
			server->secure_listen_socket,
			&server->secure_accept_overlapped,
			server->secure_accept_buf,
			sizeof(server->secure_accept_buf));
		if (server->secure_accept_target == INVALID_SOCKET) {
			CLOSESOCKET(server->plain_accept_target);
			CloseHandle(server->iocp);
			return -1;
		}
	}

	return 0;
}

static unsigned long long
get_current_time_ms(void)
{
	FILETIME ft;
	GetSystemTimeAsFileTime(&ft);

	ULARGE_INTEGER uli;
	uli.LowPart = ft.dwLowDateTime;
	uli.HighPart = ft.dwHighDateTime;
					
	// Convert Windows file time (100ns since 1601-01-01) to 
	// Unix epoch time (seconds since 1970-01-01)
	// 116444736000000000 = number of 100ns intervals from 1601 to 1970
	return (uli.QuadPart - 116444736000000000ULL) / 10000ULL; // TODO: Make sure this is returning miliseconds
}

static int
start_stream_operations(TinyHTTPStream *stream, SOCKET sock,
	OVERLAPPED *recv_overlapped, OVERLAPPED *send_overlapped)
{
	int state = tinyhttp_stream_state(stream);

	DUMP_STATE(tinyhttp_stream_state(stream));

	if ((state & TINYHTTP_STREAM_RECV) && !(state & TINYHTTP_STREAM_RECV_STARTED)) {
		ptrdiff_t cap;
		char *dst = tinyhttp_stream_recv_buf(stream, &cap);
		memset(recv_overlapped, 0, sizeof(*recv_overlapped));
		int ok = ReadFile((HANDLE) sock, dst, cap, NULL, recv_overlapped);
		if (!ok && GetLastError() != ERROR_IO_PENDING)
			return -1;
#if DUMP_IO
			printf("RECV STARTED (cap=%lld)\n", cap);
#endif
	}

	DUMP_STATE(tinyhttp_stream_state(stream));

	if (state & TINYHTTP_STREAM_SEND && !(state & TINYHTTP_STREAM_SEND_STARTED)) {
		ptrdiff_t len;
		char *src = tinyhttp_stream_send_buf(stream, &len);
		memset(send_overlapped, 0, sizeof(*send_overlapped));
		int ok = WriteFile((HANDLE) sock, src, len, NULL, send_overlapped);
		if (!ok && GetLastError() != ERROR_IO_PENDING)
			return -1;
#if DUMP_IO
			printf("SEND STARTED (len=%lld)\n", len);
#endif
	}

	DUMP_STATE(tinyhttp_stream_state(stream));

	return 0;
}

static void
intern_accepted_socket(TinyHTTPServer *server, SOCKET accepted_socket, int secure)
{
	if (server->num_conns == TINYHTTP_SERVER_CONN_LIMIT) {
		CLOSESOCKET(accepted_socket);
		return;
	}

	if (socket_set_block(accepted_socket, 0) < 0) {
		CLOSESOCKET(accepted_socket);
		return;
	}

	int idx = 0;
	while (server->stream_sockets[idx] != INVALID_SOCKET)
		idx++;

	server->stream_sockets[idx] = accepted_socket;
	TinyHTTPStream *stream = &server->stream_state[idx];

	tinyhttp_stream_init(stream, server->memfunc, server->memfuncdata);
	int state = tinyhttp_stream_state(stream);

	DUMP_STATE(tinyhttp_stream_state(stream));

	if (CreateIoCompletionPort((HANDLE) accepted_socket, server->iocp, 0, 0) == NULL) {
		tinyhttp_stream_free(stream);
		server->stream_sockets[idx] = INVALID_SOCKET;
		CLOSESOCKET(accepted_socket);
		return;
	}

	OVERLAPPED *recv_overlapped = &server->recv_overlapped[idx];
	OVERLAPPED *send_overlapped = &server->send_overlapped[idx];
	if (start_stream_operations(stream, accepted_socket, recv_overlapped, send_overlapped) < 0) {
		tinyhttp_stream_free(stream);
		server->stream_sockets[idx] = INVALID_SOCKET;
		CLOSESOCKET(accepted_socket);
		return;
	}

	DUMP_STATE(tinyhttp_stream_state(stream));

	if (secure) {
		// TODO
	}

	server->num_conns++;
}

static int
process_network_events(TinyHTTPServer *server, int timeout)
{
	// TODO: timeouts

	DWORD timeout2;
	if (timeout < 0)
		timeout2 = INFINITE;
	else
		timeout2 = timeout;

	DWORD transferred;
	ULONG_PTR key; 
	OVERLAPPED *overlapped;
	BOOL result = GetQueuedCompletionStatus(server->iocp,
		&transferred, &key, &overlapped, timeout2);

	// Handle timeouts and error on the completion function itself
	if (!result && overlapped == NULL) {
		if (GetLastError() == WAIT_TIMEOUT)
				return 0;
		return -1;
	}

	ASSERT(overlapped);

	if (overlapped == &server->plain_accept_overlapped) {
		if (result) {

			// New plain connection
#if DUMP_IO
			printf("ACCEPT COMPLETED (plain)\n");
#endif
			SOCKET accepted_socket = server->plain_accept_target;
			server->plain_accept_target = INVALID_SOCKET;

			intern_accepted_socket(server, accepted_socket, 0);

		} else {
			// Accept failed
			CLOSESOCKET(server->plain_accept_target);
			// TODO
		}

		server->plain_accept_target = start_accept_operation(
			&server->accept_func,
			server->plain_listen_socket,
			&server->plain_accept_overlapped,
			server->plain_accept_buf,
			sizeof(server->plain_accept_buf));
		if (server->plain_accept_target == INVALID_SOCKET)
			return -1; // Can't recover

		return 0;
	}

	if (overlapped == &server->secure_accept_overlapped) {
		if (result) {

			// New secure connection
#if DUMP_IO
			printf("ACCEPT COMPLETED (secure)\n");
#endif
			SOCKET accepted_socket = server->plain_accept_target;
			server->plain_accept_target = INVALID_SOCKET;

			intern_accepted_socket(server, accepted_socket, 1);

		} else {
			// Accept failed
			CLOSESOCKET(server->secure_accept_target);
			// TODO
		}

		server->secure_accept_target = start_accept_operation(
			&server->accept_func,
			server->secure_listen_socket,
			&server->secure_accept_overlapped,
			server->secure_accept_buf,
			sizeof(server->secure_accept_buf));
		if (server->secure_accept_target == INVALID_SOCKET)
			return -1; // Can't recover

		return 0;
	}

	int idx = key;
	TinyHTTPStream *stream = &server->stream_state[idx];

	SOCKET sock = server->stream_sockets[idx];
	OVERLAPPED *recv_overlapped = &server->recv_overlapped[idx];
	OVERLAPPED *send_overlapped = &server->send_overlapped[idx];

	DUMP_STATE(tinyhttp_stream_state(stream));

	if (!result) {
		// A read or write operation failed
		tinyhttp_stream_free(stream);
	} else {

		if (recv_overlapped == overlapped) {
#if DUMP_IO
			printf("RECV COMPLETED (num=%ld)\n", transferred);
			print_bytes("N >> ", stream->in.data + stream->in.head, transferred);
#endif
			tinyhttp_stream_recv_ack(stream, transferred);
			if (transferred == 0)
				tinyhttp_stream_free(stream);
		} else {
			ASSERT(send_overlapped == overlapped);
#if DUMP_IO
			printf("SEND COMPLETED (num=%ld)\n", transferred);
			print_bytes("N << ", stream->out.data + stream->out.head, transferred);
#endif
			tinyhttp_stream_send_ack(stream, transferred);
		}

		if (start_stream_operations(stream, sock, recv_overlapped, send_overlapped) < 0)
			tinyhttp_stream_free(stream);
	}

	DUMP_STATE(tinyhttp_stream_state(stream));

	int state = tinyhttp_stream_state(stream);

	if (state & TINYHTTP_STREAM_READY) {
		int ready_idx = (server->ready_head + server->ready_count) % TINYHTTP_SERVER_CONN_LIMIT;
		server->ready_queue[ready_idx] = idx;
		server->ready_count++;
	}

	DUMP_STATE(tinyhttp_stream_state(stream));

	if (state == TINYHTTP_STREAM_FREE) {
		// TODO: Remove from the ready list
		CLOSESOCKET(sock);
		invalidate_handles_to_stream(server, stream);
		server->stream_sockets[idx] = INVALID_SOCKET;
		server->num_conns--;
	}

	DUMP_STATE(tinyhttp_stream_state(stream));

	return 0;
}
#endif

TinyHTTPServer* tinyhttp_server_init(TinyHTTPServerConfig config,
	TinyHTTPMemoryFunc memfunc, void *memfuncdata)
{
	TinyHTTPServer *server = memfunc(TINYHTTP_MEM_MALLOC, NULL, sizeof(TinyHTTPServer), memfuncdata);
	if (server == NULL)
		return NULL;

	server->memfunc = memfunc;
	server->memfuncdata = memfuncdata;

	server->num_conns = 0;
	server->ready_head = 0;
	server->ready_count = 0;

	for (int i = 0; i < TINYHTTP_SERVER_CONN_LIMIT; i++) {
		server->stream_gens[i] = 1;
		server->stream_sockets[i] = INVALID_SOCKET;
	}

	server->plain_listen_socket = socket_listen(config.plain_addr,
		config.plain_port, config.plain_backlog, config.reuse);

#if defined(_WIN32)
	server->deinit_winsock = 0;
	if (server->plain_listen_socket == INVALID_SOCKET && WSAGetLastError() == WSANOTINITIALISED) {
		WSADATA data;
		if (WSAStartup(MAKEWORD(2, 2), &data) == NO_ERROR) {
			server->deinit_winsock = 1;
			server->plain_listen_socket = socket_listen(config.plain_addr,
				config.plain_port, config.plain_backlog, config.reuse);
		}
	}
#endif

	if (server->plain_listen_socket == INVALID_SOCKET) {
		memfunc(TINYHTTP_MEM_FREE, server, sizeof(TinyHTTPServer), NULL);
		return NULL;
	}

	server->secure_listen_socket = INVALID_SOCKET;
	if (config.secure) {
		server->secure_listen_socket = socket_listen(config.secure_addr,
			config.secure_port, config.secure_backlog, config.reuse);
		if (server->secure_listen_socket == INVALID_SOCKET) {

			CLOSESOCKET(server->plain_listen_socket);

			memfunc(TINYHTTP_MEM_FREE, server, sizeof(TinyHTTPServer), NULL);
			return NULL;
		}
	}

	if (server_init_platform(server, config) < 0) {

		CLOSESOCKET(server->plain_listen_socket);

		if (server->secure_listen_socket != INVALID_SOCKET)
			CLOSESOCKET(server->secure_listen_socket);

		memfunc(TINYHTTP_MEM_FREE, server, sizeof(TinyHTTPServer), NULL);
		return NULL;
	}

	return server;
}

void tinyhttp_server_free(TinyHTTPServer *server)
{
	for (int i = 0; i < TINYHTTP_SERVER_CONN_LIMIT; i++) {
		if (server->stream_sockets[i] != INVALID_SOCKET) {
			CLOSESOCKET(server->stream_sockets[i]);
			tinyhttp_stream_free(&server->stream_state[i]);
		}
	}

	CLOSESOCKET(server->plain_listen_socket);

	if (server->secure_listen_socket != INVALID_SOCKET)
		CLOSESOCKET(server->secure_listen_socket);

	server_free_platform(server);

	TinyHTTPMemoryFunc memfunc = server->memfunc;
	void *memfuncdata = server->memfuncdata;
	memfunc(TINYHTTP_MEM_FREE, server, sizeof(TinyHTTPServer), memfuncdata);
}

int tinyhttp_server_wait(TinyHTTPServer *server, TinyHTTPRequest **req,
	TinyHTTPResponse *res, int timeout)
{
	unsigned long long start_time_ms = -1ULL;
	if (timeout >= 0) {
		start_time_ms = get_current_time_ms();
		if (start_time_ms == -1ULL)
			return -1;
	}

	while (server->ready_count == 0) {

		int timeout2;
		if (timeout < 0)
			timeout2 = -1;
		else {
			unsigned long long current_time_ms = get_current_time_ms();
			if (current_time_ms == -1ULL)
				return -1;
			if (current_time_ms < start_time_ms)
				return -1;
			if (current_time_ms - start_time_ms > INT_MAX)
				return -1;
			int elapsed = (int) (current_time_ms - start_time_ms);
			if (elapsed > timeout)
				return 1;
			timeout2 = timeout - elapsed;
		}

		int ret = process_network_events(server, timeout2);
		if (ret < 0)
			return -1;
	}

	ASSERT(server->ready_count > 0);

	int idx = server->ready_queue[server->ready_head];
	server->ready_head = (server->ready_head + 1) % TINYHTTP_SERVER_CONN_LIMIT;
	server->ready_count--;

	unsigned short gen = server->stream_gens[idx];
	TinyHTTPStream *stream = &server->stream_state[idx];

	*res = (TinyHTTPResponse) { .server=server, .gen=gen, .idx=idx };
	*req = tinyhttp_stream_request(stream);

	return 0;
}

void tinyhttp_response_status(TinyHTTPResponse res, int status)
{
	TinyHTTPStream *stream = response_to_stream(res);
	if (stream == NULL)
		return; // Invalid handle

	tinyhttp_stream_response_status(stream, status);
}

void tinyhttp_response_header(TinyHTTPResponse res, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	tinyhttp_response_header_fmt(res, fmt, args);
	va_end(args);
}

void tinyhttp_response_header_fmt(TinyHTTPResponse res, const char *fmt, va_list args)
{
	TinyHTTPStream *stream = response_to_stream(res);
	if (stream == NULL)
		return; // Invalid handle

	tinyhttp_stream_response_header_fmt(stream, fmt, args);
}

void tinyhttp_response_body_setmincap(TinyHTTPResponse res, ptrdiff_t mincap)
{
	TinyHTTPStream *stream = response_to_stream(res);
	if (stream == NULL)
		return; // Invalid handle

	tinyhttp_stream_response_body_setmincap(stream, mincap);
}

char* tinyhttp_response_body_buf(TinyHTTPResponse res, ptrdiff_t *cap)
{
	TinyHTTPStream *stream = response_to_stream(res);
	if (stream == NULL) {
		*cap = 0;
		return NULL; // Invalid handle
	}

	return tinyhttp_stream_response_body_buf(stream, cap);
}

void tinyhttp_response_body_ack(TinyHTTPResponse res, ptrdiff_t num)
{
	TinyHTTPStream *stream = response_to_stream(res);
	if (stream == NULL)
		return; // Invalid handle

	tinyhttp_stream_response_body_ack(stream, num);
}

void tinyhttp_response_send(TinyHTTPResponse res)
{
	TinyHTTPStream *stream = response_to_stream(res);
	if (stream == NULL)
		return; // Invalid handle

	tinyhttp_stream_response_send(stream);

	invalidate_handles_to_stream(res.server, stream);

	TinyHTTPServer *server = res.server;
	int idx = stream - server->stream_state;

	if (tinyhttp_stream_request(stream)) {
		int ready_idx = (server->ready_head + server->ready_count) % TINYHTTP_SERVER_CONN_LIMIT;
		server->ready_queue[ready_idx] = idx;
		server->ready_count++;
	}

	int state = tinyhttp_stream_state(stream);

#if defined(__linux__)
	SOCKET sock = server->stream_sockets[idx];
	struct epoll_event epoll_buf;
	epoll_buf.data.fd = idx;
	epoll_buf.events = 0;
	if (state & TINYHTTP_STREAM_RECV) epoll_buf.events |= EPOLLIN;
	if (state & TINYHTTP_STREAM_SEND) epoll_buf.events |= EPOLLOUT;
	if (epoll_ctl(server->epoll_fd, EPOLL_CTL_MOD, sock, &epoll_buf) < 0) {
		ASSERT(0); // TODO
	}
#elif defined(_WIN32)
	SOCKET sock = server->stream_sockets[idx];
	OVERLAPPED *recv_overlapped = &server->recv_overlapped[idx];
	OVERLAPPED *send_overlapped = &server->send_overlapped[idx];
	if (start_stream_operations(stream, sock, recv_overlapped, send_overlapped) < 0) {
		ASSERT(0); // TODO
	}
#endif
}

void tinyhttp_response_undo(TinyHTTPResponse res)
{
	TinyHTTPStream *stream = response_to_stream(res);
	if (stream == NULL)
		return; // Invalid handle

	tinyhttp_stream_response_undo(stream);
}

////////////////////////////////////////////////////////////////////////////////////
// HTTP ROUTER                                                                    //
////////////////////////////////////////////////////////////////////////////////////
#ifdef TINYHTTP_ROUTER_ENABLE

#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>

typedef struct {
	char *ptr;
	int len;
} string;

#define S(X) ((string) {(X), sizeof(X)-1})

typedef enum {
	ROUTE_STATIC_DIR,
} RouteType;

typedef struct {
	RouteType type;
	string endpoint;
	string path;
	int dir_listing;
} Route;

struct TinyHTTPRouter {
	int num_routes;
	int max_routes;
	Route routes[];
};

TinyHTTPRouter *tinyhttp_router_init(void)
{
	int max_routes = 32;
	TinyHTTPRouter *router = malloc(max_routes * sizeof(TinyHTTPRouter));
	if (router == NULL)
		return NULL;
	router->max_routes = max_routes;
	router->num_routes = 0;
	return router;
}

void tinyhttp_router_free(TinyHTTPRouter *router)
{
	free(router);
}

void tinyhttp_router_dir(TinyHTTPRouter *router, string endpoint, string path, int dir_listing)
{
	if (router->num_routes == router->max_routes)
		abort();
	Route *route = &router->routes[router->num_routes++];
	route->type = ROUTE_STATIC_DIR;
	route->endpoint = endpoint;
	route->path = path;
	route->dir_listing = dir_listing;
}

static int
valid_component_char(char c)
{
	return is_alpha(c) || is_digit(c) || c == '-' || c == '_' || c == '.'; // TODO
}

static int
parse_path(string path, string *comps, int max_comps)
{
	// We treat relative and absolute paths the same
	if (path.len > 0 && path.ptr[0] == '/') {
		path.ptr++;
		path.len--;
		if (path.len == 0)
			return 0;
	}

	int num = 0;
	int cur = 0;
	for (;;) {
		if (cur == path.len || !valid_component_char(path.ptr[cur]))
			return -1; // Empty component
		int start = cur;
		do
			cur++;
		while (cur < path.len && valid_component_char(path.ptr[cur]));
		string comp = { path.ptr + start, cur - start };

		if (eqstr(comp, S(".."))) {
			if (num == 0)
				return -1;
			num--;
		} else if (!eqstr(comp, S("."))) {
			if (num == max_comps)
				return -1;
			comps[num++] = comp;
		}

		if (cur < path.len) {
			if (path.ptr[cur] != '/')
				return -1;
			cur++;
		}

		if (cur == path.len)
			break;
	}

	return num;
}

static int swap_parents(string original_parent_path, string new_parent_path, string path, char *mem, int max)
{
	int num_original_parent_path_comps;
	string original_parent_path_comps[TINYHTTP_ROUTER_MAX_PATH_COMPONENTS];

	int num_new_parent_path_comps;
	string new_parent_path_comps[TINYHTTP_ROUTER_MAX_PATH_COMPONENTS];

	int num_path_comps;
	string path_comps[TINYHTTP_ROUTER_MAX_PATH_COMPONENTS];

	num_original_parent_path_comps = parse_path(original_parent_path, original_parent_path_comps, TINYHTTP_ROUTER_MAX_PATH_COMPONENTS);
	num_new_parent_path_comps      = parse_path(new_parent_path,      new_parent_path_comps,      TINYHTTP_ROUTER_MAX_PATH_COMPONENTS);
	num_path_comps                 = parse_path(path,                 path_comps,                 TINYHTTP_ROUTER_MAX_PATH_COMPONENTS);
	if (num_original_parent_path_comps < 0 || num_new_parent_path_comps < 0 || num_path_comps < 0)
		return -1;

	int match = 1;
	if (num_path_comps < num_original_parent_path_comps)
		match = 0;
	else {
		for (int i = 0; i < num_original_parent_path_comps; i++)
			if (!eqstr(original_parent_path_comps[i], path_comps[i])) {
				match = 0;
				break;
			}
	}
	if (!match)
		return 0;

	int num_result_comps = num_new_parent_path_comps + num_path_comps - num_original_parent_path_comps;
	if (num_result_comps < 0 || num_result_comps > TINYHTTP_ROUTER_MAX_PATH_COMPONENTS)
		return -1;

	string result_comps[TINYHTTP_ROUTER_MAX_PATH_COMPONENTS];
	for (int i = 0; i < num_new_parent_path_comps; i++)
		result_comps[i] = new_parent_path_comps[i];

	for (int i = 0; i < num_path_comps; i++)
		result_comps[num_new_parent_path_comps + i] = path_comps[num_original_parent_path_comps + i];

	int result_flat_len = 0;
	for (int i = 0; i < num_result_comps; i++)
		result_flat_len += result_comps[i].len + 1;

	if (result_flat_len >= max)
		return -1;
	int copied = 0;
	for (int i = 0; i < num_result_comps; i++) {
		if (i > 0)
			mem[copied++] = '/';
		memcpy(mem + copied, result_comps[i].ptr, result_comps[i].len);
		copied += result_comps[i].len;
	}

	mem[copied] = '\0';
	return result_flat_len;
}

static void
respond_with_regular_file(TinyHTTPServer *server, TinyHTTPResponse response, int fd, int file_size)
{
	http_response_write_status(server, response, 200);

	int cap;
	void *dst = http_response_write_body_ptr(server, response, file_size, &cap);
	if (dst) {
		int copied = 0;
		while (copied < file_size) {
			int ret = read(fd, dst + copied, file_size - copied);
			if (ret < 0) {
				if (errno == EINTR)
					continue;
				http_response_undo(server, response);
				http_response_write_status(server, response, 500);
				http_response_send(server, response);
				return;
			}
			if (ret == 0)
				break;
			copied += ret;
		}
		if (copied < file_size) {
			http_response_undo(server, response);
			http_response_write_status(server, response, 500);
			http_response_send(server, response);
			return;
		}
	}
	http_response_write_body_ack(server, response, file_size);
	http_response_send(server, response);
}

static void
respond_with_dir_listing(TinyHTTPServer *server, TinyHTTPResponse response, DIR *dir)
{
	http_response_write_status(server, response, 200);
	http_response_write_header(server, response, "Content-Type: text/html");
	http_response_write_body(server, response, S("<html><head></head><body><ul>"));
	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		string name = { entry->d_name, strlen(entry->d_name) }; // TODO: Check that d_name is always zero terminated
		if (eqstr(name, S(".")) || eqstr(name, S("..")))
			continue;
		int cap;
		char *ptr = http_response_write_body_ptr(server, response, 128, &cap);
		int len = snprintf(ptr, cap, "<li><a href=''>%s</a></li>", entry->d_name); // TODO: add link
		if (len < 0 || len > cap) {
			// TODO
		}
		http_response_write_body_ack(server, response, len);
	}
	http_response_write_body(server, response, S("</ul></body></html>"));
	http_response_send(server, response);
}

static int
serve_static_dir(TinyHTTPServer *server, TinyHTTPResponse response, string base_endpoint, string base_path, string endpoint, int dir_listing)
{
	char mem[1<<12];
	int res = swap_parents(base_endpoint, base_path, endpoint, mem, sizeof(mem));
	if (res <= 0)
		return res;
	string path = {mem, res}; // Note that this is zero terminated

	int fd = open(path.ptr, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			return 0;
		http_response_write_status(server, response, 500);
		http_response_send(server, response);
		return 1;
	}

	struct stat info;
	if (fstat(fd, &info) < 0) {
		http_response_write_status(server, response, 500);
		http_response_send(server, response);
		close(fd);
		return 1;
	}

	if (S_ISDIR(info.st_mode)) {

		int fd2 = openat(fd, "index.html", O_RDONLY);
		if (fd2 < 0) {
			if (errno != ENOENT) {
				http_response_write_status(server, response, 500);
				http_response_send(server, response);
				close(fd);
				return 1;
			}
			// Allow falling through
		} else {

			struct stat info2;
			if (fstat(fd2, &info2) < 0) {
				http_response_write_status(server, response, 500);
				http_response_send(server, response);
				close(fd2);
				close(fd);
				return 1;
			}

			respond_with_regular_file(server, response, fd2, info2.st_size);

			close(fd2);
			close(fd);
			return 1;
		}
		// Allow falling through
	}

	if (S_ISDIR(info.st_mode)) {

		if (!dir_listing) {
			close(fd);
			return 0;
		}

		DIR *dir = fdopendir(fd);
		if (dir == NULL) {
			http_response_write_status(server, response, 500);
			http_response_send(server, response);
			close(fd);
			return 1;
		}

		respond_with_dir_listing(server, response, dir);
		closedir(dir); // This also closes fd
		return 1;
	}

	if (!S_ISREG(info.st_mode)) {
		http_response_write_status(server, response, 500);
		http_response_send(server, response);
		close(fd);
		return 1;
	}
	int file_size = info.st_size;

	respond_with_regular_file(server, response, fd, file_size);
	close(fd);
	return 1;
}

void http_router_resolve(TinyHTTPRouter *router, TinyHTTPServer *server, TinyHTTPRequest *request, TinyHTTPResponse response)
{
	for (int i = 0; i < router->num_routes; i++) {
		Route *route = &router->routes[i];
		switch (route->type) {
		case ROUTE_STATIC_DIR:
			if (1 == serve_static_dir(server, response, route->endpoint, route->path, request->path, route->dir_listing))
				return;
			break;

		default:
			http_response_write_status(server, response, 500);
			http_response_send(server, response);
			return;
		}
	}
	http_response_write_status(server, response, 404);
	http_response_send(server, response);
}

#endif // TINYHTTP_ROUTER_ENABLE