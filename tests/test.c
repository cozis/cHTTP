#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "test.h"
#include "picohttpparser.h"

//////////////////////////////////////////////////////////////////////////////////////
// TEST CASES
//////////////////////////////////////////////////////////////////////////////////////

#define BASIC_REQUEST_STRING		\
	"GET / HTTP/1.1\r\n"			\
	"Host: 127.0.0.1:8080\r\n"		\
	"User-Agent: curl/7.81.0\r\n"	\
	"Accept: */*\r\n"				\
	"\r\n"

static void test_init(void)
{
	TinyHTTPStream stream;

	TEST_START
	tinyhttp_stream_init(&stream, memfunc, NULL);

	int state = tinyhttp_stream_state(&stream);

	// These flags must be set on init
	TEST(state & TINYHTTP_STREAM_RECV);

	// These must be unset
	TEST(!(state & TINYHTTP_STREAM_DIED));
	TEST(!(state & TINYHTTP_STREAM_READY));
	TEST(!(state & TINYHTTP_STREAM_REUSE));
	TEST(!(state & TINYHTTP_STREAM_RECV_STARTED));
	TEST(!(state & TINYHTTP_STREAM_SEND_STARTED));

	tinyhttp_stream_free(&stream);
	TEST_END
}

static void test_kill(void)
{
	TinyHTTPStream stream;

	TEST_START
	tinyhttp_stream_init(&stream, memfunc, NULL);

	TEST(!(tinyhttp_stream_state(&stream) & TINYHTTP_STREAM_DIED));

	tinyhttp_stream_kill(&stream);

	TEST(tinyhttp_stream_state(&stream) & TINYHTTP_STREAM_DIED);

	tinyhttp_stream_free(&stream);
	TEST_END
}

static void
test_recv_started_flag(void)
{
	ptrdiff_t cap;
	TinyHTTPStream stream;

	TEST_START
	tinyhttp_stream_init(&stream, memfunc, NULL);

	TEST(!(tinyhttp_stream_state(&stream) & TINYHTTP_STREAM_RECV_STARTED));

	tinyhttp_stream_recv_buf(&stream, &cap);

	TEST(tinyhttp_stream_state(&stream) & TINYHTTP_STREAM_RECV_STARTED);

	tinyhttp_stream_recv_ack(&stream, 0);

	TEST(!(tinyhttp_stream_state(&stream) & TINYHTTP_STREAM_RECV_STARTED));

	tinyhttp_stream_free(&stream);
	TEST_END
}

static void
test_send_started_flag(void)
{
	ptrdiff_t cap;
	TinyHTTPStream stream;

	TEST_START
	tinyhttp_stream_init(&stream, memfunc, NULL);

	TEST(!(tinyhttp_stream_state(&stream) & TINYHTTP_STREAM_SEND_STARTED));

	tinyhttp_stream_send_buf(&stream, &cap);

	TEST(tinyhttp_stream_state(&stream) & TINYHTTP_STREAM_SEND_STARTED);

	tinyhttp_stream_send_ack(&stream, 0);

	TEST(!(tinyhttp_stream_state(&stream) & TINYHTTP_STREAM_SEND_STARTED));

	tinyhttp_stream_free(&stream);
	TEST_END
}

static void test_basic_exchange()
{
	TinyHTTPStream stream;

	TEST_START
	tinyhttp_stream_init(&stream, memfunc, NULL);

	// Send request
	send_request(&stream, BASIC_REQUEST_STRING);

	// Build response
	tinyhttp_stream_response_status(&stream, 200);
	tinyhttp_stream_response_send(&stream);

	// Receive response
	char buf[1<<12];
	Response res;
	recv_response(&stream, &res, buf, sizeof(buf));

	// We expect the status line:
	//   HTTP/1.1 200 OK
	TEST(res.minor == 1);
	TEST(res.status_code == 200);
	TEST(tinyhttp_streq(res.status_text, TINYHTTP_STRING("OK")));

	tinyhttp_stream_free(&stream);
	TEST_END
}

//////////////////////////////////////////////////////////////////////////////////////
// ENTRY POINT
//////////////////////////////////////////////////////////////////////////////////////

int main(void)
{
	test_init();
	test_kill();
	test_recv_started_flag();
	test_send_started_flag();
	test_basic_exchange();
	test_reuse();
	test_chunking();
	test_parse_request();
	printf("OK\n");
	return 0;
}

//////////////////////////////////////////////////////////////////////////////////////
// Helper Functions
//////////////////////////////////////////////////////////////////////////////////////

void *memfunc(TinyHTTPMemoryFuncTag tag, void *ptr, int len, void *data)
{
	(void) data;
	switch (tag) {

		case TINYHTTP_MEM_MALLOC:
		return malloc(len);

		case TINYHTTP_MEM_FREE:
		free(ptr);
		return NULL;
	}
	return NULL;
}

static int
buffer_into_stream(TinyHTTPStream *stream, const char *src, int len)
{
	int state = tinyhttp_stream_state(stream);

	ptrdiff_t copied = 0;
	while (copied < len && (state & TINYHTTP_STREAM_RECV)) {

		char *dst;
		ptrdiff_t cap;
		ptrdiff_t cpy;

		dst = tinyhttp_stream_recv_buf(stream, &cap);

		cpy = len - copied;
		if (cpy > cap) cpy = cap;

		memcpy(dst, src + copied, cpy);

		tinyhttp_printbytes("  >> ", src + copied, cpy);

		copied += cpy;
		tinyhttp_stream_recv_ack(stream, cpy);
		state = tinyhttp_stream_state(stream);
	}

	printf("\n");
	return copied;
}

static int
stream_into_buffer(TinyHTTPStream *stream, char *dst, int cap)
{
	int state = tinyhttp_stream_state(stream);
	
	int copied = 0;
	while (copied < cap && (state & TINYHTTP_STREAM_SEND)) {

		char *src;
		ptrdiff_t len;
		ptrdiff_t cpy;

		src = tinyhttp_stream_send_buf(stream, &len);

		cpy = cap - copied;
		if (cpy > len) cpy = len;

		memcpy(dst + copied, src, cpy);

		tinyhttp_printbytes("  << ", src, cpy);

		copied += cpy;
		tinyhttp_stream_send_ack(stream, cpy);
		state = tinyhttp_stream_state(stream);
	}

	printf("\n");
	return copied;
}

int match_request(TinyHTTPRequest *r1, TinyHTTPRequest *r2)
{
	if (r1->method != r2->method)
		return 0;

	if (r1->minor != r2->minor)
		return 0;

	if (!tinyhttp_streq(r1->path, r2->path))
		return 0;

	if (r1->num_headers != r2->num_headers)
		return 0;

	for (int i = 0; i < r2->num_headers; i++) {
		if (!tinyhttp_streq(r1->headers[i].name, r2->headers[i].name))
			return 0;
		if (!tinyhttp_streq(r1->headers[i].value, r2->headers[i].value))
			return 0;
	}

	if (r1->body_len != r2->body_len)
		return 0;

	if (r2->body_len == 0) {
		if (r1->body != NULL)
			return 0;
	} else {
		if (memcmp(r1->body, r2->body, r2->body_len))
			return 0;
	}

	return 1;
}

static void
expect_request(TinyHTTPStream *stream, TinyHTTPRequest expreq)
{
	int state = tinyhttp_stream_state(stream);
	TEST(state & TINYHTTP_STREAM_READY);

	TinyHTTPRequest *req = tinyhttp_stream_request(stream);
	TEST(req);
	TEST(match_request(req, &expreq));
}

int parse_request(TinyHTTPString txt, TinyHTTPRequest *req, char *buf, int max)
{
	const char *method;
	size_t method_len;

	const char *path;
	size_t path_len;

	int minor;

	struct phr_header headers[TINYHTTP_HEADER_LIMIT];
	size_t num_headers = TINYHTTP_HEADER_LIMIT;

	int ret = phr_parse_request(
		txt.ptr, txt.len,
		&method, &method_len,
		&path, &path_len,
		&minor,
		headers, &num_headers,
		0);
	ptrdiff_t head_len = ret;

	if (method_len == 3 && !memcmp("GET", method, 3)) {
		req->method = TINYHTTP_METHOD_GET;
	} else if (method_len == 4 && !memcmp("POST", method, 4)) {
		req->method = TINYHTTP_METHOD_POST;
	} else {
		return -1;
	}

	req->minor = minor;
	req->path  = (TinyHTTPString) { path, path_len };
	req->num_headers = num_headers;

	for (int i = 0; i < (int) num_headers; i++) {
		req->headers[i].name = (TinyHTTPString) {
			headers[i].name,
			headers[i].name_len,
		};
		req->headers[i].value = (TinyHTTPString) {
			headers[i].value,
			headers[i].value_len,
		};
	}

	int transfer_encoding_index = tinyhttp_findheader(req, TINYHTTP_STRING("Transfer-Encoding"));
	if (transfer_encoding_index != -1) {
		// TODO: For now, we consider request as chunked just for having the Transfer-Encoding header

		if (txt.len - head_len > max)
			return -1;
		memcpy(buf, txt.ptr + head_len, txt.len - head_len);

		struct phr_chunked_decoder decoder;
		memset(&decoder, 0, sizeof(decoder));
		decoder.consume_trailer = 1;  // Process any trailing headers

		// Decode the chunked body
		size_t decoded_size = txt.len - head_len;
		ssize_t ret = phr_decode_chunked(&decoder, buf, &decoded_size);
		if (ret < 0)
			return -1;

		req->body = buf;
		req->body_len = decoded_size;
		return 0;
	}

	int content_length_index = tinyhttp_findheader(req, TINYHTTP_STRING("Content-Length"));
	if (content_length_index != -1) {

		__builtin_trap(); // TODO

		return 0;
	}

	req->body = NULL;
	req->body_len = 0;
	return 0;
}

static void
parse_response(TinyHTTPString txt, Response *res)
{
	int minor;

	int         status_code;
	const char *status_text;
	size_t      status_text_len;

	struct phr_header headers[TINYHTTP_HEADER_LIMIT];
	size_t num_headers = TINYHTTP_HEADER_LIMIT;

	int ret = phr_parse_response(
		txt.ptr, txt.len,
		&minor,
		&status_code, &status_text, &status_text_len,
		headers, &num_headers,
		0);
	TEST(ret == txt.len);

	res->minor = minor;
	res->status_code = status_code;
	res->status_text = (TinyHTTPString) { status_text, status_text_len };

	res->num_headers = num_headers;
	for (int i = 0; i < (int) num_headers; i++) {
		res->headers[i].name = (TinyHTTPString) {
			headers[i].name,
			headers[i].name_len
		};
		res->headers[i].value = (TinyHTTPString) {
			headers[i].value,
			headers[i].value_len
		};
	}

	res->body = NULL; // TODO
	res->body_len = 0; // TODO
}

void send_request(TinyHTTPStream *stream, const char *str)
{
	int received = buffer_into_stream(stream, str, strlen(str));
	TEST(received == (int) strlen(str));

	TinyHTTPRequest req;
	char buf[1<<12];
	TEST(parse_request((TinyHTTPString) {str, strlen(str)}, &req, buf, sizeof(buf)) == 0);

	expect_request(stream, req);
}

void recv_response(TinyHTTPStream *stream, Response *res, char *dst, int cap)
{
	int len = stream_into_buffer(stream, dst, cap);

	int state = tinyhttp_stream_state(stream);
	TEST((state & TINYHTTP_STREAM_SEND) == 0);

	parse_response((TinyHTTPString) { dst, len }, res);
}

int header_exists(Response *res, TinyHTTPString name)
{
	for (int i = 0; i < res->num_headers; i++)
		if (tinyhttp_streqcase(res->headers[i].name, name))
			return 1;
	return 0;
}

int header_exists_with_value(Response *res, TinyHTTPString name, TinyHTTPString value)
{
	for (int i = 0; i < res->num_headers; i++)
		if (tinyhttp_streqcase(res->headers[i].name, name))
			return tinyhttp_streqcase(res->headers[i].value, value);
	return 0;
}

//////////////////////////////////////////////////////////////////////////////////////
// THE END
//////////////////////////////////////////////////////////////////////////////////////