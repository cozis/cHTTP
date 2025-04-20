#include "test.h"

// This file tests the behavior of the "Connection" header

// HTTP/1.1, No "Connection" header
#define REQUEST_HTTP1_1_NO_CONNECTION_HEADER	\
	"GET / HTTP/1.1\r\n"						\
	"Host: 127.0.0.1:8080\r\n"					\
	"\r\n"

// HTTP/1.1, "Connection" header with invalid value
#define REQUEST_HTTP1_1_CONNECTION_INVALID	\
	"GET / HTTP/1.1\r\n"					\
	"Host: 127.0.0.1:8080\r\n"				\
	"Connection: zzz\r\n"					\
	"\r\n"

// HTTP/1.1, "Connection: Keep-Alive" header
#define REQUEST_HTTP1_1_CONNECTION_KEEPALIVE	\
	"GET / HTTP/1.1\r\n"						\
	"Host: 127.0.0.1:8080\r\n"					\
	"Connection: Keep-Alive\r\n"				\
	"\r\n"

// HTTP/1.1, "Connection: Close" header
#define REQUEST_HTTP1_1_CONNECTION_CLOSE	\
	"GET / HTTP/1.1\r\n"					\
	"Host: 127.0.0.1:8080\r\n"				\
	"Connection: Close\r\n"					\
	"\r\n"

// HTTP/1.0, No "Connection" header
#define REQUEST_HTTP1_0_NO_CONNECTION_HEADER	\
	"GET / HTTP/1.0\r\n"						\
	"\r\n"

// HTTP/1.0, "Connection" header with invalid value
#define REQUEST_HTTP1_0_CONNECTION_INVALID	\
	"GET / HTTP/1.0\r\n"					\
	"Connection: zzz\r\n"					\
	"\r\n"

// HTTP/1.0, "Connection: Keep-Alive" header
#define REQUEST_HTTP1_0_CONNECTION_KEEPALIVE	\
	"GET / HTTP/1.0\r\n"						\
	"Connection: Keep-Alive\r\n"				\
	"\r\n"

// HTTP/1.0, "Connection: Close" header
#define REQUEST_HTTP1_0_CONNECTION_CLOSE	\
	"GET / HTTP/1.0\r\n"					\
	"Connection: Close\r\n"					\
	"\r\n"

static void test_setreuse(void)
{
	TinyHTTPStream stream;
	
	TEST_START
	tinyhttp_stream_init(&stream, memfunc, NULL);

	TEST(!(tinyhttp_stream_state(&stream) & TINYHTTP_STREAM_REUSE));

	tinyhttp_stream_setreuse(&stream, 1);

	TEST(tinyhttp_stream_state(&stream) & TINYHTTP_STREAM_REUSE);

	tinyhttp_stream_setreuse(&stream, 0);

	TEST(!(tinyhttp_stream_state(&stream) & TINYHTTP_STREAM_REUSE));
	
	tinyhttp_stream_setreuse(&stream, 5847295);

	TEST(tinyhttp_stream_state(&stream) & TINYHTTP_STREAM_REUSE);
	
	tinyhttp_stream_free(&stream);
	TEST_END
}
	

typedef enum {
	DONT_REUSE,
	ALLOW_REUSE,
} ServerReuse;

typedef enum {
	INCONNHDR_NONE,
	INCONNHDR_KEEPALIVE,
	INCONNHDR_CLOSE,
	INCONNHDR_INVALID,
} InputConnectionHeader;

typedef enum {
	OUTCONNHDR_MISSING_OR_KEEPALIVE,
	OUTCONNHDR_CLOSE,
} OutputConnectionHeader;

static void test_reuse_helper(
	ServerReuse server_reuse,
	InputConnectionHeader input_conn_header,
	int input_http_minor_version,
	OutputConnectionHeader expect_output_conn_header,
	int expect_output_http_minor_version,
	const char *file, int line)
{
	TinyHTTPStream stream;

	TEST_START2(file, line)
	tinyhttp_stream_init(&stream, memfunc, NULL);
	tinyhttp_stream_setreuse(&stream, server_reuse);

	if (input_http_minor_version == 1) {
		switch (input_conn_header) {
			case INCONNHDR_NONE     : send_request(&stream, REQUEST_HTTP1_1_NO_CONNECTION_HEADER); break;
			case INCONNHDR_KEEPALIVE: send_request(&stream, REQUEST_HTTP1_1_CONNECTION_KEEPALIVE); break;
			case INCONNHDR_CLOSE    : send_request(&stream, REQUEST_HTTP1_1_CONNECTION_CLOSE);     break;
			case INCONNHDR_INVALID  : send_request(&stream, REQUEST_HTTP1_1_CONNECTION_INVALID);   break;
		}
	} else {
		switch (input_conn_header) {
			case INCONNHDR_NONE     : send_request(&stream, REQUEST_HTTP1_0_NO_CONNECTION_HEADER); break;
			case INCONNHDR_KEEPALIVE: send_request(&stream, REQUEST_HTTP1_0_CONNECTION_KEEPALIVE); break;
			case INCONNHDR_CLOSE    : send_request(&stream, REQUEST_HTTP1_0_CONNECTION_CLOSE);     break;
			case INCONNHDR_INVALID  : send_request(&stream, REQUEST_HTTP1_0_CONNECTION_INVALID);   break;
		}
	}

	// Build a dummy response
	tinyhttp_stream_response_status(&stream, 200);
	tinyhttp_stream_response_send(&stream);

	Response res;
	char buf[1<<10];
	recv_response(&stream, &res, buf, sizeof(buf));

	TEST(res.minor == expect_output_http_minor_version);

	int state = tinyhttp_stream_state(&stream);
	switch (expect_output_conn_header) {

		case OUTCONNHDR_MISSING_OR_KEEPALIVE:
		{
			TEST(!header_exists(&res, TINYHTTP_STRING("Connection"))
				|| header_exists_with_value(&res, TINYHTTP_STRING("Connection"), TINYHTTP_STRING("Keep-Alive")));
			TEST((state & TINYHTTP_STREAM_DIED) == 0);
		}
		break;

		case OUTCONNHDR_CLOSE:
		{
			TEST(header_exists_with_value(&res, TINYHTTP_STRING("Connection"), TINYHTTP_STRING("Close")));
			TEST(state & TINYHTTP_STREAM_DIED);
		}
		break;
	}

	tinyhttp_stream_free(&stream);
	TEST_END
}

void test_reuse(void)
{
	// Relevant specs:
	//   RFC 9112, Section 9.3. (Persistence)
	//   RFC 9112, Section 9.6. (Tear-down)
	//   RFC 9110, Section 7.6.1. (Connection)

	test_setreuse();
	test_reuse_helper(DONT_REUSE,  INCONNHDR_NONE,      1, OUTCONNHDR_CLOSE,                1, __FILE__, __LINE__);
	test_reuse_helper(DONT_REUSE,  INCONNHDR_KEEPALIVE, 1, OUTCONNHDR_CLOSE,                1, __FILE__, __LINE__);
	test_reuse_helper(DONT_REUSE,  INCONNHDR_CLOSE,     1, OUTCONNHDR_CLOSE,                1, __FILE__, __LINE__);
	test_reuse_helper(DONT_REUSE,  INCONNHDR_INVALID,   1, OUTCONNHDR_CLOSE,                1, __FILE__, __LINE__);
	test_reuse_helper(ALLOW_REUSE, INCONNHDR_NONE,      1, OUTCONNHDR_MISSING_OR_KEEPALIVE, 1, __FILE__, __LINE__);
	test_reuse_helper(ALLOW_REUSE, INCONNHDR_KEEPALIVE, 1, OUTCONNHDR_MISSING_OR_KEEPALIVE, 1, __FILE__, __LINE__);
	test_reuse_helper(ALLOW_REUSE, INCONNHDR_CLOSE,     1, OUTCONNHDR_CLOSE,                1, __FILE__, __LINE__);
	test_reuse_helper(ALLOW_REUSE, INCONNHDR_INVALID,   1, OUTCONNHDR_MISSING_OR_KEEPALIVE, 1, __FILE__, __LINE__);
	test_reuse_helper(DONT_REUSE,  INCONNHDR_NONE,      0, OUTCONNHDR_CLOSE,                0, __FILE__, __LINE__);
	test_reuse_helper(DONT_REUSE,  INCONNHDR_KEEPALIVE, 0, OUTCONNHDR_CLOSE,                0, __FILE__, __LINE__);
	test_reuse_helper(DONT_REUSE,  INCONNHDR_CLOSE,     0, OUTCONNHDR_CLOSE,                0, __FILE__, __LINE__);
	test_reuse_helper(DONT_REUSE,  INCONNHDR_INVALID,   0, OUTCONNHDR_CLOSE,                0, __FILE__, __LINE__);
	test_reuse_helper(ALLOW_REUSE, INCONNHDR_NONE,      0, OUTCONNHDR_CLOSE,                0, __FILE__, __LINE__);
	test_reuse_helper(ALLOW_REUSE, INCONNHDR_KEEPALIVE, 0, OUTCONNHDR_CLOSE,                0, __FILE__, __LINE__);
	test_reuse_helper(ALLOW_REUSE, INCONNHDR_CLOSE,     0, OUTCONNHDR_CLOSE,                0, __FILE__, __LINE__);
	test_reuse_helper(ALLOW_REUSE, INCONNHDR_INVALID,   0, OUTCONNHDR_CLOSE,                0, __FILE__, __LINE__);
}
