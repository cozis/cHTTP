#include "test.h"

void test_chunking(void)
{
	{
		TinyHTTPStream stream;

		TEST_START
		tinyhttp_stream_init(&stream, memfunc, NULL);

		// Send request
		send_request(&stream,
			"POST / HTTP/1.1\r\n"
			"Host: 127.0.0.1:8080\r\n"
			"User-Agent: curl/7.81.0\r\n"
			"Accept: */*\r\n"
			"Transfer-Encoding: Chunked\r\n"
			"Content-Type: application/x-www-form-urlencoded\r\n"
			"\r\n"
			"d\r\n"
			"Hello, world!\r\n"
			"0\r\n"
			"\r\n"
		);

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
}