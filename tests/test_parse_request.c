#include <string.h>
#include "test.h"

static void test_helper(char *src, int len, int expret, TinyHTTPRequest *expreq)
{
	if (len < 0) len = strlen(src);
	TinyHTTPRequest req;
	int ret = tinyhttp_parserequest(src, len, -1ULL, &req);
	TEST(ret == expret);
	if (expret > 0) {
		TEST(match_request(&req, expreq));
	}
}

void test_parse_request(void)
{
	{
		char src[] =
			"GET / HTTP/1.1\r\n"
			"Host: 127.0.0.1:8080\r\n"
			"Connection: Keep-Alive\r\n"
			"\r\n";
		TinyHTTPRequest req;
		req.method = TINYHTTP_METHOD_GET;
		req.minor = 1;
		req.path = TINYHTTP_STRING("/");
		req.num_headers = 2;
		req.headers[0].name  = TINYHTTP_STRING("Host");
		req.headers[0].value = TINYHTTP_STRING("127.0.0.1:8080");
		req.headers[1].name  = TINYHTTP_STRING("Connection");
		req.headers[1].value = TINYHTTP_STRING("Keep-Alive");
		req.body = NULL;
		req.body_len = 0;

		for (int i = 0; i < strlen(src)-1; i++)
			test_helper(src, i, 0, &req);

		test_helper(src, strlen(src), strlen(src), &req);
	}
}
