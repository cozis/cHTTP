#include <stdlib.h>
#include <string.h>
#include "test.h"

static void *memfunc(HTTP_MemoryFuncTag tag,
	void *ptr, int len, void *data)
{
	(void) data;
	switch (tag) {

		case HTTP_MEMFUNC_MALLOC:
		return malloc(len);

		case HTTP_MEMFUNC_FREE:
		free(ptr);
		return NULL;
	}
	return NULL;
}

static void test_engine_server(void)
{
	HTTP_Engine eng;

	{
		int client = 0;
		memset(&eng, 0, sizeof(eng));
		http_engine_init(&eng, client, memfunc, NULL);
		TEST_EQ((int) http_engine_state(&eng), HTTP_ENGINE_STATE_SERVER_RECV_BUF);
		http_engine_free(&eng);
	}

	{
		int client = 1;
		memset(&eng, 0, sizeof(eng));
		http_engine_init(&eng, client, memfunc, NULL);
		TEST_EQ((int) http_engine_state(&eng), HTTP_ENGINE_STATE_CLIENT_PREP_URL);
		http_engine_free(&eng);
	}
}

static int read_from_client_engine(HTTP_Engine *eng, char *dst, int cap)
{
	TEST_EQ(http_engine_state(eng), HTTP_ENGINE_STATE_CLIENT_SEND_BUF);

	int num = 0;
	do {
		int len;
		char *src = http_engine_sendbuf(eng, &len);
		TEST_EQ(http_engine_state(eng), HTTP_ENGINE_STATE_CLIENT_SEND_ACK);
		
		TEST(src != NULL);
		TEST(cap - num >= len);
		memcpy(dst + num, src, len);

		num += len;
		http_engine_sendack(eng, len);
	} while (http_engine_state(eng) == HTTP_ENGINE_STATEBIT_SEND_BUF);

	return num;
}

static void send_into_client_engine(HTTP_Engine *eng, char *src, int len)
{
	int num = 0;
	while (num < len) {
		TEST_EQ(http_engine_state(eng), HTTP_ENGINE_STATE_CLIENT_RECV_BUF);

		int cap;
		char *dst = http_engine_recvbuf(eng, &cap);
		TEST_EQ(http_engine_state(eng), HTTP_ENGINE_STATE_CLIENT_RECV_ACK);
		TEST(dst != NULL);
		TEST(cap > 0);

		int cpy = len - num;
		if (cpy > cap) cpy = cap;

		memcpy(dst, src + num, cpy);

		num += cpy;
		http_engine_recvack(eng, cpy);
	}
}

static void test_engine_client_basic_flow(void)
{
	int client = 1;
	HTTP_Engine eng;
	http_engine_init(&eng, client, memfunc, NULL);
	TEST_EQ(http_engine_state(&eng), HTTP_ENGINE_STATE_CLIENT_PREP_URL);

	http_engine_url(&eng, HTTP_METHOD_GET, "http://some.url.com/some/endpoint", 1);
	TEST_EQ(http_engine_state(&eng), HTTP_ENGINE_STATE_CLIENT_PREP_HEADER);

	http_engine_header(&eng, "headerA: valueA", -1);
	TEST_EQ(http_engine_state(&eng), HTTP_ENGINE_STATE_CLIENT_PREP_HEADER);

	http_engine_body(&eng, "Hello, world!", -1);
	TEST_EQ(http_engine_state(&eng), HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF);

	http_engine_done(&eng);
	TEST_EQ(http_engine_state(&eng), HTTP_ENGINE_STATE_CLIENT_SEND_BUF);

	{
		char sendbuf[1<<10];
		int  sendnum;
		sendnum = read_from_client_engine(&eng, sendbuf, (int) sizeof(sendbuf));

		char expect[] =
			"GET /some/endpoint HTTP/1.1\r\n"
			"Host: some.url.com\r\n"
			"headerA: valueA\r\n"
			"Connection: Keep-Alive\r\n"
			"Content-Length: 13        \r\n"
			"\r\n"
			"Hello, world!";

		TEST_EQ(sendnum, strlen(expect));
		TEST_EQ(memcmp(expect, sendbuf, strlen(expect)), 0);
	}

	{
		char response[] =
			"HTTP/1.1 200 OK\r\n"
			"\r\n";
		send_into_client_engine(&eng, response, strlen(response));
	}

	TEST_EQ(http_engine_state(&eng), HTTP_ENGINE_STATE_CLIENT_READY);

	http_engine_free(&eng);
}

void test_branch_coverage_engine(void)
{
	test_engine_server();
	test_engine_client_basic_flow();
}
