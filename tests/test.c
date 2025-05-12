#include <stdlib.h>
#include <string.h>
#include "test.h"

static const char *statestr(HTTP_EngineState state)
{
	switch (state) {
		case HTTP_ENGINE_STATE_NONE                : return "NONE";
		case HTTP_ENGINE_STATE_CLIENT_PREP_URL     : return "CLIENT_PREP_URL";
		case HTTP_ENGINE_STATE_CLIENT_PREP_HEADER  : return "CLIENT_PREP_HEADER";
		case HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF: return "CLIENT_PREP_BODY_BUF";
		case HTTP_ENGINE_STATE_CLIENT_PREP_BODY_ACK: return "CLIENT_PREP_BODY_ACK";
		case HTTP_ENGINE_STATE_CLIENT_PREP_ERROR   : return "CLIENT_PREP_ERROR";
		case HTTP_ENGINE_STATE_CLIENT_SEND_BUF     : return "CLIENT_SEND_BUF";
		case HTTP_ENGINE_STATE_CLIENT_SEND_ACK     : return "CLIENT_SEND_ACK";
		case HTTP_ENGINE_STATE_CLIENT_RECV_BUF     : return "CLIENT_RECV_BUF";
		case HTTP_ENGINE_STATE_CLIENT_RECV_ACK     : return "CLIENT_RECV_ACK";
		case HTTP_ENGINE_STATE_CLIENT_READY        : return "CLIENT_READY";
		case HTTP_ENGINE_STATE_CLIENT_CLOSED       : return "CLIENT_CLOSED";
		case HTTP_ENGINE_STATE_SERVER_RECV_BUF     : return "SERVER_RECV_BUF";
		case HTTP_ENGINE_STATE_SERVER_RECV_ACK     : return "SERVER_RECV_ACK";
		case HTTP_ENGINE_STATE_SERVER_PREP_STATUS  : return "SERVER_PREP_STATUS";
		case HTTP_ENGINE_STATE_SERVER_PREP_HEADER  : return "SERVER_PREP_HEADER";
		case HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF: return "SERVER_PREP_BODY_BUF";
		case HTTP_ENGINE_STATE_SERVER_PREP_BODY_ACK: return "SERVER_PREP_BODY_ACK";
		case HTTP_ENGINE_STATE_SERVER_PREP_ERROR   : return "SERVER_PREP_ERROR";
		case HTTP_ENGINE_STATE_SERVER_SEND_BUF     : return "SERVER_SEND_BUF";
		case HTTP_ENGINE_STATE_SERVER_SEND_ACK     : return "SERVER_SEND_ACK";
		case HTTP_ENGINE_STATE_SERVER_CLOSED       : return "SERVER_CLOSED";
	}
	return "???";
}

void testeq_engstate(HTTP_EngineState l, HTTP_EngineState r, HTTP_String uneval_l, HTTP_String uneval_r, const char *file, int line)
{
	if (l != r) {
		printf("Test failed at %s:%d\n", file, line);
		printf("  TEST_EQ(%.*s, %.*s) -> TEST_EQ(%s, %s)\n",
			(int) uneval_l.len, uneval_l.ptr,
			(int) uneval_r.len, uneval_r.ptr,
			statestr(l), statestr(r));
		abort();
	}
}

void testeq_int(int l, int r, HTTP_String uneval_l, HTTP_String uneval_r, const char *file, int line)
{
	if (l != r) {
		printf("Test failed at %s:%d\n", file, line);
		printf("  TEST_EQ(%.*s, %.*s) -> TEST_EQ(%d, %d)\n",
			(int) uneval_l.len, uneval_l.ptr,
			(int) uneval_r.len, uneval_r.ptr,
			l, r);
		abort();
	}
}

void testeq_str(HTTP_String l, HTTP_String r, HTTP_String uneval_l, HTTP_String uneval_r, const char *file, int line)
{
	if (!http_streq(l, r)) {
		printf("Test failed at %s:%d\n", file, line);
		printf("  TEST_EQ(\"%.*s\", \"%.*s\") -> TEST_EQ(%.*s, %.*s)\n",
			(int) uneval_l.len, uneval_l.ptr,
			(int) uneval_r.len, uneval_r.ptr,
			(int) l.len, l.ptr,
			(int) r.len, r.ptr);
		abort();
	}
}

void test_branch_coverage_parse(void);
void test_branch_coverage_engine(void);
void test_fuzz_engine(void);

int main(void)
{
	char *tests[] = {
	};

	for (int i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		HTTP_Request req;
		int ret = http_parse_request(tests[i], strlen(tests[i]), &req);
		TEST(ret == 0);
	}

	//test_branch_coverage_parse();
	test_branch_coverage_engine();
	//test_fuzz_engine();

	return 0;
}
