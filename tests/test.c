#include <string.h>
#include "../http.h"

#define TEST(X) {if (!(X)) __builtin_trap(); }

void test_branch_coverage(void);

int main(void)
{
	char *tests[] = {
	};

	for (int i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		HTTP_Request req;
		int ret = http_parse_request(tests[i], strlen(tests[i]), &req);
		TEST(ret == 0);
	}

	test_branch_coverage();

	return 0;
}
