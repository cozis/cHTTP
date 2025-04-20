#include <stdio.h>
#include "../tinyhttp.h"

typedef struct {

	int minor;

	int status_code;
	TinyHTTPString status_text;

	int num_headers;
	TinyHTTPHeader headers[TINYHTTP_HEADER_LIMIT];

	char *body;
	int   body_len;
} Response;

// Memory function used to initialize TinyHTTPStream
// TODO: Maybe choose a better name for this
void *memfunc(TinyHTTPMemoryFuncTag tag, void *ptr, int len, void *data);

// Moves the request "str" into the stream, checks that the stream
// became ready and that it parsed the request correctly. When this
// functions returns the stream is ready for a response.
void send_request(TinyHTTPStream *stream, const char *str);

// Copies into the "dst" buffer the output bytes from the stream
// (up to "cap" bytes) and parses them as an HTTP response into
// "res".
void recv_response(TinyHTTPStream *stream, Response *res, char *dst, int cap);

int header_exists(Response *res, TinyHTTPString name);
int header_exists_with_value(Response *res, TinyHTTPString name, TinyHTTPString value);

#define TEST(X) {if (!(X)) { printf("Test failed at %s:%d\n", __FILE__, __LINE__); fflush(stdout); __builtin_trap(); }}

#define TEST_START printf("Test %s:%d\n", __FILE__, __LINE__);
#define TEST_START2(file, line) printf("Test %s:%d\n", (file), (line));
#define TEST_END

void test_reuse(void);