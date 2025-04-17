#include <signal.h>
#include <stdlib.h>
#include "tinyhttp.h"

sig_atomic_t should_exit = 0;

static void
signal_handler(int sig)
{
	if (sig == SIGINT)
		should_exit = 1;
}

static void *memfunc(TinyHTTPMemoryFuncTag tag,
	void *ptr, int len, void *data)
{
	(void) data;
	switch (tag) {

		case TINYHTTP_MEM_MALLOC:
		return malloc(len);

		case TINYHTTP_MEM_REALLOC:
		return realloc(ptr, len);

		case TINYHTTP_MEM_FREE:
		free(ptr);
		return NULL;
	}
	return NULL;
}

int main(void)
{
	signal(SIGINT, signal_handler);

	TinyHTTPServerConfig config = {

		.reuse = 1,

		.plain_addr = "127.0.0.1",
		.plain_port = 8080,
		.plain_backlog = 32,

		.secure = 1,
		.secure_addr = "127.0.0.1",
		.secure_port = 8443,
		.secure_backlog = 32,

		.cert_file = "cert.pem",
		.private_key_file = "privkey.pem",
	};

	TinyHTTPServer *server = tinyhttp_server_init(config, memfunc, NULL);
	if (server == NULL)
		return -1;

	while (!should_exit) {
		TinyHTTPRequest *req;
		TinyHTTPResponse res;
		if (tinyhttp_server_wait(server, &req, &res, 1000))
			continue; // Timeout or error
		tinyhttp_response_status(res, 200);
		tinyhttp_response_send(res);
	}

	tinyhttp_server_free(server);
	return 0;
}
