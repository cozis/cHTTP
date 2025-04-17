#include <signal.h>
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

		.secure = 0,
		.secure_addr = "127.0.0.1",
		.secure_port = 8443,

		.cert_file = "cert.pem",
		.private_key_file = "privkey.pem",
	};

	TinyHTTPServer *server = tinyhttp_server_init(config, memfunc, NULL);
	if (server == NULL)
		return -1;

	TinyHTTPRouter *router = tinyhttp_router_init();
	if (router == NULL) {
		tinyhttp_server_free(server);
		return -1;
	}

	tinyhttp_router_dir(router, "/", "/docroot", 0);

	while (!should_exit) {
		TinyHTTPRequest *req;
		TinyHTTPResponse res;
		if (tinyhttp_server_wait(server, &req, &res, 1000))
			continue; // Timeout or error
		tinyhttp_router_resolve(router, server, req, res);
	}

	tinyhttp_router_free(router);
	tinyhttp_server_free(server);
	return 0;
}