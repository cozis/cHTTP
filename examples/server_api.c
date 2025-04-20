#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include "../tinyhttp.h"

sig_atomic_t should_exit = 0;

static void
signal_handler(int sig)
{
	if (sig == SIGINT)
		should_exit = 1;
}

int main(void)
{
	signal(SIGINT, signal_handler);

	TinyHTTPServerConfig config = {
		.reuse = 1,
		.plain_addr = NULL,
		.plain_port = 8080,
		.plain_backlog = 32,
	};

	TinyHTTPServer *server = tinyhttp_server_init(config);
	if (server == NULL)
		return -1;

	while (!should_exit) {

		int ret;
		TinyHTTPRequest *req;
		TinyHTTPResponse res;

		ret = tinyhttp_server_wait(server, &req, &res, 1000);
		if (ret < 0) return -1; // Error
		if (ret > 0) continue; // Timeout

		tinyhttp_response_status(res, 200);
		tinyhttp_response_body(res, "Hello, world!", -1);

		//tinyhttp_response_undo(res);
		//tinyhttp_response_status(res, 500);

		tinyhttp_response_send(res);
	}

	tinyhttp_server_free(server);
	return 0;
}
