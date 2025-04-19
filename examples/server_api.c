#include <stdio.h>
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
		.plain_addr = NULL,
		.plain_port = 8080,
		.plain_backlog = 32,
	};

	TinyHTTPServer *server = tinyhttp_server_init(config, memfunc, NULL);
	if (server == NULL)
		return -1;

	while (!should_exit) {
		
		TinyHTTPRequest *req;
		TinyHTTPResponse res;
		
		int ret = tinyhttp_server_wait(server, &req, &res, 1000);
		if (ret < 0) return -1; // Error
		if (ret > 0) continue; // Timeout
		
		tinyhttp_response_status(res, 200);
		
		tinyhttp_response_body_setmincap(res, 1<<10);
		ptrdiff_t cap;
		char *buf = tinyhttp_response_body_buf(res, &cap);
		int len = buf ? snprintf(buf, cap, "Hello, world!") : 0;
		if (len < 0 || len > cap) abort();
		tinyhttp_response_body_ack(res, len);
		
		tinyhttp_response_send(res);
	}

	tinyhttp_server_free(server);
	return 0;
}