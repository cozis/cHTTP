# TinyHTTP

TinyHTTP is a library for building cross-platform and fully non-blocking HTTP 1.1 clients and servers in C.

## Roadmap and status

The project is still in the prototyping phase. I'm working on testing for robustness and compliance to RFC 9110, 9111, 9112, and 3986. The server is missing timers and HTTPS. The client is just a proof of concept at this point.

## Overview

The architecture looks like this:

```
         +--------+
         | ROUTER |
+--------+--------+
| CLIENT | SERVER |
+--------+--------+
|      ENGINE     |
+-----------------+
|      PARSER     |
+-----------------+
```

At the lowest level there are HTTP request, HTTP respons, and URI parser. Then comes the HTTP "engine", which contains the HTTP 1.1 state machine. These two layers don't depend on basically anything. Probably only freestanding libc headers. The engine is designed in such a way that it does not perform I/O. Instead, applications feed it bytes from the network and eventually get a request or response object from it. When data needs to be output, the engine lets that know to the application. An HTTP engine represents the communication between one server and one client, so a non-blocking server would typically use an array of engines.

To give you the general idea, a simple blocking server using the engine would look somewhat like this:
```c
int main(void)
{
	SOCKET listen_fd = start_server("127.0.0.1", 8080);

	for (;;) {

		SOCKET client_fd = accept(listen_fd, NULL, NULL);

		int is_client = 0; // If this were true, the engine would behave as the client instead

		HTTP_Engine eng;
		http_engine_init(&eng, is_client, memfunc, NULL);

		// Loop until the engine is in the CLOSED state
		for (int closed = 0; !closed; ) {

			// The engine may be in one of 4 states:
			//   RECV_BUF    -> Bytes are expected from the network
			//   SEND_BUF    -> Bytes need to be sent on the network
			//   PREP_STATUS -> A request is available
			//   CLOSED      -> The connection was shut down at the HTTP level
			switch (http_engine_state(&eng)) {

				case HTTP_ENGINE_STATE_SERVER_CLOSED:
				closed = 1;
				break;

				case HTTP_ENGINE_STATE_SERVER_RECV_BUF:
				{
					int cap;
					char *dst = http_engine_recvbuf(&eng, &cap);
					int ret = recv(client_fd, dst, cap, 0);
					if (ret <= 0) {
						http_engine_close(&eng);
						break;
					}
					http_engine_recvack(&eng, ret);
				}
				break;

				case HTTP_ENGINE_STATE_SERVER_SEND_BUF:
				{
					int len;
					char *src = http_engine_sendbuf(&eng, &len);
					int ret = send(client_fd, src, len, 0);
					if (ret <= 0) {
						http_engine_close(&eng);
						break;
					}
					http_engine_sendack(&eng, ret);
				}
				break;

				case HTTP_ENGINE_STATE_SERVER_PREP_STATUS:
				{
					HTTP_Request *req = http_engine_getreq(&eng);

					http_engine_status(&eng, 200);
					http_engine_header(&eng, "Server: tinyhttp", 16);
					http_engine_body(&eng, "Hello, world!", 13);
					http_engine_done(&eng);
				}
				break;
			}
		}

		http_engine_free(&eng);
		close(client_fd);
	}

	close(listen_fd);
	return 0;
}
```
This interface allows TinyHTTP to decouple the HTTP logic from the I/O. This has many advantages such as simplifying testing and decoupling TLS from the HTTP logic.

On top of the engine, TinyHTTP implements a fully functional and easy to use client and server. Both use `poll()` to handle non-blocking operations. The server API looks like this:

```c
#include "http.h"

int main(void)
{
	int ret;
	HTTP_Server server;

	ret = http_server_init(&server, "127.0.0.1", 8080);
	if (ret < 0) return -1;

	for (;;) {
		HTTP_Request *req;
		HTTP_ResponseHandle res;

		ret = http_server_wait(&server, &req, &res, -1);
		if (ret < 0)
			return -1;
		if (ret == 0)
			continue;

		http_response_status(res, 200);
		http_response_header(res, "Server: tinyhttp");
		http_response_body(res, "Hello, world!", 13);
		http_response_done(res);
	}

	http_server_free(&server);
	return 0;
}
```

while the client interface looks like this (note that I omitted error checking for making easier to digest)

```c
#include <stdio.h>
#include "http.h"

int main(void)
{
	HTTP_Client client;
	HTTP_TLSContext tls;

	// Initialize the TLS stuff
	http_tls_global_init();
	http_tls_init(&tls);

	// Initialize the client context
	http_client_init(&clients[0]);

	// Start the request
	http_client_startreq(&clients[0], HTTP_METHOD_GET, "https://coz.is/hello.html", NULL, 0, NULL, 0, &tls);

	// Wait for the request to complete
	// (you could wait for more multiple request at once)
	HTTP_Client *wait_list[] = { &client };
	http_client_waitall(waitlist, 1, -1);

	// Read the response
	HTTP_Response *res;
	http_client_result(&clients[0], &res);
	fwrite(res->body.ptr, 1, res->body.len, stdout);

	// Free the client context
	http_client_free(&clients);

	// Free the TLS stuff
	http_tls_free(&tls);
	http_tls_global_free();
	return 0;
}
```

The client supports HTTPS by using OpenSSL, but the implementation is incomplete. You can get basic requests going but most things are not working yet. The server only supports plain text HTTP, but the interface is more mature. I think it's a great choice for small to medium websites (up to 500 concurrent users I'd say).

The last layer is the router, which sits on top of the HTTP server. This simplifies the work of serving files from disk or setting up routes with dynamic content in an easy and safe way. Here's an example:

```c
#include "http.h"

void endpoint_login(HTTP_Request *req, HTTP_ResponseHandle res, void *ctx)
{
	http_response_status(res, 200);
	http_response_body(res, "Hello!", -1);
	http_response_done(res);
}

int main(void)
{
	HTTP_Router *router = http_router_init();

	// Make /say_hello a dynamic resource
	http_router_func(router, HTTP_METHOD_POST, HTTP_STR("/say_hello"), callback, NULL);

	// Requests to resources in the root folder are served from the examples folder
	http_router_dir(router, HTTP_STR("/"), HTTP_STR("/examples"));

	return http_serve("127.0.0.1", 8080, router);
}
```