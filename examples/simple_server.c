#include <stdio.h>
#include <stdlib.h>
#include "../tinyhttp.h"

// This is an example of how to use the TinyHTTP simplified
// server API to build a cross-platform HTTP server.

int main(void)
{
	HTTP_Server server;

	// Initialize a server listening on the given interface
	// and with the given port.
	int ret = http_server_init(&server, "127.0.0.1", 8080);
	if (ret < 0) {
		printf("http_server_init failed\n");
		return -1;
	}

	for (;;) {

		// Set for how many milliseconds the server will wait for
		// requests this iteration. If -1, the function will not
		// timeout.
		int timeout_ms = 1000;

		HTTP_Request *req;
		HTTP_ResponseHandle res;
		ret = http_server_wait(&server, &req, &res, timeout_ms);

		if (ret == 0)
			continue; // Timeout

		if (ret < 0)
			break; // An unrecoverable error occurred

		// You can access the request data through the
		// "req" pointer. For this example, we only allow
		// GET requests to the "/hello" endpoint

		if (req->method != HTTP_METHOD_GET) {

			// Respond with the status code 405
			http_response_status(res, 405);

			// Mark the response as complete. If you don't
			// call this, the client will just hang!
			http_response_done(res);

			// Go back to waiting
			continue;
		}

		// Compare the requested resource with "/hello".
		// The HTTP_STR macro can be used on string literals to
		// get the length automatically. It is equivalent to:
		//
		//   (HTTP_String) { literal, sizeof(literal)-1 }
		//
		if (!http_streq(req->url.path, HTTP_STR("/hello"))) {

			// Some other resource was requested
			http_response_status(res, 404);
			http_response_done(res);
			continue;
		}

		// Now we send the success response
		http_response_status(res, 200);

		// Set zero or more headers
		// You must pass a string in the form:
		//
		//   <name>: <spaces?> <value> <spaces?>
		//
		// It's important you don't use the \r character
		// and there are no spaces before the ':' character.
		//
		// You should avoid adding the "Connection",
		// "Transfer-Encoding", or "Content-Length" headers
		// since they are added automatically.
		http_response_header(res, "first-header: %d", 99);
		http_response_header(res, "second-header: %s", "Some string");

		// After having set any headers, we can optionally
		// add some content to the request

		// Add some bytes to the payload in terms of a pointer
		// and length pair. If the length is -1, the bytes are
		// assumed to be null-terminated.
		http_response_body(res, "Hello, world!", -1);

		// Now let's say we are in the middle of building a
		// response and an error occurres. In that case, we
		// can undo all the progress since the first status
		// call and start all over:
		int error = rand() & 1;
		if (error) {
			http_response_undo(res);
			http_response_status(res, 500);
			http_response_done(res);
			continue;
		}

		// Let's add some more bytes
		http_response_body(res, " How's it going??", -1);

		// Ok. Done!
		http_response_done(res);
	}

	http_server_free(&server);
	return 0;
}