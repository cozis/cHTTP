#include <stdio.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#define CLOSE_SOCKET closesocket
#else
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#define SOCKET int
#define INVALID_SOCKET -1
#define CLOSE_SOCKET close
#endif

#include <http.h>

// This example showcases how to use the engine interface
// to build a blocking HTTP server that works on Windows
// and Linux.

// Callback used by the engine to manage dynamic memory
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

static void produce_response(HTTP_Engine *eng)
{
	// All considerations in simple_server.c for how responses
	// are built also applies here, where http_engine_XXX functions
	// are used instead of http_response_XXX functions.

	// Set the response status
	http_engine_status(eng, 200);

	// Set zero or more headers
	http_engine_header(eng, "Server: tinyhttp", -1);

	// Set some bytes in the body
	http_engine_body(eng, "Hello, world!", 13);

	// This is one difference from the http_response_XXX API.
	// It's possible to write response content directly into
	// the engine's output buffer. This avoids copies in some
	// circumstances.

	char msg[] = " What's up??";

	// First, set how many bytes the output buffer will need
	// to hold at least:
	http_engine_bodycap(eng, sizeof(msg)-1);

	// Now get the location for the write. The returned pointer
	// points to a region of size "cap", which equal or greater
	// to the previously set minimum capacity. 
	int cap;
	char *dst = http_engine_bodybuf(eng, &cap);

	// If an error occurred internally, the returned pointer will
	// be NULL and the capacity 0. In this case, you can just skip
	// this write. The engine will automatically be closed when the
	// "http_engine_done" function is called.
	if (dst) {
		memcpy(dst, msg, sizeof(msg)-1);

		// Tell the engine how many bytes the application wrote to the
		// provided buffer.
		http_engine_bodyack(eng, sizeof(msg)-1);
	}

	// If an error occurs, you can undo all progress and start
	// from scratch
	int error = rand() & 1;
	if (error) {
		http_engine_undo(eng);
		http_engine_status(eng, 500);
		http_engine_done(eng);
		return;
	}

	http_engine_done(eng);
}

int main(void)
{
	// Interface and port the server will be listening on.
	char *addr = "127.0.0.1";
	int port = 8080;

#ifdef _WIN32
	WSADATA wd;
	if (WSAStartup(MAKEWORD(2, 2), &wd))
		return -1;
#endif

	// Create the listening socket
	SOCKET listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd == INVALID_SOCKET)
		return -1;

	// Ignore the cooldown time for the bound interface to
	// avoid that annoying "address in use" error
	int reuse = 1;
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (void*) &reuse, sizeof(reuse));

	// Fill out the address struct
	struct sockaddr_in bind_buf;
	{
		struct in_addr addr_buf;
		if (inet_pton(AF_INET, addr, &addr_buf) != 1)
			return -1;

		bind_buf.sin_family = AF_INET;
		bind_buf.sin_port   = htons(port);
		bind_buf.sin_addr   = addr_buf;
		memset(&bind_buf.sin_zero, 0, sizeof(bind_buf.sin_zero));
	}

	// Associate the listening socket to the interface
	if (bind(listen_fd, (struct sockaddr*) &bind_buf, sizeof(bind_buf)) < 0)
		return -1;

	// Allow incoming connections
	if (listen(listen_fd, 32) < 0)
		return -1;

	for (;;) {

		printf("Waiting for a connection\n");

		// Get an incoming connection from the kernel
		SOCKET client_fd = accept(listen_fd, NULL, NULL);
		if (client_fd == INVALID_SOCKET)
			continue;

		printf("New connection\n");

		// Initialize the HTTP state machine
		HTTP_Engine eng;
		http_engine_init(&eng, 0, memfunc, NULL);

		for (;;) {
			
			// At this point, the engine can be in one
			// of four states:
			//   1) RECV_BUF: The engine is waiting for bytes from the network
			//   2) SEND_BUF: The engine wants to write bytes from the network
			//   3) CLOSED: The connection shut down at the HTTP layer
			//   4) PREP_STATUS: A request was received and the associated response
			//                   needs to be generated.
			HTTP_EngineState state = http_engine_state(&eng);

			if (state == HTTP_ENGINE_STATE_SERVER_PREP_STATUS) {

				produce_response(&eng);

			} else if (state == HTTP_ENGINE_STATE_SERVER_RECV_BUF) {

				printf("Receiving bytes\n");

				// Get a pointer to the engine's input buffer
				int cap;
				char *dst = http_engine_recvbuf(&eng, &cap);

				// The application can write up to "cap" bytes
				// to the "dst" buffer.

				int ret = recv(client_fd, dst, cap, 0);
				if (ret <= 0) {
					// If the peer disconnected or an error occurred,
					// we can "close" the engine. This makes it so any
					// further operation on the engine will be a no-op
					// and the next time we query the state we will get
					// CLOSED.
					http_engine_close(&eng);
					ret = 0;
				}

				printf("Received %d bytes\n", ret);

				// Tell the engine how many bytes we wrote to
				// the buffer.
				http_engine_recvack(&eng, ret);

			} else if (state == HTTP_ENGINE_STATE_SERVER_SEND_BUF) {

				// This code is the same as the recv case except
				// we read from the buffer instead of writing.

				printf("Sending bytes\n");
				
				int len;
				char *src = http_engine_sendbuf(&eng, &len);

				// Here "src" points to "len" bytes that need to
				// be sent over the network.
				int ret = send(client_fd, src, len, 0);
				if (ret < 0) {
					http_engine_close(&eng);
					ret = 0;
				}

				printf("Sent %d bytes\n", ret);

				http_engine_sendack(&eng, ret);

			} else {
				// HTTP_ENGINE_STATE_SERVER_CLOSED
				printf("HTTP close\n");
				break;
			}
		}

		printf("Closing connection\n");

		http_engine_free(&eng);
		CLOSE_SOCKET(client_fd);
	}

	CLOSE_SOCKET(listen_fd);

#ifdef _WIN32
	WSACleanup();
#endif

	return 0;
}