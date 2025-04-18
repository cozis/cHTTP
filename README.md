# TinyHTTP

TinyHTTP is an HTTP server library. It's small, robust, and fast.

**NOTE**: This is still a prototype! I got the basic version working and am spending some time making it more robust. After that, I will add chunked encoding, HTTPS support, and work on compliancy to RFC 9112.

## Features
* Self-contained
* Cross-Platform (Windows, Linux)
* HTTP/1.1 fully compliant to RFC 9112 with pipelining, chunked encoding, connection reuse (in progress)
* Fully non-blocking (epoll on Linux, iocp on Windows)
* HTTPS (OpenSSL on Linux, Schannel on Windows) (in progress)
* Zero-copy interface

## Limitations
* Single-threaded
* IPv4 only

## How it works / Getting Started

There are two ways to use TinyHTTP: the server interface and the stream interface.

The server interface is a complete server implementation designed to easily set up a new server.

The stream interface is more involved but completely stand-alone, doesn't performs I/O directly, and is easily embeddable in custom event loops. You can think of this as the core of the library where HTTP is implemented. It's designed to work well with readiness-based (select, poll, epoll) and completion-based event loops (iocp, io_uring).

To use TinyHTTP, be sure to enable the modules you are interested and tweak the configurations in from `tinyhttp.h`

```c
#define TINYHTTP_SERVER_ENABLE 1
#define TINYHTTP_ROUTER_ENABLE 0
#define TINYHTTP_HTTPS_ENABLE  0

#define TINYHTTP_ROUTER_MAX_PATH_COMPONENTS 32

#define TINYHTTP_HEADER_LIMIT 32
#define TINYHTTP_SERVER_CONN_LIMIT (1<<10)
#define TINYHTTP_SERVER_EPOLL_BATCH_SIZE (1<<10)
```

then, drop the `tinyhttp.c` and `tinyhttp.h` in your project as they were your files.

## Example

This is the code needed to create an HTTP/HTTPS server using the server API:

```c
#include <stdio.h>
#include <stdlib.h>
#include "tinyhttp.h"

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

	for (;;) {
		TinyHTTPRequest *req;
		TinyHTTPResponse res;
		int ret = tinyhttp_server_wait(server, &req, &res, 1000);
		if (ret < 0) return -1; // Error
		if (ret > 0) continue; // Timeout
		tinyhttp_response_status(res, 200);
		tinyhttp_response_send(res);
	}

	tinyhttp_server_free(server);
	return 0;
}
```

And this is an example of a server using the stream API. It's more verbose but offers a high degree of control.

(NOTE: This code needs to be updated)

```c
void respond(TinyHTTPStream *stream)
{
  TinyHTTPRequest *req = tinyhttp_stream_request(stream);
  if (req->method != TINYHTTP_METHOD_GET)
    tinyhttp_stream_status(stream, 405);
  else
    tinyhttp_stream_status(stream, 200);
  tinyhttp_stream_send(stream);
}

int main(void)
{
  int listen_fd = socket(AF_INET, SOCK_STREAM, 0);

  struct sockaddr_in buf;
  buf.sin_family = AF_INET;
  buf.sin_port   = htons(port);
  buf.sin_addr.s_addr = htonl(INADDR_ANY);
  bind(listen_fd, (struct sockaddr*) &buf, sizeof(buf));

  listen(listen_fd, 32);

  int num_conns = 0;
  int fds[1000];
  TinyHTTPStream streams[1000];

  for (int i = 0; i < 1000; i++)
    fds[i] = -1;

  for (;;) {
    // TODO: timeouts

    fd_set readset;
    fd_set writeset;
    FD_ZERO(&readset);
    FD_ZERO(&writeset);

    FD_SET(&readset);
    int max_fd = listen_fd;
    for (int i = 0; i < 1000; i++) {
      if (fds[i] == -1) continue;
      int state = tinyhttp_stream_state(&streams[i]);
      if (state & TINYHTTP_STREAM_RECV)
        FD_SET(fds[i], &readset);
      if (state & TINYHTTP_STREAM_SEND)
        FD_SET(fds[i], &writeset);
      if (state & (TINYHTTP_STREAM_RECV | TINYHTTP_STREAM_SEND))
        if (max_fd < fds[i]) max_fd = fds[i];
    }

    int num = select(max_fd+1, &readset, &writeset, NULL, NULL);

    if (FD_ISSET(liste_fd, &readset)) {
      // TODO
    }

    int ready_queue[1000];
    int ready_head = 0;
    int ready_count = 0;
    for (int i = 0; i < 1000; i++) {
      // TODO
    }

    while (ready_count > 0) {

      int idx = ready_queue[ready_head];
      TinyHTTPStream *stream = &streams[idx];

      TinyHTTPRequest *req = tinyhttp_stream_request(stream);
      assert(req);

      respond(stream);

      ready_head = (ready_head + 1) % 1000;
      ready_count--;
      if (tinyhttp_stream_request(stream)) {
        ready_queue[(ready_head + ready_count) % 1000] = idx;
        ready_count++;
      }
    }
  }

  close(listen_fd);
  return 0;
}
```