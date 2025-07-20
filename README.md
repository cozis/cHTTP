# cHTTP

This is an HTTP client and server library for C.

Here are some examples of how it looks like on the client and server. If you want to learn more, go through the files in `examples/` (they are intended to be skimmed in order).

Here is a client performing a GET request:
```c
#include <chttp.h>

int main(void)
{
    http_global_init();

    HTTP_String headers[] = {
        HTTP_STR("User-Agent: cHTTP"),
    };

    HTTP_RequestHandle handle;
    HTTP_Response *res = http_get(
        HTTP_STR("http://example.com/index.html"),
        headers, HTTP_COUNT(headers),
        &handle
    );

    fwrite(res->body.ptr, 1, res->body.ptr, stdout);

    http_request_free(handle);
    http_global_free();
    return 0;
}
```

And this is an HTTP server:
```c
#include <chttp.h>

int main(void)
{
    http_global_init();
    HTTP_Server *server = http_server_init(HTTP_STR("127.0.0.1"), 8080);

    for (;;) {

        HTTP_Request *req;
        HTTP_ResponseHandle res;
        http_server_wait(server, &req, &res);

        http_response_status(res, 200);
        http_response_header(res, "Content-Type: text/plain");
        http_response_body(res, HTTP_STR("Hello, world!"));
        http_response_done(res);
    }

    http_server_free(server);
    http_global_free();
    return 0;
}
```

## Use Cases

cHTTP is perfect for tooling or production environments of limited scale (up to about 1000 concurrent connections). To scale it further, users can take cHTTP's I/O independant HTTP state machine and use it in conjunction with more scalable I/O solutions (see examples/engine).

## Why another HTTP library?

This is my attempt at solving the "HTTP problem" for the C language. Writing C programs that behave as or interact with web services is always more painful than necessary in C. You either need to use `libcurl` which is overkill in most situations or link a large scale web servers to serve simple pages. This library targets smaller scale use-cases and tries to be as nice as possible to work with. Even then, it is fast. No performance is left on the table unless there is a specific reason. And if you do want to work at larger scales by using more sophisticate I/O systems (io_uring, I/O completion ports, etc) you can reuse the core state machine of the library that is I/O independant.

## Features & Limitations
* HTTP/1.1 server & client
* Cross-platform (Windows & Linux)
* TLS (HTTPS) support using OpenSSL
* Minimal dependencies (libc and OpenSSL)
* Non-blocking design based on `poll()`
* I/O independant core reusable with more sophisticated I/O models
* Virtual hosts
* Single-threaded
