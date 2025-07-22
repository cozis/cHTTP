# cHTTP
cHTTP is an HTTP **client and server** library for C with minimal dependencies and **distributed as a single chttp.c** file.

## Features & Limitations

* HTTP 1.1 client and server
* Fully non-blocking
* Cross-Platform (Windows & Linux)
* HTTPS support (using OpenSSL)
* Virtual Hosts
* Single-threaded
* Zero-copy interface

## Example

Here is a client performing a GET request:
```c
#include <stdio.h>
#include <chttp.h>

int main(void)
{
    http_global_init();

    HTTP_String url = HTTP_STR("http://example.com/index.html");

    HTTP_String headers[] = {
        HTTP_STR("User-Agent: cHTTP"),
    };

    HTTP_Response *res = http_get(url, headers, 1);

    fwrite(res->body.ptr, 1, res->body.len, stdout);

    http_response_free(res);
    http_global_free();
    return 0;
}
```

And this is a server:
```c
#include <chttp.h>

int main(void)
{
    http_global_init();
    HTTP_Server *server = http_server_init(HTTP_STR("127.0.0.1"), 8080);

    for (;;) {

        HTTP_Request *req;
        HTTP_ResponseBuilder builder;
        http_server_wait(server, &req, &builder);

        http_response_builder_status(builder, 200);
        http_response_builder_header(builder, "Content-Type: text/plain");
        http_response_builder_body(builder, HTTP_STR("Hello, world!"));
        http_response_builder_done(builder);
    }

    http_server_free(server);
    http_global_free();
    return 0;
}
```

## Platform Support
cHTTP officially supports Linux and Windows.

## HTTPS support
Currently, HTTPS is implemented using OpenSSL which comes preinstalled on Linux but not Windows. It must be enabled by passing the `-DHTTPS_ENABLED` flag to gcc when building.

## Scalability
cHTTP is designed to reach moderate scale to allow a compact and easy to work with implementation. The non-blocking I/O is based on `poll()` which I would say works up to about 500 concurrent connections. If you have more than that, you should consider APIs like epoll, io_uring,
and I/O completion ports. If you do go that route, you can still reuse the cHTTP I/O independant core (see HTTP_Engine) to handle the HTTP protocol for you, both for client and server.
