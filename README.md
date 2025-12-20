# cHTTP
cHTTP is an HTTP client and server library distributed as a single file with support for HTTPS, virtual hosts, fully non-blocking operations.

## Quick Start

### Your first request

The simplest way to perform a GET request looks like this:

```c
#include "chttp.h"

int main(void)
{
    CHTTP_Response *response;

    int ret = chttp_get(CHTTP_STR("http://coz.is/"), NULL, 0, &response);
    if (ret == CHTTP_OK) {
        printf("Received %d bytes\n", response->body.len);
        chttp_free_response(response);
    } else {
        printf("Request failure: %s\n", chttp_strerror(ret));
    }
    return 0;
}
```

(Note the `http:` schema. If you want HTTPS, you'll have to enable it explicitly! Refer to the HTTPS section.)

Copy this code to `first_request.c` near `chttp.c` and compile it by running:

```sh
# Linux
gcc chttp.c first_request.c -o first_request

# Windows (mingw)
gcc chttp.c first_request.c -o first_request.exe -lws2_32
```

Then, run the program

```sh
# Linux
./first_request

# Windows
.\first_request.exe
```

Done!

### Your first server

The setup for a basic server looks like this:

```c
#include "chttp.h"

int main(void)
{
    int ret;

    CHTTP_Server server;
    ret = chttp_server_init(&server);
    if (ret < 0) {
        fprintf(stderr, "Couldn't initialize server (%s)\n", chttp_strerror(ret));
        return -1;
    }

    chttp_server_set_reuse_addr(&server, true);
    chttp_server_set_trace_bytes(&server, true);

    ret = chttp_server_listen_tcp(&server, CHTTP_STR("127.0.0.1"), 8080);
    if (ret < 0) {
        fprintf(stderr, "Couldn't start listening (%s)\n", chttp_strerror(ret));
        return -1;
    }

    for (;;) {

        CHTTP_Request *request;
        CHTTP_ResponseBuilder builder;
        chttp_server_wait_request(&server, &request, &builder);

        chttp_response_builder_status(builder, 200);
        chttp_response_builder_body(builder, CHTTP_STR("Hello, world!"));
        chttp_response_builder_send(builder);
    }

    chttp_server_free(&server);
    return 0;
}
```

Copy this code to a `first_server.c` file and compile it by running

```sh
# Linux
gcc chttp.c first_server.c -o first_server

# Windows (mingw)
gcc chttp.c first_server.c -o first_server.exe -lws2_32
```

Then, run the program

```sh
# Linux
./first_server

# Windows
.\first_server.exe
```

While the program is running, open a browser and visit `http://127.0.0.1:8080/`. You should see the text "Hello, world!" sent by the server and a log of the HTTP requests and responses processed by the server in the console.

## HTTPS

HTTPS is supported via OpenSSL, which is easily available on Linux and less so on Windows.

First, install the OpenSSL development libraries:

```sh
# Ubuntu/Debian Linux
sudo apt install libssl-dev gcc
```

Then, enable HTTPS by compiling your program with the following flags:

```sh
# Linux
gcc chttp.c main.c -lssl -lcrypto -DHTTPS_ENABLED

# Windows
gcc chttp.c main.c -lws2_32 -lssl -lcrypto -DHTTPS_ENABLED
```

## Development Status

The major limitation of cHTTP is HTTPS on Windows. For that to work correctly it will be necessary to port the OpenSSL code to SChannel.

Other limitations:
* HTTP client doesn't follow redirections (responses with code 3xx)
* Support for HTTP client cookies is limited
* HTTP server adherence to the spec can be improved

## Contributing

Contributions are welcome! The following are some notes on how to work with the codebase. Don't worry if you get something wrong. I will remind you.

The source code in the src/ directory is intended to be be amalgamated into a single file before compilation. The amalgamation is not only intended as a distribution method, but also as easy-access documentation, and therefore need to be readable. For this reasons:

* You never need need to include other cHTTP source files
* All inclusions of third-party headers are to be placed inside src/includes.h
* All files must start with a single empty line, unless they start with an overview comment of the file, in which case they must have no empty lines at the beginning of the file.
* All files must end with a single empty line.