#include <stdbool.h>
#include <chttp.h>

// This example shows how to set up an HTTPS (HTTP over TLS)
// server.

int main(void)
{
    // To setup an HTTPS server, we need to use the *_ex variant
    // of the server initialization function as it offers more
    // control. Server objects can serve HTTP traffic, HTTPS
    // traffic, or both at the same time. The init_ex function
    // allows us to control this behavior.

    // The first argument is the local interface address. It
    // works just as the other examples but is shared between
    // HTTP and HTTPS. Then come the HTTP port and HTTPS port
    // arguments. If you want to disable HTTP or HTTPS you can
    // pass zero to its port argument. If the HTTPS port is
    // not zero, you need to pass the file names of the server's
    // certificate and private key.
    HTTP_Server *server = http_server_init_ex(
        HTTP_STR("127.0.0.1"), // HTTP and HTTPS port
        8080, // HTTP port
        8443, // HTTPS port
        HTTP_STR("cert.pem"),
        HTTP_STR("privkey.pem")
    );
    if (server == NULL)
        return -1;

    // Just to be clear, to initialize a plain HTTP server
    // using the *_ex function we would do this:
    //
    //   HTTP_Server *server = http_server_init_ex(
    //     HTTP_STR("127.0.0.1"), // HTTP and HTTPS port
    //     8080,                  // HTTP port
    //     0,                     // HTTPS disabled
    //     HTTP_STR(""),          // ignore
    //     HTTP_STR("")           // ignore
    //   );
    //
    // and if we wanted and HTTPS-only server we would
    // do this:
    //
    //   HTTP_Server *server = http_server_init_ex(
    //     HTTP_STR("127.0.0.1"), // HTTP and HTTPS port
    //     0,                     // HTTP disabled
    //     8443,                  // HTTPS port
    //     HTTP_STR("cert.pem"),
    //     HTTP_STR("privkey.pem")
    //   );

    // Everything else is identical to the simple HTTP server
    // example.

    for (;;) {

        HTTP_Request *req;
        HTTP_ResponseHandle res;

        int ret = http_server_wait(server, &res, &res);
        if (ret < 0) return -1;

        http_response_status(res, 200);
        http_response_header(res, "Content-Type: text/plain");
        http_response_body(res, HTTP_STR("Hello"));
        http_response_body(res, HTTP_STR(", world!"));
        http_response_done(res);
    }

    http_server_free(server);
    return 0;
}