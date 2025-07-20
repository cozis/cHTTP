#include <stdbool.h>
#include <http.h>

// This example shows how to set up a basic HTTP server

int main(void)
{
    // Choose the interface to listen on and the port.
    // Currently, servers can only bind to IPv4 addresses.
    HTTP_String addr = HTTP_STR("127.0.0.1");
    uint16_t    port = 8080;

    bool all_interfaces = false;

    // If you want to bind to all interfaces, you can
    // set the address to an empty string.
    if (all_interfaces)
        addr = HTTP_STR("");

    // Instanciate the HTTP server object
    HTTP_Server *server = http_server_init(addr, port);
    if (server == NULL)
        return -1;

    // Now we loop forever. Every iteration will serve
    // a single HTTP request
    for (;;) {

        HTTP_Request *req;
        HTTP_ResponseHandle res;

        // Block until a request is available
        int ret = http_server_wait(server, &res, &res);

        // The wait functions returns 0 on success and -1
        // on error. By "error" I mean an unrecoverable
        // condition. There is no other option than kill
        // the process.
        if (ret < 0)
            return -1;

        // The request information is accessible from
        // the [req] variable. Most fields in the request
        // struct are reference to the original request
        // string. They use type HTTP_String and are not
        // null-terminated. This means you'll have to make
        // sure to express the length when interacting with
        // libc:
        HTTP_String path = req->url.path;
        printf("requested path [%.*s]\n", (int) path.len, path.ptr);

        // To find a specific header value, you can either
        // iterate over the [req->headers] array or use
        // a helper function. Note that this compares header
        // names case-insensitively.
        int idx = http_find_header(req->headers, req->num_headers, HTTP_STR("Some-Header-Name"));
        if (idx == -1) {
            // Header wasn't found
        } else {
            // Found
            HTTP_String value = req->headers[idx].value;
            printf("Header has value [%.*s]\n", (int) value.len, value.ptr);
        }

        // To create a response, you will need to specify
        // status code, headers, and content in the proper
        // order.

        // First the status code
        http_response_status(res, 200);

        // Then zero or more headers
        http_response_header(res, "Content-Type: text/plain");

        // Then you can write zero or more chunks of the response body
        http_response_body(res, HTTP_STR("Hello"));
        http_response_body(res, HTTP_STR(", world!"));

        // Then, mark the request as complete (Very important or the server will hang!)
        http_response_done(res);

        // Note that none of the http_response_* functions return errors.
        // This is by design to simplify user endpoint code. If at any point
        // something goes wrong, the server will send a code 4xx or 5xx to
        // the client or abort the TCP connection entirely.
    }

    // This program will loop forever, but if you write
    // your server in a way to exit gracefully, this is
    // you the server object is freed:
    http_server_free(server);

    // Have fun. Bye!
    return 0;
}