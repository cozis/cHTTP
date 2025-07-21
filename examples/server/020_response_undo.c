#include <stddef.h>
#include <chttp.h>

// This example shows how undo a response that is being built
// when an error occurs.

int main(void)
{
    HTTP_Server *server = http_server_init(HTTP_STR("127.0.0.1"), 8080);
    if (server == NULL)
        return -1;

    for (;;) {

        HTTP_Request *req;
        HTTP_ResponseHandle res;

        int ret = http_server_wait(server, &req, &res);
        if (ret < 0) return -1;

        // Say we are building a request..

        http_response_status(res, 200);
        http_response_header(res, HTTP_STR("Content-Type: text/plain"));

        // .. and in the middle of building an error condition
        // occurs. Maybe a file was missing or an allocation fails.
        // The proper response in this case would be a code 500
        // with an error message, but we already wrote the first
        // part of the response assuming the operation would succede.
        //
        // You can use the *_undo function to reset the response
        // building process

        bool error_occurred = true;
        if (error_occurred) {

            http_response_undo(res);

            // Now we are back to setting the status code
            http_response_status(res, 500);
            http_response_header(res, HTTP_STR("Content-Type: text/plain"));
            http_response_body(res, HTTP_STR("An error occurred!"));
            http_response_done(res);

        } else {

            // If no error occures, we finish as planned
            http_response_body(res, HTTP_STR("Hello, world!"));
            http_response_done(res);
        }
    }

    http_server_free(server);
    return 0;
}
