#include <stddef.h>

#include "../chttp.h"

int main(void)
{
    // To test this program you need to add the following
    // lines to your hosts file:
    //
    //   127.0.0.1    websiteA.com
    //   127.0.0.1    websiteB.com
    //   127.0.0.1    websiteC.com
    //
    // That you can find at /etc/hosts on Linux and
    // C:\Windows\System32\drivers\etc\hosts on Windows

    int ret;

    HTTP_Server server;
    ret = http_server_init(&server);
    if (ret < 0) {
        fprintf(stderr, "Couldn't initialize server (%s)\n", http_strerror(ret));
        return -1;
    }

    http_server_set_reuse_addr(&server, true);
    http_server_set_trace_bytes(&server, true);

    HTTP_String local_addr = HTTP_STR("127.0.0.1");
    uint16_t    local_port = 8080;
    ret = http_server_listen_tcp(&server, local_addr, local_port);
    if (ret < 0) {
        fprintf(stderr, "Couldn't start listening (%s)\n", http_strerror(ret));
        return -1;
    }

    // The following loop will serve responses for
    //
    //   http://websiteA.com:8080/
    //   http://websiteB.com:8080/
    //   http://websiteC.com:8080/
    //
    // If a host name is missing or there isn't one
    //
    //   http://127.0.0.1:8080/
    //
    // The websiteA.com handler is used

    for (;;) {

        HTTP_Request *req;
        HTTP_ResponseBuilder builder;
        http_server_wait_request(&server, &req, &builder);

        if (http_match_host(req, HTTP_STR("websiteB.com"), local_port)) {
            // Website B
            http_response_builder_status(builder, 200);
            http_response_builder_body(builder, HTTP_STR("Hello from websiteB.com!"));
            http_response_builder_send(builder);

        } else if (http_match_host(req, HTTP_STR("websiteC.com"), local_port)) {
            // Website C
            http_response_builder_status(builder, 200);
            http_response_builder_body(builder, HTTP_STR("Hello from websiteC.com!"));
            http_response_builder_send(builder);
        } else {
            // Serve websiteA by default
            http_response_builder_status(builder, 200);
            http_response_builder_body(builder, HTTP_STR("Hello from websiteA.com!"));
            http_response_builder_send(builder);
        }
    }

    http_server_free(&server);
    return 0;
}
