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

    CHTTP_Server server;
    ret = chttp_server_init(&server);
    if (ret < 0) {
        fprintf(stderr, "Couldn't initialize server (%s)\n", chttp_strerror(ret));
        return -1;
    }

    chttp_server_set_reuse_addr(&server, true);
    chttp_server_set_trace_bytes(&server, true);

    CHTTP_String local_addr = CHTTP_STR("127.0.0.1");
    uint16_t    local_port = 8080;
    ret = chttp_server_listen_tcp(&server, local_addr, local_port);
    if (ret < 0) {
        fprintf(stderr, "Couldn't start listening (%s)\n", chttp_strerror(ret));
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

        CHTTP_Request *req;
        CHTTP_ResponseBuilder builder;
        chttp_server_wait_request(&server, &req, &builder);

        if (chttp_match_host(req, CHTTP_STR("websiteB.com"), local_port)) {
            // Website B
            chttp_response_builder_status(builder, 200);
            chttp_response_builder_body(builder, CHTTP_STR("Hello from websiteB.com!"));
            chttp_response_builder_send(builder);

        } else if (chttp_match_host(req, CHTTP_STR("websiteC.com"), local_port)) {
            // Website C
            chttp_response_builder_status(builder, 200);
            chttp_response_builder_body(builder, CHTTP_STR("Hello from websiteC.com!"));
            chttp_response_builder_send(builder);
        } else {
            // Serve websiteA by default
            chttp_response_builder_status(builder, 200);
            chttp_response_builder_body(builder, CHTTP_STR("Hello from websiteA.com!"));
            chttp_response_builder_send(builder);
        }
    }

    chttp_server_free(&server);
    return 0;
}
