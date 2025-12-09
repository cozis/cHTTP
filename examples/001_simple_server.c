#include "../chttp.h"

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
