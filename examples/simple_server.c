#include "../chttp.h"

int main(void)
{
    int ret;

    HTTP_Server server;
    ret = http_server_init(&server);
    if (ret < 0) {
        fprintf(stderr, "Couldn't initialize server (%s)\n", http_strerror(ret));
        return -1;
    }

    http_server_set_reuse_addr(&server, true);
    http_server_set_trace_bytes(&server, true);

    ret = http_server_listen_tcp(&server, HTTP_STR("127.0.0.1"), 8080);
    if (ret < 0) {
        fprintf(stderr, "Couldn't start listening (%s)\n", http_strerror(ret));
        return -1;
    }

    for (;;) {

        HTTP_Request *request;
        HTTP_ResponseBuilder builder;
        http_server_wait_request(&server, &request, &builder);

        http_response_builder_status(builder, 200);
        http_response_builder_body(builder, HTTP_STR("Hello, world!"));
        http_response_builder_send(builder);
    }

    http_server_free(&server);
    return 0;
}
