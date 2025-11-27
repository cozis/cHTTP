#include <stddef.h>

#include "../chttp.h"

int main(void)
{
    HTTP_String local_addr = HTTP_STR("127.0.0.1");
    uint16_t    local_port = 8443;

    HTTP_String cert_file  = HTTP_STR("websiteA_cert.pem");
    HTTP_String key_file   = HTTP_STR("websiteA_key.pem");

    HTTP_Server server;
    int ret = http_server_init(&server);
    if (ret < 0) {
        fprintf(stderr, "Couldn't initialize server (%s)\n", http_strerror(ret));
        return -1;
    }

    http_server_set_reuse_addr(&server, true);
    http_server_set_trace_bytes(&server, true);

    ret = http_server_listen_tls(&server, local_addr, local_port, cert_file, key_file);
    if (ret < 0) {
        fprintf(stderr, "Couldn't start listening (%s)\n", http_strerror(ret));
        return -1;
    }

    for (;;) {

        HTTP_Request *req;
        HTTP_ResponseBuilder builder;
        http_server_wait_request(&server, &req, &builder);

        http_response_builder_status(builder, 200);
        http_response_builder_body(builder, HTTP_STR("Hello from websiteA.com!"));
        http_response_builder_send(builder);
    }

    http_server_free(&server);
    return 0;
}
