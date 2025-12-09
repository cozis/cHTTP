#include <stddef.h>

#include "../chttp.h"

int main(void)
{
    CHTTP_String local_addr = CHTTP_STR("127.0.0.1");
    uint16_t    local_port = 8443;

    CHTTP_String cert_file  = CHTTP_STR("websiteA_cert.pem");
    CHTTP_String key_file   = CHTTP_STR("websiteA_key.pem");

    CHTTP_Server server;
    int ret = chttp_server_init(&server);
    if (ret < 0) {
        fprintf(stderr, "Couldn't initialize server (%s)\n", chttp_strerror(ret));
        return -1;
    }

    chttp_server_set_reuse_addr(&server, true);
    chttp_server_set_trace_bytes(&server, true);

    ret = chttp_server_listen_tls(&server, local_addr, local_port, cert_file, key_file);
    if (ret < 0) {
        fprintf(stderr, "Couldn't start listening (%s)\n", chttp_strerror(ret));
        return -1;
    }

    for (;;) {

        CHTTP_Request *req;
        CHTTP_ResponseBuilder builder;
        chttp_server_wait_request(&server, &req, &builder);

        chttp_response_builder_status(builder, 200);
        chttp_response_builder_body(builder, CHTTP_STR("Hello from websiteA.com!"));
        chttp_response_builder_send(builder);
    }

    chttp_server_free(&server);
    return 0;
}
