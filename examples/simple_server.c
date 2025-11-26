#include "../chttp.h"

#ifdef _WIN32
#define POLL WSAPoll
#else
#define POLL poll
#endif

int main(void)
{
    HTTP_Server server;
    if (http_server_init(&server) < 0)
        return -1;

    http_server_set_reuse_addr(&server, true);
    http_server_set_trace_bytes(&server, true);

    if (http_server_listen_tcp(&server, HTTP_STR("127.0.0.1"), 8080) < 0)
        return -1;

    for (;;) {

        void *ptrs[HTTP_SERVER_POLL_CAPACITY];
        struct pollfd polled[HTTP_SERVER_POLL_CAPACITY];

        EventRegister reg = {
            .ptrs=ptrs,
            .polled=polled,
            .max_polled=HTTP_SERVER_POLL_CAPACITY,
            .num_polled=0,
        };

        if (http_server_register_events(&server, &reg) < 0)
            return -1;

        if (reg.num_polled > 0)
            POLL(reg.polled, reg.num_polled, -1);

        if (http_server_process_events(&server, &reg) < 0)
            return -1;

        HTTP_Request *request;
        HTTP_ResponseBuilder builder;
        if (http_server_next_request(&server, &request, &builder)) {
            http_response_builder_status(builder, 200);
            http_response_builder_send(builder);
        }
    }

    http_server_free(&server);
    return 0;
}
