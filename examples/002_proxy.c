
#ifdef _WIN32
#include <winsock2.h>
#define POLL WSAPoll
#else
#include <poll.h>
#define POLL poll
#endif

#include "../chttp.h"

int main()
{
    int ret;

    CHTTP_String remote = CHTTP_STR("http://coz.is");

    CHTTP_Client client;
    ret = chttp_client_init(&client);
    if (ret < 0) {
        printf("Couldn't initialize client (%s)\n", chttp_strerror(ret));
        return -1;
    }

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

    bool used[CHTTP_SERVER_CAPACITY];
    for (int i = 0; i < CHTTP_SERVER_CAPACITY; i++)
        used[i] = false;

    CHTTP_ResponseBuilder pending[CHTTP_SERVER_CAPACITY];
    int num_pending = 0;

    for (;;) {

        #define POLL_CAPACITY (CHTTP_CLIENT_POLL_CAPACITY + CHTTP_SERVER_POLL_CAPACITY)

        void *ptrs[POLL_CAPACITY];
        struct pollfd polled[POLL_CAPACITY];

        EventRegister server_reg = {
            ptrs,
            polled,
            0
        };
        chttp_server_register_events(&server, &server_reg);

        EventRegister client_reg = {
            ptrs   + server_reg.num_polled,
            polled + server_reg.num_polled,
            0
        };
        chttp_client_register_events(&client, &client_reg);

        if (server_reg.num_polled > 0 ||
            client_reg.num_polled > 0) {
            int num_polled = server_reg.num_polled
                           + client_reg.num_polled;
            POLL(polled, num_polled, -1);
        }

        int result;
        void *user;
        CHTTP_Response *response;
        chttp_client_process_events(&client, client_reg);
        while (chttp_client_next_response(&client, &result, &user, &response)) {

            CHTTP_ResponseBuilder *builder = (CHTTP_ResponseBuilder*) user;

            int i = builder - pending;
            assert(i > -1);
            assert(i < CHTTP_SERVER_CAPACITY);

            if (result == CHTTP_OK) {
                chttp_response_builder_status(*builder, response->status);
                chttp_response_builder_body(*builder, response->body);
                chttp_response_builder_send(*builder);
            } else {
                chttp_response_builder_status(*builder, 500);
                chttp_response_builder_send(*builder);
            }

            used[i] = false;
            num_pending--;
        }

        CHTTP_Request *request;
        CHTTP_ResponseBuilder response_builder;
        chttp_server_process_events(&server, server_reg);
        while (chttp_server_next_request(&server, &request, &response_builder)) {

            int i = 0;
            while (used[i]) {
                i++;
                assert(i < CHTTP_SERVER_CAPACITY);
            }

            CHTTP_String path = request->url.path;
            if (path.len == 0)
                path = CHTTP_STR("/");

            char target[1<<10];
            int target_len = snprintf(target, sizeof(target),
                "%.*s%.*s", CHTTP_UNPACK(remote), CHTTP_UNPACK(path));
            if (target_len < 0 || target_len >= (int) sizeof(target)) {
                chttp_response_builder_status(response_builder, 500);
                chttp_response_builder_send(response_builder);
                continue;
            }

            CHTTP_RequestBuilder request_builder = chttp_client_get_builder(&client);
            chttp_request_builder_set_user(request_builder, &pending[i]);
            chttp_request_builder_trace(request_builder, true);
            chttp_request_builder_method(request_builder, request->method);
            chttp_request_builder_target(request_builder, (CHTTP_String) { target, target_len });
            ret = chttp_request_builder_send(request_builder);
            if (ret < 0) {
                chttp_response_builder_status(response_builder, 500);
                chttp_response_builder_send(response_builder);
                continue;
            }

            used[i] = true;
            pending[i] = response_builder;
            num_pending++;
        }
    }

    chttp_server_free(&server);
    chttp_client_free(&client);
    return 0;
}
