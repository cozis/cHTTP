
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

    HTTP_String remote = HTTP_STR("http://coz.is");

    HTTP_Client client;
    ret = http_client_init(&client);
    if (ret < 0) {
        printf("Couldn't initialize client (%s)\n", http_strerror(ret));
        return -1;
    }

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

    bool used[HTTP_SERVER_CAPACITY];
    for (int i = 0; i < HTTP_SERVER_CAPACITY; i++)
        used[i] = false;

    HTTP_ResponseBuilder pending[HTTP_SERVER_CAPACITY];
    int num_pending = 0;

    for (;;) {

        #define POLL_CAPACITY (HTTP_CLIENT_POLL_CAPACITY + HTTP_SERVER_POLL_CAPACITY)

        void *ptrs[POLL_CAPACITY];
        struct pollfd polled[POLL_CAPACITY];

        EventRegister server_reg = {
            ptrs,
            polled,
            0
        };
        http_server_register_events(&server, &server_reg);

        EventRegister client_reg = {
            ptrs   + server_reg.num_polled,
            polled + server_reg.num_polled,
            0
        };
        http_client_register_events(&client, &client_reg);

        if (server_reg.num_polled > 0 ||
            client_reg.num_polled > 0) {
            int num_polled = server_reg.num_polled
                           + client_reg.num_polled;
            POLL(polled, num_polled, -1);
        }

        int result;
        void *user;
        HTTP_Response *response;
        http_client_process_events(&client, client_reg);
        while (http_client_next_response(&client, &result, &user, &response)) {

            HTTP_ResponseBuilder *builder = (HTTP_ResponseBuilder*) user;

            int i = builder - pending;
            assert(i > -1);
            assert(i < HTTP_SERVER_CAPACITY);

            if (result == HTTP_OK) {
                http_response_builder_status(*builder, response->status);
                http_response_builder_body(*builder, response->body);
                http_response_builder_send(*builder);
            } else {
                http_response_builder_status(*builder, 500);
                http_response_builder_send(*builder);
            }

            used[i] = false;
            num_pending--;
        }

        HTTP_Request *request;
        HTTP_ResponseBuilder response_builder;
        http_server_process_events(&server, server_reg);
        while (http_server_next_request(&server, &request, &response_builder)) {

            int i = 0;
            while (used[i]) {
                i++;
                assert(i < HTTP_SERVER_CAPACITY);
            }

            HTTP_String path = request->url.path;
            if (path.len == 0)
                path = HTTP_STR("/");

            char target[1<<10];
            int target_len = snprintf(target, sizeof(target),
                "%.*s%.*s", HTTP_UNPACK(remote), HTTP_UNPACK(path));
            if (target_len < 0 || target_len >= (int) sizeof(target)) {
                http_response_builder_status(response_builder, 500);
                http_response_builder_send(response_builder);
                continue;
            }

            HTTP_RequestBuilder request_builder = http_client_get_builder(&client);
            http_request_builder_set_user(request_builder, &pending[i]);
            http_request_builder_trace(request_builder, true);
            http_request_builder_method(request_builder, request->method);
            http_request_builder_target(request_builder, (HTTP_String) { target, target_len });
            ret = http_request_builder_send(request_builder);
            if (ret < 0) {
                http_response_builder_status(response_builder, 500);
                http_response_builder_send(response_builder);
                continue;
            }

            used[i] = true;
            pending[i] = response_builder;
            num_pending++;
        }
    }

    http_server_free(&server);
    http_client_free(&client);
    return 0;
}
