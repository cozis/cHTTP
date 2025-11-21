#include "../chttp.h"

#ifdef _WIN32
#define POLL WSAPoll
#else
#define POLL poll
#endif

int main(void)
{
    HTTP_Client client;
    if (http_client_init(&client) < 0)
        return -1;

    HTTP_RequestBuilder builder;
    if (http_client_get_builder(&client, NULL, &builder) < 0)
        return -1;

    http_request_builder_url(builder,
        HTTP_METHOD_GET,
        HTTP_STR("http://coz.is")
    );

    http_request_builder_header(builder,
        HTTP_STR("Greeting: Hello from the cHTTP example!"));

    if (http_request_builder_send(builder) < 0)
        return -1;

    for (;;) {

        void *ptrs[HTTP_CLIENT_CAPACITY+1];
        struct pollfd polled[HTTP_CLIENT_CAPACITY+1];

        EventRegister reg = {
            .ptrs=ptrs,
            .polled=polled,
            .num_polled=0,
            .max_polled=HTTP_CLIENT_CAPACITY+1,
        };

        if (http_client_register_events(&client, &reg) < 0)
            return -1;

        if (reg.num_polled > 0)
            POLL(reg.polled, reg.num_polled, -1);

        if (http_client_process_events(&client, &reg) < 0)
            return -1;

        HTTP_Response *response;
        while (http_client_next_response(&client, &response)) {
            // TODO
            http_free_response(response);
        }
    }

    http_client_free(&client);
    return 0;
}
