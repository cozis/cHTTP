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

    HTTP_RequestBuilder builder = http_client_get_builder(&client);

    http_request_builder_set_trace_bytes(builder, true);

    http_request_builder_method(builder, HTTP_METHOD_GET);
    http_request_builder_target(builder, HTTP_STR("http://coz.is"));
    http_request_builder_header(builder, HTTP_STR("Greeting: Hello from the cHTTP example!"));

    if (http_request_builder_send(builder) < 0)
        return -1;

    void *user;
    HTTP_Response *response;
    if (http_client_wait_response(&client, &response, &user) < 0)
        return -1;

    printf("Received a response!\n");

    http_client_free(&client);
    return 0;
}
