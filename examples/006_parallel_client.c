#include "../chttp.h"

int main(void)
{
    int ret;

    CHTTP_Client client;
    ret = chttp_client_init(&client);
    if (ret < 0) {
        printf("Couldn't initialize client (%s)\n", chttp_strerror(ret));
        return -1;
    }

    CHTTP_RequestBuilder builder = chttp_client_get_builder(&client);

    chttp_request_builder_method(builder, CHTTP_METHOD_GET);
    chttp_request_builder_target(builder, CHTTP_STR("http://coz.is"));
    chttp_request_builder_header(builder, CHTTP_STR("Greeting: Hello from the cHTTP example!"));

    ret = chttp_request_builder_send(builder);
    if (ret < 0) {
        printf("Couldn't build request (%s)\n", chttp_strerror(ret));
        return -1;
    }

    int result;
    void *user;
    CHTTP_Response *response;
    chttp_client_wait_response(&client, &result, &user, &response);

    if (result == CHTTP_OK) {
        printf("Received %d bytes\n", response->body.len);
    } else {
        printf("Couldn't receive response (%s)\n", chttp_strerror(result));
    }

    chttp_free_response(response);
    chttp_client_free(&client);
    return 0;
}
