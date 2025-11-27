#include "../chttp.h"

int main(void)
{
    int ret;

    HTTP_Client client;
    ret = http_client_init(&client);
    if (ret < 0) {
        printf("Couldn't initialize client (%s)\n", http_strerror(ret));
        return -1;
    }

    HTTP_RequestBuilder builder = http_client_get_builder(&client);

    http_request_builder_method(builder, HTTP_METHOD_GET);
    http_request_builder_target(builder, HTTP_STR("http://coz.is"));
    http_request_builder_header(builder, HTTP_STR("Greeting: Hello from the cHTTP example!"));

    ret = http_request_builder_send(builder);
    if (ret < 0) {
        printf("Couldn't build request (%s)\n", http_strerror(ret));
        return -1;
    }

    int result;
    void *user;
    HTTP_Response *response;
    http_client_wait_response(&client, &result, &user, &response);

    if (result == HTTP_OK) {
        printf("Received %d bytes\n", response->body.len);
    } else {
        printf("Couldn't receive response (%s)\n", http_strerror(result));
    }

    http_free_response(response);
    http_client_free(&client);
    return 0;
}
