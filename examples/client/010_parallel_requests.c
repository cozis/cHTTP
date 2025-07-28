#include <stddef.h>
#include <chttp.h>

int main(void)
{
    http_global_init();
    HTTP_Client *client = http_client_init();
    if (client == NULL)
        return -1;

    HTTP_Response *responses[2];

    HTTP_String urls[] = {
        HTTP_STR("http://coz.is"),
        HTTP_STR("http://coz.is"),
    };

    bool trace = false;

    HTTP_RequestBuilder builder;
    if (http_client_get_builder(client, &builder) < 0) return -1;
    http_request_builder_trace(builder, trace);
    http_request_builder_user_data(builder, &responses[0]);
    http_request_builder_line(builder, HTTP_METHOD_GET, urls[0]);
    http_request_builder_submit(builder);

    if (http_client_get_builder(client, &builder) < 0) return -1;
    http_request_builder_trace(builder, trace);
    http_request_builder_user_data(builder, &responses[1]);
    http_request_builder_line(builder, HTTP_METHOD_GET, urls[1]);
    http_request_builder_submit(builder);

    for (int i = 0; i < 2; i++) {
        void **dst;
        HTTP_Response *output;
        if (http_client_wait(client, &output, (void*) &dst) < 0)
            return -1;
        *dst = output;
    }

    HTTP_Response *responseA = responses[0];
    HTTP_Response *responseB = responses[1];

    // ... process responses ...

    http_response_free(responseA);
    http_response_free(responseB);
    http_client_free(client);
    http_global_free();
    return 0;
}