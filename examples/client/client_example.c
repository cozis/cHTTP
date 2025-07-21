#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <chttp.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: %s <url1> [url2 ...]\n", argv[0]);
        return 1;
    }

    http_global_init();
    HTTP_Client *client = http_client_init();

    for (int i = 1; i < argc; i++) {
        HTTP_RequestBuilder builder;
        if (http_client_get_builder(client, &builder) < 0) {
            printf("request creation error\n");
            return -1;
        }
        http_request_builder_line(builder, HTTP_METHOD_GET, (HTTP_String) { argv[i], strlen(argv[i]) });
        http_request_builder_submit(builder);
        printf("request submitted\n");
    }

    for (int i = 1; i < argc; i++) {

        HTTP_Response *res;
        if (http_client_wait(client, &res, NULL) < 0) {
            printf("request wait error\n");
            return -1;
        }

        printf("Status: %d\n", res->status);
        printf("Body: %.*s\n", HTTP_UNPACK(res->body));

        http_response_free(res);
    }

    http_client_free(client);
    http_global_free();
    return 0;
} 