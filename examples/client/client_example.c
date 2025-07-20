#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <chttp.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <url1> [url2 ...]\n", argv[0]);
        return 1;
    }

    http_global_init();
    HTTP_Client *client = http_client_init();

    HTTP_RequestHandle reqs[100];
    
    for (int i = 1; i < argc; i++) {
        int k = i-1;
        if (http_client_request(client, &reqs[k]) < 0) {
            printf("request creation error\n");
            return -1;
        }
        http_request_line(reqs[k], HTTP_METHOD_GET, (HTTP_String) { argv[i], strlen(argv[i]) });
        http_request_submit(reqs[k]);
        printf("request submitted\n");
    }

    for (int i = 1; i < argc; i++)
        if (http_client_wait(client, NULL) < 0) {
            printf("request wait error\n");
            return -1;
        }

    printf("all requests completed\n");

    for (int i = 1; i < argc; i++) {

        HTTP_Response *result = http_request_result(reqs[i-1]);
        if (!result) {
            fprintf(stderr, "No result from HTTP request\n");
            http_request_free(reqs[i-1]);
            return 1;
        }

        printf("Status: %d\n", result->status);
        printf("Body: %.*s\n", HTTP_UNPACK(result->body));

        http_request_free(reqs[i-1]);
    }

    http_client_free(client);
    http_global_free();
    return 0;
} 