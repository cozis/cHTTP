#include <stdio.h>
#include <chttp.h>

// This is an example of how to use cHTTP to perform
// a basic GET request.

int main(void)
{
    http_global_init();

    // List any headers the request should hold
    HTTP_String headers[] = {
        HTTP_STR("User-Agent: cHTTP"),
    };

    // Perform the request. This will block the thread
    // until an error occurs or the request completes.
    HTTP_Response *res = http_get(
        HTTP_STR("http://example.com/index.html"),
        headers, HTTP_COUNT(headers)
    );

    // The http_get function returns NULL if the request
    // couldn't be performed.
    if (res == NULL) return -1;

    // If the request succeded (note that responses with
    // status 4xx and 5xx are not considered as errors in
    // this context) the returned value holds the parsed
    // version of the response and the output handle is set.

    printf("status code: %d\n", res->status);

    for (int i = 0; i < res->num_headers; i++) {
        HTTP_Header header = res->headers[i];
        printf(
            "header %d: [%.*s] [%.*s]\n",
            i,
            HTTP_UNPACK(header.name),
            HTTP_UNPACK(header.value)
        );
    }

    printf("body: %.*s\n", HTTP_UNPACK(res->body));

    // When we are done reading from the response object
    // we must free the request's resources.
    http_request_free(res);

    // All done. Deinitialize the library.
    http_global_free();
    return 0;
}