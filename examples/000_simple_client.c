#include "../chttp.h"

int main(void)
{
    HTTP_Response *response;

    int ret = http_get(HTTP_STR("http://coz.is/"), NULL, 0, &response);
    if (ret == HTTP_OK) {
        printf("Received %d bytes\n", response->body.len);
        http_free_response(response);
    } else {
        printf("Request failure: %s\n", http_strerror(ret));
    }
    return 0;
}
