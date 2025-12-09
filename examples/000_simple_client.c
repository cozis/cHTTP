#include "../chttp.h"

int main(void)
{
    CHTTP_Response *response;

    int ret = chttp_get(CHTTP_STR("http://coz.is/"), NULL, 0, &response);
    if (ret == CHTTP_OK) {
        printf("Received %d bytes\n", response->body.len);
        chttp_free_response(response);
    } else {
        printf("Request failure: %s\n", chttp_strerror(ret));
    }
    return 0;
}
