#ifndef CLIENT_INCLUDED
#define CLIENT_INCLUDED

#include <stdbool.h>
#include "parse.h"

void http_global_init(void);
void http_global_free(void);

typedef struct HTTP_Client HTTP_Client;

typedef struct {
    void *data0;
    int   data1;
    int   data2;
} HTTP_RequestHandle;

HTTP_Client*   http_client_init     (void);
void           http_client_free     (HTTP_Client *client);
int            http_client_request  (HTTP_Client *client, HTTP_RequestHandle *handle);
int            http_client_wait     (HTTP_Client *client, HTTP_RequestHandle *handle);
void           http_request_trace   (HTTP_RequestHandle handle, bool trace);
void           http_request_line    (HTTP_RequestHandle handle, HTTP_Method method, HTTP_String url);
void           http_request_header  (HTTP_RequestHandle handle, char *header, int len);
void           http_request_body    (HTTP_RequestHandle handle, char *body, int len);
void           http_request_submit  (HTTP_RequestHandle handle);
HTTP_Response* http_request_result  (HTTP_RequestHandle handle);
void           http_request_free    (HTTP_RequestHandle handle);

#endif // CLIENT_INCLUDED