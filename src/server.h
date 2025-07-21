#ifndef HTTP_SERVER_INCLUDED
#define HTTP_SERVER_INCLUDED

#include <stdint.h>

#ifndef HTTP_AMALGAMATION
#include "parse.h"
#endif

typedef struct {
    void *data0;
    int   data1;
    int   data2;
} HTTP_ResponseBuilder;

typedef struct HTTP_Server HTTP_Server;

HTTP_Server *http_server_init(HTTP_String addr, uint16_t port);

HTTP_Server *http_server_init_ex(HTTP_String addr, uint16_t port,
    uint16_t secure_port, HTTP_String cert_key, HTTP_String private_key);

void         http_server_free              (HTTP_Server *server);
int          http_server_wait              (HTTP_Server *server, HTTP_Request **req, HTTP_ResponseBuilder *handle);
int          http_server_add_website       (HTTP_Server *server, HTTP_String domain, HTTP_String cert_file, HTTP_String key_file);
void         http_response_builder_status  (HTTP_ResponseBuilder res, int status);
void         http_response_builder_header  (HTTP_ResponseBuilder res, HTTP_String str);
void         http_response_builder_body    (HTTP_ResponseBuilder res, HTTP_String str);
void         http_response_builder_bodycap (HTTP_ResponseBuilder res, int mincap);
char*        http_response_builder_bodybuf (HTTP_ResponseBuilder res, int *cap);
void         http_response_builder_bodyack (HTTP_ResponseBuilder res, int num);
void         http_response_builder_undo    (HTTP_ResponseBuilder res);
void         http_response_builder_done    (HTTP_ResponseBuilder res);

#endif // HTTP_SERVER_INCLUDED