#ifndef HTTP_SERVER_INCLUDED
#define HTTP_SERVER_INCLUDED

#include <stdint.h>
#include "parse.h"

typedef struct {
    void *data0;
    int   data1;
    int   data2;
} HTTP_ResponseHandle;

typedef struct HTTP_Server HTTP_Server;

HTTP_Server *http_server_init(HTTP_String addr, uint16_t port);

HTTP_Server *http_server_init_ex(HTTP_String addr, uint16_t port,
    uint16_t secure_port, HTTP_String cert_key, HTTP_String private_key);

void         http_server_free        (HTTP_Server *server);
int          http_server_wait        (HTTP_Server *server, HTTP_Request **req, HTTP_ResponseHandle *handle);
int          http_server_add_website (HTTP_Server *server, HTTP_String domain, HTTP_String cert_file, HTTP_String key_file);
void         http_response_status    (HTTP_ResponseHandle res, int status);
void         http_response_header    (HTTP_ResponseHandle res, const char *fmt, ...);
void         http_response_body      (HTTP_ResponseHandle res, char *src, int len);
void         http_response_bodycap   (HTTP_ResponseHandle res, int mincap);
char*        http_response_bodybuf   (HTTP_ResponseHandle res, int *cap);
void         http_response_bodyack   (HTTP_ResponseHandle res, int num);
void         http_response_undo      (HTTP_ResponseHandle res);
void         http_response_done      (HTTP_ResponseHandle res);

#endif // HTTP_SERVER_INCLUDED