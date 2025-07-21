#ifndef HTTP_ROUTER_INCLUDED
#define HTTP_ROUTER_INCLUDED

#ifndef HTTP_AMALGAMATION
#include "server.h"
#endif

typedef struct HTTP_Router HTTP_Router;
typedef void (*HTTP_RouterFunc)(HTTP_Request*, HTTP_ResponseHandle, void*);;

HTTP_Router* http_router_init    (void);
void         http_router_free    (HTTP_Router *router);
void         http_router_resolve (HTTP_Router *router, HTTP_Request *req, HTTP_ResponseHandle res);
void         http_router_dir     (HTTP_Router *router, HTTP_String endpoint, HTTP_String path);
void         http_router_func    (HTTP_Router *router, HTTP_Method method, HTTP_String endpoint, HTTP_RouterFunc func, void*);
int          http_serve          (char *addr, int port, HTTP_Router *router);

#endif // HTTP_ROUTER_INCLUDED