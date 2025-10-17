#ifndef PARSE_INCLUDED
#define PARSE_INCLUDED

#ifndef HTTP_AMALGAMATION
#include "basic.h"
#endif

#define HTTP_MAX_HEADERS 32

typedef struct {
	unsigned int data;
} HTTP_IPv4;

typedef struct {
	unsigned short data[8];
} HTTP_IPv6;

typedef enum {
	HTTP_HOST_MODE_VOID = 0,
	HTTP_HOST_MODE_NAME,
	HTTP_HOST_MODE_IPV4,
	HTTP_HOST_MODE_IPV6,
} HTTP_HostMode;

typedef struct {
	HTTP_HostMode mode;
	HTTP_String   text;
	union {
		HTTP_String name;
		HTTP_IPv4   ipv4;
		HTTP_IPv6   ipv6;
	};
} HTTP_Host;

typedef struct {
	HTTP_String userinfo;
	HTTP_Host   host;
	int         port;
} HTTP_Authority;

// ZII
typedef struct {
	HTTP_String    scheme;
	HTTP_Authority authority;
	HTTP_String    path;
	HTTP_String    query;
	HTTP_String    fragment;
} HTTP_URL;

typedef enum {
	HTTP_METHOD_GET,
	HTTP_METHOD_HEAD,
	HTTP_METHOD_POST,
	HTTP_METHOD_PUT,
	HTTP_METHOD_DELETE,
	HTTP_METHOD_CONNECT,
	HTTP_METHOD_OPTIONS,
	HTTP_METHOD_TRACE,
	HTTP_METHOD_PATCH,
} HTTP_Method;

typedef struct {
	HTTP_String name;
	HTTP_String value;
} HTTP_Header;

typedef struct {
    bool        secure;
	HTTP_Method method;
	HTTP_URL    url;
	int         minor;
	int         num_headers;
	HTTP_Header headers[HTTP_MAX_HEADERS];
	HTTP_String body;
} HTTP_Request;

typedef struct {
    void*       context;
	int         minor;
	int         status;
	HTTP_String reason;
	int         num_headers;
	HTTP_Header headers[HTTP_MAX_HEADERS];
	HTTP_String body;
} HTTP_Response;

int         http_parse_ipv4     (char *src, int len, HTTP_IPv4     *ipv4);
int         http_parse_ipv6     (char *src, int len, HTTP_IPv6     *ipv6);
int         http_parse_url      (char *src, int len, HTTP_URL      *url);
int         http_parse_request  (char *src, int len, HTTP_Request  *req);
int         http_parse_response (char *src, int len, HTTP_Response *res);

int         http_find_header    (HTTP_Header *headers, int num_headers, HTTP_String name);

HTTP_String http_get_cookie     (HTTP_Request *req, HTTP_String name);
HTTP_String http_get_param      (HTTP_String body, HTTP_String str, char *mem, int cap);
int         http_get_param_i    (HTTP_String body, HTTP_String str);

// Checks whether the request was meant for the host with the given
// domain an port. If port is -1, the default value of 80 is assumed.
bool http_match_host(HTTP_Request *req, HTTP_String domain, int port);

#endif // PARSE_INCLUDED