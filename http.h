/*
 * HTTP Library - Amalgamated Header
 * Generated automatically - do not edit manually
 */

#ifndef HTTP_AMALGAMATION_H
#define HTTP_AMALGAMATION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

#define HTTP_STR(X) ((HTTP_String) {(X), sizeof(X)-1})
#define HTTP_CEIL(X, Y) (((X) + (Y) - 1) / (Y))

typedef struct {
	char *ptr;
	long  len;
} HTTP_String;

int         http_streq     (HTTP_String s1, HTTP_String s2);
int         http_streqcase (HTTP_String s1, HTTP_String s2);
HTTP_String http_trim      (HTTP_String s);

#define HTTP_COUNT(X) (sizeof(X) / sizeof((X)[0]))
#define HTTP_ASSERT(X) {if (!(X)) { __builtin_trap(); }}

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
	HTTP_Method method;
	HTTP_URL    url;
	int         minor;
	int         num_headers;
	HTTP_Header headers[HTTP_MAX_HEADERS];
	HTTP_String body;
} HTTP_Request;

typedef struct {
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
HTTP_String http_getqueryparam  (HTTP_Request *req, HTTP_String name);
HTTP_String http_getbodyparam   (HTTP_Request *req, HTTP_String name);
HTTP_String http_getcookie      (HTTP_Request *req, HTTP_String name);

typedef enum {
	HTTP_MEMFUNC_MALLOC,
	HTTP_MEMFUNC_FREE,
} HTTP_MemoryFuncTag;

typedef void*(*HTTP_MemoryFunc)(HTTP_MemoryFuncTag tag,
	void *ptr, int len, void *data);

typedef struct {

	HTTP_MemoryFunc memfunc;
	void *memfuncdata;

	unsigned long long curs;

	char*        data;
	unsigned int head;
	unsigned int size;
	unsigned int used;
	unsigned int limit;

	char*        read_target;
	unsigned int read_target_size;

	int flags;
} HTTP_ByteQueue;

typedef unsigned long long HTTP_ByteQueueOffset;

#define HTTP_ENGINE_STATEBIT_CLIENT        (1 << 0)
#define HTTP_ENGINE_STATEBIT_CLOSED        (1 << 1)
#define HTTP_ENGINE_STATEBIT_RECV_BUF      (1 << 2)
#define HTTP_ENGINE_STATEBIT_RECV_ACK      (1 << 3)
#define HTTP_ENGINE_STATEBIT_SEND_BUF      (1 << 4)
#define HTTP_ENGINE_STATEBIT_SEND_ACK      (1 << 5)
#define HTTP_ENGINE_STATEBIT_REQUEST       (1 << 6)
#define HTTP_ENGINE_STATEBIT_RESPONSE      (1 << 7)
#define HTTP_ENGINE_STATEBIT_PREP          (1 << 8)
#define HTTP_ENGINE_STATEBIT_PREP_HEADER   (1 << 9)
#define HTTP_ENGINE_STATEBIT_PREP_BODY_BUF (1 << 10)
#define HTTP_ENGINE_STATEBIT_PREP_BODY_ACK (1 << 11)
#define HTTP_ENGINE_STATEBIT_PREP_ERROR    (1 << 12)
#define HTTP_ENGINE_STATEBIT_PREP_URL      (1 << 13)
#define HTTP_ENGINE_STATEBIT_PREP_STATUS   (1 << 14)
#define HTTP_ENGINE_STATEBIT_CLOSING       (1 << 15)

typedef enum {
	HTTP_ENGINE_STATE_NONE = 0,
	HTTP_ENGINE_STATE_CLIENT_PREP_URL      = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_URL,
	HTTP_ENGINE_STATE_CLIENT_PREP_HEADER   = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_HEADER,
	HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_BODY_BUF,
	HTTP_ENGINE_STATE_CLIENT_PREP_BODY_ACK = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_BODY_ACK,
	HTTP_ENGINE_STATE_CLIENT_PREP_ERROR    = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_ERROR,
	HTTP_ENGINE_STATE_CLIENT_SEND_BUF      = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_SEND_BUF,
	HTTP_ENGINE_STATE_CLIENT_SEND_ACK      = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_SEND_ACK,
	HTTP_ENGINE_STATE_CLIENT_RECV_BUF      = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_RECV_BUF,
	HTTP_ENGINE_STATE_CLIENT_RECV_ACK      = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_RECV_ACK,
	HTTP_ENGINE_STATE_CLIENT_READY         = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_RESPONSE,
	HTTP_ENGINE_STATE_CLIENT_CLOSED        = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_CLOSED,
	HTTP_ENGINE_STATE_SERVER_RECV_BUF      = HTTP_ENGINE_STATEBIT_RECV_BUF,
	HTTP_ENGINE_STATE_SERVER_RECV_ACK      = HTTP_ENGINE_STATEBIT_RECV_ACK,
	HTTP_ENGINE_STATE_SERVER_PREP_STATUS   = HTTP_ENGINE_STATEBIT_REQUEST | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_STATUS,
	HTTP_ENGINE_STATE_SERVER_PREP_HEADER   = HTTP_ENGINE_STATEBIT_REQUEST | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_HEADER,
	HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF = HTTP_ENGINE_STATEBIT_REQUEST | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_BODY_BUF,
	HTTP_ENGINE_STATE_SERVER_PREP_BODY_ACK = HTTP_ENGINE_STATEBIT_REQUEST | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_BODY_ACK,
	HTTP_ENGINE_STATE_SERVER_PREP_ERROR    = HTTP_ENGINE_STATEBIT_REQUEST | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_ERROR,
	HTTP_ENGINE_STATE_SERVER_SEND_BUF      = HTTP_ENGINE_STATEBIT_SEND_BUF,
	HTTP_ENGINE_STATE_SERVER_SEND_ACK      = HTTP_ENGINE_STATEBIT_SEND_ACK,
	HTTP_ENGINE_STATE_SERVER_CLOSED        = HTTP_ENGINE_STATEBIT_CLIENT,
} HTTP_EngineState;

typedef struct {
	HTTP_EngineState state;
	HTTP_ByteQueue   input;
	HTTP_ByteQueue   output;
	int numexch;
	int reqsize;
	int closing;
	int keepalive;
	HTTP_ByteQueueOffset response_offset;
	HTTP_ByteQueueOffset content_length_offset;
	HTTP_ByteQueueOffset content_length_value_offset;
	union {
		HTTP_Request  req;
		HTTP_Response res;
	} result;
} HTTP_Engine;

void             http_engine_init    (HTTP_Engine *eng, int client, HTTP_MemoryFunc memfunc, void *memfuncdata);
void             http_engine_free    (HTTP_Engine *eng);

void             http_engine_close   (HTTP_Engine *eng);
HTTP_EngineState http_engine_state   (HTTP_Engine *eng);

const char*      http_engine_statestr(HTTP_EngineState state); // TODO: remove

char*            http_engine_recvbuf (HTTP_Engine *eng, int *cap);
void             http_engine_recvack (HTTP_Engine *eng, int num);
char*            http_engine_sendbuf (HTTP_Engine *eng, int *len);
void             http_engine_sendack (HTTP_Engine *eng, int num);

HTTP_Request*    http_engine_getreq  (HTTP_Engine *eng);
HTTP_Response*   http_engine_getres  (HTTP_Engine *eng);

void             http_engine_url     (HTTP_Engine *eng, HTTP_Method method, HTTP_String url, int minor);
void             http_engine_status  (HTTP_Engine *eng, int status);
void             http_engine_header  (HTTP_Engine *eng, const char *src, int len);
void             http_engine_body    (HTTP_Engine *eng, void *src, int len); 
void             http_engine_bodycap (HTTP_Engine *eng, int mincap);
char*            http_engine_bodybuf (HTTP_Engine *eng, int *cap);
void             http_engine_bodyack (HTTP_Engine *eng, int num);
void             http_engine_done    (HTTP_Engine *eng);
void             http_engine_undo    (HTTP_Engine *eng);
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

int http_create_test_certificate(HTTP_String C, HTTP_String O, HTTP_String CN,
    HTTP_String cert_file, HTTP_String key_file);

typedef struct HTTP_Router HTTP_Router;
typedef void (*HTTP_RouterFunc)(HTTP_Request*, HTTP_ResponseHandle, void*);;

HTTP_Router* http_router_init    (void);
void         http_router_free    (HTTP_Router *router);
void         http_router_resolve (HTTP_Router *router, HTTP_Request *req, HTTP_ResponseHandle res);
void         http_router_dir     (HTTP_Router *router, HTTP_String endpoint, HTTP_String path);
void         http_router_func    (HTTP_Router *router, HTTP_Method method, HTTP_String endpoint, HTTP_RouterFunc func, void*);
int          http_serve          (char *addr, int port, HTTP_Router *router);


#ifdef __cplusplus
}
#endif

#endif /* HTTP_AMALGAMATION_H */
