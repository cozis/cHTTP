#ifndef HTTP_INCLUDED
#define HTTP_INCLUDED

#ifndef HTTP_PARSE
#define HTTP_PARSE 1
#endif

#ifndef HTTP_ENGINE
#define HTTP_ENGINE 1
#endif

#ifndef HTTP_CLIENT
#define HTTP_CLIENT 1
#endif

#ifndef HTTP_SERVER
#define HTTP_SERVER 1
#endif

#ifndef HTTP_ROUTER
#define HTTP_ROUTER 1
#endif

/////////////////////////////////////////////////////////////////////
// UTILITIES
/////////////////////////////////////////////////////////////////////

#define HTTP_STR(X) ((HTTP_String) {(X), sizeof(X)-1})
#define HTTP_CEIL(X, Y) (((X) + (Y) - 1) / (Y))

typedef struct {
	char *ptr;
	long  len;
} HTTP_String;

int         http_streq     (HTTP_String s1, HTTP_String s2);
int         http_streqcase (HTTP_String s1, HTTP_String s2);
HTTP_String http_trim      (HTTP_String s);

/////////////////////////////////////////////////////////////////////
// HTTP PARSER
/////////////////////////////////////////////////////////////////////
#if HTTP_PARSE

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

int http_parse_ipv4     (char *src, int len, HTTP_IPv4     *ipv4);
int http_parse_ipv6     (char *src, int len, HTTP_IPv6     *ipv6);
int http_parse_url      (char *src, int len, HTTP_URL      *url);
int http_parse_request  (char *src, int len, HTTP_Request  *req);
int http_parse_response (char *src, int len, HTTP_Response *res);

HTTP_String http_getbodyparam (HTTP_Request *req, HTTP_String name);
HTTP_String http_getcookie    (HTTP_Request *req, HTTP_String name);

#endif // HTTP_PARSE
/////////////////////////////////////////////////////////////////////
// HTTP BYTE QUEUE
/////////////////////////////////////////////////////////////////////
#if HTTP_ENGINE

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

#endif // HTTP_ENGINE
/////////////////////////////////////////////////////////////////////
// HTTP ENGINE
/////////////////////////////////////////////////////////////////////
#if HTTP_ENGINE

#define HTTP_ENGINE_STATEBIT_CLIENT       (1 << 0)
#define HTTP_ENGINE_STATEBIT_CLOSED       (1 << 1)
#define HTTP_ENGINE_STATEBIT_RECV_BUF     (1 << 2)
#define HTTP_ENGINE_STATEBIT_RECV_ACK     (1 << 3)
#define HTTP_ENGINE_STATEBIT_SEND_BUF     (1 << 4)
#define HTTP_ENGINE_STATEBIT_SEND_ACK     (1 << 5)
#define HTTP_ENGINE_STATEBIT_REQUEST      (1 << 6)
#define HTTP_ENGINE_STATEBIT_RESPONSE     (1 << 7)
#define HTTP_ENGINE_STATEBIT_PREP         (1 << 8)
#define HTTP_ENGINE_STATEBIT_PREP_HEADER  (1 << 9)
#define HTTP_ENGINE_STATEBIT_PREP_BODY    (1 << 10)
#define HTTP_ENGINE_STATEBIT_PREP_ERROR   (1 << 11)
#define HTTP_ENGINE_STATEBIT_PREP_URL     (1 << 12)
#define HTTP_ENGINE_STATEBIT_PREP_STATUS  (1 << 13)
#define HTTP_ENGINE_STATEBIT_CLOSING      (1 << 14)

typedef enum {
	HTTP_ENGINE_STATE_NONE = 0,
	HTTP_ENGINE_STATE_CLIENT_PREP_URL     = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_URL,
	HTTP_ENGINE_STATE_CLIENT_PREP_HEADER  = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_HEADER,
	HTTP_ENGINE_STATE_CLIENT_PREP_BODY    = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_BODY,
	HTTP_ENGINE_STATE_CLIENT_PREP_ERROR   = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_ERROR,
	HTTP_ENGINE_STATE_CLIENT_SEND_BUF     = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_SEND_BUF,
	HTTP_ENGINE_STATE_CLIENT_SEND_ACK     = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_SEND_ACK,
	HTTP_ENGINE_STATE_CLIENT_RECV_BUF     = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_RECV_BUF,
	HTTP_ENGINE_STATE_CLIENT_RECV_ACK     = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_RECV_ACK,
	HTTP_ENGINE_STATE_CLIENT_READY        = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_RESPONSE,
	HTTP_ENGINE_STATE_CLIENT_CLOSED       = HTTP_ENGINE_STATEBIT_CLIENT | HTTP_ENGINE_STATEBIT_CLOSED,
	HTTP_ENGINE_STATE_SERVER_RECV_BUF     = HTTP_ENGINE_STATEBIT_RECV_BUF,
	HTTP_ENGINE_STATE_SERVER_RECV_ACK     = HTTP_ENGINE_STATEBIT_RECV_ACK,
	HTTP_ENGINE_STATE_SERVER_PREP_STATUS  = HTTP_ENGINE_STATEBIT_REQUEST | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_STATUS,
	HTTP_ENGINE_STATE_SERVER_PREP_HEADER  = HTTP_ENGINE_STATEBIT_REQUEST | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_HEADER,
	HTTP_ENGINE_STATE_SERVER_PREP_BODY    = HTTP_ENGINE_STATEBIT_REQUEST | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_BODY,
	HTTP_ENGINE_STATE_SERVER_PREP_ERROR   = HTTP_ENGINE_STATEBIT_REQUEST | HTTP_ENGINE_STATEBIT_PREP | HTTP_ENGINE_STATEBIT_PREP_ERROR,
	HTTP_ENGINE_STATE_SERVER_SEND_BUF     = HTTP_ENGINE_STATEBIT_SEND_BUF,
	HTTP_ENGINE_STATE_SERVER_SEND_ACK     = HTTP_ENGINE_STATEBIT_SEND_ACK,
	HTTP_ENGINE_STATE_SERVER_CLOSED       = HTTP_ENGINE_STATEBIT_CLIENT,
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

char*            http_engine_recvbuf (HTTP_Engine *eng, int *cap);
void             http_engine_recvack (HTTP_Engine *eng, int num);
char*            http_engine_sendbuf (HTTP_Engine *eng, int *len);
void             http_engine_sendack (HTTP_Engine *eng, int num);

HTTP_Request*    http_engine_getreq  (HTTP_Engine *eng);
HTTP_Response*   http_engine_getres  (HTTP_Engine *eng);

void             http_engine_url     (HTTP_Engine *eng, HTTP_Method method, char *url, int minor);
void             http_engine_status  (HTTP_Engine *eng, int status);
void             http_engine_header  (HTTP_Engine *eng, const char *src, int len);
void             http_engine_body    (HTTP_Engine *eng, void *src, int len); 
void             http_engine_bodycap (HTTP_Engine *eng, int mincap);
char*            http_engine_bodybuf (HTTP_Engine *eng, int *cap);
void             http_engine_bodyack (HTTP_Engine *eng, int num);
void             http_engine_done    (HTTP_Engine *eng);
void             http_engine_undo    (HTTP_Engine *eng);

#endif // HTTP_ENGINE
/////////////////////////////////////////////////////////////////////
// HTTP CLIENT AND SERVER
/////////////////////////////////////////////////////////////////////
#if HTTP_CLIENT || HTTP_SERVER

typedef unsigned long long HTTP_Socket;

#endif // HTTP_CLIENT || HTTP_SERVER
/////////////////////////////////////////////////////////////////////
// HTTP CLIENT
/////////////////////////////////////////////////////////////////////
#if HTTP_CLIENT

#define HTTP_CLIENT_TLS 0

#define HTTP_CLIENT_WAIT_LIMIT (1<<9)

typedef struct { _Alignas(void*) char data[32]; } HTTP_TLSContext;
typedef struct { _Alignas(void*) char data[32]; } HTTP_TLSClientContext;

typedef enum {
	HTTP_STATE_CLIENT_IDLE,
	HTTP_STATE_CLIENT_CONNECT,
	HTTP_STATE_CLIENT_TLS_HANDSHAKE_RECV,
	HTTP_STATE_CLIENT_TLS_HANDSHAKE_SEND,
	HTTP_STATE_CLIENT_RECV,
	HTTP_STATE_CLIENT_SEND,
	HTTP_STATE_CLIENT_CLOSED,
	HTTP_STATE_CLIENT_READY,
} HTTP_ClientState;

enum {
	HTTP_CLIENT_OK                = 0,
	HTTP_CLIENT_ERROR_INVURL      = -1,
	HTTP_CLIENT_ERROR_NOSYS       = -2,
	HTTP_CLIENT_ERROR_INVPROTO    = -3,
	HTTP_CLIENT_ERROR_FSOCK       = -4,
	HTTP_CLIENT_ERROR_FCONNECT    = -5,
	HTTP_CLIENT_ERROR_DNS         = -6,
	HTTP_CLIENT_ERROR_FSSLNEW     = -7,
	HTTP_CLIENT_ERROR_FRECV       = -8,
	HTTP_CLIENT_ERROR_FSSLREAD    = -9,
	HTTP_CLIENT_ERROR_FSEND       = -10,
	HTTP_CLIENT_ERROR_FSSLWRITE   = -11,
	HTTP_CLIENT_ERROR_FGETSOCKOPT = -12,
	HTTP_CLIENT_ERROR_FSSLCONNECT = -13,
};

typedef struct {
	int secure;
	int code;
	HTTP_Socket fd;
	HTTP_Engine eng;
	HTTP_ClientState state;
	HTTP_TLSClientContext tls;
} HTTP_Client;

void http_tls_global_init(void);
void http_tls_global_free(void);

int  http_tls_init(HTTP_TLSContext *tls);
void http_tls_free(HTTP_TLSContext *tls);

void http_client_init(HTTP_Client *client);
void http_client_free(HTTP_Client *client);

void http_client_startreq(
	HTTP_Client *client, HTTP_Method method,
	const char *url, HTTP_String *headers,
	int num_headers, char *body, int body_len,
	HTTP_TLSContext *tls);

int http_client_waitany(HTTP_Client **clients, int num_clients, int timeout);
int http_client_waitall(HTTP_Client **clients, int num_clients, int timeout);

int http_client_result(HTTP_Client *client, HTTP_Response **res);
const char *http_client_strerror(int code);

#endif // HTTP_CLIENT
/////////////////////////////////////////////////////////////////////
// HTTP SERVER
/////////////////////////////////////////////////////////////////////
#if HTTP_SERVER

#define HTTP_MAX_CLIENTS_PER_SERVER (1<<9)

typedef unsigned long long HTTP_BitsetWord;
typedef struct {
	HTTP_BitsetWord data[HTTP_CEIL(HTTP_MAX_CLIENTS_PER_SERVER,
		sizeof(HTTP_BitsetWord))];
} HTTP_Bitset;

typedef struct {
	int head;
	int count;
	int items[HTTP_MAX_CLIENTS_PER_SERVER];
	HTTP_Bitset set;
} HTTP_IntQueue;

typedef struct {
	void *ptr;
	int   idx;
	int   gen;
} HTTP_ResponseHandle;

typedef struct {
	HTTP_Socket    fd;
	HTTP_Engine    eng;
	unsigned short gen;
} HTTP_ServerConnection;

typedef struct {
	HTTP_Socket   listen_fd;
	HTTP_IntQueue ready;
	int           num_conns;
	HTTP_ServerConnection conns[HTTP_MAX_CLIENTS_PER_SERVER];
} HTTP_Server;

int http_server_init(HTTP_Server *server,
	const char *addr, int port);

void http_server_free(HTTP_Server *server);

int http_server_wait(HTTP_Server *server, HTTP_Request **req,
	HTTP_ResponseHandle *res, int timeout);

void http_response_status(HTTP_ResponseHandle res, int status);
void http_response_header(HTTP_ResponseHandle res, const char *fmt, ...);
void http_response_body(HTTP_ResponseHandle res, char *src, int len);
void http_response_done(HTTP_ResponseHandle res);
void http_response_undo(HTTP_ResponseHandle res);

#endif // HTTP_SERVER
/////////////////////////////////////////////////////////////////////
// HTTP ROUTER
/////////////////////////////////////////////////////////////////////
#if HTTP_ROUTER

typedef struct HTTP_Router HTTP_Router;
typedef void (*HTTP_RouterFunc)(HTTP_Request*, HTTP_ResponseHandle, void*);;

HTTP_Router* http_router_init    (void);
void         http_router_free    (HTTP_Router *router);
void         http_router_resolve (HTTP_Router *router, HTTP_Request *req, HTTP_ResponseHandle res);
void         http_router_dir     (HTTP_Router *router, HTTP_String endpoint, HTTP_String path);
void         http_router_func    (HTTP_Router *router, HTTP_Method method, HTTP_String endpoint, HTTP_RouterFunc func, void*);
int          http_serve          (const char *addr, int port, HTTP_Router *router);

#endif // HTTP_ROUTER
/////////////////////////////////////////////////////////////////////
// THE END
/////////////////////////////////////////////////////////////////////
#endif // HTTP_INCLUDED