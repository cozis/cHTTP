#ifndef HTTP_ENGINE_INCLUDED
#define HTTP_ENGINE_INCLUDED
#include "parse.h"

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
#endif // HTTP_ENGINE_INCLUDED
