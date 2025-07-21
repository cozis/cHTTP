#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>

#ifndef HTTP_AMALGAMATION
#include "engine.h"
#include "server.h"
#include "socket_pool.h"
#endif

#define MAX_CONNS (1<<10)

typedef struct {
    bool         used;
    uint16_t     gen;
    HTTP_Engine  engine;
    SocketHandle sock;
} Connection;

struct HTTP_Server {

    SocketPool *socket_pool;

    int num_conns;
    Connection conns[MAX_CONNS];

    int ready_head;
    int ready_count;
    int ready[MAX_CONNS];
};

HTTP_Server *http_server_init(HTTP_String addr, uint16_t port)
{
    return http_server_init_ex(addr, port, 0, HTTP_STR(""), HTTP_STR(""));
}

HTTP_Server *http_server_init_ex(HTTP_String addr, uint16_t port,
    uint16_t secure_port, HTTP_String cert_file, HTTP_String key_file)
{
    HTTP_Server *server = malloc(sizeof(HTTP_Server));
    if (server == NULL)
        return NULL;

    int backlog = 32;
    bool reuse_addr = true;
    SocketPool *socket_pool = socket_pool_init(addr, port, secure_port, MAX_CONNS, reuse_addr, backlog, cert_file, key_file);
    if (socket_pool == NULL) {
        free(server);
        return NULL;
    }

    server->socket_pool = socket_pool;
    server->num_conns = 0;
    server->ready_head = 0;
    server->ready_count = 0;

    for (int i = 0; i < MAX_CONNS; i++) {
        server->conns[i].used = false;
        server->conns[i].gen = 1;
    }

    return server;
}

void http_server_free(HTTP_Server *server)
{
    for (int i = 0, j = 0; j < server->num_conns; i++) {

        if (!server->conns[i].used)
            continue;
        j++;

        // TODO
    }

    socket_pool_free(server->socket_pool);
    free(server);
}

int http_server_add_website(HTTP_Server *server, HTTP_String domain, HTTP_String cert_file, HTTP_String key_file)
{
    return socket_pool_add_cert(server->socket_pool, domain.ptr, domain.len, cert_file.ptr, cert_file.len, key_file.ptr, key_file.len);
}

static void* server_memfunc(HTTP_MemoryFuncTag tag, void *ptr, int len, void *data) {
    (void)data;
    switch (tag) {
        case HTTP_MEMFUNC_MALLOC:
            return malloc(len);
        case HTTP_MEMFUNC_FREE:
            free(ptr);
            return NULL;
    }
    return NULL;
}

int http_server_wait(HTTP_Server *server, HTTP_Request **req, HTTP_ResponseHandle *handle)
{
    while (server->ready_count == 0) {

        SocketEvent event = socket_pool_wait(server->socket_pool);
        switch (event.type) {

            case SOCKET_EVENT_DIED:
            {
                Connection *conn = event.user_data;
                HTTP_ASSERT(conn);

                http_engine_free(&conn->engine);
                conn->used = false;
                conn->gen++;
                server->num_conns--;
            }
            break;

            case SOCKET_EVENT_READY:
            {
                Connection *conn = event.user_data;
                if (conn == NULL) {

                    // Connection was just accepted

                    if (server->num_conns == MAX_CONNS) {
                        socket_pool_close(server->socket_pool, event.handle);
                        break;
                    }

                    int i = 0;
                    while (server->conns[i].used)
                        i++;

                    conn = &server->conns[i];
                    conn->used = true;
                    conn->sock = event.handle;
                    http_engine_init(&conn->engine, 0, server_memfunc, NULL);
                    socket_pool_set_user_data(server->socket_pool, event.handle, conn);
                    server->num_conns++;
                }

                switch (http_engine_state(&conn->engine)) {

                    int len;
                    char *buf;

                    case HTTP_ENGINE_STATE_SERVER_RECV_BUF:
                    buf = http_engine_recvbuf(&conn->engine, &len);
                    if (buf) {
                        int ret = socket_pool_read(server->socket_pool, conn->sock, buf, len);
                        http_engine_recvack(&conn->engine, ret);
                    }
                    break;

                    case HTTP_ENGINE_STATE_SERVER_SEND_BUF:
                    buf = http_engine_sendbuf(&conn->engine, &len);
                    if (buf) {
                        int ret = socket_pool_write(server->socket_pool, conn->sock, buf, len);
                        http_engine_sendack(&conn->engine, ret);
                    }
                    break;

                    default:
                    break;
                }

                switch (http_engine_state(&conn->engine)) {

                    int tail;

                    case HTTP_ENGINE_STATE_SERVER_PREP_STATUS:
                    tail = (server->ready_head + server->ready_count) % MAX_CONNS;
                    server->ready[tail] = conn - server->conns;
                    server->ready_count++;
                    break;

                    case HTTP_ENGINE_STATE_SERVER_CLOSED:
                    socket_pool_close(server->socket_pool, conn->sock);
                    break;

                    default:
                    break;
                }
            }
            break;

            case SOCKET_EVENT_ERROR:
            return -1;

            case SOCKET_EVENT_SIGNAL:
            return 1;
        }
    }

    int index = server->ready[server->ready_head];
    server->ready_head = (server->ready_head + 1) % MAX_CONNS;
    server->ready_count--;

    *req = http_engine_getreq(&server->conns[index].engine);
    *handle = (HTTP_ResponseHandle) { server, index, server->conns[index].gen };
    return 0;
}

static Connection*
handle2conn(HTTP_ResponseHandle handle)
{
	HTTP_Server *server = handle.data0;
	if (handle.data1 >= MAX_CONNS)
		return NULL;

	Connection *conn = &server->conns[handle.data1];
	if (conn->gen != handle.data2)
		return NULL;

	return conn;
}

void http_response_status(HTTP_ResponseHandle res, int status)
{
	Connection *conn = handle2conn(res);
	if (conn == NULL)
		return;

	http_engine_status(&conn->engine, status);
}

void http_response_header(HTTP_ResponseHandle res, HTTP_String str)
{
	Connection *conn = handle2conn(res);
	if (conn == NULL)
		return;

	http_engine_header(&conn->engine, str);
}

void http_response_body(HTTP_ResponseHandle res, HTTP_String str)
{
	Connection *conn = handle2conn(res);
	if (conn == NULL)
		return;

	http_engine_body(&conn->engine, str);
}

void http_response_bodycap(HTTP_ResponseHandle res, int mincap)
{
	Connection *conn = handle2conn(res);
	if (conn == NULL)
		return;

	http_engine_bodycap(&conn->engine, mincap);
}

char *http_response_bodybuf(HTTP_ResponseHandle res, int *cap)
{
	Connection *conn = handle2conn(res);
	if (conn == NULL) {
		*cap = 0;
		return NULL;
	}

	return http_engine_bodybuf(&conn->engine, cap);
}

void http_response_bodyack(HTTP_ResponseHandle res, int num)
{
	Connection *conn = handle2conn(res);
	if (conn == NULL)
		return;

	http_engine_bodyack(&conn->engine, num);
}

void http_response_undo(HTTP_ResponseHandle res)
{
	Connection *conn = handle2conn(res);
	if (conn == NULL)
		return;

	http_engine_undo(&conn->engine);
}

void http_response_done(HTTP_ResponseHandle res)
{
    HTTP_Server *server = res.data0;
    Connection *conn = handle2conn(res);
    if (conn == NULL)
        return;

    http_engine_done(&conn->engine);

    conn->gen++;
    if (conn->gen == 0 || conn->gen == UINT16_MAX)
        conn->gen = 1;

    HTTP_EngineState state = http_engine_state(&conn->engine);

    if (state == HTTP_ENGINE_STATE_SERVER_PREP_STATUS) {
        int tail = (server->ready_head + server->ready_count) % MAX_CONNS;
        server->ready[tail] = res.data1;
        server->ready_count++;
    }

    if (state == HTTP_ENGINE_STATE_SERVER_CLOSED)
        socket_pool_close(server->socket_pool, conn->sock);
}