#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>

#ifndef HTTP_AMALGAMATION
#include "engine.h"
#include "socket.h"
#include "server.h"
#endif

#define MAX_CONNS (1<<10)

typedef struct {
    bool        used;
    uint16_t    gen;
    Socket      socket;
    HTTP_Engine engine;
} Connection;

struct HTTP_Server {
    SocketGroup group;

    SOCKET_TYPE listen_fd;
    SOCKET_TYPE secure_fd;

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
    uint16_t secure_port, HTTP_String cert_key, HTTP_String private_key)
{
    HTTP_Server *server = malloc(sizeof(HTTP_Server));
    if (server == NULL)
        return NULL;

    int backlog = 32;
    bool reuse_addr = true;

    if (port == 0 && secure_port == 0) {
        // You must have at least one!
        free(server);
        return NULL;
    }

    if (port == 0)
        server->listen_fd = BAD_SOCKET;
    else {
        server->listen_fd = listen_socket(addr, port, reuse_addr, backlog);
        if (server->listen_fd == BAD_SOCKET) {
            free(server);
            return NULL;
        }
    }

    if (secure_port == 0)
        server->secure_fd = BAD_SOCKET;
    else {

        if (socket_group_init_server(&server->group, cert_key, private_key) < 0) {
            CLOSE_SOCKET(server->listen_fd);
            free(server);
            return NULL;
        }

        server->secure_fd = listen_socket(addr, secure_port, reuse_addr, backlog);
        if (server->secure_fd == BAD_SOCKET) {
            socket_group_free(&server->group);
            CLOSE_SOCKET(server->listen_fd);
            free(server);
            return NULL;
        }
    }

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

    CLOSE_SOCKET(server->secure_fd);
    CLOSE_SOCKET(server->listen_fd);
    if (server->secure_fd != BAD_SOCKET)
        socket_group_free(&server->group);
    free(server);
}

int http_server_add_website(HTTP_Server *server, HTTP_String domain, HTTP_String cert_file, HTTP_String key_file)
{
    return socket_group_add_domain(&server->group, domain, cert_file, key_file);
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

        int num_polled = 0;
        struct pollfd polled[MAX_CONNS+2];
        int          indices[MAX_CONNS+2];

        if (server->num_conns < MAX_CONNS) {

            if (server->listen_fd != BAD_SOCKET) {
                polled[num_polled].fd = server->listen_fd;
                polled[num_polled].events = POLLIN;
                polled[num_polled].revents = 0;
                indices[num_polled] = -1;
                num_polled++;
            }

            if (server->secure_fd != BAD_SOCKET) {
                polled[num_polled].fd = server->secure_fd;
                polled[num_polled].events = POLLIN;
                polled[num_polled].revents = 0;
                indices[num_polled] = -1;
                num_polled++;
            }
        }

        for (int i = 0, j = 0; i < server->num_conns; i++) {

            Connection *conn = &server->conns[i];

            if (!conn->used)
                continue;
            j++;

            int events = 0;
            switch (conn->socket.event) {
                case SOCKET_WANT_NONE: events = 0; break;
                case SOCKET_WANT_READ: events = POLLIN; break;
                case SOCKET_WANT_WRITE: events = POLLOUT; break;
            }

            if (events) {
                polled[num_polled].fd = conn->socket.fd;
                polled[num_polled].events = events;
                polled[num_polled].revents = 0;
                indices[num_polled] = i;
                num_polled++;
            }
        }

        int timeout = -1;
        POLL(polled, num_polled, timeout);

        for (int i = 0; i < num_polled; i++) {

            if (polled[i].fd == server->listen_fd || polled[i].fd == server->secure_fd) {

                bool secure = false;
                if (polled[i].fd == server->secure_fd)
                    secure = true;

                if ((polled[i].revents & POLLIN) && server->num_conns < MAX_CONNS) {

                    SOCKET_TYPE new_fd = accept(polled[i].fd, NULL, NULL);
                    if (new_fd == BAD_SOCKET) {
                        // TODO
                    }

                    int k = 0;
                    while (server->conns[k].used)
                        k++;

                    server->conns[k].used = true;
                    socket_accept(&server->conns[k].socket, secure ? &server->group : NULL, new_fd);

                    http_engine_init(&server->conns[k].engine, 0, server_memfunc, NULL);
                    server->num_conns++;
                }

            } else {

                int connidx = indices[i];
                Connection *conn = &server->conns[connidx];

                socket_update(&conn->socket);

                if (socket_state(&conn->socket) == SOCKET_STATE_ESTABLISHED_READY) {

                    switch (http_engine_state(&conn->engine)) {

                        int len;
                        char *buf;

                        case HTTP_ENGINE_STATE_SERVER_RECV_BUF:
                        buf = http_engine_recvbuf(&conn->engine, &len);
                        if (buf) {
                            int ret = socket_read(&conn->socket, buf, len);
                            http_engine_recvack(&conn->engine, ret);
                        }
                        break;

                        case HTTP_ENGINE_STATE_SERVER_SEND_BUF:
                        buf = http_engine_sendbuf(&conn->engine, &len);
                        if (buf) {
                            int ret = socket_write(&conn->socket, buf, len);
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
                        server->ready[tail] = connidx;
                        server->ready_count++;
                        break;

                        case HTTP_ENGINE_STATE_SERVER_CLOSED:
                        socket_close(&conn->socket);
                        break;

                        default:
                        break;

                    }
                }

                if (socket_state(&conn->socket) == SOCKET_STATE_DIED) {
                    socket_free(&conn->socket);
                    http_engine_free(&conn->engine);
                    conn->used = false;
                    server->num_conns--;
                }
            }
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

    if (state == HTTP_ENGINE_STATE_SERVER_CLOSED) {
        socket_close(&conn->socket);
        http_engine_free(&conn->engine);
        server->num_conns--;
    }
}