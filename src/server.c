#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <poll.h>
#include <stdlib.h>
#include "engine.h"
#include "socket.h"
#include "server.h"

#define MAX_CONNS (1<<10)

typedef struct {
    bool        used;
    uint16_t    gen;
    Socket      socket;
    HTTP_Engine engine;
} Connection;

struct HTTP_Server {
    SocketGroup group;

    int listen_fd;
    int secure_fd;

    int num_conns;
    Connection conns[MAX_CONNS];

    int ready_head;
    int ready_count;
    int ready[MAX_CONNS];
};

static int listen_socket(HTTP_String addr, uint16_t port, bool reuse_addr, int backlog)
{
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0)
        return -1;

    {
        int flags = fcntl(listen_fd, F_GETFL, 0);
        if (flags < 0) {
            close(listen_fd);
            return -1;
        }

        if (fcntl(listen_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            close(listen_fd);
            return -1;
        }
    }

    if (reuse_addr) {
        int one = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    }

    struct in_addr addr_buf;
    if (addr.len == 0)
        addr_buf.s_addr = htonl(INADDR_ANY);
    else {

        _Static_assert(sizeof(struct in_addr) == sizeof(HTTP_IPv4));
        if (http_parse_ipv4(addr.ptr, addr.len, (HTTP_IPv4*) &addr_buf) < 0) {
            close(listen_fd);
            return -1;
        }
    }

    struct sockaddr_in bind_buf;
    bind_buf.sin_family = AF_INET;
    bind_buf.sin_addr   = addr_buf;
    bind_buf.sin_port   = htons(port);
    if (bind(listen_fd, (struct sockaddr*) &bind_buf, sizeof(bind_buf)) < 0) {
        close(listen_fd);
        return -1;
    }

    if (listen(listen_fd, backlog) < 0) {
        close(listen_fd);
        return -1;
    }

    return listen_fd;
}

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
        server->listen_fd = -1;
    else {
        server->listen_fd = listen_socket(addr, port, reuse_addr, backlog);
        if (server->listen_fd < 0) {
            free(server);
            return NULL;
        }
    }

    if (secure_port == 0)
        server->secure_fd = -1;
    else {

        if (socket_group_init_server(&server->group, cert_key, private_key) < 0) {
            close(server->listen_fd);
            free(server);
            return NULL;
        }

        server->secure_fd = listen_socket(addr, secure_port, reuse_addr, backlog);
        if (server->secure_fd < 0) {
            socket_group_free(&server->group);
            close(server->listen_fd);
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

    close(server->secure_fd);
    close(server->listen_fd);
    if (server->secure_fd != -1)
        socket_group_free(&server->group);
    free(server);
}

int http_server_website(HTTP_Server *server, HTTP_String domain, HTTP_String cert_file, HTTP_String key_file)
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

            if (server->listen_fd != -1) {
                polled[num_polled].fd = server->listen_fd;
                polled[num_polled].events = POLLIN;
                polled[num_polled].revents = 0;
                indices[num_polled] = -1;
                num_polled++;
            }

            if (server->secure_fd != -1) {
                polled[num_polled].fd = server->secure_fd;
                polled[num_polled].events = POLLIN;
                polled[num_polled].revents = 0;
                indices[num_polled] = -1;
                num_polled++;
            }
        }

        for (int i = 0, j = 0; i < server->num_conns; i++) {

            if (!server->conns[i].used)
                continue;
            j++;

            int events = 0;

            if (server->conns[i].socket.ssl_ctx)
                events = server->conns[i].socket.event;
            else {
                switch (http_engine_state(&server->conns[i].engine)) {
                    case HTTP_ENGINE_STATE_SERVER_RECV_BUF: events = POLLIN;  break;
                    case HTTP_ENGINE_STATE_SERVER_SEND_BUF: events = POLLOUT; break;
                    default:break;
                }
            }

            if (events) {
                polled[num_polled].fd = server->conns[i].socket.fd;
                polled[num_polled].events = events;
                polled[num_polled].revents = 0;
                indices[num_polled] = i;
                num_polled++;
            }
        }

        int timeout = -1;
        poll(polled, num_polled, timeout);

        for (int i = 0; i < num_polled; i++) {

            if (polled[i].fd == server->listen_fd || polled[i].fd == server->secure_fd) {

                bool secure = false;
                if (polled[i].fd == server->secure_fd)
                    secure = true;

                if ((polled[i].revents & POLLIN) && server->num_conns < MAX_CONNS) {

                    int new_fd = accept(polled[i].fd, NULL, NULL);

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

void http_response_header(HTTP_ResponseHandle res, const char *fmt, ...)
{
	Connection *conn = handle2conn(res);
	if (conn == NULL)
		return;

	va_list args;
	va_start(args, fmt);
	http_engine_header_fmt2(&conn->engine, fmt, args);
	va_end(args);
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