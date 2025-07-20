#include "client.h"
#include "socket.h"
#include "engine.h"
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>

// TODO
#include <stdio.h>
#define ERROR printf("error at %s:%d\n", __FILE__, __LINE__);

#define CLIENT_MAX_CONNS 256

typedef enum {
    CLIENT_CONNECTION_FREE,
    CLIENT_CONNECTION_INIT,
    CLIENT_CONNECTION_WAIT,
    CLIENT_CONNECTION_DONE,
} ClientConnectionState;

typedef struct {
    ClientConnectionState state;
    uint16_t        gen;
    Socket          socket;
    HTTP_Engine     engine;
    bool            trace;
} ClientConnection;

struct HTTP_Client {
    SocketGroup group;
    int num_conns;
    ClientConnection conns[CLIENT_MAX_CONNS];

    int ready_head;
    int ready_count;
    int ready[CLIENT_MAX_CONNS];
};

// Rename the memory function
static void* client_memfunc(HTTP_MemoryFuncTag tag, void *ptr, int len, void *data) {
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

void http_global_init(void)
{
    socket_global_init();
}

void http_global_free(void)
{
    socket_global_free();
}

HTTP_Client *http_client_init(void)
{
    HTTP_Client *client = malloc(sizeof(HTTP_Client));
    if (client == NULL)
        return NULL;

    if (socket_group_init(&client->group) < 0) {
        free(client);
        return NULL;
    }

    for (int i = 0; i < CLIENT_MAX_CONNS; i++) {
        client->conns[i].state = CLIENT_CONNECTION_FREE;
        client->conns[i].gen  = 1;
    }

    client->num_conns = 0;
    client->ready_head = 0;
    client->ready_count = 0;

    return client;
}

void http_client_free(HTTP_Client *client)
{
    for (int i = 0, j = 0; j < client->num_conns; i++) {

        if (client->conns[i].state == CLIENT_CONNECTION_FREE)
            continue;
        j++;

        // TODO
    }

    socket_group_free(&client->group);
    free(client);
}

int http_client_request(HTTP_Client *client, HTTP_RequestHandle *handle)
{
    if (client->num_conns == CLIENT_MAX_CONNS)
        return -1;

    int i = 0;
    while (client->conns[i].state != CLIENT_CONNECTION_FREE)
        i++;

    client->conns[i].trace = false;
    client->conns[i].state = CLIENT_CONNECTION_INIT;
    http_engine_init(&client->conns[i].engine, 1, client_memfunc, NULL);

    client->num_conns++;

    *handle = (HTTP_RequestHandle) { client, i, client->conns[i].gen };
    return 0;
}

static void client_connection_update(ClientConnection *conn)
{
    HTTP_ASSERT(conn->state == CLIENT_CONNECTION_WAIT);

    socket_update(&conn->socket);

    while (socket_state(&conn->socket) == SOCKET_STATE_ESTABLISHED_READY) {

        HTTP_EngineState engine_state;
        
        engine_state = http_engine_state(&conn->engine);

        if (engine_state == HTTP_ENGINE_STATE_CLIENT_RECV_BUF) {
            int len;
            char *buf;
            buf = http_engine_recvbuf(&conn->engine, &len);
            if (buf) {
                int ret = socket_read(&conn->socket, buf, len);
                if (conn->trace)
                    print_bytes(HTTP_STR(">> "), (HTTP_String) { buf, ret });
                http_engine_recvack(&conn->engine, ret);
            }
        } else if (engine_state == HTTP_ENGINE_STATE_CLIENT_SEND_BUF) {
            int len;
            char *buf;
            buf = http_engine_sendbuf(&conn->engine, &len);
            if (buf) {
                int ret = socket_write(&conn->socket, buf, len);
                if (conn->trace)
                    print_bytes(HTTP_STR("<< "), (HTTP_String) { buf, ret });
                http_engine_sendack(&conn->engine, ret);
            }
        }

        engine_state = http_engine_state(&conn->engine);

        if (engine_state == HTTP_ENGINE_STATE_CLIENT_CLOSED ||
            engine_state == HTTP_ENGINE_STATE_CLIENT_READY)
            socket_close(&conn->socket);
    }

    if (socket_state(&conn->socket) == SOCKET_STATE_DIED)
        conn->state = CLIENT_CONNECTION_DONE;
}

int http_client_wait(HTTP_Client *client, HTTP_RequestHandle *handle)
{
    while (client->ready_count == 0) {

        int num_polled = 0;
        int indices[CLIENT_MAX_CONNS];
        struct pollfd polled[CLIENT_MAX_CONNS];

        for (int i = 0, j = 0; j < client->num_conns; i++) {

            HTTP_ASSERT(i < CLIENT_MAX_CONNS);
            ClientConnection *conn = &client->conns[i];

            if (conn->state == CLIENT_CONNECTION_FREE)
                continue;
            j++;

            int events = 0;
            if (conn->state == CLIENT_CONNECTION_WAIT) {
                switch (conn->socket.event) {
                    case SOCKET_WANT_READ : events = POLLIN;  break;
                    case SOCKET_WANT_WRITE: events = POLLOUT; break;
                    case SOCKET_WANT_NONE : events = 0;       break;
                }
            }

            if (events) {
                indices[num_polled] = i;
                polled[num_polled].fd = conn->socket.fd;
                polled[num_polled].events = events;
                polled[num_polled].revents = 0;
                num_polled++;
            }
        }

        if (num_polled == 0)
            return -1;

        poll(polled, num_polled, -1);

        for (int i = 0; i < num_polled; i++) {

            int connidx = indices[i];
            ClientConnection *conn = &client->conns[connidx];

            if (conn->state != CLIENT_CONNECTION_WAIT)
                continue;

            if (polled[i].revents == 0)
                continue;

            // TODO: handle error revents

            client_connection_update(conn);

            if (conn->state == CLIENT_CONNECTION_DONE) {
                int tail = (client->ready_head + client->ready_count) % CLIENT_MAX_CONNS;
                client->ready[tail] = connidx;
                client->ready_count++;
            }
        }
    }

    int index = client->ready[client->ready_head];
    client->ready_head = (client->ready_head + 1) % CLIENT_MAX_CONNS;
    client->ready_count--;
    *handle = (HTTP_RequestHandle) { client, index, client->conns[index].gen };
    return 0;
}

static ClientConnection *handle2clientconn(HTTP_RequestHandle handle)
{
    if (handle.data0 == NULL)
        return NULL;

    HTTP_Client *client = handle.data0;

    if (handle.data1 >= CLIENT_MAX_CONNS)
        return NULL;

    ClientConnection *conn = &client->conns[handle.data1];

    if (handle.data2 != conn->gen)
        return NULL;

    return conn;
}

void http_request_trace(HTTP_RequestHandle handle, bool trace)
{
    ClientConnection *conn = handle2clientconn(handle);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT)
        return;

    conn->trace = trace;
}

void http_request_line(HTTP_RequestHandle handle, HTTP_Method method, HTTP_String url)
{
    ClientConnection *conn = handle2clientconn(handle);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT)
        return;

    HTTP_Client *client = handle.data0;

    HTTP_URL parsed_url;
    int ret = http_parse_url(url.ptr, url.len, &parsed_url);
    if (ret != url.len) {
        // TODO
        ERROR;
        return;
    }

    bool secure = false;
    if (http_streq(parsed_url.scheme, HTTP_STR("https"))) {
        secure = true;
    } else if (!http_streq(parsed_url.scheme, HTTP_STR("http"))) {
        // TODO
        ERROR;
        return;
    }

    int port = parsed_url.authority.port;
    if (port == 0) {
        if (secure)
            port = 443;
        else
            port = 80;
    }

    SocketGroup *group = secure ? &client->group : NULL;
    switch (parsed_url.authority.host.mode) {
        case HTTP_HOST_MODE_IPV4: socket_connect_ipv4(&conn->socket, group, parsed_url.authority.host.ipv4, port); break;
        case HTTP_HOST_MODE_IPV6: socket_connect_ipv6(&conn->socket, group, parsed_url.authority.host.ipv6, port); break;
        case HTTP_HOST_MODE_NAME: socket_connect     (&conn->socket, group, parsed_url.authority.host.name, port); break;

        case HTTP_HOST_MODE_VOID:
        // TODO
        ERROR;
        return;
    }

    http_engine_url(&conn->engine, method, url, 1);
}

void http_request_header(HTTP_RequestHandle handle, char *header, int len)
{
    ClientConnection *conn = handle2clientconn(handle);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT)
        return;

    http_engine_header(&conn->engine, header, len);
}

void http_request_body(HTTP_RequestHandle handle, char *body, int len)
{
    ClientConnection *conn = handle2clientconn(handle);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT)
        return;

    http_engine_body(&conn->engine, body, len);
}

void http_request_submit(HTTP_RequestHandle handle)
{
    ClientConnection *conn = handle2clientconn(handle);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT)
        return;

    http_engine_done(&conn->engine);
    conn->state = CLIENT_CONNECTION_WAIT;
}

HTTP_Response *http_request_result(HTTP_RequestHandle handle)
{
    ClientConnection *conn = handle2clientconn(handle);
    if (conn == NULL)
        return NULL;
    if (conn->state != CLIENT_CONNECTION_DONE)
        return NULL;
    HTTP_EngineState engine_state = http_engine_state(&conn->engine);
    if (engine_state != HTTP_ENGINE_STATE_CLIENT_READY)
        return NULL;
    return http_engine_getres(&conn->engine);
}

void http_request_free(HTTP_RequestHandle handle)
{
    HTTP_Client *client = handle.data0;
    ClientConnection *conn = handle2clientconn(handle);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_DONE)
        return;
    http_engine_free(&conn->engine);
    socket_free(&conn->socket);
    conn->state = CLIENT_CONNECTION_FREE;
    client->num_conns--;
}