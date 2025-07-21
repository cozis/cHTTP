#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#define POLL WSAPoll
#endif

#ifdef __linux__
#include <poll.h>
#define POLL poll
#endif

#ifndef HTTP_AMALGAMATION
#include "client.h"
#include "engine.h"
#include "socket_pool.h"
#endif

#define CLIENT_MAX_CONNS 256

typedef enum {
    CLIENT_CONNECTION_FREE,
    CLIENT_CONNECTION_INIT,
    CLIENT_CONNECTION_INIT_ERROR,
    CLIENT_CONNECTION_WAIT,
    CLIENT_CONNECTION_DONE,
} ClientConnectionState;

typedef struct {
    ClientConnectionState state;
    uint16_t     gen;
    SocketHandle sock;
    HTTP_Engine  eng;
    bool         trace;
    void*        user_data;
} ClientConnection;

struct HTTP_Client {

    SocketPool *socket_pool;

    int num_conns;
    ClientConnection conns[CLIENT_MAX_CONNS];

    int ready_head;
    int ready_count;
    int ready[CLIENT_MAX_CONNS];
};

int http_global_init(void)
{
    int ret = socket_pool_global_init();
    if (ret < 0)
        return -1;
    return 0;
}

void http_global_free(void)
{
    socket_pool_global_free();
}

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

HTTP_Client *http_client_init(void)
{
    HTTP_Client *client = malloc(sizeof(HTTP_Client));
    if (client == NULL)
        return NULL;

    int max_socks = 100;
    SocketPool *socket_pool = socket_pool_init(HTTP_STR(""), 0, 0, max_socks, false, 0, HTTP_STR(""), HTTP_STR(""));
    if (socket_pool == NULL) {
        free(client);
        return NULL;
    }
    client->socket_pool = socket_pool;

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

    socket_pool_free(client->socket_pool);
    free(client);
}

int http_client_get_builder(HTTP_Client *client, HTTP_RequestBuilder *builder)
{
    if (client->num_conns == CLIENT_MAX_CONNS)
        return -1;

    int i = 0;
    while (client->conns[i].state != CLIENT_CONNECTION_FREE)
        i++;

    client->conns[i].sock = -1;
    client->conns[i].user_data = NULL;
    client->conns[i].trace = false;
    client->conns[i].state = CLIENT_CONNECTION_INIT;
    http_engine_init(&client->conns[i].eng, 1, client_memfunc, NULL);

    client->num_conns++;

    *builder = (HTTP_RequestBuilder) { client, i, client->conns[i].gen };
    return 0;
}

int http_client_wait(HTTP_Client *client, HTTP_Response **result, void **user_data)
{
    while (client->ready_count == 0) {

        SocketEvent event = socket_pool_wait(client->socket_pool);
        switch (event.type) {

            case SOCKET_EVENT_DIED:
            {
                ClientConnection *conn = event.user_data;
                conn->state = CLIENT_CONNECTION_DONE;

                int tail = (client->ready_head + client->ready_count) % CLIENT_MAX_CONNS;
                client->ready[tail] = conn - client->conns;
                client->ready_count++;
            }
            break;

            case SOCKET_EVENT_READY:
            {
                ClientConnection *conn = event.user_data;

                if (conn->sock == -1)
                    conn->sock = event.handle;

                HTTP_EngineState engine_state;
                engine_state = http_engine_state(&conn->eng);

                if (engine_state == HTTP_ENGINE_STATE_CLIENT_RECV_BUF) {
                    int len;
                    char *buf;
                    buf = http_engine_recvbuf(&conn->eng, &len);
                    if (buf) {
                        int ret = socket_pool_read(client->socket_pool, conn->sock, buf, len);
                        if (conn->trace)
                            print_bytes(HTTP_STR(">> "), (HTTP_String) { buf, ret });
                        http_engine_recvack(&conn->eng, ret);
                    }
                } else if (engine_state == HTTP_ENGINE_STATE_CLIENT_SEND_BUF) {
                    int len;
                    char *buf;
                    buf = http_engine_sendbuf(&conn->eng, &len);
                    if (buf) {
                        int ret = socket_pool_write(client->socket_pool, conn->sock, buf, len);
                        if (conn->trace)
                            print_bytes(HTTP_STR("<< "), (HTTP_String) { buf, ret });
                        http_engine_sendack(&conn->eng, ret);
                    }
                }

                engine_state = http_engine_state(&conn->eng);

                if (engine_state == HTTP_ENGINE_STATE_CLIENT_CLOSED ||
                    engine_state == HTTP_ENGINE_STATE_CLIENT_READY)
                    socket_pool_close(client->socket_pool, conn->sock);
            }
            break;

            case SOCKET_EVENT_ERROR:
            return -1;

            case SOCKET_EVENT_SIGNAL:
            return 1;
        }
    }

    int index = client->ready[client->ready_head];
    client->ready_head = (client->ready_head + 1) % CLIENT_MAX_CONNS;
    client->ready_count--;

    ClientConnection *conn = &client->conns[index];

    HTTP_Response *result2 = http_engine_getres(&conn->eng);

    if (result)
        *result = result2;

    if (user_data)
        *user_data = conn->user_data;

    if (result2 == NULL) {
        http_engine_free(&conn->eng);
        conn->state = CLIENT_CONNECTION_FREE;
        client->num_conns--;
    } else {
        result2->context = client;
    }

    return 0;
}

static ClientConnection *client_builder_to_conn(HTTP_RequestBuilder handle)
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

void http_request_builder_user_data(HTTP_RequestBuilder builder, void *user_data)
{
    ClientConnection *conn = client_builder_to_conn(builder);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT)
        return;

    conn->user_data = user_data;
}

void http_request_builder_trace(HTTP_RequestBuilder builder, bool trace)
{
    ClientConnection *conn = client_builder_to_conn(builder);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT)
        return;

    conn->trace = trace;
}

void http_request_builder_line(HTTP_RequestBuilder builder, HTTP_Method method, HTTP_String url)
{
    ClientConnection *conn = client_builder_to_conn(builder);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT)
        return;

    HTTP_Client *client = builder.data0;

    HTTP_URL parsed_url;
    int ret = http_parse_url(url.ptr, url.len, &parsed_url);
    if (ret != url.len) {
        conn->state = CLIENT_CONNECTION_INIT_ERROR;
        return;
    }

    bool secure = false;
    if (http_streq(parsed_url.scheme, HTTP_STR("https"))) {
        secure = true;
    } else if (!http_streq(parsed_url.scheme, HTTP_STR("http"))) {
        conn->state = CLIENT_CONNECTION_INIT_ERROR;
        return;
    }

    int port = parsed_url.authority.port;
    if (port == 0) {
        if (secure)
            port = 443;
        else
            port = 80;
    }

    switch (parsed_url.authority.host.mode) {
        case HTTP_HOST_MODE_IPV4: ret = socket_pool_connect_ipv4(client->socket_pool, secure, parsed_url.authority.host.ipv4, port, conn); break;
        case HTTP_HOST_MODE_IPV6: ret = socket_pool_connect_ipv6(client->socket_pool, secure, parsed_url.authority.host.ipv6, port, conn); break;
        case HTTP_HOST_MODE_NAME: ret = socket_pool_connect     (client->socket_pool, secure, parsed_url.authority.host.name, port, conn); break;
        case HTTP_HOST_MODE_VOID: ret = -1; return;
    }

    if (ret < 0) {
        conn->state = CLIENT_CONNECTION_INIT_ERROR;
        return;
    }

    http_engine_url(&conn->eng, method, url, 1);
}

void http_request_builder_header(HTTP_RequestBuilder handle, HTTP_String str)
{
    ClientConnection *conn = client_builder_to_conn(handle);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT)
        return;

    http_engine_header(&conn->eng, str);
}

void http_request_builder_body(HTTP_RequestBuilder handle, HTTP_String str)
{
    ClientConnection *conn = client_builder_to_conn(handle);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT)
        return;

    http_engine_body(&conn->eng, str);
}

void http_request_builder_submit(HTTP_RequestBuilder handle)
{
    HTTP_Client *client = handle.data0;
    ClientConnection *conn = client_builder_to_conn(handle);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT &&
        conn->state != CLIENT_CONNECTION_INIT_ERROR)
        return;

    // TODO: invalidate the handle

    if (conn->state == CLIENT_CONNECTION_INIT_ERROR) {

        conn->state = CLIENT_CONNECTION_DONE;

        int tail = (client->ready_head + client->ready_count) % CLIENT_MAX_CONNS;
        client->ready[tail] = conn - client->conns;
        client->ready_count++;

    } else {
        http_engine_done(&conn->eng);
        conn->state = CLIENT_CONNECTION_WAIT;
    }
}

void http_response_free(HTTP_Response *res)
{
    HTTP_Client *client = res->context;

    ClientConnection *conn = NULL;
    for (int i = 0, j = 0; j < client->num_conns; i++) {

        if (client->conns[i].state == CLIENT_CONNECTION_FREE)
            continue;
        j++;

        if (client->conns[i].state != CLIENT_CONNECTION_DONE)
            continue;

        if (http_engine_getres(&client->conns[i].eng) == res) {
            conn = &client->conns[i];
            break;
        }
    }

    HTTP_ASSERT(conn);

    http_engine_free(&conn->eng);
    conn->state = CLIENT_CONNECTION_FREE;
    client->num_conns--;
}

static HTTP_Client *default_client___; // TODO: deinitialize the default client when http_global_free is called

static HTTP_Client *get_default_client(void)
{
    if (default_client___ == NULL)
        default_client___ = http_client_init();
    return default_client___;
}

HTTP_Response *http_get(HTTP_String url, HTTP_String *headers, int num_headers)
{
    HTTP_Client *client = get_default_client();
    if (client == NULL)
        return NULL;

    HTTP_RequestBuilder builder;
    int ret = http_client_get_builder(client, &builder);
    if (ret < 0)
        return NULL;
    http_request_builder_line(builder, HTTP_METHOD_GET, url);
    for (int i = 0; i < num_headers; i++)
        http_request_builder_header(builder, headers[i]);
    http_request_builder_submit(builder);

    HTTP_Response *res;
    ret = http_client_wait(client, &res, NULL); // TODO: it's assumed there is only one request pending
    if (ret < 0)
        return NULL;

    return res;
}

HTTP_Response *http_post(HTTP_String url, HTTP_String *headers, int num_headers, HTTP_String body)
{
    HTTP_Client *client = get_default_client();
    if (client == NULL)
        return NULL;

    HTTP_RequestBuilder builder;
    int ret = http_client_get_builder(client, &builder);
    if (ret < 0)
        return NULL;
    http_request_builder_line(builder, HTTP_METHOD_POST, url);
    for (int i = 0; i < num_headers; i++)
        http_request_builder_header(builder, headers[i]);
    http_request_builder_body(builder, body);
    http_request_builder_submit(builder);

    HTTP_Response *res;
    ret = http_client_wait(client, &res, NULL); // TODO: it's assumed there is only one request pending
    if (ret < 0)
        return NULL;

    return res;
}