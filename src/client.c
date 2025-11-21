
void http_client_conn_init(HTTP_ClientConn *conn)
{
    // TODO
}

void http_client_conn_free(HTTP_ClientConn *conn)
{
    // TODO
}

int http_client_init(HTTP_Client *client)
{
    client->num_conns = 0;
    for (int i = 0; i < HTTP_CLIENT_CAPACITY; i++)
        client->conns[i].state = HTTP_CLIENT_CONN_FREE;

    client->num_ready = 0;
    client->ready_head = 0;

    if (socket_manager_init(&client->sockets,
        client->socket_pool, HTTP_CLIENT_CAPACITY) < 0)
        return -1;
    return 0;
}

void http_client_free(HTTP_Client *client)
{
    socket_manager_free(&client->sockets);

    for (int i = 0, j = 0; j < client->num_conns; i++) {
        HTTP_ClientConn *conn = &client->conns[i];
        if (conn->state == HTTP_CLIENT_CONN_FREE)
            continue;
        j++;

        http_client_conn_free(conn);
    }
}

int http_client_wakeup(HTTP_Client *client)
{
    if (socket_manager_wakeup(&client->sockets) < 0)
        return -1;
    return 0;
}

int http_client_get_builder(HTTP_Client *client,
    HTTP_Response *response, HTTP_RequestBuilder *builder)
{
    // TODO
}

void http_request_builder_url(HTTP_RequestBuilder builder,
    HTTP_String url)
{
    // TODO
}

void http_request_builder_header(HTTP_RequestBuilder builder,
    HTTP_String str)
{
    // TODO
}

void http_request_builder_body(HTTP_RequestBuilder builder,
    HTTP_String str)
{
    // TODO
}

int http_request_builder_send(HTTP_RequestBuilder builder)
{
    // TODO
}

int http_client_register_events(HTTP_Client *client,
    EventRegister *reg)
{
    if (socket_manager_register_events(&client->sockets, reg) < 0)
        return -1;
    return 0;
}

int http_client_process_events(HTTP_Client *client,
    EventRegister *reg)
{
    SocketEvent events[HTTP_CLIENT_CAPACITY];
    int num_events = socket_manager_translate_events(
        &client->sockets, events, reg);

    for (int i = 0; i < num_events; i++) {

        if (events[i].type == SOCKET_EVENT_DISCONNECT) {

            // TODO

        } else if (events[i].type == SOCKET_EVENT_READY) {

            // TODO
        }

        // TODO
    }

    return 0;
}

bool http_client_next_response(HTTP_Client *client,
    HTTP_Response **response)
{
    if (client->num_ready == 0)
        return false;

    HTTP_ClientConn *conn = &client->conns[client->ready_head];
    client->ready_head = (client->ready_head + 1) % HTTP_CLIENT_CAPACITY;
    client->num_ready--;

    assert(conn->state == HTTP_CLIENT_CONN_COMPLETE);
    *response = &conn->response;
    return true;
}

void http_free_response(HTTP_Response *res)
{
    // TODO
}
