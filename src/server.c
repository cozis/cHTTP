
int http_server_init(HTTP_Server *server)
{
    server->num_conns = 0;
    for (int i = 0; i < HTTP_SERVER_CAPACITY; i++)
        server->conns[i].state = HTTP_SERVER_CONN_FREE;

    server->num_ready = 0;
    server->ready_head = 0;

    if (socket_manager_init(&server->sockets,
        &server->socket_pool, HTTP_SERVER_CAPACITY) < 0)
        return -1;
    return 0;
}

void http_server_free(HTTP_Server *server)
{
    socket_manager_free(&server->sockets);

    for (int i = 0, j = 0; j < server->num_conns; i++) {
        HTTP_ServerConn *conn = &server->conns[i];
        if (conn->state != HTTP_SERVER_CONN_FREE)
            continue;
        j++;

        http_server_conn_free(conn);
    }
}

int http_server_listen_tcp(HTTP_Server *server,
    String addr, Port port)
{
    if (socket_manager_listen_tcp(&server->sockets, addr, port) < 0)
        return -1;
    return 0;
}

int http_server_listen_tls(HTTP_Server *server,
    String addr, Port port, String cert_file_name,
    String key_file_name)
{
    if (socket_manager_listen_tls(&server->sockets, addr,
        port, cert_file_name, key_file_name) < 0)
        return -1;
    return 0;
}

int http_server_add_certificate(HTTP_Server *server,
    HTTP_String domain, HTTP_String cert_file, HTTP_String key_file)
{
    if (socket_manager_add_certificate(&server->sockets,
        domain, cert_file, key_file) < 0)
        return -1;
    return 0;
}

int http_server_wakeup(HTTP_Server *server)
{
    if (socket_manager_wakeup(&server->sockets) < 0)
        return -1;
    return 0;
}

int http_server_register_events(HTTP_Server *server,
    struct pollfd *polled, int max_polled)
{
    return socket_manager_register_events(&server->sockets, polled, max_polled);
}

// Look at the head of the input buffer to see if
// a request was buffered. If it was, change the
// connection's status to WAIT_STATUS and push it
// to the ready queue. If the request is invalid,
// close the socket.
static void
check_request_buffer(HTTP_Server *server, HTTP_ServerConn *conn)
{
    assert(conn->state == HTTP_SERVER_CONN_BUFFERING);

    ByteView src = byte_queue_read_buf(&conn->input);
    int ret = http_parse_request(src.ptr, src.len, &conn->request);
    if (ret < 0) {

        // Invalid request
        byte_queue_read_ack(&conn->input, 0);
        socket_close(&server->sockets, conn->handle);

    } else if (ret == 0) {

        // Still waiting
        byte_queue_read_ack(&conn->input, 0);

        // If the queue reached its limit and we still didn't receive
        // a complete request, abort the exchange.
        if (byte_queue_full(&conn->input))
            socket_close(&server->sockets, conn->handle);

    } else {

        // Ready
        assert(ret == 1);

        conn->state = HTTP_SERVER_CONN_STATUS;
        conn->request_len = ret;
        conn->response_offset = byte_queue_offset(&conn->output);

        // Push to the ready queue
        assert(server->num_ready < HTTP_SERVER_CAPACITY);
        int tail = (server->ready_head + server->num_ready) % HTTP_SERVER_CAPACITY;
        server->ready[tail] = conn - server->conns;
        server->num_ready++;
    }
}

bool http_server_next_request(HTTP_Server *server,
    HTTP_Request **request, HTTP_ResponseBuilder *builder)
{
    if (server->num_ready == 0)
        return false;

    HTTP_ServerConn *conn = &server->conns[server->ready_head];
    server->ready_head = (server->ready_head + 1) % HTTP_SERVER_CAPACITY;
    server->num_ready--;

    assert(conn->state == HTTP_SERVER_CONN_WAIT_STATUS);
    *request = &conn->request;
    *builder = (HTTP_ResponseBuilder) { server, conn - server->conns, conn->gen };
    return true;
}

int http_server_process_events(HTTP_Server *server,
    struct pollfd *polled, int num_polled)
{
    SocketEvent events[HTTP_SERVER_CAPACITY];
    int num_events = socket_manger_translate_events(&server->sockets, polled, num_polled);
    if (num_events < 0)
        return -1;

    for (int i = 0; i < num_events; i++) {

        HTTP_ServerConn *conn = events[i].user;

        if (events[i].type == SOCKET_EVENT_DISCONNECT) {

            http_server_conn_free(conn);
            server->num_conns--;

        } else if (events[i].type == SOCKET_EVENT_READY) {

            if (events[i].user == NULL) {

                if (server->num_conns == HTTP_SERVER_CAPACITY) {
                    socket_close(&server->sockets, events[i].handle);
                    continue;
                }

                int i = 0;
                while (server->conns[i].state != HTTP_SERVER_CONN_FREE) {
                    i++;
                    assert(i < HTTP_SERVER_CAPACITY);
                }

                conn = &server->conns[i];
                http_server_conn_init(conn, events[i].handle);
                server->num_conns++;

                socket_set_user(&server->sockets, events[i].handle, conn);
            }

            if (conn->state == HTTP_SERVER_CONN_BUFFERING) {

                int min_recv = 1<<10;
                byte_queue_write_setmincap(&conn->input, min_recv);

                // Note that it's extra important that we don't
                // buffer while the user is building the response.
                // If we did that, a resize would invalidate all
                // pointers on the parsed request structure.
                int num = 0;
                ByteView dst = byte_queue_write_buf(&conn->input);
                if (dst.len) num = socket_recv(&server->sockets, conn->handle, dst.ptr, dst.len);
                byte_queue_write_ack(&conn->input, num);

                if (byte_queue_error(&conn->output))
                    socket_close(&server->sockets, conn->handle);
                else
                    check_request_buffer(server, conn);

            } else if (conn->state == HTTP_SERVER_CONN_FLUSHING) {

                int num = 0;
                ByteView src = byte_queue_read_buf(&conn->output);
                if (src.len) num = socket_recv(&server->sockets, conn->handle, src.ptr, src.len);
                byte_queue_read_ack(&conn->output, num);

                if (byte_queue_error(&conn->output))
                    socket_close(&server->sockets, conn->handle);
                else if (byte_queue_empty(&conn->output)) {
                    // We finished sending the response. Now we can
                    // either close the connection or process a new
                    // buffered request.
                    if (conn->closing) {
                        socket_close(&server->sockets, conn->handle);
                    } else {
                        check_request_buffer(server, conn);
                    }
                }
            }
        }
    }

    return 0;
}

// Get a connection pointer from a response builder.
// If the builder is invalid, returns NULL.
// Note that only connections in the responding states
// can be returned, as any builder is invalidated by
// incrementing the connection's generation counter
// when a response is completed.
static HTTP_ServerConn*
builder_to_conn(HTTP_ResponseBuilder builder)
{
    HTTP_Server *server = builder.server;
    if (server == NULL)
        return NULL;

    if (server->index > HTTP_SERVER_CAPACITY)
        return NULL;

    HTTP_ServerConn *conn = server->conns[server->index];
    if (conn->gen != builder.gen)
        return NULL;

    return conn;
}

static void
write_status(HTTP_ServerConn *conn, int status)
{
    byte_queue_write(&conn->output, xxx);
}

void http_response_builder_status(HTTP_ResponseBuilder builder, int status)
{
    HTTP_ServerConn *conn = builder_to_conn(builder);
    if (conn == NULL)
        return;

    if (conn->state != HTTP_SERVER_CONN_WAIT_STATUS) {
        // Reset all response content and start from scrach.
        byte_queue_remove_from_offset(&conn->output, conn->response_offset);
        conn->state = HTTP_SERVER_CONN_WAIT_STATUS;
    }

    write_status(conn, status);

    conn->state = HTTP_SERVER_CONN_WAIT_HEADER;
}

void http_response_builder_header(HTTP_ResponseBuilder builder, String str)
{
    HTTP_ServerConn *conn = builder_to_conn(builder);
    if (conn == NULL)
        return;

    if (conn->state != HTTP_SERVER_CONN_WAIT_HEADER)
        return;

    byte_queue_write(&conn->output, xxx);
}

static void append_special_headers(HTTP_ServerConn *conn)
{
    // TODO
}

static void patch_special_headers(HTTP_ServerConn *conn)
{
    // TODO
}

void http_response_builder_body(HTTP_ResponseBuilder builder, String str)
{
    HTTP_ServerConn *conn = builder_to_conn(builder);
    if (conn == NULL)
        return;

    if (conn->state != HTTP_SERVER_CONN_WAIT_HEADER) {
        append_special_headers(conn);
        conn->state = HTTP_SERVER_CONN_WAIT_BODY;
    }

    if (conn->state != HTTP_SERVER_CONN_WAIT_BODY)
        return;

    byte_queue_write(&conn->output, str);
}

void http_response_builder_send(HTTP_ResponseBuilder builder, String str)
{
    HTTP_ServerConn *conn = builder_to_conn(builder);
    if (conn == NULL)
        return;

    if (conn->state == HTTP_SERVER_CONN_WAIT_STATUS) {
        write_status(conn, 500);
        conn->state = HTTP_SERVER_CONN_WAIT_HEADER;
    }

    if (conn->state == HTTP_SERVER_CONN_WAIT_HEADER) {
        append_special_headers(conn);
        conn->state = HTTP_SERVER_CONN_WAIT_BODY;
    }

    assert(conn->state == HTTP_SERVER_CONN_WAIT_BODY);
    patch_special_headers(conn);

    // Remove the buffered request
    byte_queue_read_ack(&conn->input, conn->request_len);

    conn->state = HTTP_SERVER_CONN_FLUSHING;
    conn->gen++;
}
