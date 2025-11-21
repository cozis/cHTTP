
static void http_client_conn_init(HTTP_ClientConn *conn,
    SocketHandle handle, uint32_t input_buffer_limit,
    uint32_t output_buffer_limit)
{
    conn->state = HTTP_CLIENT_CONN_WAIT_LINE;
    conn->handle = handle;
    conn->gen = 0;
    byte_queue_init(&conn->input, input_buffer_limit);
    byte_queue_init(&conn->output, output_buffer_limit);
}

static void http_client_conn_free(HTTP_ClientConn *conn)
{
    byte_queue_free(&conn->output);
    byte_queue_free(&conn->input);
}

int http_client_init(HTTP_Client *client)
{
    client->input_buffer_limit = 1<<20;
    client->output_buffer_limit = 1<<20;

    client->num_conns = 0;
    for (int i = 0; i < HTTP_CLIENT_CAPACITY; i++) {
        client->conns[i].state = HTTP_CLIENT_CONN_FREE;
        client->conns[i].gen = 0;
    }

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

void http_client_set_input_limit(HTTP_Client *client, uint32_t limit)
{
    client->input_buffer_limit = limit;
}

void http_client_set_output_limit(HTTP_Client *client, uint32_t limit)
{
    client->output_buffer_limit = limit;
}

int http_client_wakeup(HTTP_Client *client)
{
    if (socket_manager_wakeup(&client->sockets) < 0)
        return -1;
    return 0;
}

int http_client_register_events(HTTP_Client *client,
    EventRegister *reg)
{
    if (socket_manager_register_events(&client->sockets, reg) < 0)
        return -1;
    return 0;
}

// Get a connection pointer from a request builder.
// If the builder is invalid, returns NULL.
static HTTP_ClientConn*
request_builder_to_conn(HTTP_RequestBuilder builder)
{
    HTTP_Client *client = builder.client;
    if (client == NULL)
        return NULL;

    if (builder.index >= HTTP_CLIENT_CAPACITY)
        return NULL;

    HTTP_ClientConn *conn = &client->conns[builder.index];
    if (builder.gen != conn->gen)
        return NULL;

    return conn;
}

int http_client_get_builder(HTTP_Client *client,
    HTTP_Response *response, HTTP_RequestBuilder *builder)
{
    HTTP_ClientConn *conn = NULL;

    if (response != NULL && response->context != NULL) {
        // Reuse the connection from the previous response
        conn = (HTTP_ClientConn*) response->context;

        // Mark the response as freed
        response->context = NULL;

        // Reset the connection for a new request
        byte_queue_read_ack(&conn->input, byte_queue_read_buf(&conn->input).len);
        byte_queue_read_ack(&conn->output, byte_queue_read_buf(&conn->output).len);
        conn->state = HTTP_CLIENT_CONN_WAIT_LINE;

    } else {
        // Find a free connection slot
        if (client->num_conns == HTTP_CLIENT_CAPACITY)
            return -1;

        int i = 0;
        while (client->conns[i].state != HTTP_CLIENT_CONN_FREE)
            i++;

        conn = &client->conns[i];
        conn->state = HTTP_CLIENT_CONN_WAIT_LINE;
        conn->handle = SOCKET_HANDLE_INVALID;
        conn->client = client;
        byte_queue_init(&conn->input, client->input_buffer_limit);
        byte_queue_init(&conn->output, client->output_buffer_limit);
        client->num_conns++;
    }

    *builder = (HTTP_RequestBuilder) {
        client,
        conn - client->conns,
        conn->gen
    };

    return 0;
}

void http_request_builder_url(HTTP_RequestBuilder builder,
    HTTP_Method method, HTTP_String url)
{
    HTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return;

    if (conn->state != HTTP_CLIENT_CONN_WAIT_LINE)
        return;

    // Parse the URL to extract components
    HTTP_URL parsed_url;
    if (http_parse_url(url.ptr, url.len, &parsed_url) != 1)
        return;

    // Store method and parsed URL for connection establishment
    conn->method = method;
    conn->url = parsed_url;

    // Convert method enum to string
    const char *method_str;
    switch (method) {
        case HTTP_METHOD_GET:     method_str = "GET"; break;
        case HTTP_METHOD_HEAD:    method_str = "HEAD"; break;
        case HTTP_METHOD_POST:    method_str = "POST"; break;
        case HTTP_METHOD_PUT:     method_str = "PUT"; break;
        case HTTP_METHOD_DELETE:  method_str = "DELETE"; break;
        case HTTP_METHOD_CONNECT: method_str = "CONNECT"; break;
        case HTTP_METHOD_OPTIONS: method_str = "OPTIONS"; break;
        case HTTP_METHOD_TRACE:   method_str = "TRACE"; break;
        case HTTP_METHOD_PATCH:   method_str = "PATCH"; break;
        default: return;
    }

    // Build request line: METHOD path HTTP/1.1\r\n
    byte_queue_write_fmt(&conn->output, "%s %.*s HTTP/1.1\r\n",
        method_str,
        parsed_url.path.len, parsed_url.path.ptr);

    // Add Host header automatically
    byte_queue_write_fmt(&conn->output, "Host: %.*s",
        parsed_url.authority.host.text.len,
        parsed_url.authority.host.text.ptr);

    if (parsed_url.authority.port > 0) {
        byte_queue_write_fmt(&conn->output, ":%d", parsed_url.authority.port);
    }
    byte_queue_write(&conn->output, "\r\n", 2);

    conn->state = HTTP_CLIENT_CONN_WAIT_HEADER;
}

void http_request_builder_header(HTTP_RequestBuilder builder,
    HTTP_String str)
{
    HTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return;

    if (conn->state != HTTP_CLIENT_CONN_WAIT_HEADER)
        return;

    // Validate header: must contain a colon and no control characters
    bool has_colon = false;
    for (int i = 0; i < str.len; i++) {
        char c = str.ptr[i];
        if (c == ':')
            has_colon = true;
        // Reject control characters (especially \r and \n)
        if (c < 0x20 && c != '\t')
            return;
    }
    if (!has_colon)
        return;

    byte_queue_write(&conn->output, str.ptr, str.len);
    byte_queue_write(&conn->output, "\r\n", 2);
}

void http_request_builder_body(HTTP_RequestBuilder builder,
    HTTP_String str)
{
    HTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return;

    // Transition from WAIT_HEADER to WAIT_BODY if needed
    if (conn->state == HTTP_CLIENT_CONN_WAIT_HEADER) {
        // End headers section
        byte_queue_write(&conn->output, "\r\n", 2);
        conn->state = HTTP_CLIENT_CONN_WAIT_BODY;
    }

    if (conn->state != HTTP_CLIENT_CONN_WAIT_BODY)
        return;

    byte_queue_write(&conn->output, str.ptr, str.len);
}

int http_request_builder_send(HTTP_RequestBuilder builder)
{
    HTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return -1;

    // Finalize the request
    if (conn->state == HTTP_CLIENT_CONN_WAIT_HEADER) {
        // No body, just end headers
        byte_queue_write(&conn->output, "\r\n", 2);
    }

    // Establish connection if not already connected
    if (conn->handle == SOCKET_HANDLE_INVALID) {

        // Determine if connection should be secure
        bool secure = false;
        if (conn->url.scheme.len == 5 &&
            strncmp(conn->url.scheme.ptr, "https", 5) == 0) {
            secure = true;
        }

        // Prepare connection target
        ConnectTarget target;
        target.port = conn->url.authority.port;
        if (target.port <= 0)
            target.port = secure ? 443 : 80;

        // Set up target based on host type
        if (conn->url.authority.host.mode == HTTP_HOST_MODE_NAME) {
            target.type = CONNECT_TARGET_NAME;
            target.name = conn->url.authority.host.name;
        } else if (conn->url.authority.host.mode == HTTP_HOST_MODE_IPV4) {
            target.type = CONNECT_TARGET_IPV4;
            target.ipv4 = conn->url.authority.host.ipv4;
        } else if (conn->url.authority.host.mode == HTTP_HOST_MODE_IPV6) {
            target.type = CONNECT_TARGET_IPV6;
            target.ipv6 = conn->url.authority.host.ipv6;
        } else {
            // Invalid host mode - clean up connection
            http_client_conn_free(conn);
            conn->state = HTTP_CLIENT_CONN_FREE;
            conn->client->num_conns--;
            return -1;
        }

        if (socket_connect(&conn->client->sockets, 1, &target, secure, conn) < 0) {
            // Connection failed - clean up
            http_client_conn_free(conn);
            conn->state = HTTP_CLIENT_CONN_FREE;
            conn->client->num_conns--;
            return -1;
        }
    }

    conn->state = HTTP_CLIENT_CONN_FLUSHING;
    conn->gen++;

    return 0;
}

// Look at the input buffer to see if a complete response
// was buffered. If it was, change the connection's status
// to COMPLETE and push it to the ready queue.
static void
check_response_buffer(HTTP_Client *client, HTTP_ClientConn *conn)
{
    assert(conn->state == HTTP_CLIENT_CONN_BUFFERING);

    ByteView src = byte_queue_read_buf(&conn->input);
    int ret = http_parse_response(src.ptr, src.len, &conn->response);

    if (ret < 0) {
        // Invalid response
        byte_queue_read_ack(&conn->input, 0);
        socket_close(&client->sockets, conn->handle);

    } else if (ret == 0) {
        // Still waiting
        byte_queue_read_ack(&conn->input, 0);

        // If the queue reached its limit and we still didn't receive
        // a complete response, abort the exchange.
        if (byte_queue_full(&conn->input))
            socket_close(&client->sockets, conn->handle);

    } else {
        // Ready
        assert(ret == 1);

        conn->state = HTTP_CLIENT_CONN_COMPLETE;
        conn->response.context = conn;

        // Push to the ready queue
        assert(client->num_ready < HTTP_CLIENT_CAPACITY);
        int tail = (client->ready_head + client->num_ready) % HTTP_CLIENT_CAPACITY;
        client->ready[tail] = conn - client->conns;
        client->num_ready++;
    }
}

int http_client_process_events(HTTP_Client *client,
    EventRegister *reg)
{
    SocketEvent events[HTTP_CLIENT_CAPACITY];
    int num_events = socket_manager_translate_events(
        &client->sockets, events, reg);
    if (num_events < 0)
        return -1;

    for (int i = 0; i < num_events; i++) {

        HTTP_ClientConn *conn = events[i].user;

        if (events[i].type == SOCKET_EVENT_DISCONNECT) {

            if (conn != NULL) {
                http_client_conn_free(conn);
                conn->state = HTTP_CLIENT_CONN_FREE;
                client->num_conns--;
            }

        } else if (events[i].type == SOCKET_EVENT_READY) {

            if (conn == NULL)
                continue;

            // Store the handle if this is a new connection
            if (conn->handle == SOCKET_HANDLE_INVALID)
                conn->handle = events[i].handle;

            if (conn->state == HTTP_CLIENT_CONN_FLUSHING) {

                // Send request data
                int num = 0;
                ByteView src = byte_queue_read_buf(&conn->output);
                if (src.len)
                    num = socket_send(&client->sockets, conn->handle, src.ptr, src.len);
                byte_queue_read_ack(&conn->output, num);

                if (byte_queue_error(&conn->output)) {
                    socket_close(&client->sockets, conn->handle);
                } else if (byte_queue_empty(&conn->output)) {
                    // Request fully sent, now wait for response
                    conn->state = HTTP_CLIENT_CONN_BUFFERING;
                }

            } else if (conn->state == HTTP_CLIENT_CONN_BUFFERING) {

                // Receive response data
                int min_recv = 1<<10;
                byte_queue_write_setmincap(&conn->input, min_recv);

                int num = 0;
                ByteView dst = byte_queue_write_buf(&conn->input);
                if (dst.len)
                    num = socket_recv(&client->sockets, conn->handle, dst.ptr, dst.len);
                byte_queue_write_ack(&conn->input, num);

                if (byte_queue_error(&conn->input))
                    socket_close(&client->sockets, conn->handle);
                else
                    check_response_buffer(client, conn);
            }
        }
    }

    return 0;
}

bool http_client_next_response(HTTP_Client *client,
    HTTP_Response **response)
{
    if (client->num_ready == 0)
        return false;

    HTTP_ClientConn *conn = &client->conns[client->ready[client->ready_head]];
    client->ready_head = (client->ready_head + 1) % HTTP_CLIENT_CAPACITY;
    client->num_ready--;

    assert(conn->state == HTTP_CLIENT_CONN_COMPLETE);
    *response = &conn->response;
    return true;
}

void http_free_response(HTTP_Response *response)
{
    if (response == NULL || response->context == NULL)
        return;

    HTTP_ClientConn *conn = (HTTP_ClientConn*) response->context;

    // Free the connection resources
    http_client_conn_free(conn);
    conn->state = HTTP_CLIENT_CONN_FREE;
    conn->client->num_conns--;

    // Mark response as freed
    response->context = NULL;
}
