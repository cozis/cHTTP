
static void http_server_conn_init(HTTP_ServerConn *conn,
    SocketHandle handle, uint32_t input_buffer_limit,
    uint32_t output_buffer_limit)
{
    conn->state = HTTP_SERVER_CONN_BUFFERING;
    conn->handle = handle;
    conn->closing = false;
    byte_queue_init(&conn->input, input_buffer_limit);
    byte_queue_init(&conn->output, output_buffer_limit);
}

static void http_server_conn_free(HTTP_ServerConn *conn)
{
    byte_queue_free(&conn->output);
    byte_queue_free(&conn->input);
}

int http_server_init(HTTP_Server *server)
{
    server->input_buffer_limit = 1<<20;
    server->output_buffer_limit = 1<<20;

    server->trace_bytes = false;
    server->reuse_addr = false;
    server->backlog = 32;

    server->num_conns = 0;
    for (int i = 0; i < HTTP_SERVER_CAPACITY; i++) {
        server->conns[i].state = HTTP_SERVER_CONN_FREE;
        server->conns[i].gen = 0;
    }

    server->num_ready = 0;
    server->ready_head = 0;

    return socket_manager_init(&server->sockets,
        server->socket_pool, HTTP_SERVER_CAPACITY);
}

void http_server_free(HTTP_Server *server)
{
    socket_manager_free(&server->sockets);

    for (int i = 0, j = 0; j < server->num_conns; i++) {
        HTTP_ServerConn *conn = &server->conns[i];
        if (conn->state == HTTP_SERVER_CONN_FREE)
            continue;
        j++;

        http_server_conn_free(conn);
    }
}

void http_server_set_input_limit(HTTP_Server *server, uint32_t limit)
{
    server->input_buffer_limit = limit;
}

void http_server_set_output_limit(HTTP_Server *server, uint32_t limit)
{
    server->output_buffer_limit = limit;
}

void http_server_set_trace_bytes(HTTP_Server *server, bool value)
{
    server->trace_bytes = value;
}

void http_server_set_reuse_addr(HTTP_Server *server, bool reuse)
{
    server->reuse_addr = reuse;
}

void http_server_set_backlog(HTTP_Server *server, int backlog)
{
    server->backlog = backlog;
}

int http_server_listen_tcp(HTTP_Server *server,
    HTTP_String addr, Port port)
{
    return socket_manager_listen_tcp(&server->sockets,
        addr, port, server->backlog, server->reuse_addr);
}

int http_server_listen_tls(HTTP_Server *server,
    HTTP_String addr, Port port, HTTP_String cert_file_name,
    HTTP_String key_file_name)
{
    return socket_manager_listen_tls(&server->sockets,
        addr, port, server->backlog, server->reuse_addr,
        cert_file_name, key_file_name);
}

int http_server_add_certificate(HTTP_Server *server,
    HTTP_String domain, HTTP_String cert_file, HTTP_String key_file)
{
    return socket_manager_add_certificate(&server->sockets,
        domain, cert_file, key_file);
}

int http_server_wakeup(HTTP_Server *server)
{
    return socket_manager_wakeup(&server->sockets);
}

void http_server_register_events(HTTP_Server *server,
    EventRegister *reg)
{
    socket_manager_register_events(&server->sockets, reg);
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
        assert(ret > 0);

        // Stop receiving I/O events while we are building the response
        socket_silent(&server->sockets, conn->handle, true);

        conn->state = HTTP_SERVER_CONN_WAIT_STATUS;
        conn->request_len = ret;
        conn->response_offset = byte_queue_offset(&conn->output);

        // Push to the ready queue
        assert(server->num_ready < HTTP_SERVER_CAPACITY);
        int tail = (server->ready_head + server->num_ready) % HTTP_SERVER_CAPACITY;
        server->ready[tail] = conn - server->conns;
        server->num_ready++;
    }
}

static void
http_server_conn_process_events(HTTP_Server *server, HTTP_ServerConn *conn)
{
    if (conn->state == HTTP_SERVER_CONN_FLUSHING) {

        ByteView src = byte_queue_read_buf(&conn->output);

        int num = 0;
        if (src.len)
            num = socket_send(&server->sockets, conn->handle, src.ptr, src.len);

        if (server->trace_bytes)
            print_bytes(HTTP_STR("<< "), (HTTP_String) { src.ptr, num });

        byte_queue_read_ack(&conn->output, num);

        if (byte_queue_error(&conn->output)) {
            socket_close(&server->sockets, conn->handle);
            return;
        }

        if (byte_queue_empty(&conn->output)) {
            // We finished sending the response. Now we can
            // either close the connection or process a new
            // buffered request.
            if (conn->closing) {
                socket_close(&server->sockets, conn->handle);
                return;
            }
            conn->state = HTTP_SERVER_CONN_BUFFERING;
        }
    }

    if (conn->state == HTTP_SERVER_CONN_BUFFERING) {

        int min_recv = 1<<10;
        byte_queue_write_setmincap(&conn->input, min_recv);

        // Note that it's extra important that we don't
        // buffer while the user is building the response.
        // If we did that, a resize would invalidate all
        // pointers on the parsed request structure.
        ByteView dst = byte_queue_write_buf(&conn->input);

        int num = 0;
        if (dst.len)
            num = socket_recv(&server->sockets, conn->handle, dst.ptr, dst.len);

        if (server->trace_bytes)
            print_bytes(HTTP_STR(">> "), (HTTP_String) { dst.ptr, num });

        byte_queue_write_ack(&conn->input, num);

        if (byte_queue_error(&conn->input)) {
            socket_close(&server->sockets, conn->handle);
        } else {
            check_request_buffer(server, conn);
        }
    }
}

void http_server_process_events(HTTP_Server *server,
    EventRegister reg)
{
    SocketEvent events[HTTP_SERVER_CAPACITY];
    int num_events = socket_manager_translate_events(&server->sockets, events, reg);

    for (int i = 0; i < num_events; i++) {

        HTTP_ServerConn *conn = events[i].user;

        if (events[i].type == SOCKET_EVENT_DISCONNECT) {

            http_server_conn_free(conn); // TODO: what if this was in the ready queue?
            server->num_conns--;

        } else if (events[i].type == SOCKET_EVENT_READY) {

            if (events[i].user == NULL) {

                if (server->num_conns == HTTP_SERVER_CAPACITY) {
                    socket_close(&server->sockets, events[i].handle);
                    continue;
                }

                int j = 0;
                while (server->conns[j].state != HTTP_SERVER_CONN_FREE) {
                    j++;
                    assert(i < HTTP_SERVER_CAPACITY);
                }

                conn = &server->conns[j];
                http_server_conn_init(conn,
                    events[i].handle,
                    server->input_buffer_limit,
                    server->output_buffer_limit);
                server->num_conns++;

                socket_set_user(&server->sockets, events[i].handle, conn);
            }

            while (socket_ready(&server->sockets, events[i].handle)
                && conn->state != HTTP_SERVER_CONN_WAIT_STATUS)
                http_server_conn_process_events(server, conn);
        }
    }
}

bool http_server_next_request(HTTP_Server *server,
    HTTP_Request **request, HTTP_ResponseBuilder *builder)
{
    if (server->num_ready == 0)
        return false;

    HTTP_ServerConn *conn = &server->conns[server->ready[server->ready_head]];
    server->ready_head = (server->ready_head + 1) % HTTP_SERVER_CAPACITY;
    server->num_ready--;

    assert(conn->state == HTTP_SERVER_CONN_WAIT_STATUS);
    *request = &conn->request;
    *builder = (HTTP_ResponseBuilder) { server, conn - server->conns, conn->gen };
    return true;
}

void http_server_wait_request(HTTP_Server *server,
    HTTP_Request **request, HTTP_ResponseBuilder *builder)
{
    for (;;) {
        void *ptrs[HTTP_SERVER_POLL_CAPACITY];
        struct pollfd polled[HTTP_SERVER_POLL_CAPACITY];

        EventRegister reg = { ptrs, polled, 0 };
        http_server_register_events(server, &reg);

        if (reg.num_polled > 0)
            POLL(reg.polled, reg.num_polled, -1);

        http_server_process_events(server, reg);

        if (http_server_next_request(server, request, builder))
            break;
    }
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

    if (builder.index > HTTP_SERVER_CAPACITY)
        return NULL;

    HTTP_ServerConn *conn = &server->conns[builder.index];
    if (builder.gen != conn->gen)
        return NULL;

    return conn;
}

static const char*
get_status_text(int code)
{
	switch(code) {

		case 100: return "Continue";
		case 101: return "Switching Protocols";
		case 102: return "Processing";

		case 200: return "OK";
		case 201: return "Created";
		case 202: return "Accepted";
		case 203: return "Non-Authoritative Information";
		case 204: return "No Content";
		case 205: return "Reset Content";
		case 206: return "Partial Content";
		case 207: return "Multi-Status";
		case 208: return "Already Reported";

		case 300: return "Multiple Choices";
		case 301: return "Moved Permanently";
		case 302: return "Found";
		case 303: return "See Other";
		case 304: return "Not Modified";
		case 305: return "Use Proxy";
		case 306: return "Switch Proxy";
		case 307: return "Temporary Redirect";
		case 308: return "Permanent Redirect";

		case 400: return "Bad Request";
		case 401: return "Unauthorized";
		case 402: return "Payment Required";
		case 403: return "Forbidden";
		case 404: return "Not Found";
		case 405: return "Method Not Allowed";
		case 406: return "Not Acceptable";
		case 407: return "Proxy Authentication Required";
		case 408: return "Request Timeout";
		case 409: return "Conflict";
		case 410: return "Gone";
		case 411: return "Length Required";
		case 412: return "Precondition Failed";
		case 413: return "Request Entity Too Large";
		case 414: return "Request-URI Too Long";
		case 415: return "Unsupported Media Type";
		case 416: return "Requested Range Not Satisfiable";
		case 417: return "Expectation Failed";
		case 418: return "I'm a teapot";
		case 420: return "Enhance your calm";
		case 422: return "Unprocessable Entity";
		case 426: return "Upgrade Required";
		case 429: return "Too many requests";
		case 431: return "Request Header Fields Too Large";
		case 449: return "Retry With";
		case 451: return "Unavailable For Legal Reasons";

		case 500: return "Internal Server Error";
		case 501: return "Not Implemented";
		case 502: return "Bad Gateway";
		case 503: return "Service Unavailable";
		case 504: return "Gateway Timeout";
		case 505: return "HTTP Version Not Supported";
		case 509: return "Bandwidth Limit Exceeded";
	}
	return "???";
}

static void
write_status(HTTP_ServerConn *conn, int status)
{
    byte_queue_write_fmt(&conn->output,
		"HTTP/1.1 %d %s\r\n",
		status, get_status_text(status));
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

static bool is_header_valid(HTTP_String str)
{
    bool has_colon = false;
    for (int i = 0; i < str.len; i++) {
        char c = str.ptr[i];
        if (c == ':')
            has_colon = true;
        // Reject control characters (especially \r and \n)
        if (c < 0x20 && c != '\t')
            return false;
    }
    return has_colon;
}

void http_response_builder_header(HTTP_ResponseBuilder builder, HTTP_String str)
{
    HTTP_ServerConn *conn = builder_to_conn(builder);
    if (conn == NULL)
        return;

    if (conn->state != HTTP_SERVER_CONN_WAIT_HEADER)
        return;

    // Header must contain a colon and no control characters
    // to prevent HTTP response splitting attacks
    if (!is_header_valid(str)) return; // Silently drop it

	byte_queue_write(&conn->output, str.ptr, str.len);
	byte_queue_write(&conn->output, "\r\n", 2);
}

static void append_special_headers(HTTP_ServerConn *conn)
{
    HTTP_String s;

    if (conn->closing) {
        s = HTTP_STR("Connection: Close\r\n");
        byte_queue_write(&conn->output, s.ptr, s.len);
    } else {
        s = HTTP_STR("Connection: Keep-Alive\r\n");
        byte_queue_write(&conn->output, s.ptr, s.len);
    }

    s = HTTP_STR("Content-Length: ");
    byte_queue_write(&conn->output, s.ptr, s.len);

    conn->content_length_value_offset = byte_queue_offset(&conn->output);

    #define TEN_SPACES "          "
    _Static_assert(sizeof(TEN_SPACES) == 10+1);

    s = HTTP_STR(TEN_SPACES "\r\n");
    byte_queue_write(&conn->output, s.ptr, s.len);

    byte_queue_write(&conn->output, "\r\n", 2);
	conn->content_length_offset = byte_queue_offset(&conn->output);
}

static void patch_special_headers(HTTP_ServerConn *conn)
{
    int content_length = byte_queue_size_from_offset(&conn->output, conn->content_length_offset);

    char tmp[11];
    int len = snprintf(tmp, sizeof(tmp), "%d", content_length);
    assert(len > 0 && len < 11);

    byte_queue_patch(&conn->output, conn->content_length_value_offset, tmp, len);
}

void http_response_builder_body(HTTP_ResponseBuilder builder, HTTP_String str)
{
    HTTP_ServerConn *conn = builder_to_conn(builder);
    if (conn == NULL)
        return;

    if (conn->state == HTTP_SERVER_CONN_WAIT_HEADER) {
        append_special_headers(conn);
        conn->state = HTTP_SERVER_CONN_WAIT_BODY;
    }

    if (conn->state != HTTP_SERVER_CONN_WAIT_BODY)
        return;

    byte_queue_write(&conn->output, str.ptr, str.len);
}

void http_response_builder_body_cap(HTTP_ResponseBuilder builder, int cap)
{
    HTTP_ServerConn *conn = builder_to_conn(builder);
    if (conn == NULL)
        return;

    if (conn->state == HTTP_SERVER_CONN_WAIT_HEADER) {
        append_special_headers(conn);
        conn->state = HTTP_SERVER_CONN_WAIT_BODY;
    }

    if (conn->state != HTTP_SERVER_CONN_WAIT_BODY)
        return;

    byte_queue_write_setmincap(&conn->output, cap);
}

char *http_response_builder_body_buf(HTTP_ResponseBuilder builder, int *cap)
{
    HTTP_ServerConn *conn = builder_to_conn(builder);
    if (conn == NULL)
        return NULL;

    if (conn->state == HTTP_SERVER_CONN_WAIT_HEADER) {
        append_special_headers(conn);
        conn->state = HTTP_SERVER_CONN_WAIT_BODY;
    }

    if (conn->state != HTTP_SERVER_CONN_WAIT_BODY)
        return NULL;

    ByteView tmp = byte_queue_write_buf(&conn->output);
    *cap = tmp.len;
    return tmp.ptr;
}

void http_response_builder_body_ack(HTTP_ResponseBuilder builder, int num)
{
    HTTP_ServerConn *conn = builder_to_conn(builder);
    if (conn == NULL)
        return;

    if (conn->state != HTTP_SERVER_CONN_WAIT_BODY)
        return;

    byte_queue_write_ack(&conn->output, num);
}

void http_response_builder_send(HTTP_ResponseBuilder builder)
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

    // Enable back I/O events
    socket_silent(&builder.server->sockets, conn->handle, false);

    http_server_conn_process_events(builder.server, conn);
}
