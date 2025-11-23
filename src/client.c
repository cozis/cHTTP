
static void http_client_conn_free(HTTP_ClientConn *conn)
{
    byte_queue_free(&conn->output);
    byte_queue_free(&conn->input);
}

int http_client_init(HTTP_Client *client)
{
    client->input_buffer_limit = 1<<20;
    client->output_buffer_limit = 1<<20;

    client->cookie_jar.count = 0;

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

    for (int i = 0; i < client->cookie_jar.count; i++)
        free(client->cookie_jar.items[i].name.ptr);

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

HTTP_RequestBuilder http_client_get_builder(HTTP_Client *client)
{
    // Find a free connection slot
    if (client->num_conns == HTTP_CLIENT_CAPACITY)
        return (HTTP_RequestBuilder) { NULL, -1, -1 };

    int i = 0;
    while (client->conns[i].state != HTTP_CLIENT_CONN_FREE) {
        i++;
        assert(i < HTTP_CLIENT_CAPACITY);
    }
    client->num_conns++;

    client->conns[i].state = HTTP_CLIENT_CONN_WAIT_LINE;
    client->conns[i].handle = SOCKET_HANDLE_INVALID;
    client->conns[i].client = client;
    client->conns[i].user = NULL;
    client->conns[i].trace_bytes = false;
    byte_queue_init(&client->conns[i].input,  client->input_buffer_limit);
    byte_queue_init(&client->conns[i].output, client->output_buffer_limit);

    return (HTTP_RequestBuilder) { client, i, client->conns[i].gen };
}

// TODO: test this function
static bool is_subdomain(HTTP_String domain, HTTP_String subdomain)
{
    if (http_streq(domain, subdomain))
        return true; // Exact match

    if (domain.len > subdomain.len)
        return false;

    HTTP_String subdomain_suffix = {
        subdomain.ptr + subdomain.len - domain.len,
        domain.len
    };
    if (subdomain_suffix.ptr[-1] != '.' || !http_streq(domain, subdomain_suffix))
        return false;

    return true;
}

// TODO: test this function
static bool is_subpath(HTTP_String path, HTTP_String subpath)
{
    if (path.len > subpath.len)
        return false;

    if (subpath.len != path.len && subpath.ptr[path.len] != '/')
        return false;

    subpath.len = path.len;
    return http_streq(path, subpath);
}

static bool should_send_cookie(HTTP_CookieJarEntry entry, HTTP_URL url)
{
    // TODO: If the cookie is expired, ignore it regardless

    if (entry.exact_domain) {
        // Cookie domain and URL domain must match exactly
        if (!http_streq(entry.domain, url.authority.host.text))
            return false;
    } else {
        // The URL's domain must match or be a subdomain of the cookie's domain
        if (!is_subdomain(entry.domain, url.authority.host.text))
            return false;
    }

    if (entry.exact_path) {
        // Cookie path and URL path must match exactly
        if (!http_streq(entry.path, url.path))
            return false;
    } else {
        if (!is_subpath(entry.path, url.path))
            return false;
    }

    if (entry.secure) {
        if (!http_streq(url.scheme, HTTP_STR("https")))
            return false; // Cookie was marked as secure but the target URL is not HTTPS
    }

    return true;
}

static HTTP_String get_method_string(HTTP_Method method)
{
    switch (method) {
        case HTTP_METHOD_GET    : return HTTP_STR("GET");
        case HTTP_METHOD_HEAD   : return HTTP_STR("HEAD");
        case HTTP_METHOD_POST   : return HTTP_STR("POST");
        case HTTP_METHOD_PUT    : return HTTP_STR("PUT");
        case HTTP_METHOD_DELETE : return HTTP_STR("DELETE");
        case HTTP_METHOD_CONNECT: return HTTP_STR("CONNECT");
        case HTTP_METHOD_OPTIONS: return HTTP_STR("OPTIONS");
        case HTTP_METHOD_TRACE  : return HTTP_STR("TRACE");
        case HTTP_METHOD_PATCH  : return HTTP_STR("PATCH");
    }
    return HTTP_STR("???");
}

void http_request_builder_set_user(HTTP_RequestBuilder builder, void *user)
{
    HTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return; // Invalid builder

    conn->user = user;
}

void http_request_builder_set_trace_bytes(HTTP_RequestBuilder builder, bool trace_bytes)
{
    HTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return; // Invalid builder

    conn->trace_bytes = trace_bytes;
}

void http_request_builder_url(HTTP_RequestBuilder builder,
    HTTP_Method method, HTTP_String url)
{
    HTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return; // Invalid builder

    if (conn->state != HTTP_CLIENT_CONN_WAIT_LINE)
        return; // Request line already written

    // Allocate a copy of the URL string so the parsed
    // URL pointers remain valid
    char *url_copy = malloc(url.len);
    if (url_copy == NULL) {
        conn->state = HTTP_CLIENT_CONN_COMPLETE;
        conn->result = -1;
        return;
    }
    memcpy(url_copy, url.ptr, url.len);

    conn->url_buffer.ptr = url_copy;
    conn->url_buffer.len = url.len;

    // Parse the copied URL (all url.* pointers will reference url_buffer)
    if (http_parse_url(conn->url_buffer.ptr, conn->url_buffer.len, &conn->url) < 0) {
        conn->state = HTTP_CLIENT_CONN_COMPLETE;
        conn->result = -1;
        return;
    }

    if (!http_streq(conn->url.scheme, HTTP_STR("http")) &&
        !http_streq(conn->url.scheme, HTTP_STR("https"))) {
        conn->state = HTTP_CLIENT_CONN_COMPLETE;
        conn->result = -1;
        return;
    }

    // Write method
    HTTP_String method_str = get_method_string(method);
    byte_queue_write(&conn->output, method_str.ptr, method_str.len);

    byte_queue_write(&conn->output, conn->url.path.ptr, conn->url.path.len);

    HTTP_String query = conn->url.query;
    if (query.len > 0) {
        byte_queue_write(&conn->output, "?", 1);
        byte_queue_write(&conn->output, query.ptr, query.len);
    }

    HTTP_String version = HTTP_STR("HTTP/1.1");
    byte_queue_write(&conn->output, version.ptr, version.len);

    byte_queue_write(&conn->output, "\r\n", 2);

    // Add Host header automatically
    byte_queue_write_fmt(&conn->output, "Host: %.*s",
        conn->url.authority.host.text.len,
        conn->url.authority.host.text.ptr);
    if (conn->url.authority.port > 0)
        byte_queue_write_fmt(&conn->output, ":%d", conn->url.authority.port);

    byte_queue_write(&conn->output, "\r\n", 2);

    // Find all entries from the cookie jar that should
    // be sent to this server and append headers for them
    HTTP_Client *client = builder.client;
    HTTP_CookieJar *cookie_jar = &client->cookie_jar;
    for (int i = 0; i < cookie_jar->count; i++) {
        HTTP_CookieJarEntry entry = cookie_jar->items[i];
        if (should_send_cookie(entry, conn->url)) {
            // TODO: Adding one header per cookie may cause the number of
            //       headers to increase significantly. Should probably group
            //       3-4 cookies in the same headers.
            byte_queue_write(&conn->output, "Cookie: ", 8);
            byte_queue_write(&conn->output, entry.name.ptr, entry.name.len);
            byte_queue_write(&conn->output, "=", 1);
            byte_queue_write(&conn->output, entry.value.ptr, entry.value.len);
            byte_queue_write(&conn->output, "\r\n", 2);
        }
    }

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
        // TODO: add Content-Length header
        byte_queue_write(&conn->output, "\r\n", 2);
        conn->state = HTTP_CLIENT_CONN_WAIT_BODY;
    }

    if (conn->state != HTTP_CLIENT_CONN_WAIT_BODY)
        return;

    byte_queue_write(&conn->output, str.ptr, str.len);
}

static int
url_to_connect_target(HTTP_URL url,
    ConnectTarget *target)
{
    HTTP_Authority authority = url.authority;

    if (authority.port < 1) {
        if (http_streq(url.scheme, HTTP_STR("https")))
            target->port = 443;
        else
            target->port = 80;
    } else {
        target->port = authority.port;
    }

    // Set up target based on host type
    if (authority.host.mode == HTTP_HOST_MODE_NAME) {
        target->type = CONNECT_TARGET_NAME;
        target->name = authority.host.name;
    } else if (authority.host.mode == HTTP_HOST_MODE_IPV4) {
        target->type = CONNECT_TARGET_IPV4;
        target->ipv4 = authority.host.ipv4;
    } else if (authority.host.mode == HTTP_HOST_MODE_IPV6) {
        target->type = CONNECT_TARGET_IPV6;
        target->ipv6 = authority.host.ipv6;
    } else {
        return -1;
    }

    return 0;
}

int http_request_builder_send(HTTP_RequestBuilder builder)
{
    HTTP_Client *client = builder.client;
    if (client == NULL)
        return -1;

    HTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return -1;

    if (conn->state == HTTP_CLIENT_CONN_COMPLETE)
        goto error; // Early completion due to an error

    if (conn->state == HTTP_CLIENT_CONN_WAIT_HEADER) {
        // No body, just end headers
        byte_queue_write(&conn->output, "\r\n", 2);
        conn->state = HTTP_CLIENT_CONN_WAIT_BODY;
    }

    if (conn->state != HTTP_CLIENT_CONN_WAIT_BODY)
        goto error;

    if (byte_queue_error(&conn->output))
        goto error;

    ConnectTarget target;
    if (url_to_connect_target(conn->url, &target) < 0)
        goto error;

    bool secure = http_streq(conn->url.scheme, HTTP_STR("https"));
    if (socket_connect(&client->sockets, 1, &target, secure, conn) < 0)
        goto error;

    conn->state = HTTP_CLIENT_CONN_FLUSHING;
    conn->gen++;
    return 0;

error:
    conn->state = HTTP_CLIENT_CONN_FREE;
    free(conn->url_buffer.ptr);
    byte_queue_free(&conn->input);
    byte_queue_free(&conn->output);
    client->num_conns--;
    return -1;
}

static void save_one_cookie(HTTP_CookieJar *cookie_jar,
    HTTP_Header set_cookie, HTTP_String domain, HTTP_String path)
{
    if (cookie_jar->count == HTTP_COOKIE_JAR_CAPACITY)
        return; // Cookie jar capacity reached

    HTTP_SetCookie parsed;
    if (http_parse_set_cookie(set_cookie.value, &parsed) < 0)
        return; // Ignore invalid Set-Cookie headers

    HTTP_CookieJarEntry entry;

    entry.name = parsed.name;
    entry.value = parsed.value;

    if (parsed.have_domain) {
        // TODO: Check that the server can set a cookie for this domain
        entry.exact_domain = false;
        entry.domain = parsed.domain;
    } else {
        entry.exact_domain = true;
        entry.domain = domain;
    }

    if (parsed.have_path) {
        entry.exact_path = false;
        entry.path = parsed.path;
    } else {
        // TODO: Set the path to the current endpoint minus one level
        entry.exact_path = true;
        entry.path = path;
    }

    entry.secure = parsed.secure;

    // Now copy all fields
    char *p = malloc(entry.name.len + entry.value.len + entry.domain.len + entry.path.len);
    if (p == NULL)
        return;

    memcpy(p, entry.name.ptr, entry.name.len);
    entry.name.ptr = p;
    p += entry.name.len;

    memcpy(p, entry.value.ptr, entry.value.len);
    entry.value.ptr = p;
    p += entry.value.len;

    memcpy(p, entry.domain.ptr, entry.domain.len);
    entry.domain.ptr = p;
    p += entry.domain.len;

    memcpy(p, entry.path.ptr, entry.path.len);
    entry.path.ptr = p;
    p += entry.path.len;

    cookie_jar->items[cookie_jar->count++] = entry;
}

static void save_cookies(HTTP_CookieJar *cookie_jar,
    HTTP_Header *headers, int num_headers,
    HTTP_String domain, HTTP_String path)
{
    // TODO: remove expired cookies

    for (int i = 0; i < num_headers; i++)
        if (http_streqcase(headers[i].name, HTTP_STR("Set-Cookie"))) // TODO: headers are case-insensitive, right?
            save_one_cookie(cookie_jar, headers[i], domain, path);
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
        if (conn == NULL)
            continue; // If a socket is not couple to a connection,
                      // it means the response was already returned
                      // to the user.

        if (events[i].type == SOCKET_EVENT_DISCONNECT) {

            conn->state = HTTP_CLIENT_CONN_COMPLETE;
            conn->result = -1;

        } else if (events[i].type == SOCKET_EVENT_READY) {

            // Store the handle if this is a new connection
            if (conn->handle == SOCKET_HANDLE_INVALID)
                conn->handle = events[i].handle;

            if (conn->state == HTTP_CLIENT_CONN_FLUSHING) {

                ByteView src = byte_queue_read_buf(&conn->output);

                int num = 0;
                if (src.len)
                    num = socket_send(&client->sockets, conn->handle, src.ptr, src.len);

                if (conn->trace_bytes)
                    print_bytes(HTTP_STR("<< "), (HTTP_String){src.ptr, num});

                byte_queue_read_ack(&conn->output, num);

                if (byte_queue_error(&conn->output)) {
                    socket_close(&client->sockets, conn->handle);
                    continue;
                }

                // Request fully sent, now wait for response
                if (byte_queue_empty(&conn->output))
                    conn->state = HTTP_CLIENT_CONN_BUFFERING;
            }

            if (conn->state == HTTP_CLIENT_CONN_BUFFERING) {

                // Receive response data
                int min_recv = 1<<10;
                byte_queue_write_setmincap(&conn->input, min_recv);

                ByteView dst = byte_queue_write_buf(&conn->input);

                int num = 0;
                if (dst.len)
                    num = socket_recv(&client->sockets, conn->handle, dst.ptr, dst.len);

                if (conn->trace_bytes)
                    print_bytes(HTTP_STR(">> "), (HTTP_String){dst.ptr, num});

                byte_queue_write_ack(&conn->input, num);

                if (byte_queue_error(&conn->input)) {
                    socket_close(&client->sockets, conn->handle);
                    continue;
                }

                ByteView src = byte_queue_read_buf(&conn->input);
                int ret = http_parse_response(src.ptr, src.len, &conn->response);

                if (ret == 0) {
                    // Still waiting
                    byte_queue_read_ack(&conn->input, 0);

                    // If the queue reached its limit and we still didn't receive
                    // a complete response, abort the exchange.
                    if (byte_queue_full(&conn->input))
                        socket_close(&client->sockets, conn->handle);
                    continue;
                }

                if (ret < 0) {
                    // Invalid response
                    byte_queue_read_ack(&conn->input, 0);
                    socket_close(&client->sockets, conn->handle);
                    continue;
                }

                // Ready
                assert(ret == 1);

                conn->state = HTTP_CLIENT_CONN_COMPLETE;
                conn->result = 0;

                conn->response.context = client;

                // Store received cookies in the cookie jar
                save_cookies(&client->cookie_jar,
                    conn->response.headers,
                    conn->response.num_headers,
                    conn->url.authority.host.text,
                    conn->url.path);

                // TODO: Handle redirects here
            }
        }

        if (conn->state == HTTP_CLIENT_CONN_COMPLETE) {

            // Decouple from the socket
            socket_set_user(&client->sockets, events[i].handle, NULL);

            // Push to the ready queue
            assert(client->num_ready < HTTP_CLIENT_CAPACITY);
            int tail = (client->ready_head + client->num_ready) % HTTP_CLIENT_CAPACITY;
            client->ready[tail] = conn - client->conns;
            client->num_ready++;
        }
    }

    return 0;
}

bool http_client_next_response(HTTP_Client *client,
    HTTP_Response **response, void **user)
{
    if (client->num_ready == 0)
        return false;

    HTTP_ClientConn *conn = &client->conns[client->ready[client->ready_head]];
    client->ready_head = (client->ready_head + 1) % HTTP_CLIENT_CAPACITY;
    client->num_ready--;

    assert(conn->state == HTTP_CLIENT_CONN_COMPLETE);

    if (conn->result == 0) {
        *response = &conn->response;
    } else {
        assert(conn->result == -1);
        *response = NULL;
    }
    *user = conn->user;

    return true;
}

void http_free_response(HTTP_Response *response)
{
    if (response == NULL || response->context == NULL)
        return;
    HTTP_Client *client = response->context;
    response->context = NULL;

    // TODO: I'm positive there is a better way to do this.
    //       It should just be a bouds check + subtraction.
    HTTP_ClientConn *conn = NULL;
    for (int i = 0; i < HTTP_CLIENT_CAPACITY; i++)
        if (&client->conns[i].response == response) {
            conn = &client->conns[i];
            break;
        }
    if (conn == NULL)
        return;

    conn->state = HTTP_CLIENT_CONN_FREE;
    free(conn->url_buffer.ptr);
    byte_queue_free(&conn->input);
    byte_queue_free(&conn->output);
    client->num_conns--;
}
