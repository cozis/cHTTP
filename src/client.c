
static void chttp_client_conn_free(CHTTP_ClientConn *conn)
{
    byte_queue_free(&conn->output);
    byte_queue_free(&conn->input);
}

int chttp_client_init(CHTTP_Client *client)
{
    client->input_buffer_limit = 1<<20;
    client->output_buffer_limit = 1<<20;

    client->cookie_jar.count = 0;

    client->num_conns = 0;
    for (int i = 0; i < CHTTP_CLIENT_CAPACITY; i++) {
        client->conns[i].state = CHTTP_CLIENT_CONN_FREE;
        client->conns[i].gen = 0;
    }

    client->num_ready = 0;
    client->ready_head = 0;

    return socket_manager_init(&client->sockets,
        client->socket_pool, CHTTP_CLIENT_CAPACITY);
}

void chttp_client_free(CHTTP_Client *client)
{
    socket_manager_free(&client->sockets);

    for (int i = 0; i < client->cookie_jar.count; i++)
        free(client->cookie_jar.items[i].name.ptr);

    for (int i = 0, j = 0; j < client->num_conns; i++) {
        CHTTP_ClientConn *conn = &client->conns[i];
        if (conn->state == CHTTP_CLIENT_CONN_FREE)
            continue;
        j++;

        chttp_client_conn_free(conn);
    }
}

void chttp_client_set_input_limit(CHTTP_Client *client, uint32_t limit)
{
    client->input_buffer_limit = limit;
}

void chttp_client_set_output_limit(CHTTP_Client *client, uint32_t limit)
{
    client->output_buffer_limit = limit;
}

int chttp_client_wakeup(CHTTP_Client *client)
{
    return socket_manager_wakeup(&client->sockets);
}

// Get a connection pointer from a request builder.
// If the builder is invalid, returns NULL.
static CHTTP_ClientConn*
request_builder_to_conn(CHTTP_RequestBuilder builder)
{
    CHTTP_Client *client = builder.client;
    if (client == NULL)
        return NULL;

    if (builder.index >= CHTTP_CLIENT_CAPACITY)
        return NULL;

    CHTTP_ClientConn *conn = &client->conns[builder.index];
    if (builder.gen != conn->gen)
        return NULL;

    return conn;
}

CHTTP_RequestBuilder chttp_client_get_builder(CHTTP_Client *client)
{
    // Find a free connection slot
    if (client->num_conns == CHTTP_CLIENT_CAPACITY)
        return (CHTTP_RequestBuilder) { NULL, -1, -1 };

    int i = 0;
    while (client->conns[i].state != CHTTP_CLIENT_CONN_FREE) {
        i++;
        assert(i < CHTTP_CLIENT_CAPACITY);
    }
    client->num_conns++;

    client->conns[i].state = CHTTP_CLIENT_CONN_WAIT_METHOD;
    client->conns[i].handle = SOCKET_HANDLE_INVALID;
    client->conns[i].client = client;
    client->conns[i].user = NULL;
    client->conns[i].trace_bytes = false;
    byte_queue_init(&client->conns[i].input,  client->input_buffer_limit);
    byte_queue_init(&client->conns[i].output, client->output_buffer_limit);

    return (CHTTP_RequestBuilder) { client, i, client->conns[i].gen };
}

// TODO: test this function
static bool is_subdomain(CHTTP_String domain, CHTTP_String subdomain)
{
    if (chttp_streq(domain, subdomain))
        return true; // Exact match

    if (domain.len > subdomain.len)
        return false;

    CHTTP_String subdomain_suffix = {
        subdomain.ptr + subdomain.len - domain.len,
        domain.len
    };
    if (subdomain_suffix.ptr[-1] != '.' || !chttp_streq(domain, subdomain_suffix))
        return false;

    return true;
}

// TODO: test this function
static bool is_subpath(CHTTP_String path, CHTTP_String subpath)
{
    if (path.len > subpath.len)
        return false;

    if (subpath.len != path.len && subpath.ptr[path.len] != '/')
        return false;

    subpath.len = path.len;
    return chttp_streq(path, subpath);
}

static bool should_send_cookie(CHTTP_CookieJarEntry entry, CHTTP_URL url)
{
    // TODO: If the cookie is expired, ignore it regardless

    if (entry.exact_domain) {
        // Cookie domain and URL domain must match exactly
        if (!chttp_streq(entry.domain, url.authority.host.text))
            return false;
    } else {
        // The URL's domain must match or be a subdomain of the cookie's domain
        if (!is_subdomain(entry.domain, url.authority.host.text))
            return false;
    }

    if (entry.exact_path) {
        // Cookie path and URL path must match exactly
        if (!chttp_streq(entry.path, url.path))
            return false;
    } else {
        if (!is_subpath(entry.path, url.path))
            return false;
    }

    if (entry.secure) {
        if (!chttp_streq(url.scheme, CHTTP_STR("https")))
            return false; // Cookie was marked as secure but the target URL is not HTTPS
    }

    return true;
}

static CHTTP_String get_method_string(CHTTP_Method method)
{
    switch (method) {
        case CHTTP_METHOD_GET    : return CHTTP_STR("GET");
        case CHTTP_METHOD_HEAD   : return CHTTP_STR("HEAD");
        case CHTTP_METHOD_POST   : return CHTTP_STR("POST");
        case CHTTP_METHOD_PUT    : return CHTTP_STR("PUT");
        case CHTTP_METHOD_DELETE : return CHTTP_STR("DELETE");
        case CHTTP_METHOD_CONNECT: return CHTTP_STR("CONNECT");
        case CHTTP_METHOD_OPTIONS: return CHTTP_STR("OPTIONS");
        case CHTTP_METHOD_TRACE  : return CHTTP_STR("TRACE");
        case CHTTP_METHOD_PATCH  : return CHTTP_STR("PATCH");
    }
    return CHTTP_STR("???");
}

void chttp_request_builder_set_user(CHTTP_RequestBuilder builder, void *user)
{
    CHTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return; // Invalid builder

    conn->user = user;
}

void chttp_request_builder_trace(CHTTP_RequestBuilder builder, bool trace_bytes)
{
    CHTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return; // Invalid builder

    conn->trace_bytes = trace_bytes;
}

// TODO: comment
void chttp_request_builder_insecure(CHTTP_RequestBuilder builder,
    bool insecure)
{
    CHTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return; // Invalid builder

    conn->dont_verify_cert = insecure;
}

void chttp_request_builder_method(CHTTP_RequestBuilder builder,
    CHTTP_Method method)
{
    CHTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return; // Invalid builder

    if (conn->state != CHTTP_CLIENT_CONN_WAIT_METHOD)
        return; // Request line already written

    // Write method
    CHTTP_String method_str = get_method_string(method);
    byte_queue_write(&conn->output, method_str.ptr, method_str.len);
    byte_queue_write(&conn->output, " ", 1);

    conn->state = CHTTP_CLIENT_CONN_WAIT_URL;
}

void chttp_request_builder_target(CHTTP_RequestBuilder builder,
    CHTTP_String url)
{
    CHTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return; // Invalid builder

    if (conn->state != CHTTP_CLIENT_CONN_WAIT_URL)
        return; // Request line already written

    if (url.len == 0) {
        conn->state = CHTTP_CLIENT_CONN_COMPLETE;
        conn->result = CHTTP_ERROR_BADURL;
        return;
    }

    // Allocate a copy of the URL string so the parsed
    // URL pointers remain valid
    char *url_copy = malloc(url.len);
    if (url_copy == NULL) {
        conn->state = CHTTP_CLIENT_CONN_COMPLETE;
        conn->result = CHTTP_ERROR_OOM;
        return;
    }
    memcpy(url_copy, url.ptr, url.len);

    conn->url_buffer.ptr = url_copy;
    conn->url_buffer.len = url.len;

    // Parse the copied URL (all url.* pointers will reference url_buffer)
    if (chttp_parse_url(conn->url_buffer.ptr, conn->url_buffer.len, &conn->url) < 0) {
        conn->state = CHTTP_CLIENT_CONN_COMPLETE;
        conn->result = CHTTP_ERROR_BADURL;
        return;
    }

    if (!chttp_streq(conn->url.scheme, CHTTP_STR("http")) &&
        !chttp_streq(conn->url.scheme, CHTTP_STR("https"))) {
        conn->state = CHTTP_CLIENT_CONN_COMPLETE;
        conn->result = CHTTP_ERROR_BADURL;
        return;
    }

    // Write path
    if (conn->url.path.len == 0)
        byte_queue_write(&conn->output, "/", 1);
    else
        byte_queue_write(&conn->output,
            conn->url.path.ptr,
            conn->url.path.len);

    // Write query string
    CHTTP_String query = conn->url.query;
    if (query.len > 0) {
        byte_queue_write(&conn->output, "?", 1);
        byte_queue_write(&conn->output, query.ptr, query.len);
    }

    CHTTP_String version = CHTTP_STR(" HTTP/1.1");
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
    CHTTP_Client *client = builder.client;
    CHTTP_CookieJar *cookie_jar = &client->cookie_jar;
    for (int i = 0; i < cookie_jar->count; i++) {
        CHTTP_CookieJarEntry entry = cookie_jar->items[i];
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

    CHTTP_String s;

    s = CHTTP_STR("Connection: Close\r\n");
    byte_queue_write(&conn->output, s.ptr, s.len);

    s = CHTTP_STR("Content-Length: ");
    byte_queue_write(&conn->output, s.ptr, s.len);

    conn->content_length_value_offset = byte_queue_offset(&conn->output);

    #define TEN_SPACES "          "
    _Static_assert(sizeof(TEN_SPACES) == 10+1);

    s = CHTTP_STR(TEN_SPACES "\r\n");
    byte_queue_write(&conn->output, s.ptr, s.len);

    conn->state = CHTTP_CLIENT_CONN_WAIT_HEADER;
}

void chttp_request_builder_header(CHTTP_RequestBuilder builder,
    CHTTP_String str)
{
    CHTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return;

    if (conn->state != CHTTP_CLIENT_CONN_WAIT_HEADER)
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

void chttp_request_builder_body(CHTTP_RequestBuilder builder,
    CHTTP_String str)
{
    CHTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return;

    // Transition from WAIT_HEADER to WAIT_BODY if needed
    if (conn->state == CHTTP_CLIENT_CONN_WAIT_HEADER) {
        byte_queue_write(&conn->output, "\r\n", 2);
        conn->content_length_offset = byte_queue_offset(&conn->output);
        conn->state = CHTTP_CLIENT_CONN_WAIT_BODY;
    }

    if (conn->state != CHTTP_CLIENT_CONN_WAIT_BODY)
        return;

    byte_queue_write(&conn->output, str.ptr, str.len);
}

static ConnectTarget url_to_connect_target(CHTTP_URL url)
{
    CHTTP_Authority authority = url.authority;

    ConnectTarget target;
    if (authority.port < 1) {
        if (chttp_streq(url.scheme, CHTTP_STR("https")))
            target.port = 443;
        else
            target.port = 80;
    } else {
        target.port = authority.port;
    }

    if (authority.host.mode == CHTTP_HOST_MODE_NAME) {
        target.type = CONNECT_TARGET_NAME;
        target.name = authority.host.name;
    } else if (authority.host.mode == CHTTP_HOST_MODE_IPV4) {
        target.type = CONNECT_TARGET_IPV4;
        target.ipv4 = authority.host.ipv4;
    } else if (authority.host.mode == CHTTP_HOST_MODE_IPV6) {
        target.type = CONNECT_TARGET_IPV6;
        target.ipv6 = authority.host.ipv6;
    } else {
        CHTTP_UNREACHABLE;
    }

    return target;
}

int chttp_request_builder_send(CHTTP_RequestBuilder builder)
{
    CHTTP_Client *client = builder.client;
    if (client == NULL)
        return CHTTP_ERROR_REQLIMIT;

    CHTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return CHTTP_ERROR_BADHANDLE;

    if (conn->state == CHTTP_CLIENT_CONN_COMPLETE)
        goto error; // Early completion due to an error

    if (conn->state == CHTTP_CLIENT_CONN_WAIT_HEADER) {
        byte_queue_write(&conn->output, "\r\n", 2);
        conn->content_length_offset = byte_queue_offset(&conn->output);
        conn->state = CHTTP_CLIENT_CONN_WAIT_BODY;
    }

    if (conn->state != CHTTP_CLIENT_CONN_WAIT_BODY)
        goto error;

    if (byte_queue_error(&conn->output))
        goto error;

    int content_length = byte_queue_size_from_offset(&conn->output, conn->content_length_offset);

    char tmp[11];
    int len = snprintf(tmp, sizeof(tmp), "%d", content_length);
    assert(len > 0 && len < 11);

    byte_queue_patch(&conn->output, conn->content_length_value_offset, tmp, len);

    ConnectTarget target = url_to_connect_target(conn->url);
    bool secure = chttp_streq(conn->url.scheme, CHTTP_STR("https"));
    if (socket_connect(&client->sockets, 1, &target, secure, conn->dont_verify_cert, conn) < 0)
        goto error;

    conn->state = CHTTP_CLIENT_CONN_FLUSHING;
    conn->gen++;
    return CHTTP_OK;

error:
    conn->state = CHTTP_CLIENT_CONN_FREE;
    free(conn->url_buffer.ptr);
    byte_queue_free(&conn->input);
    byte_queue_free(&conn->output);
    client->num_conns--;
    return conn->result;
}

static void save_one_cookie(CHTTP_CookieJar *cookie_jar,
    CHTTP_Header set_cookie, CHTTP_String domain, CHTTP_String path)
{
    if (cookie_jar->count == CHTTP_COOKIE_JAR_CAPACITY)
        return; // Cookie jar capacity reached

    CHTTP_SetCookie parsed;
    if (chttp_parse_set_cookie(set_cookie.value, &parsed) < 0)
        return; // Ignore invalid Set-Cookie headers

    CHTTP_CookieJarEntry entry;

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

static void save_cookies(CHTTP_CookieJar *cookie_jar,
    CHTTP_Header *headers, int num_headers,
    CHTTP_String domain, CHTTP_String path)
{
    // TODO: remove expired cookies

    for (int i = 0; i < num_headers; i++)
        if (chttp_streqcase(headers[i].name, CHTTP_STR("Set-Cookie"))) // TODO: headers are case-insensitive, right?
            save_one_cookie(cookie_jar, headers[i], domain, path);
}

void chttp_client_register_events(CHTTP_Client *client,
    EventRegister *reg)
{
    socket_manager_register_events(&client->sockets, reg);
}

void chttp_client_process_events(CHTTP_Client *client,
    EventRegister reg)
{
    SocketEvent events[CHTTP_CLIENT_CAPACITY];
    int num_events = socket_manager_translate_events(&client->sockets, events, reg);

    for (int i = 0; i < num_events; i++) {

        CHTTP_ClientConn *conn = events[i].user;
        if (conn == NULL)
            continue; // If a socket is not couple to a connection,
                      // it means the response was already returned
                      // to the user.

        if (events[i].type == SOCKET_EVENT_DISCONNECT) {

            conn->state = CHTTP_CLIENT_CONN_COMPLETE;
            conn->result = -1;

        } else if (events[i].type == SOCKET_EVENT_READY) {

            // Store the handle if this is a new connection
            if (conn->handle == SOCKET_HANDLE_INVALID)
                conn->handle = events[i].handle;

            while (socket_ready(&client->sockets, conn->handle)) {

                if (conn->state == CHTTP_CLIENT_CONN_FLUSHING) {

                    ByteView src = byte_queue_read_buf(&conn->output);

                    int num = 0;
                    if (src.len)
                        num = socket_send(&client->sockets, conn->handle, src.ptr, src.len);

                    if (conn->trace_bytes)
                        print_bytes(CHTTP_STR("<< "), (CHTTP_String){src.ptr, num});

                    byte_queue_read_ack(&conn->output, num);

                    if (byte_queue_error(&conn->output)) {
                        socket_close(&client->sockets, conn->handle);
                        continue;
                    }

                    // Request fully sent, now wait for response
                    if (byte_queue_empty(&conn->output))
                        conn->state = CHTTP_CLIENT_CONN_BUFFERING;
                }

                if (conn->state == CHTTP_CLIENT_CONN_BUFFERING) {

                    // Receive response data
                    int min_recv = 1<<10;
                    byte_queue_write_setmincap(&conn->input, min_recv);

                    ByteView dst = byte_queue_write_buf(&conn->input);

                    int num = 0;
                    if (dst.len)
                        num = socket_recv(&client->sockets, conn->handle, dst.ptr, dst.len);

                    if (conn->trace_bytes)
                        print_bytes(CHTTP_STR(">> "), (CHTTP_String){dst.ptr, num});

                    byte_queue_write_ack(&conn->input, num);

                    if (byte_queue_error(&conn->input)) {
                        socket_close(&client->sockets, conn->handle);
                        continue;
                    }

                    ByteView src = byte_queue_read_buf(&conn->input);
                    int ret = chttp_parse_response(src.ptr, src.len, &conn->response);

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
                    assert(ret > 0);

                    conn->state = CHTTP_CLIENT_CONN_COMPLETE;
                    conn->result = 0;

                    conn->response.context = client;

                    // Store received cookies in the cookie jar
                    save_cookies(&client->cookie_jar,
                        conn->response.headers,
                        conn->response.num_headers,
                        conn->url.authority.host.text,
                        conn->url.path);

                    // TODO: Handle redirects here
                    break;
                }
            }
        }

        if (conn->state == CHTTP_CLIENT_CONN_COMPLETE) {

            // Decouple from the socket
            socket_set_user(&client->sockets, events[i].handle, NULL);
            socket_close(&client->sockets, events[i].handle);

            // Push to the ready queue
            assert(client->num_ready < CHTTP_CLIENT_CAPACITY);
            int tail = (client->ready_head + client->num_ready) % CHTTP_CLIENT_CAPACITY;
            client->ready[tail] = conn - client->conns;
            client->num_ready++;
        }
    }
}

bool chttp_client_next_response(CHTTP_Client *client,
    int *result, void **user, CHTTP_Response **response)
{
    if (client->num_ready == 0)
        return false;

    CHTTP_ClientConn *conn = &client->conns[client->ready[client->ready_head]];
    client->ready_head = (client->ready_head + 1) % CHTTP_CLIENT_CAPACITY;
    client->num_ready--;

    assert(conn->state == CHTTP_CLIENT_CONN_COMPLETE);

    *result = conn->result;
    *user   = conn->user;
    if (conn->result == CHTTP_OK) {
        *response = &conn->response;
    } else {
        *response = NULL;
    }

    return true;
}

void chttp_free_response(CHTTP_Response *response)
{
    if (response == NULL || response->context == NULL)
        return;
    CHTTP_Client *client = response->context;
    response->context = NULL;

    // TODO: I'm positive there is a better way to do this.
    //       It should just be a bouds check + subtraction.
    CHTTP_ClientConn *conn = NULL;
    for (int i = 0; i < CHTTP_CLIENT_CAPACITY; i++)
        if (&client->conns[i].response == response) {
            conn = &client->conns[i];
            break;
        }
    if (conn == NULL)
        return;

    conn->state = CHTTP_CLIENT_CONN_FREE;
    free(conn->url_buffer.ptr);
    byte_queue_free(&conn->input);
    byte_queue_free(&conn->output);
    client->num_conns--;
}

#ifdef _WIN32
#define POLL WSAPoll
#else
#define POLL poll
#endif

void chttp_client_wait_response(CHTTP_Client *client,
    int *result, void **user, CHTTP_Response **response)
{
    for (;;) {

        void *ptrs[CHTTP_CLIENT_POLL_CAPACITY];
        struct pollfd polled[CHTTP_CLIENT_POLL_CAPACITY];

        EventRegister reg = { ptrs, polled, 0 };
        chttp_client_register_events(client, &reg);

        if (reg.num_polled > 0)
            POLL(reg.polled, reg.num_polled, -1);

        chttp_client_process_events(client, reg);

        if (chttp_client_next_response(client, result, user, response))
            break;
    }
}

static _Thread_local CHTTP_Client *implicit_client;

static int perform_request(CHTTP_Method method,
    CHTTP_String url, CHTTP_String *headers,
    int num_headers, CHTTP_String body,
    CHTTP_Response **response)
{
    if (implicit_client == NULL) {

        implicit_client = malloc(sizeof(CHTTP_Client));
        if (implicit_client == NULL)
            return CHTTP_ERROR_OOM;

        int ret = chttp_client_init(implicit_client);
        if (ret < 0) {
            free(implicit_client);
            implicit_client = NULL;
            return ret;
        }
    }
    CHTTP_Client *client = implicit_client;

    CHTTP_RequestBuilder builder = chttp_client_get_builder(client);
    chttp_request_builder_method(builder, method);
    chttp_request_builder_target(builder, url);
    for (int i = 0; i < num_headers; i++)
        chttp_request_builder_header(builder, headers[i]);
    chttp_request_builder_body(builder, body);
    int ret = chttp_request_builder_send(builder);
    if (ret < 0) return ret;

    int result;
    void *user;
    chttp_client_wait_response(client, &result, &user, response);
    return result;
}

int chttp_get(CHTTP_String url, CHTTP_String *headers,
    int num_headers, CHTTP_Response **response)
{
    return perform_request(CHTTP_METHOD_GET, url, headers, num_headers, CHTTP_STR(""), response);
}

int chttp_post(CHTTP_String url, CHTTP_String *headers,
    int num_headers, CHTTP_String body,
    CHTTP_Response **response)
{
    return perform_request(CHTTP_METHOD_POST, url, headers, num_headers, body, response);
}

int chttp_put(CHTTP_String url, CHTTP_String *headers,
    int num_headers, CHTTP_String body,
    CHTTP_Response **response)
{
    return perform_request(CHTTP_METHOD_PUT, url, headers, num_headers, body, response);
}

int chttp_delete(CHTTP_String url, CHTTP_String *headers,
    int num_headers, CHTTP_Response **response)
{
    return perform_request(CHTTP_METHOD_DELETE, url, headers, num_headers, CHTTP_STR(""), response);
}
