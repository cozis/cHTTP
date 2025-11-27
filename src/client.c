
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

    return socket_manager_init(&client->sockets,
        client->socket_pool, HTTP_CLIENT_CAPACITY);
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
    return socket_manager_wakeup(&client->sockets);
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

    client->conns[i].state = HTTP_CLIENT_CONN_WAIT_METHOD;
    client->conns[i].handle = SOCKET_HANDLE_INVALID;
    client->conns[i].client = client;
    client->conns[i].user = NULL;
    client->conns[i].trace_bytes = false;
    byte_queue_init(&client->conns[i].input,  client->input_buffer_limit);
    byte_queue_init(&client->conns[i].output, client->output_buffer_limit);

    return (HTTP_RequestBuilder) { client, i, client->conns[i].gen };
}

// Convert HTTP_Date to Unix timestamp (seconds since 1970-01-01 00:00:00 UTC)
// This is a simplified implementation that doesn't account for all edge cases
static time_t http_date_to_time(HTTP_Date date)
{
    // Days in each month (non-leap year)
    static const int days_in_month[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    // Calculate days since epoch (1970-01-01)
    int days = 0;

    // Add days for complete years
    for (int y = 1970; y < date.year; y++) {
        bool is_leap = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
        days += is_leap ? 366 : 365;
    }

    // Add days for complete months in current year
    for (int m = 0; m < date.month; m++) {
        days += days_in_month[m];
        // Add leap day if February and current year is leap year
        if (m == 1) { // February
            bool is_leap = (date.year % 4 == 0 && date.year % 100 != 0) || (date.year % 400 == 0);
            if (is_leap)
                days++;
        }
    }

    // Add remaining days
    days += date.day - 1;

    // Convert to seconds and add time components
    time_t timestamp = (time_t)days * 86400 + date.hour * 3600 + date.minute * 60 + date.second;

    return timestamp;
}

// Check if a cookie has expired
static bool is_cookie_expired(HTTP_CookieJarEntry entry, time_t current_time)
{
    if (entry.have_max_age) {
        // Max-Age takes precedence over Expires
        time_t expires_at = entry.creation_time + entry.max_age;
        return current_time >= expires_at;
    }

    if (entry.have_expires) {
        time_t expires_at = http_date_to_time(entry.expires);
        return current_time >= expires_at;
    }

    // No expiration set, cookie is a session cookie (never expires in this implementation)
    return false;
}

// TODO: test this function
// Domain matching is case-insensitive per RFC 6265
static bool is_subdomain(HTTP_String domain, HTTP_String subdomain)
{
    if (http_streqcase(domain, subdomain))
        return true; // Exact match

    if (domain.len > subdomain.len)
        return false;

    HTTP_String subdomain_suffix = {
        subdomain.ptr + subdomain.len - domain.len,
        domain.len
    };
    if (subdomain_suffix.ptr[-1] != '.' || !http_streqcase(domain, subdomain_suffix))
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

static bool should_send_cookie(HTTP_CookieJarEntry entry, HTTP_URL url, time_t current_time)
{
    // Check if cookie has expired
    if (is_cookie_expired(entry, current_time))
        return false;

    if (entry.exact_domain) {
        // Cookie domain and URL domain must match exactly (case-insensitive)
        if (!http_streqcase(entry.domain, url.authority.host.text))
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

void http_request_builder_trace(HTTP_RequestBuilder builder, bool trace_bytes)
{
    HTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return; // Invalid builder

    conn->trace_bytes = trace_bytes;
}

void http_request_builder_method(HTTP_RequestBuilder builder,
    HTTP_Method method)
{
    HTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return; // Invalid builder

    if (conn->state != HTTP_CLIENT_CONN_WAIT_METHOD)
        return; // Request line already written

    // Write method
    HTTP_String method_str = get_method_string(method);
    byte_queue_write(&conn->output, method_str.ptr, method_str.len);
    byte_queue_write(&conn->output, " ", 1);

    conn->state = HTTP_CLIENT_CONN_WAIT_URL;
}

void http_request_builder_target(HTTP_RequestBuilder builder,
    HTTP_String url)
{
    HTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return; // Invalid builder

    if (conn->state != HTTP_CLIENT_CONN_WAIT_URL)
        return; // Request line already written

    if (url.len == 0) {
        conn->state = HTTP_CLIENT_CONN_COMPLETE;
        conn->result = HTTP_ERROR_BADURL;
        return;
    }

    // Allocate a copy of the URL string so the parsed
    // URL pointers remain valid
    char *url_copy = malloc(url.len);
    if (url_copy == NULL) {
        conn->state = HTTP_CLIENT_CONN_COMPLETE;
        conn->result = HTTP_ERROR_OOM;
        return;
    }
    memcpy(url_copy, url.ptr, url.len);

    conn->url_buffer.ptr = url_copy;
    conn->url_buffer.len = url.len;

    // Parse the copied URL (all url.* pointers will reference url_buffer)
    if (http_parse_url(conn->url_buffer.ptr, conn->url_buffer.len, &conn->url) < 0) {
        conn->state = HTTP_CLIENT_CONN_COMPLETE;
        conn->result = HTTP_ERROR_BADURL;
        return;
    }

    if (!http_streq(conn->url.scheme, HTTP_STR("http")) &&
        !http_streq(conn->url.scheme, HTTP_STR("https"))) {
        conn->state = HTTP_CLIENT_CONN_COMPLETE;
        conn->result = HTTP_ERROR_BADURL;
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
    HTTP_String query = conn->url.query;
    if (query.len > 0) {
        byte_queue_write(&conn->output, "?", 1);
        byte_queue_write(&conn->output, query.ptr, query.len);
    }

    HTTP_String version = HTTP_STR(" HTTP/1.1");
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
    // be sent to this server and consolidate them into a single Cookie header
    HTTP_Client *client = builder.client;
    HTTP_CookieJar *cookie_jar = &client->cookie_jar;
    time_t current_time = time(NULL);

    bool first_cookie = true;
    for (int i = 0; i < cookie_jar->count; i++) {
        HTTP_CookieJarEntry entry = cookie_jar->items[i];
        if (should_send_cookie(entry, conn->url, current_time)) {
            if (first_cookie) {
                byte_queue_write(&conn->output, "Cookie: ", 8);
                first_cookie = false;
            } else {
                byte_queue_write(&conn->output, "; ", 2);
            }
            byte_queue_write(&conn->output, entry.name.ptr, entry.name.len);
            byte_queue_write(&conn->output, "=", 1);
            byte_queue_write(&conn->output, entry.value.ptr, entry.value.len);
        }
    }
    if (!first_cookie) {
        byte_queue_write(&conn->output, "\r\n", 2);
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

static ConnectTarget url_to_connect_target(HTTP_URL url)
{
    HTTP_Authority authority = url.authority;

    ConnectTarget target;
    if (authority.port < 1) {
        if (http_streq(url.scheme, HTTP_STR("https")))
            target.port = 443;
        else
            target.port = 80;
    } else {
        target.port = authority.port;
    }

    if (authority.host.mode == HTTP_HOST_MODE_NAME) {
        target.type = CONNECT_TARGET_NAME;
        target.name = authority.host.name;
    } else if (authority.host.mode == HTTP_HOST_MODE_IPV4) {
        target.type = CONNECT_TARGET_IPV4;
        target.ipv4 = authority.host.ipv4;
    } else if (authority.host.mode == HTTP_HOST_MODE_IPV6) {
        target.type = CONNECT_TARGET_IPV6;
        target.ipv6 = authority.host.ipv6;
    } else {
        HTTP_UNREACHABLE;
    }

    return target;
}

int http_request_builder_send(HTTP_RequestBuilder builder)
{
    HTTP_Client *client = builder.client;
    if (client == NULL)
        return HTTP_ERROR_REQLIMIT;

    HTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return HTTP_ERROR_BADHANDLE;

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

    ConnectTarget target = url_to_connect_target(conn->url);
    bool secure = http_streq(conn->url.scheme, HTTP_STR("https"));
    if (socket_connect(&client->sockets, 1, &target, secure, conn) < 0)
        goto error;

    conn->state = HTTP_CLIENT_CONN_FLUSHING;
    conn->gen++;
    return HTTP_OK;

error:
    conn->state = HTTP_CLIENT_CONN_FREE;
    free(conn->url_buffer.ptr);
    byte_queue_free(&conn->input);
    byte_queue_free(&conn->output);
    client->num_conns--;
    return conn->result;
}

// Compute default path from request path per RFC 6265 Section 5.1.4
static HTTP_String compute_default_cookie_path(HTTP_String request_path)
{
    // If the uri-path is empty or does not begin with "/", return "/"
    if (request_path.len == 0 || request_path.ptr[0] != '/')
        return HTTP_STR("/");

    // If the uri-path contains only a single "/" character, return "/"
    if (request_path.len == 1)
        return HTTP_STR("/");

    // Find the last "/" before the last character
    int last_slash = -1;
    for (int i = request_path.len - 1; i > 0; i--) {
        if (request_path.ptr[i] == '/') {
            last_slash = i;
            break;
        }
    }

    // Return path up to (but not including) the right-most "/"
    if (last_slash > 0)
        return (HTTP_String) { request_path.ptr, last_slash };

    return HTTP_STR("/");
}

static void save_one_cookie(HTTP_CookieJar *cookie_jar,
    HTTP_Header set_cookie, HTTP_String domain, HTTP_String path)
{
    HTTP_SetCookie parsed;
    if (http_parse_set_cookie(set_cookie.value, &parsed) < 0)
        return; // Ignore invalid Set-Cookie headers

    HTTP_CookieJarEntry entry;

    entry.name = parsed.name;
    entry.value = parsed.value;
    entry.creation_time = time(NULL);

    if (parsed.have_domain) {
        // Validate that the server can set a cookie for this domain
        // Per RFC 6265 Section 5.3: The Domain attribute must domain-match the request host
        if (!is_subdomain(parsed.domain, domain)) {
            // Server tried to set a cookie for a domain it doesn't control
            return;
        }
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
        // Use default path computation per RFC 6265
        HTTP_String default_path = compute_default_cookie_path(path);
        entry.exact_path = false;
        entry.path = default_path;
    }

    entry.secure = parsed.secure;

    // Store expiration information
    entry.have_expires = parsed.have_date;
    if (parsed.have_date)
        entry.expires = parsed.date;

    entry.have_max_age = parsed.have_max_age;
    if (parsed.have_max_age)
        entry.max_age = parsed.max_age;

    // Check if this cookie replaces an existing one
    // Per RFC 6265: A cookie is identified by name, domain, and path
    int existing_index = -1;
    for (int i = 0; i < cookie_jar->count; i++) {
        HTTP_CookieJarEntry *existing = &cookie_jar->items[i];
        if (http_streq(existing->name, entry.name) &&
            http_streqcase(existing->domain, entry.domain) &&
            http_streq(existing->path, entry.path)) {
            existing_index = i;
            break;
        }
    }

    // Allocate memory for all string fields
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

    if (existing_index >= 0) {
        // Replace existing cookie
        free(cookie_jar->items[existing_index].name.ptr); // This frees the entire allocated block
        cookie_jar->items[existing_index] = entry;
    } else {
        // Add new cookie if there's space
        if (cookie_jar->count < HTTP_COOKIE_JAR_CAPACITY) {
            cookie_jar->items[cookie_jar->count++] = entry;
        } else {
            // No space, free the allocated memory
            free(entry.name.ptr);
        }
    }
}

static void save_cookies(HTTP_CookieJar *cookie_jar,
    HTTP_Header *headers, int num_headers,
    HTTP_String domain, HTTP_String path)
{
    // Remove expired cookies from the jar
    time_t current_time = time(NULL);
    int write_idx = 0;
    for (int read_idx = 0; read_idx < cookie_jar->count; read_idx++) {
        if (!is_cookie_expired(cookie_jar->items[read_idx], current_time)) {
            // Keep this cookie
            if (write_idx != read_idx) {
                cookie_jar->items[write_idx] = cookie_jar->items[read_idx];
            }
            write_idx++;
        } else {
            // Free expired cookie
            free(cookie_jar->items[read_idx].name.ptr);
        }
    }
    cookie_jar->count = write_idx;

    // Process Set-Cookie headers
    for (int i = 0; i < num_headers; i++)
        if (http_streqcase(headers[i].name, HTTP_STR("Set-Cookie")))
            save_one_cookie(cookie_jar, headers[i], domain, path);
}

void http_client_register_events(HTTP_Client *client,
    EventRegister *reg)
{
    socket_manager_register_events(&client->sockets, reg);
}

void http_client_process_events(HTTP_Client *client,
    EventRegister reg)
{
    SocketEvent events[HTTP_CLIENT_CAPACITY];
    int num_events = socket_manager_translate_events(&client->sockets, events, reg);

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

            while (socket_ready(&client->sockets, conn->handle)) {

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
                    assert(ret > 0);

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
                    break;
                }
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
}

bool http_client_next_response(HTTP_Client *client,
    int *result, void **user, HTTP_Response **response)
{
    if (client->num_ready == 0)
        return false;

    HTTP_ClientConn *conn = &client->conns[client->ready[client->ready_head]];
    client->ready_head = (client->ready_head + 1) % HTTP_CLIENT_CAPACITY;
    client->num_ready--;

    assert(conn->state == HTTP_CLIENT_CONN_COMPLETE);

    *result = conn->result;
    *user   = conn->user;
    if (conn->result == HTTP_OK) {
        *response = &conn->response;
    } else {
        *response = NULL;
    }

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

#ifdef _WIN32
#define POLL WSAPoll
#else
#define POLL poll
#endif

void http_client_wait_response(HTTP_Client *client,
    int *result, void **user, HTTP_Response **response)
{
    for (;;) {

        void *ptrs[HTTP_CLIENT_POLL_CAPACITY];
        struct pollfd polled[HTTP_CLIENT_POLL_CAPACITY];

        EventRegister reg = { ptrs, polled, 0 };
        http_client_register_events(client, &reg);

        if (reg.num_polled > 0)
            POLL(reg.polled, reg.num_polled, -1);

        http_client_process_events(client, reg);

        if (http_client_next_response(client, result, user, response))
            break;
    }
}

static _Thread_local HTTP_Client *implicit_client;

static int perform_request(HTTP_Method method,
    HTTP_String url, HTTP_String *headers,
    int num_headers, HTTP_String body,
    HTTP_Response **response)
{
    if (implicit_client == NULL) {

        implicit_client = malloc(sizeof(HTTP_Client));
        if (implicit_client == NULL)
            return HTTP_ERROR_OOM;

        int ret = http_client_init(implicit_client);
        if (ret < 0) {
            free(implicit_client);
            implicit_client = NULL;
            return ret;
        }
    }
    HTTP_Client *client = implicit_client;

    HTTP_RequestBuilder builder = http_client_get_builder(client);
    http_request_builder_method(builder, method);
    http_request_builder_target(builder, url);
    for (int i = 0; i < num_headers; i++)
        http_request_builder_header(builder, headers[i]);
    http_request_builder_body(builder, body);
    int ret = http_request_builder_send(builder);
    if (ret < 0) return ret;

    int result;
    void *user;
    http_client_wait_response(client, &result, &user, response);
    return result;
}

int http_get(HTTP_String url, HTTP_String *headers,
    int num_headers, HTTP_Response **response)
{
    return perform_request(HTTP_METHOD_GET, url, headers, num_headers, HTTP_STR(""), response);
}

int http_post(HTTP_String url, HTTP_String *headers,
    int num_headers, HTTP_String body,
    HTTP_Response **response)
{
    return perform_request(HTTP_METHOD_POST, url, headers, num_headers, body, response);
}

int http_put(HTTP_String url, HTTP_String *headers,
    int num_headers, HTTP_String body,
    HTTP_Response **response)
{
    return perform_request(HTTP_METHOD_PUT, url, headers, num_headers, body, response);
}

int http_delete(HTTP_String url, HTTP_String *headers,
    int num_headers, HTTP_Response **response)
{
    return perform_request(HTTP_METHOD_DELETE, url, headers, num_headers, HTTP_STR(""), response);
}
