// From RFC 9112
//   request-target = origin-form
//                  / absolute-form
//                  / authority-form
//                  / asterisk-form
//   origin-form    = absolute-path [ "?" query ]
//   absolute-form  = absolute-URI
//   authority-form = uri-host ":" port
//   asterisk-form  = "*"
//
// From RFC 9110
//   URI-reference = <URI-reference, see [URI], Section 4.1>
//   absolute-URI  = <absolute-URI, see [URI], Section 4.3>
//   relative-part = <relative-part, see [URI], Section 4.2>
//   authority     = <authority, see [URI], Section 3.2>
//   uri-host      = <host, see [URI], Section 3.2.2>
//   port          = <port, see [URI], Section 3.2.3>
//   path-abempty  = <path-abempty, see [URI], Section 3.3>
//   segment       = <segment, see [URI], Section 3.3>
//   query         = <query, see [URI], Section 3.4>
//
//   absolute-path = 1*( "/" segment )
//   partial-URI   = relative-part [ "?" query ]
//
// From RFC 3986:
//   segment       = *pchar
//   pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
//   pct-encoded   = "%" HEXDIG HEXDIG
//   sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
//                 / "*" / "+" / "," / ";" / "="
//   unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
//   query         = *( pchar / "/" / "?" )
//   absolute-URI  = scheme ":" hier-part [ "?" query ]
//   hier-part     = "//" authority path-abempty
//                 / path-absolute
//                 / path-rootless
//                 / path-empty
//   scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )

typedef struct {
	char *src;
	int len;
	int cur;
} Scanner;

static int is_digit(char c)
{
	return c >= '0' && c <= '9';
}

static int is_alpha(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static int is_hex_digit(char c)
{
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

// From RFC 3986:
//   sub-delims = "!" / "$" / "&" / "'" / "(" / ")"
//              / "*" / "+" / "," / ";" / "="
static int is_sub_delim(char c)
{
	return c == '!' || c == '$' || c == '&' || c == '\''
		|| c == '(' || c == ')' || c == '*' || c == '+'
		|| c == ',' || c == ';' || c == '=';
}

// From RFC 3986:
//   unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
static int is_unreserved(char c)
{
	return is_alpha(c) || is_digit(c)
		|| c == '-' || c == '.'
		|| c == '_' || c == '~';
}

// From RFC 3986:
//   pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
static int is_pchar(char c)
{
	return is_unreserved(c) || is_sub_delim(c) || c == ':' || c == '@';
}

static int is_tchar(char c)
{
	return is_digit(c) || is_alpha(c)
		|| c == '!' || c == '#' || c == '$'
		|| c == '%' || c == '&' || c == '\''
		|| c == '*' || c == '+' || c == '-'
		|| c == '.' || c == '^' || c == '_'
		|| c == '~';
}

static int is_vchar(char c)
{
	return c >= ' ' && c <= '~';
}

#define CONSUME_OPTIONAL_SEQUENCE(scanner, func)                                        \
    while ((scanner)->cur < (scanner)->len && (func)((scanner)->src[(scanner)->cur]))   \
        (scanner)->cur++;

static int
consume_absolute_path(Scanner *s)
{
	if (s->cur == s->len || s->src[s->cur] != '/')
		return -1; // ERROR
	s->cur++;

	for (;;) {

        CONSUME_OPTIONAL_SEQUENCE(s, is_pchar);

		if (s->cur == s->len || s->src[s->cur] != '/')
			break;
		s->cur++;
	}

	return 0;
}

// If abempty=1:
//   path-abempty  = *( "/" segment )
// else:
//   path-absolute = "/" [ segment-nz *( "/" segment ) ]
//   path-rootless = segment-nz *( "/" segment )
//   path-empty    = 0<pchar>
static int parse_path(Scanner *s, HTTP_String *path, int abempty)
{
	int start = s->cur;

	if (abempty) {

		// path-abempty
		while (s->cur < s->len && s->src[s->cur] == '/') {
			do
				s->cur++;
			while (s->cur < s->len && is_pchar(s->src[s->cur]));
		}

	} else if (s->cur < s->len && (s->src[s->cur] == '/')) {

		// path-absolute
		s->cur++;
		if (s->cur < s->len && is_pchar(s->src[s->cur])) {
			s->cur++;
			for (;;) {

                CONSUME_OPTIONAL_SEQUENCE(s, is_pchar);

				if (s->cur == s->len || s->src[s->cur] != '/')
					break;
				s->cur++;
			}
		}

	} else if (s->cur < s->len && is_pchar(s->src[s->cur])) {

		// path-rootless
		s->cur++;
		for (;;) {

            CONSUME_OPTIONAL_SEQUENCE(s, is_pchar)

			if (s->cur == s->len || s->src[s->cur] != '/')
				break;
			s->cur++;
		}

	} else {
		// path->empty
		// (do nothing)
	}

	*path = (HTTP_String) {
		s->src + start,
		s->cur - start,
	};
	if (path->len == 0)
		path->ptr = NULL;

	return 0;
}

// RFC 3986:
//   query = *( pchar / "/" / "?" )
static int is_query(char c)
{
	return is_pchar(c) || c == '/' || c == '?';
}

// RFC 3986:
//   fragment = *( pchar / "/" / "?" )
static int is_fragment(char c)
{
	return is_pchar(c) || c == '/' || c == '?';
}

static int little_endian(void)
{
    uint16_t x = 1;
    return *((uint8_t*) &x);
}

static void invert_bytes(void *p, int len)
{
	char *c = p;
	for (int i = 0; i < len/2; i++) {
		char tmp = c[i];
		c[i] = c[len-i-1];
		c[len-i-1] = tmp;
	}
}

static int parse_ipv4(Scanner *s, HTTP_IPv4 *ipv4)
{
	unsigned int out = 0;
	int i = 0;
	for (;;) {

		if (s->cur == s->len || !is_digit(s->src[s->cur]))
			return -1;

		int b = 0;
		do {
			int x = s->src[s->cur++] - '0';
			if (b > (UINT8_MAX - x) / 10)
				return -1;
			b = b * 10 + x;
		} while (s->cur < s->len && is_digit(s->src[s->cur]));

		out <<= 8;
		out |= (unsigned char) b;

		i++;
		if (i == 4)
			break;

		if (s->cur == s->len || s->src[s->cur] != '.')
			return -1;
		s->cur++;
	}

	if (little_endian())
		invert_bytes(&out, 4);

	ipv4->data = out;
	return 0;
}

static int hex_digit_to_int(char c)
{
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	if (c >= '0' && c <= '9') return c - '0';
	return -1;
}

static int parse_ipv6_comp(Scanner *s)
{
	unsigned short buf;

	if (s->cur == s->len || !is_hex_digit(s->src[s->cur]))
		return -1;
	buf = hex_digit_to_int(s->src[s->cur]);
	s->cur++;

	if (s->cur == s->len || !is_hex_digit(s->src[s->cur]))
		return buf;
	buf <<= 4;
	buf |= hex_digit_to_int(s->src[s->cur]);
	s->cur++;

	if (s->cur == s->len || !is_hex_digit(s->src[s->cur]))
		return buf;
	buf <<= 4;
	buf |= hex_digit_to_int(s->src[s->cur]);
	s->cur++;

	if (s->cur == s->len || !is_hex_digit(s->src[s->cur]))
		return buf;
	buf <<= 4;
	buf |= hex_digit_to_int(s->src[s->cur]);
	s->cur++;

	return (int) buf;
}

static int parse_ipv6(Scanner *s, HTTP_IPv6 *ipv6)
{
	unsigned short head[8];
	unsigned short tail[8];
	int head_len = 0;
	int tail_len = 0;

	if (s->len - s->cur > 1
		&& s->src[s->cur+0] == ':'
		&& s->src[s->cur+1] == ':')
		s->cur += 2;
	else {

		for (;;) {

			int ret = parse_ipv6_comp(s);
			if (ret < 0) return ret;

			head[head_len++] = (unsigned short) ret;
			if (head_len == 8) break;

			if (s->cur == s->len || s->src[s->cur] != ':')
				return -1;
			s->cur++;

			if (s->cur < s->len && s->src[s->cur] == ':') {
				s->cur++;
				break;
			}
		}
	}

	if (head_len < 8) {
		while (s->cur < s->len && is_hex_digit(s->src[s->cur])) {

			int ret = parse_ipv6_comp(s);
			if (ret < 0) return ret;

			tail[tail_len++] = (unsigned short) ret;
			if (head_len + tail_len == 8) break;

			if (s->cur == s->len || s->src[s->cur] != ':')
				break;
			s->cur++;
		}
	}

	for (int i = 0; i < head_len; i++)
		ipv6->data[i] = head[i];

	for (int i = 0; i < 8 - head_len - tail_len; i++)
		ipv6->data[head_len + i] = 0;

	for (int i = 0; i < tail_len; i++)
		ipv6->data[8 - tail_len + i] = tail[i];

	if (little_endian())
		for (int i = 0; i < 8; i++)
			invert_bytes(&ipv6->data[i], 2);

	return 0;
}

// From RFC 3986:
//   reg-name = *( unreserved / pct-encoded / sub-delims )
static int is_regname(char c)
{
	return is_unreserved(c) || is_sub_delim(c);
}

static int parse_regname(Scanner *s, HTTP_String *regname)
{
	if (s->cur == s->len || !is_regname(s->src[s->cur]))
		return -1;
	int start = s->cur;
	do
		s->cur++;
	while (s->cur < s->len && is_regname(s->src[s->cur]));
	regname->ptr = s->src + start;
	regname->len = s->cur - start;
	return 0;
}

static int parse_host(Scanner *s, HTTP_Host *host)
{
	int ret;
	if (s->cur < s->len && s->src[s->cur] == '[') {

		s->cur++;

		int start = s->cur;
		HTTP_IPv6 ipv6;
		ret = parse_ipv6(s, &ipv6);
		if (ret < 0) return ret;

		host->mode = HTTP_HOST_MODE_IPV6;
		host->ipv6 = ipv6;
		host->text = (HTTP_String) { s->src + start, s->cur - start };

		if (s->cur == s->len || s->src[s->cur] != ']')
			return -1;
		s->cur++;

	} else {

		int start = s->cur;
		HTTP_IPv4 ipv4;
		ret = parse_ipv4(s, &ipv4);
		if (ret >= 0) {
			host->mode = HTTP_HOST_MODE_IPV4;
			host->ipv4 = ipv4;
		} else {
			s->cur = start;

			HTTP_String regname;
			ret = parse_regname(s, &regname);
			if (ret < 0) return ret;

			host->mode = HTTP_HOST_MODE_NAME;
			host->name = regname;
		}
		host->text = (HTTP_String) { s->src + start, s->cur - start };
	}

	return 0;
}

// scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
static int is_scheme_head(char c)
{
	return is_alpha(c);
}

static int is_scheme_body(char c)
{
	return is_alpha(c)
		|| is_digit(c)
		|| c == '+'
		|| c == '-'
		|| c == '.';
}

// userinfo = *( unreserved / pct-encoded / sub-delims / ":" )
// Note: percent-encoded characters (%XX) are not currently validated
static int is_userinfo(char c)
{
	return is_unreserved(c) || is_sub_delim(c) || c == ':';
}

// authority = [ userinfo "@" ] host [ ":" port ]
static int parse_authority(Scanner *s, HTTP_Authority *authority)
{
	HTTP_String userinfo;
	{
		int start = s->cur;

        CONSUME_OPTIONAL_SEQUENCE(s, is_userinfo);

		if (s->cur < s->len && s->src[s->cur] == '@') {
			userinfo = (HTTP_String) {
				s->src + start,
				s->cur - start
			};
			s->cur++;
		} else {
			// Rollback
			s->cur = start;
			userinfo = (HTTP_String) {NULL, 0};
		}
	}

	HTTP_Host host;
	{
		int ret = parse_host(s, &host);
		if (ret < 0)
			return ret;
	}

	int port = 0;
	if (s->cur < s->len && s->src[s->cur] == ':') {
		s->cur++;
		if (s->cur < s->len && is_digit(s->src[s->cur])) {
			port = s->src[s->cur++] - '0';
			while (s->cur < s->len && is_digit(s->src[s->cur])) {
				int x = s->src[s->cur++] - '0';
				if (port > (UINT16_MAX - x) / 10)
					return -1; // ERROR: Port too big
				port = port * 10 + x;
			}
		}
	}

	authority->userinfo = userinfo;
	authority->host = host;
	authority->port = port;
	return 0;
}

static int parse_uri(Scanner *s, HTTP_URL *url, int allow_fragment)
{
	HTTP_String scheme = {0};
	{
		int start = s->cur;
		if (s->cur == s->len || !is_scheme_head(s->src[s->cur]))
			return -1; // ERROR: Missing scheme
		do
			s->cur++;
		while (s->cur < s->len && is_scheme_body(s->src[s->cur]));
		scheme = (HTTP_String) {
			s->src + start,
			s->cur - start,
		};

		if (s->cur == s->len || s->src[s->cur] != ':')
			return -1; // ERROR: Missing ':' after scheme
		s->cur++;
	}

	int abempty = 0;
	HTTP_Authority authority = {0};
	if (s->len - s->cur > 1
		&& s->src[s->cur+0] == '/'
		&& s->src[s->cur+1] == '/') {

		s->cur += 2;

		int ret = parse_authority(s, &authority);
		if (ret < 0) return ret;

		abempty = 1;
	}

	HTTP_String path;
	int ret = parse_path(s, &path, abempty);
	if (ret < 0) return ret;

	HTTP_String query = {0};
	if (s->cur < s->len && s->src[s->cur] == '?') {
		int start = s->cur;
		do
			s->cur++;
		while (s->cur < s->len && is_query(s->src[s->cur]));
		query = (HTTP_String) {
			s->src + start,
			s->cur - start,
		};
	}

	HTTP_String fragment = {0};
	if (allow_fragment && s->cur < s->len && s->src[s->cur] == '#') {
		int start = s->cur;
		do
			s->cur++;
		while (s->cur < s->len && is_fragment(s->src[s->cur]));
		fragment = (HTTP_String) {
			s->src + start,
			s->cur - start,
		};
	}

	url->scheme    = scheme;
	url->authority = authority;
	url->path      = path;
	url->query     = query;
	url->fragment  = fragment;

	return 1;
}

// authority-form = host ":" port
// host           = IP-literal / IPv4address / reg-name
// IP-literal    = "[" ( IPv6address / IPvFuture  ) "]"
// reg-name      = *( unreserved / pct-encoded / sub-delims )
static int parse_authority_form(Scanner *s, HTTP_Host *host, int *port)
{
	int ret;

	ret = parse_host(s, host);
	if (ret < 0) return ret;

	// Default port value
	*port = 0;

	if (s->cur == s->len || s->src[s->cur] != ':')
		return 0; // No port
	s->cur++;

	if (s->cur == s->len || !is_digit(s->src[s->cur]))
		return 0; // No port

	int buf = 0;
	do {
		int x = s->src[s->cur++] - '0';
		if (buf > (UINT16_MAX - x) / 10)
			return -1; // ERROR
		buf = buf * 10 + x;
	} while (s->cur < s->len && is_digit(s->src[s->cur]));

	*port = buf;
	return 0;
}

static int parse_origin_form(Scanner *s, HTTP_String *path, HTTP_String *query)
{
	int ret, start;

	start = s->cur;
	ret = consume_absolute_path(s);
	if (ret < 0) return ret;
	*path = (HTTP_String) { s->src + start, s->cur - start };

	if (s->cur < s->len && s->src[s->cur] == '?') {
		start = s->cur;
		do
			s->cur++;
		while (s->cur < s->len && is_query(s->src[s->cur]));
		*query = (HTTP_String) { s->src + start, s->cur - start };
	} else
		*query = (HTTP_String) { NULL, 0 };

	return 0;
}

static int parse_asterisk_form(Scanner *s)
{
	if (s->len - s->cur < 2
		|| s->src[s->cur+0] != '*'
		|| s->src[s->cur+1] != ' ')
		return -1;
	s->cur++;
	return 0;
}

static int parse_request_target(Scanner *s, HTTP_URL *url)
{
	int ret;

	memset(url, 0, sizeof(HTTP_URL));

	// asterisk-form
	ret = parse_asterisk_form(s);
	if (ret >= 0) return ret;

	ret = parse_uri(s, url, 0);
	if (ret >= 0) return ret;

	ret = parse_authority_form(s, &url->authority.host, &url->authority.port);
	if (ret >= 0) return ret;

	ret = parse_origin_form(s, &url->path, &url->query);
	if (ret >= 0) return ret;

	return -1;
}

bool consume_str(Scanner *scan, HTTP_String token)
{
    assert(token.len > 0);

    if (token.len > scan->len - scan->cur)
        return false;

    for (int i = 0; i < token.len; i++)
        if (scan->src[scan->cur + i] != token.ptr[i])
            return false;

    scan->cur += token.len;
    return true;
}

static int is_header_body(char c)
{
	return is_vchar(c) || c == ' ' || c == '\t';
}

static int parse_headers(Scanner *s, HTTP_Header *headers, int max_headers)
{
	int num_headers = 0;
    while (!consume_str(s, HTTP_STR("\r\n"))) {

        // RFC 9112:
		//   field-line = field-name ":" OWS field-value OWS
		//
		// RFC 9110:
		//   field-value    = *field-content
		//   field-content  = field-vchar
		//                    [ 1*( SP / HTAB / field-vchar ) field-vchar ]
		//   field-vchar    = VCHAR / obs-text
		//   obs-text       = %x80-FF

		int start;

		if (s->cur == s->len || !is_tchar(s->src[s->cur]))
			return -1; // ERROR
		start = s->cur;
		do
			s->cur++;
		while (s->cur < s->len && is_tchar(s->src[s->cur]));
		HTTP_String name = { s->src + start, s->cur - start };

		if (s->cur == s->len || s->src[s->cur] != ':')
			return -1; // ERROR
		s->cur++;

        start = s->cur;
        CONSUME_OPTIONAL_SEQUENCE(s, is_header_body);
		HTTP_String body = { s->src + start, s->cur - start };
		body = http_trim(body);

        if (num_headers < max_headers)
            headers[num_headers++] = (HTTP_Header) { name, body };

        if (!consume_str(s, HTTP_STR("\r\n"))) {
            return -1;
        }
    }

    return num_headers;
}

typedef enum {
    TRANSFER_ENCODING_OPTION_CHUNKED,
    TRANSFER_ENCODING_OPTION_COMPRESS,
    TRANSFER_ENCODING_OPTION_DEFLATE,
    TRANSFER_ENCODING_OPTION_GZIP,
} TransferEncodingOption;

static bool is_space(char c)
{
    return c == ' ' || c == '\t';
}

static int
parse_transfer_encoding(HTTP_String src, TransferEncodingOption *dst, int max)
{
    Scanner s = { src.ptr, src.len, 0 };

    int num = 0;
    for (;;) {

        CONSUME_OPTIONAL_SEQUENCE(&s, is_space);

        TransferEncodingOption opt;
        if (0) {}
        else if (consume_str(&s, HTTP_STR("chunked")))  opt = TRANSFER_ENCODING_OPTION_CHUNKED;
        else if (consume_str(&s, HTTP_STR("compress"))) opt = TRANSFER_ENCODING_OPTION_COMPRESS;
        else if (consume_str(&s, HTTP_STR("deflate")))  opt = TRANSFER_ENCODING_OPTION_DEFLATE;
        else if (consume_str(&s, HTTP_STR("gzip")))     opt = TRANSFER_ENCODING_OPTION_GZIP;
        else return -1; // Invalid option

        if (num == max)
            return -1; // Too many options
        dst[num++] = opt;

        CONSUME_OPTIONAL_SEQUENCE(&s, is_space);

        if (s.cur == s.len)
            break;

        if (s.src[s.cur] != ',')
            return -1; // Missing comma separator
    }

    return num;
}

static int
parse_content_length(const char *src, int len, uint64_t *out)
{
    int cur = 0;
    while (cur < len && (src[cur] == ' ' || src[cur] == '\t'))
        cur++;

    if (cur == len || !is_digit(src[cur]))
        return -1;

    uint64_t buf = 0;
    do {
        int d = src[cur++] - '0';
        if (buf > (UINT64_MAX - d) / 10)
            return -1;
        buf = buf * 10 + d;
    } while (cur < len && is_digit(src[cur]));

    *out = buf;
    return 0;
}

static int parse_body(Scanner *s,
    HTTP_Header *headers, int num_headers,
    HTTP_String *body, bool body_expected)
{

    // RFC 9112 section 6:
    //   The presence of a message body in a request is signaled by a Content-Length or
    //   Transfer-Encoding header field. Request message framing is independent of method
    //   semantics.

    int header_index = http_find_header(headers, num_headers, HTTP_STR("Transfer-Encoding"));
    if (header_index != -1) {

        // RFC 9112 section 6.1:
        //   A server MAY reject a request that contains both Content-Length and Transfer-Encoding
        //   or process such a request in accordance with the Transfer-Encoding alone. Regardless,
        //   the server MUST close the connection after responding to such a request to avoid the
        //   potential attacks.
        if (http_find_header(headers, num_headers, HTTP_STR("Content-Length")) != -1)
            return -1;

        HTTP_String value = headers[header_index].value;

        // RFC 9112 section 6.1:
        //   If any transfer coding other than chunked is applied to a request's content, the
        //   sender MUST apply chunked as the final transfer coding to ensure that the message
        //   is properly framed. If any transfer coding other than chunked is applied to a
        //   response's content, the sender MUST either apply chunked as the final transfer
        //   coding or terminate the message by closing the connection.

        TransferEncodingOption opts[8];
        int num = parse_transfer_encoding(value, opts, HTTP_COUNT(opts));
        if (num != 1 || opts[0] != TRANSFER_ENCODING_OPTION_CHUNKED)
            return -1;

        HTTP_String chunks_maybe[128];
        HTTP_String *chunks = chunks_maybe;
        int num_chunks = 0;
        int max_chunks = HTTP_COUNT(chunks_maybe);

        #define FREE_CHUNK_LIST         \
            if (chunks != chunks_maybe) \
                free(chunks);

        char *content_start = s->src + s->cur;

        for (;;) {

            // RFC 9112 section 7.1:
            //   The chunked transfer coding wraps content in order to transfer it as a series of chunks,
            //   each with its own size indicator, followed by an OPTIONAL trailer section containing
            //   trailer fields.

            if (s->cur == s->len) {
                FREE_CHUNK_LIST
                return 0; // Incomplete request
            }

            if (!is_hex_digit(s->src[s->cur])) {
                FREE_CHUNK_LIST
                return -1;
            }

            int chunk_len = 0;

            do {
                char c = s->src[s->cur++];
                int  n = hex_digit_to_int(c);
                if (chunk_len > (INT_MAX - n) / 16) {
                    FREE_CHUNK_LIST
                    return -1; // overflow
                }
                chunk_len = chunk_len * 16 + n;
            } while (s->cur < s->len && is_hex_digit(s->src[s->cur]));

            if (s->cur == s->len) {
                FREE_CHUNK_LIST
                return 0; // Incomplete request
            }
            if (s->src[s->cur] != '\r') {
                FREE_CHUNK_LIST
                return -1;
            }
            s->cur++;

            if (s->cur == s->len) {
                FREE_CHUNK_LIST
                return 0;
            }
            if (s->src[s->cur] != '\n') {
                FREE_CHUNK_LIST
                return -1;
            }
            s->cur++;

            char *chunk_ptr = s->src + s->cur;

            if (chunk_len > s->len - s->cur) {
                FREE_CHUNK_LIST
                return 0; // Incomplete request
            }
            s->cur += chunk_len;

            if (s->cur == s->len)
                return 0; // Incomplete request
            if (s->src[s->cur] != '\r') {
                FREE_CHUNK_LIST
                return -1;
            }
            s->cur++;

            if (s->cur == s->len) {
                FREE_CHUNK_LIST
                return 0; // Incomplete request
            }
            if (s->src[s->cur] != '\n') {
                FREE_CHUNK_LIST
                return -1;
            }
            s->cur++;

            if (chunk_len == 0)
                break;

            if (num_chunks == max_chunks) {

                max_chunks *= 2;

                HTTP_String *new_chunks = malloc(max_chunks * sizeof(HTTP_String));
                if (new_chunks == NULL) {
                    if (chunks != chunks_maybe)
                        free(chunks);
                    return -1;
                }

                for (int i = 0; i < num_chunks; i++)
                    new_chunks[i] = chunks[i];

                if (chunks != chunks_maybe)
                    free(chunks);

                chunks = new_chunks;
            }
            chunks[num_chunks++] = (HTTP_String) { chunk_ptr, chunk_len };
        }

        char *content_ptr = content_start;
        for (int i = 0; i < num_chunks; i++) {
            memmove(content_ptr, chunks[i].ptr, chunks[i].len);
            content_ptr += chunks[i].len;
        }

        *body = (HTTP_String) {
            content_start,
            content_ptr - content_start
        };

        if (chunks != chunks_maybe)
            free(chunks);

        return 1;
    }

    // RFC 9112 section 6.3:
    //   If a valid Content-Length header field is present without Transfer-Encoding,
    //   its decimal value defines the expected message body length in octets.

    header_index = http_find_header(headers, num_headers, HTTP_STR("Content-Length"));
    if (header_index != -1) {

        // Have Content-Length
        HTTP_String value = headers[header_index].value;

        uint64_t tmp;
        if (parse_content_length(value.ptr, value.len, &tmp) < 0)
            return -1;
        if (tmp > INT_MAX)
            return -1;
        int len = (int) tmp;

        if (len > s->len - s->cur)
            return 0; // Incomplete request

        *body = (HTTP_String) { s->src + s->cur, len };

        s->cur += len;
        return 1;
    }

    // No Content-Length or Transfer-Encoding
    if (body_expected) return -1;

    *body = (HTTP_String) { NULL, 0 };
    return 1;
}

static int contains_head(char *src, int len)
{
    int cur = 0;
    while (len - cur > 3) {
        if (src[cur+0] == '\r' &&
            src[cur+1] == '\n' &&
            src[cur+2] == '\r' &&
            src[cur+3] == '\n')
            return 1;
        cur++;
    }
    return 0;
}

static int parse_request(Scanner *s, HTTP_Request *req)
{
    if (!contains_head(s->src + s->cur, s->len - s->cur))
        return 0;

    req->secure = false;

    if (0) {}
    else if (consume_str(s, HTTP_STR("GET ")))     req->method = HTTP_METHOD_GET;
    else if (consume_str(s, HTTP_STR("POST ")))    req->method = HTTP_METHOD_POST;
    else if (consume_str(s, HTTP_STR("PUT ")))     req->method = HTTP_METHOD_PUT;
    else if (consume_str(s, HTTP_STR("HEAD ")))    req->method = HTTP_METHOD_HEAD;
    else if (consume_str(s, HTTP_STR("DELETE ")))  req->method = HTTP_METHOD_DELETE;
    else if (consume_str(s, HTTP_STR("CONNECT "))) req->method = HTTP_METHOD_CONNECT;
    else if (consume_str(s, HTTP_STR("OPTIONS "))) req->method = HTTP_METHOD_OPTIONS;
    else if (consume_str(s, HTTP_STR("TRACE ")))   req->method = HTTP_METHOD_TRACE;
    else if (consume_str(s, HTTP_STR("PATCH ")))   req->method = HTTP_METHOD_PATCH;
    else return -1;

    {
        Scanner s2 = *s;
        int peek = s->cur;
        while (peek < s->len && s->src[peek] != ' ')
            peek++;
        if (peek == s->len)
            return -1;
        s2.len = peek;

        int ret = parse_request_target(&s2, &req->url);
        if (ret < 0) return ret;

        s->cur = s2.cur;
    }

    if (consume_str(s, HTTP_STR(" HTTP/1.1\r\n"))) {
        req->minor = 1;
    } else if (consume_str(s, HTTP_STR(" HTTP/1.0\r\n")) || consume_str(s, HTTP_STR(" HTTP/1\r\n"))) {
        req->minor = 0;
    } else {
        return -1;
    }

    int num_headers = parse_headers(s, req->headers, HTTP_MAX_HEADERS);
    if (num_headers < 0)
        return num_headers;
    req->num_headers = num_headers;

    // Request methods that typically don't have a body
    bool body_expected = true;
    if (req->method == HTTP_METHOD_GET ||
        req->method == HTTP_METHOD_HEAD ||
        req->method == HTTP_METHOD_DELETE ||
        req->method == HTTP_METHOD_OPTIONS ||
        req->method == HTTP_METHOD_TRACE)
        body_expected = false;

    return parse_body(s, req->headers, req->num_headers, &req->body, body_expected);
}

int http_find_header(HTTP_Header *headers, int num_headers, HTTP_String name)
{
	for (int i = 0; i < num_headers; i++)
		if (http_streqcase(name, headers[i].name))
			return i;
	return -1;
}

static int parse_response(Scanner *s, HTTP_Response *res)
{
	if (!contains_head(s->src + s->cur, s->len - s->cur))
		return 0;

    if (consume_str(s, HTTP_STR("HTTP/1.1 "))) {
        res->minor = 1;
    } else if (consume_str(s, HTTP_STR("HTTP/1.0 ")) || consume_str(s, HTTP_STR("HTTP/1 "))) {
        res->minor = 0;
    } else {
        return -1;
    }

    if (s->len - s->cur < 4
        || !is_digit(s->src[s->cur+0])
        || !is_digit(s->src[s->cur+1])
        || !is_digit(s->src[s->cur+2])
        || s->src[s->cur+3] != ' ')
        return -1;
    s->cur += 5;

    res->status =
        (s->src[s->cur-2] - '0') * 1 +
        (s->src[s->cur-3] - '0') * 10 +
        (s->src[s->cur-4] - '0') * 100;

    // Parse reason phrase: HTAB / SP / VCHAR / obs-text
    // Note: obs-text (obsolete text, octets 0x80-0xFF) is not validated
    while (s->cur < s->len && (
        s->src[s->cur] == '\t' ||
        s->src[s->cur] == ' ' ||
        is_vchar(s->src[s->cur])))
        s->cur++;

    if (s->len - s->cur < 2
        || s->src[s->cur+0] != '\r'
        || s->src[s->cur+1] != '\n')
        return -1;
    s->cur += 2;

    int num_headers = parse_headers(s, res->headers, HTTP_MAX_HEADERS);
    if (num_headers < 0)
        return num_headers;
    res->num_headers = num_headers;

    // Responses with certain status codes don't have a body:
    // - 1xx (Informational)
    // - 204 (No Content)
    // - 304 (Not Modified)
    // Note: HEAD responses also don't have a body, but we can't determine
    // that here without access to the request method
    bool body_expected = true;
    if ((res->status >= 100 && res->status < 200) ||
        res->status == 204 ||
        res->status == 304)
        body_expected = false;

    return parse_body(s, res->headers, res->num_headers, &res->body, body_expected);
}

int http_parse_ipv4(char *src, int len, HTTP_IPv4 *ipv4)
{
    Scanner s = {src, len, 0};
    int ret = parse_ipv4(&s, ipv4);
    if (ret < 0) return ret;
    return s.cur;
}

int http_parse_ipv6(char *src, int len, HTTP_IPv6 *ipv6)
{
    Scanner s = {src, len, 0};
    int ret = parse_ipv6(&s, ipv6);
    if (ret < 0) return ret;
    return s.cur;
}

int http_parse_url(char *src, int len, HTTP_URL *url)
{
    Scanner s = {src, len, 0};
    int ret = parse_uri(&s, url, 1);
    if (ret == 1)
        return s.cur;
    return ret;
}

int http_parse_request(char *src, int len, HTTP_Request *req)
{
    Scanner s = {src, len, 0};
    int ret = parse_request(&s, req);
    if (ret == 1)
        return s.cur;
    return ret;
}

int http_parse_response(char *src, int len, HTTP_Response *res)
{
    Scanner s = {src, len, 0};
    int ret = parse_response(&s, res);
    if (ret == 1)
        return s.cur;
    return ret;
}

HTTP_String http_get_cookie(HTTP_Request *req, HTTP_String name)
{
    // Simple cookie parsing - does not handle quoted values or special characters
    // See RFC 6265 for full cookie specification

    for (int i = 0; i < req->num_headers; i++) {

        if (!http_streqcase(req->headers[i].name, HTTP_STR("Cookie")))
            continue;

        char *src = req->headers[i].value.ptr;
        int   len = req->headers[i].value.len;
        int   cur = 0;

        // Cookie: name1=value1; name2=value2; name3=value3

        for (;;) {

            while (cur < len && src[cur] == ' ')
                cur++;

            int off = cur;
            while (cur < len && src[cur] != '=')
                cur++;

            HTTP_String cookie_name = { src + off, cur - off };

            if (cur == len)
                break;
            cur++;

            off = cur;
            while (cur < len && src[cur] != ';')
                cur++;

            HTTP_String cookie_value = { src + off, cur - off };

            if (http_streq(name, cookie_name))
                return cookie_value;

            if (cur == len)
                break;
            cur++;
        }
    }

    return HTTP_STR("");
}

HTTP_String http_get_param(HTTP_String body, HTTP_String str, char *mem, int cap)
{
    // This is just a best-effort implementation

    char *src = body.ptr;
    int   len = body.len;
    int   cur = 0;

    if (cur < len && src[cur] == '?')
        cur++;

    while (cur < len) {

        HTTP_String name;
        {
            int off = cur;
            while (cur < len && src[cur] != '=' && src[cur] != '&')
                cur++;
            name = (HTTP_String) { src + off, cur - off };
        }

        HTTP_String body = HTTP_STR("");
        if (cur < len) {
            cur++;
            if (src[cur-1] == '=') {
                int off = cur;
                while (cur < len && src[cur] != '&')
                    cur++;
                body = (HTTP_String) { src + off, cur - off };

                if (cur < len)
                    cur++;
            }
        }

        if (http_streq(str, name)) {

            bool percent_encoded = false;
            for (int i = 0; i < body.len; i++)
                if (body.ptr[i] == '+' || body.ptr[i] == '%') {
                    percent_encoded = true;
                    break;
                }

            if (!percent_encoded)
                return body;

            if (body.len > cap)
                return (HTTP_String) { NULL, 0 };

            HTTP_String decoded = { mem, 0 };
            for (int i = 0; i < body.len; i++) {

                char c = body.ptr[i];
                if (c == '+')
                    c = ' ';
                else {
                    if (body.ptr[i] == '%') {
                        if (body.len - i < 3
                            || !is_hex_digit(body.ptr[i+1])
                            || !is_hex_digit(body.ptr[i+2]))
                            return (HTTP_String) { NULL, 0 };

                        int h = hex_digit_to_int(body.ptr[i+1]);
                        int l = hex_digit_to_int(body.ptr[i+2]);
                        c = (h << 4) | l;

                        i += 2;
                    }
                }

                decoded.ptr[decoded.len++] = c;
            }

            return decoded;
        }
    }

    return HTTP_STR("");
}

int http_get_param_i(HTTP_String body, HTTP_String str)
{
    char buf[128];
    HTTP_String out = http_get_param(body, str, buf, (int) sizeof(buf));
    if (out.len == 0 || !is_digit(out.ptr[0]))
        return -1;

    int cur = 0;
    int res = 0;
    do {
        int d = out.ptr[cur++] - '0';
        if (res > (INT_MAX - d) / 10)
            return -1;
        res = res * 10 + d;
    } while (cur < out.len && is_digit(out.ptr[cur]));

    return res;
}

bool http_match_host(HTTP_Request *req, HTTP_String domain, int port)
{
    int idx = http_find_header(req->headers, req->num_headers, HTTP_STR("Host"));
    assert(idx != -1); // Requests without the host header are always rejected

    char tmp[1<<8];
    if (port > -1 && port != 80) {
        int ret = snprintf(tmp, sizeof(tmp), "%.*s:%d", domain.len, domain.ptr, port);
        assert(ret > 0);
        domain = (HTTP_String) { tmp, ret };
    }

    HTTP_String host = req->headers[idx].value;
    return http_streq(host, domain);
}


// <day-name>, <day> <month> <year> <hour>:<minute>:<second> GMT
static int parse_date(Scanner *s, HTTP_Date *out)
{
    struct { HTTP_String str; HTTP_WeekDay val; } week_day_table[] = {
        { HTTP_STR("Mon, "), HTTP_WEEKDAY_MON },
        { HTTP_STR("Tue, "), HTTP_WEEKDAY_TUE },
        { HTTP_STR("Wed, "), HTTP_WEEKDAY_WED },
        { HTTP_STR("Thu, "), HTTP_WEEKDAY_THU },
        { HTTP_STR("Fri, "), HTTP_WEEKDAY_FRI },
        { HTTP_STR("Sat, "), HTTP_WEEKDAY_SAT },
        { HTTP_STR("Sun, "), HTTP_WEEKDAY_SUN },
    };

    bool found = false;
    for (int i = 0; i < HTTP_COUNT(week_day_table); i++)
        if (consume_str(s, week_day_table[i].str)) {
            out->week_day = week_day_table[i].val;
            found = true;
            break;
        }
    if (!found)
        return -1;

    if (1 >= s->len - s->cur
        || !is_digit(s->src[s->cur+0])
        || !is_digit(s->src[s->cur+1]))
        return -1;
    out->day
        = (s->src[s->cur+0] - '0') * 10
        + (s->src[s->cur+1] - '0') * 1;
    s->cur += 2;

    struct { HTTP_String str; HTTP_Month val; } month_table[] = {
        { HTTP_STR(" Jan "), HTTP_MONTH_JAN },
        { HTTP_STR(" Feb "), HTTP_MONTH_FEB },
        { HTTP_STR(" Mar "), HTTP_MONTH_MAR },
        { HTTP_STR(" Apr "), HTTP_MONTH_APR },
        { HTTP_STR(" May "), HTTP_MONTH_MAY },
        { HTTP_STR(" Jun "), HTTP_MONTH_JUN },
        { HTTP_STR(" Jul "), HTTP_MONTH_JUL },
        { HTTP_STR(" Aug "), HTTP_MONTH_AUG },
        { HTTP_STR(" Sep "), HTTP_MONTH_SEP },
        { HTTP_STR(" Oct "), HTTP_MONTH_OCT },
        { HTTP_STR(" Nov "), HTTP_MONTH_NOV },
        { HTTP_STR(" Dec "), HTTP_MONTH_DEC },
    };

    found = false;
    for (int i = 0; i < HTTP_COUNT(month_table); i++)
        if (consume_str(s, month_table[i].str)) {
            out->month = month_table[i].val;
            found = true;
            break;
        }
    if (!found)
        return -1;

    if (3 >= s->len - s->cur
        || !is_digit(s->src[s->cur+0])
        || !is_digit(s->src[s->cur+1])
        || !is_digit(s->src[s->cur+2])
        || !is_digit(s->src[s->cur+3]))
        return -1;
    out->year
        = (s->src[s->cur+0] - '0') * 1000
        + (s->src[s->cur+1] - '0') * 100
        + (s->src[s->cur+2] - '0') * 10
        + (s->src[s->cur+3] - '0') * 1;
    s->cur += 4;

    if (s->cur == s->len || s->src[s->cur] != ' ')
        return -1;
    s->cur++;

    if (7 >= s->len - s->cur
        || !is_digit(s->src[s->cur+0])
        || !is_digit(s->src[s->cur+1])
        || s->src[s->cur+2] != ':'
        || !is_digit(s->src[s->cur+3])
        || !is_digit(s->src[s->cur+4])
        || s->src[s->cur+5] != ':'
        || !is_digit(s->src[s->cur+6])
        || !is_digit(s->src[s->cur+7])
        || s->src[s->cur+8] != ' '
        || s->src[s->cur+9] != 'G'
        || s->src[s->cur+10] != 'M'
        || s->src[s->cur+11] != 'T')
        return -1;
    out->hour
        = (s->src[s->cur+0] - '0') * 10
        + (s->src[s->cur+1] - '0') * 1;
    out->minute
        = (s->src[s->cur+3] - '0') * 10
        + (s->src[s->cur+4] - '0') * 1;
    out->second
        = (s->src[s->cur+6] - '0') * 10
        + (s->src[s->cur+7] - '0') * 1;
    s->cur += 12;
    return 0;
}

// cookie-octet = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
//              ; US-ASCII characters excluding CTLs,
//              ; whitespace, DQUOTE, comma, semicolon,
//              ; and backslash
static bool is_cookie_octet(char c)
{
    return c == 0x21 ||
           (c >= 0x23 && c <= 0x2B) ||
           (c >= 0x2D && c <= 0x3A) ||
           (c >= 0x3C && c <= 0x5B) ||
           (c >= 0x5D && c <= 0x7E);
}

int http_parse_set_cookie(HTTP_String str, HTTP_SetCookie *out)
{
    Scanner s = { str.ptr, str.len, 0 };

    // cookie-name = token
    if (s.cur == s.len || !is_tchar(s.src[s.cur]))
        return -1;
    int off = s.cur;
    do
        s.cur++;
    while (s.cur < s.len && is_tchar(s.src[s.cur]));
    out->name = (HTTP_String) { s.src + off, s.cur - off };

    // cookie-pair = cookie-name "=" cookie-value
    if (s.cur == s.len || s.src[s.cur] != '=')
        return -1;
    s.cur++;

    // cookie-value = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
    if (s.cur < s.len && s.src[s.cur] == '"') {
        s.cur++; // Consume opening double quote
        int off = s.cur;
        while (s.cur < s.len && is_cookie_octet(s.src[s.cur]))
            s.cur++;
        if (s.cur == s.len || s.src[s.cur] != '"')
            return -1; // Missing closing double quote
        out->value = (HTTP_String) { s.src + off, s.cur - off };
        s.cur++; // Consume closing double quote
    } else {
        int off = s.cur;
        while (s.cur < s.len && is_cookie_octet(s.src[s.cur]))
            s.cur++;
        out->value = (HTTP_String) { s.src + off, s.cur - off };
    }

    // *( ";" SP cookie-av )
    //
    // cookie-av = expires-av / max-age-av / domain-av /
    //             path-av / secure-av / httponly-av /
    //             extension-av
    out->secure = false;
    out->http_only = false;
    out->have_date = false;
    out->have_max_age = false;
    out->have_domain = false;
    out->have_path = false;
    while (consume_str(&s, HTTP_STR("; "))) {
        if (consume_str(&s, HTTP_STR("Expires="))) {

            // expires-av = "Expires=" sane-cookie-date
            if (parse_date(&s, &out->date) < 0)
                return -1;
            out->have_date = true;

        } else if (consume_str(&s, HTTP_STR("Max-Age="))) {

            // max-age-av = "Max-Age=" non-zero-digit *DIGIT

            uint32_t value = 0;
            if (s.cur == s.len || !is_digit(s.src[s.cur]))
                return -1;
            do {
                int d = s.src[s.cur++] - '0';
                if (value > (UINT32_MAX - d) / 10)
                    return -1;
                value = value * 10 + d;
            } while (s.cur < s.len && is_digit(s.src[s.cur]));

            out->have_max_age = true;
            out->max_age = value;

        } else if (consume_str(&s, HTTP_STR("Domain="))) {

            // domain-av = "Domain=" domain-value
            // domain-value = <subdomain>
            //              ; defined in RFC 1034, Section 3.5
            //
            // From RFC 1034:
            //   <subdomain> ::= <label> | <subdomain> "." <label>
            //   <label> ::= <letter> [ [ <ldh-str> ] <let-dig> ]
            //   <ldh-str> ::= <let-dig-hyp> | <let-dig-hyp> <ldh-str>
            //   <let-dig-hyp> ::= <let-dig> | "-"
            //   <let-dig> ::= <letter> | <digit>
            //   <letter> ::= any one of the 52 alphabetic characters A through Z in upper case and a through z in lower case
            //   <digit> ::= any one of the ten digits 0 through 9
            //
            // If my understanding is correct, a domain is a list of labels
            // concatenated by dots. Each label may contain letters, digits,
            // hyphens, but the first character must be a letter and the last
            // one can't be a hyphen.

            int off = s.cur;
            if (s.cur == s.len || !is_alpha(s.src[s.cur]))
                return -1;
            do
                s.cur++;
            while (s.cur < s.len && (
                is_digit(s.src[s.cur]) ||
                is_alpha(s.src[s.cur]) ||
                s.src[s.cur] == '-'));

            if (s.src[s.cur-1] == '-')
                return -1;

            while (s.cur < s.len && s.src[s.cur] == '.') {
                s.cur++; // Consume dot

                if (s.cur == s.len || !is_alpha(s.src[s.cur]))
                    return -1;
                do
                    s.cur++;
                while (s.cur < s.len && (
                    is_digit(s.src[s.cur]) ||
                    is_alpha(s.src[s.cur]) ||
                    s.src[s.cur] == '-'));

                if (s.src[s.cur-1] == '-')
                    return -1;
            }

            out->have_domain = true;
            out->domain = (HTTP_String) { s.src + off, s.cur - off };

        } else if (consume_str(&s, HTTP_STR("Path="))) {

            // path-av = "Path=" path-value
            // path-value = <any CHAR except CTLs or ";">

            int off = s.cur;
            while (s.cur < s.len && s.src[s.cur] >= 0x20 && s.src[s.cur] != 0x7F && s.src[s.cur] != ';')
                s.cur++;

            out->have_path = true;
            out->path = (HTTP_String) { s.src + off, s.cur - off };

        } else if (consume_str(&s, HTTP_STR("Secure"))) {

            // secure-av = "Secure"
            out->secure = true;

        } else if (consume_str(&s, HTTP_STR("HttpOnly"))) {

            // httponly-av = "HttpOnly"
            out->http_only = true;

        } else {
            return -1; // Invalid attribute
        }
    }

    return 0;
}
