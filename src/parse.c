#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "parse.h"
#include "basic.h"

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
	//  URI-reference = <URI-reference, see [URI], Section 4.1>
	//  absolute-URI  = <absolute-URI, see [URI], Section 4.3>
	//  relative-part = <relative-part, see [URI], Section 4.2>
	//  authority     = <authority, see [URI], Section 3.2>
	//  uri-host      = <host, see [URI], Section 3.2.2>
	//  port          = <port, see [URI], Section 3.2.3>
	//  path-abempty  = <path-abempty, see [URI], Section 3.3>
	//  segment       = <segment, see [URI], Section 3.3>
	//  query         = <query, see [URI], Section 3.4>
	//
	//  absolute-path = 1*( "/" segment )
	//  partial-URI   = relative-part [ "?" query ]
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

static int
consume_absolute_path(Scanner *s)
{
	if (s->cur == s->len || s->src[s->cur] != '/')
		return -1; // ERROR
	s->cur++;

	for (;;) {

		while (s->cur < s->len && is_pchar(s->src[s->cur]))
			s->cur++;

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

				while (s->cur < s->len && is_pchar(s->src[s->cur]))
					s->cur++;

				if (s->cur == s->len || s->src[s->cur] != '/')
					break;
				s->cur++;
			}
		}

	} else if (s->cur < s->len && is_pchar(s->src[s->cur])) {

		// path-rootless
		s->cur++;
		for (;;) {

			while (s->cur < s->len && is_pchar(s->src[s->cur]))
				s->cur++;

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
static int is_userinfo(char c)
{
	return is_unreserved(c) || is_sub_delim(c) || c == ':'; // TODO: PCT encoded
}

// authority = [ userinfo "@" ] host [ ":" port ]
static int parse_authority(Scanner *s, HTTP_Authority *authority)
{
	HTTP_String userinfo;
	{
		int start = s->cur;
		while (s->cur < s->len && is_userinfo(s->src[s->cur]))
			s->cur++;
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

static int is_header_body(char c)
{
	return is_vchar(c) || c == ' ' || c == '\t';
}

static int parse_headers(Scanner *s, HTTP_Header *headers, int max_headers)
{
	int num_headers = 0;
	for (;;) {

		if (s->len - s->cur > 1
			&& s->src[s->cur+0] == '\r'
			&& s->src[s->cur+1] == '\n') {
			s->cur += 2;
			break;
		}

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
		while (s->cur < s->len && is_header_body(s->src[s->cur]))
			s->cur++;
		HTTP_String body = { s->src + start, s->cur - start };
		body = http_trim(body);

		if (s->len - s->cur < 2
			|| s->src[s->cur+0] != '\r'
			|| s->src[s->cur+1] != '\n')
			return -1; // ERROR
		s->cur += 2;

		if (num_headers < max_headers)
			headers[num_headers++] = (HTTP_Header) { name, body };
	}

	return num_headers;
}

static int
parse_content_length(const char *src, int len, unsigned long long *out)
{
	int cur = 0;
	while (cur < len && (src[cur] == ' ' || src[cur] == '\t'))
		cur++;

	if (cur == len || !is_digit(src[cur]))
		return -1;

	unsigned long long buf = 0;
	do {
		int d = src[cur++] - '0';
		if (buf > (UINT64_MAX - d) / 10)
			return -1;
		buf = buf * 10 + d;
	} while (cur < len && is_digit(src[cur]));

	*out = buf;
	return 0;
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

	if (s->len - s->cur >= 3
		&& s->src[s->cur+0] == 'G'
		&& s->src[s->cur+1] == 'E'
		&& s->src[s->cur+2] == 'T') {
		s->cur += 3;
		req->method = HTTP_METHOD_GET;
	} else if (s->len - s->cur >= 4
		&& s->src[s->cur+0] == 'P'
		&& s->src[s->cur+1] == 'O'
		&& s->src[s->cur+2] == 'S'
		&& s->src[s->cur+3] == 'T') {
		s->cur += 4;
		req->method = HTTP_METHOD_POST;
	} else if (s->len - s->cur >= 3
		&& s->src[s->cur+0] == 'P'
		&& s->src[s->cur+1] == 'U'
		&& s->src[s->cur+2] == 'T') {
		s->cur += 3;
		req->method = HTTP_METHOD_PUT;
	} else if (s->len - s->cur >= 4
		&& s->src[s->cur+0] == 'H'
		&& s->src[s->cur+1] == 'E'
		&& s->src[s->cur+2] == 'A'
		&& s->src[s->cur+3] == 'D') {
		s->cur += 4;
		req->method = HTTP_METHOD_HEAD;
	} else if (s->len - s->cur >= 6
		&& s->src[s->cur+0] == 'D'
		&& s->src[s->cur+1] == 'E'
		&& s->src[s->cur+2] == 'L'
		&& s->src[s->cur+3] == 'E'
		&& s->src[s->cur+4] == 'T'
		&& s->src[s->cur+5] == 'E') {
		s->cur += 6;
		req->method = HTTP_METHOD_DELETE;
	} else if (s->len - s->cur >= 7
		&& s->src[s->cur+0] == 'C'
		&& s->src[s->cur+1] == 'O'
		&& s->src[s->cur+2] == 'N'
		&& s->src[s->cur+3] == 'N'
		&& s->src[s->cur+4] == 'E'
		&& s->src[s->cur+5] == 'C'
		&& s->src[s->cur+6] == 'T') {
		s->cur += 7;
		req->method = HTTP_METHOD_CONNECT;
	} else if (s->len - s->cur >= 7
		&& s->src[s->cur+0] == 'O'
		&& s->src[s->cur+1] == 'P'
		&& s->src[s->cur+2] == 'T'
		&& s->src[s->cur+3] == 'I'
		&& s->src[s->cur+4] == 'O'
		&& s->src[s->cur+5] == 'N'
		&& s->src[s->cur+6] == 'S') {
		s->cur += 7;
		req->method = HTTP_METHOD_OPTIONS;
	} else if (s->len - s->cur >= 5
		&& s->src[s->cur+0] == 'T'
		&& s->src[s->cur+1] == 'R'
		&& s->src[s->cur+2] == 'A'
		&& s->src[s->cur+3] == 'C'
		&& s->src[s->cur+4] == 'E') {
		s->cur += 5;
		req->method = HTTP_METHOD_TRACE;
	} else if (s->len - s->cur >= 5
		&& s->src[s->cur+0] == 'P'
		&& s->src[s->cur+1] == 'A'
		&& s->src[s->cur+2] == 'T'
		&& s->src[s->cur+3] == 'C'
		&& s->src[s->cur+4] == 'H') {
		s->cur += 5;
		req->method = HTTP_METHOD_PATCH;
	} else {
		return -1;
	}

	if (s->cur == s->len || s->src[s->cur] != ' ')
		return -1;
	s->cur++;

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

	{
		if (s->len - s->cur < 7
			|| s->src[s->cur+0] != ' '
			|| s->src[s->cur+1] != 'H'
			|| s->src[s->cur+2] != 'T'
			|| s->src[s->cur+3] != 'T'
			|| s->src[s->cur+4] != 'P'
			|| s->src[s->cur+5] != '/'
			|| s->src[s->cur+6] != '1')
			return -1; // ERROR
		s->cur += 7;

		if (s->cur == s->len || s->src[s->cur] != '.')
			req->minor = 0;
		else {
			s->cur++;
			if (s->cur == s->len || !is_digit(s->src[s->cur]))
				return -1; // ERROR;
			req->minor = s->src[s->cur] - '0';
			s->cur++;
		}

		if (s->len - s->cur < 2
			|| s->src[s->cur+0] != '\r'
			|| s->src[s->cur+1] != '\n')
			return -1; // ERROR
		s->cur += 2;
	}

	int num_headers = parse_headers(s, req->headers, HTTP_MAX_HEADERS);
	if (num_headers < 0)
		return num_headers;
	req->num_headers = num_headers;

	// TODO
	return 1;
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

	if (s->len - s->cur < 6
		|| s->src[s->cur+0] != 'H'
		|| s->src[s->cur+1] != 'T'
		|| s->src[s->cur+2] != 'T'
		|| s->src[s->cur+3] != 'P'
		|| s->src[s->cur+4] != '/'
		|| s->src[s->cur+5] != '1')
		return -1; // ERROR
	s->cur += 6;

	if (s->cur == s->len || s->src[s->cur] != '.')
		res->minor = 0;
	else {
		s->cur++;
		if (s->cur == s->len || !is_digit(s->src[s->cur]))
			return -1; // ERROR
		res->minor = s->src[s->cur] - '0';
		s->cur++;
	}

	if (s->len - s->cur < 5
		|| s->src[s->cur+0] != ' '
		|| !is_digit(s->src[s->cur+1])
		|| !is_digit(s->src[s->cur+2])
		|| !is_digit(s->src[s->cur+3])
		|| s->src[s->cur+4] != ' ')
		return -1;
	s->cur += 5;

	res->status =
		(s->src[s->cur-2] - '0') * 1 +
		(s->src[s->cur-3] - '0') * 10 +
		(s->src[s->cur-4] - '0') * 100;

	while (s->cur < s->len && (
		s->src[s->cur] == '\t' ||
		s->src[s->cur] == ' ' ||
		is_vchar(s->src[s->cur]))) // TODO: obs-text
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

	int content_length_index = http_find_header(
		res->headers, res->num_headers,
		HTTP_STR("Content-Length"));
	if (content_length_index == -1) {
		res->body.ptr = NULL;
		res->body.len = 0;
		return 1;
	}

	// TODO: transfer-encoding

	HTTP_String content_length_str = res->headers[content_length_index].value;

	unsigned long long content_length;
	if (parse_content_length(content_length_str.ptr, content_length_str.len, &content_length) < 0) {
		HTTP_ASSERT(0); // TODO
	}

	if (content_length > 1<<20) {
		HTTP_ASSERT(0); // TODO
	}

	if (content_length > (unsigned long long) (s->len - s->cur))
		return 0;

	res->body.ptr = s->src + s->cur;
	res->body.len = content_length;
	return 1;
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

HTTP_String http_getqueryparam(HTTP_Request *req, HTTP_String name)
{
    // TODO
	return (HTTP_String) {NULL, 0};
}

HTTP_String http_getbodyparam(HTTP_Request *req, HTTP_String name)
{
	// TODO
	return (HTTP_String) {NULL, 0};
}

HTTP_String http_getcookie(HTTP_Request *req, HTTP_String name)
{
	// TODO
	return (HTTP_String) {NULL, 0};
}
