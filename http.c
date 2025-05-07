#include "http.h"

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#define ASSERT(X) {if (!(X)) __builtin_trap();}
#define UNREACHABLE __builtin_trap();

int http_streq(HTTP_String s1, HTTP_String s2)
{
	if (s1.len != s2.len)
		return 0;
	for (int i = 0; i < s1.len; i++)
		if (s1.ptr[i] != s2.ptr[i])
			return 0;
	return 1;
}

static char to_lower(char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A' + 'a';
	return c;
}

int http_streqcase(HTTP_String s1, HTTP_String s2)
{
	if (s1.len != s2.len)
		return 0;
	for (int i = 0; i < s1.len; i++)
		if (to_lower(s1.ptr[i]) != to_lower(s2.ptr[i]))
			return 0;
	return 1;
}

HTTP_String http_trim(HTTP_String s)
{
	int i = 0;
	while (i < s.len && (s.ptr[i] == ' ' || s.ptr[i] == '\t'))
		i++;

	if (i == s.len) {
		s.ptr = NULL;
		s.len = 0;
	} else {
		s.ptr += i;
		s.len -= i;
		while (s.ptr[s.len-1] == ' ' || s.ptr[s.len-1] == '\t')
			s.len--;
	}

	return s;
}

/////////////////////////////////////////////////////////////////////
// HTTP PARSER
/////////////////////////////////////////////////////////////////////

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

	unsigned long long content_length;
	for (int i = 0; i < num_headers; i++)
		if (http_streqcase(res->headers[i].name, HTTP_STR("Content-Length"))) {
			if (parse_content_length(res->headers[i].value.ptr, res->headers[i].value.len, &content_length) < 0)
				return -1;
			break;
		}

	if (content_length > 1<<20) {
		// TODO
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

/////////////////////////////////////////////////////////////////////
// HTTP BYTE QUEUE
/////////////////////////////////////////////////////////////////////
#if HTTP_ENGINE

// This is the implementation of a byte queue useful
// for systems that need to process engs of bytes.
//
// It features sticky errors, a zero-copy interface,
// and a safe mechanism to patch previously written
// bytes.
//
// Only up to 4GB of data can be stored at once.

enum {
	BYTE_QUEUE_ERROR = 1 << 0,
	BYTE_QUEUE_READ  = 1 << 1,
	BYTE_QUEUE_WRITE = 1 << 2,
};

static void*
callback_malloc(HTTP_ByteQueue *queue, int len)
{
	return queue->memfunc(HTTP_MEMFUNC_MALLOC, NULL, len, queue->memfuncdata);
}

static void
callback_free(HTTP_ByteQueue *queue, void *ptr, int len)
{
	queue->memfunc(HTTP_MEMFUNC_FREE, ptr, len, queue->memfuncdata);
}

// Initialize the queue
static void
byte_queue_init(HTTP_ByteQueue *queue, unsigned int limit, HTTP_MemoryFunc memfunc, void *memfuncdata)
{
	queue->flags = 0;
	queue->head = 0;
	queue->size = 0;
	queue->used = 0;
	queue->curs = 0;
	queue->limit = limit;
	queue->data = NULL;
	queue->read_target = NULL;
	queue->memfunc = memfunc;
	queue->memfuncdata = memfuncdata;
}

// Deinitialize the queue
static void
byte_queue_free(HTTP_ByteQueue *queue)
{
	if (queue->read_target) {
		if (queue->read_target != queue->data)
			callback_free(queue, queue->read_target, queue->read_target_size);
		queue->read_target = NULL;
		queue->read_target_size = 0;
	}

	callback_free(queue, queue->data, queue->size);
	queue->data = NULL;
}

static int
byte_queue_error(HTTP_ByteQueue *queue)
{
	return queue->flags & BYTE_QUEUE_ERROR;
}

static void
byte_queue_setlimit(HTTP_ByteQueue *queue, unsigned int value)
{
	queue->limit = value;
}

static int
byte_queue_empty(HTTP_ByteQueue *queue)
{
	return queue->used == 0;
}

// Start a read operation on the queue.
//
// This function returnes the pointer to the memory region containing the bytes
// to read. Callers can't read more than [*len] bytes from it. To complete the
// read, the [byte_queue_read_ack] function must be called with the number of
// bytes that were acknowledged by the caller.
//
// Note:
//   - You can't have more than one pending read.
static char*
byte_queue_read_buf(HTTP_ByteQueue *queue, int *len)
{
	if (queue->flags & BYTE_QUEUE_ERROR) {
		*len = 0;
		return NULL;
	}

	ASSERT((queue->flags & BYTE_QUEUE_READ) == 0);
	queue->flags |= BYTE_QUEUE_READ;
	queue->read_target      = queue->data;
	queue->read_target_size = queue->size;

	*len = queue->used;
	if (queue->data == NULL)
		return NULL;
	return queue->data + queue->head;
}

// Complete a previously started operation on the queue.
static void
byte_queue_read_ack(HTTP_ByteQueue *queue, int num)
{
	ASSERT(num >= 0);

	if (queue->flags & BYTE_QUEUE_ERROR)
		return;

	if ((queue->flags & BYTE_QUEUE_READ) == 0)
		return;

	queue->flags &= ~BYTE_QUEUE_READ;

	ASSERT((unsigned int) num <= queue->used);
	queue->head += (unsigned int) num;
	queue->used -= (unsigned int) num;
	queue->curs += (unsigned int) num;

	if (queue->read_target) {
		if (queue->read_target != queue->data)
			callback_free(queue, queue->read_target, queue->read_target_size);
		queue->read_target = NULL;
		queue->read_target_size = 0;
	}
}

static char*
byte_queue_write_buf(HTTP_ByteQueue *queue, int *cap)
{
	if ((queue->flags & BYTE_QUEUE_ERROR) || queue->data == NULL) {
		*cap = 0;
		return NULL;
	}

	ASSERT((queue->flags & BYTE_QUEUE_WRITE) == 0);
	queue->flags |= BYTE_QUEUE_WRITE;

	unsigned int ucap = queue->size - (queue->head + queue->used);
	if (ucap > INT_MAX) ucap = INT_MAX;

	*cap = (int) ucap;
	return queue->data + (queue->head + queue->used);
}

static void
byte_queue_write_ack(HTTP_ByteQueue *queue, int num)
{
	ASSERT(num >= 0);

	if (queue->flags & BYTE_QUEUE_ERROR)
		return;

	if ((queue->flags & BYTE_QUEUE_WRITE) == 0)
		return;

	queue->flags &= ~BYTE_QUEUE_WRITE;
	queue->used += (unsigned int) num;
}

// Sets the minimum capacity for the next write operation
// and returns 1 if the content of the queue was moved, else
// 0 is returned.
//
// You must not call this function while a write is pending.
// In other words, you must do this:
//
//   byte_queue_write_setmincap(queue, mincap);
//   dst = byte_queue_write_buf(queue, &cap);
//   ...
//   byte_queue_write_ack(num);
//
// And NOT this:
//
//   dst = byte_queue_write_buf(queue, &cap);
//   byte_queue_write_setmincap(queue, mincap); <-- BAD
//   ...
//   byte_queue_write_ack(num);
//
static int
byte_queue_write_setmincap(HTTP_ByteQueue *queue, int mincap)
{
	ASSERT(mincap >= 0);
	unsigned int umincap = (unsigned int) mincap;

	// Sticky error
	if (queue->flags & BYTE_QUEUE_ERROR)
		return 0;

	// In general, the queue's contents look like this:
	//
	//                           size
	//                           v
	//   [___xxxxxxxxxxxx________]
	//   ^   ^           ^
	//   0   head        head + used
	//
	// This function needs to make sure that at least [mincap]
	// bytes are available on the right side of the content.
	//
	// We have 3 cases:
	//
	//   1) If there is enough memory already, this function doesn't
	//      need to do anything.
	//
	//   2) If there isn't enough memory on the right but there is
	//      enough free memory if we cound the left unused region,
	//      then the content is moved back to the
	//      start of the buffer.
	//
	//   3) If there isn't enough memory considering both sides, this
	//      function needs to allocate a new buffer.
	//
	// If there are pending read or write operations, the application
	// is holding pointers to the buffer, so we need to make sure
	// to not invalidate them. The only real problem is pending reads
	// since this function can only be called before starting a write
	// opearation.
	//
	// To avoid invalidating the read pointer when we allocate a new
	// buffer, we don't free the old buffer. Instead, we store the
	// pointer in the "old" field so that the read ack function can
	// free it.
	//
	// To avoid invalidating the pointer when we are moving back the
	// content since there is enough memory at the start of the buffer,
	// we just avoid that. Even if there is enough memory considering
	// left and right free regions, we allocate a new buffer.

	ASSERT((queue->flags & BYTE_QUEUE_WRITE) == 0);

	unsigned int total_free_space = queue->size - queue->used;
	unsigned int free_space_after_data = queue->size - queue->used - queue->head;

	int moved = 0;
	if (free_space_after_data < umincap) {

		if (total_free_space < umincap || (queue->read_target == queue->data)) {
			// Resize required

			if (queue->used + umincap > queue->limit) {
				queue->flags |= BYTE_QUEUE_ERROR;
				return 0;
			}

			unsigned int size;
			if (queue->size > UINT32_MAX / 2)
				size = UINT32_MAX;
			else
				size = 2 * queue->size;

			if (size < queue->used + umincap)
				size = queue->used + umincap;

			if (size > queue->limit)
				size = queue->limit;

			char *data = callback_malloc(queue, size);
			if (!data) {
				queue->flags |= BYTE_QUEUE_ERROR;
				return 0;
			}

			if (queue->used > 0)
				memcpy(data, queue->data + queue->head, queue->used);

			if (queue->read_target != queue->data)
				callback_free(queue, queue->data, queue->size);

			queue->data = data;
			queue->head = 0;
			queue->size = size;

		} else {
			// Move required
			memmove(queue->data, queue->data + queue->head, queue->used);
			queue->head = 0;
		}

		moved = 1;
	}

	return moved;
}

static HTTP_ByteQueueOffset
byte_queue_offset(HTTP_ByteQueue *queue)
{
	if (queue->flags & BYTE_QUEUE_ERROR)
		return (HTTP_ByteQueueOffset) { 0 };
	return (HTTP_ByteQueueOffset) { queue->curs + queue->used };
}

static unsigned int
byte_queue_size_from_offset(HTTP_ByteQueue *queue, HTTP_ByteQueueOffset off)
{
	return queue->curs + queue->used - off;
}

static void
byte_queue_patch(HTTP_ByteQueue *queue, HTTP_ByteQueueOffset off,
	char *src, unsigned int len)
{
	// Check that the offset is in range
	ASSERT(off >= queue->curs && off - queue->curs < queue->used);

	// Check that the length is in range
	ASSERT(len <= queue->used - (off - queue->curs));

	// Perform the patch
	char *dst = queue->data + queue->head + (off - queue->curs);
	memcpy(dst, src, len);
}

static void
byte_queue_remove_from_offset(HTTP_ByteQueue *queue, HTTP_ByteQueueOffset offset)
{
	unsigned long long num = (queue->curs + queue->used) - offset;
	ASSERT(num <= queue->used);

	queue->used -= num;
}

static void
byte_queue_write(HTTP_ByteQueue *queue, const char *str, int len)
{
	if (len < 0) len = strlen(str);

	int cap;
	byte_queue_write_setmincap(queue, len);
	char *dst = byte_queue_write_buf(queue, &cap);
	if (dst) memcpy(dst, str, len);
	byte_queue_write_ack(queue, len);
}

static void
byte_queue_write_fmt2(HTTP_ByteQueue *queue, const char *fmt, va_list args)
{
	if (queue->flags & BYTE_QUEUE_ERROR)
		return;

	va_list args2;
	va_copy(args2, args);

	int cap;
	byte_queue_write_setmincap(queue, 128);
	char *dst = byte_queue_write_buf(queue, &cap);

	int len = vsnprintf(dst, cap, fmt, args);
	if (len < 0) {
		queue->flags |= BYTE_QUEUE_ERROR;
		va_end(args2);
		va_end(args);
		return;
	}

	if (len > cap) {
		byte_queue_write_ack(queue, 0);
		byte_queue_write_setmincap(queue, len+1);
		dst = byte_queue_write_buf(queue, &cap);
		vsnprintf(dst, cap, fmt, args2);
	}

	byte_queue_write_ack(queue, len);

	va_end(args2);
	va_end(args);
}

static void
byte_queue_write_fmt(HTTP_ByteQueue *queue, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	byte_queue_write_fmt2(queue, fmt, args);
	va_end(args);
}

#endif // HTTP_ENGINE
/////////////////////////////////////////////////////////////////////
// HTTP ENGINE
/////////////////////////////////////////////////////////////////////
#if HTTP_ENGINE

#if !HTTP_PARSE
#error "HTTP_ENGINE depends on HTTP_PARSE"
#endif

#define TEN_SPACES "          "

void http_engine_init(HTTP_Engine *eng, int client, HTTP_MemoryFunc memfunc, void *memfuncdata)
{
	if (client)
		eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_URL;
	else
		eng->state = HTTP_ENGINE_STATE_SERVER_RECV_BUF;

	eng->closing = 0;
	eng->numexch = 0;

	byte_queue_init(&eng->input,  1<<20, memfunc, memfuncdata);
	byte_queue_init(&eng->output, 1<<20, memfunc, memfuncdata);
}

void http_engine_free(HTTP_Engine *eng)
{
	byte_queue_free(&eng->input);
	byte_queue_free(&eng->output);
	eng->state = HTTP_ENGINE_STATE_NONE;
}

void http_engine_close(HTTP_Engine *eng)
{
	if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT)
		eng->state = HTTP_ENGINE_STATE_CLIENT_CLOSED;
	else
		eng->state = HTTP_ENGINE_STATE_SERVER_CLOSED;
}

HTTP_EngineState http_engine_state(HTTP_Engine *eng)
{
	return eng->state;
}

char *http_engine_recvbuf(HTTP_Engine *eng, int *cap)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_RECV_BUF) == 0) {
		*cap = 0;
		return NULL;
	}

	eng->state &= ~HTTP_ENGINE_STATEBIT_RECV_BUF;
	eng->state |=  HTTP_ENGINE_STATEBIT_RECV_ACK;

	byte_queue_write_setmincap(&eng->input, 1<<9);
	if (byte_queue_error(&eng->input)) {
		*cap = 0;
		eng->state = HTTP_ENGINE_STATE_SERVER_CLOSED;
		return NULL;
	}

	return byte_queue_write_buf(&eng->input, cap);
}

static int find_header(HTTP_Request *req, HTTP_String name)
{
	for (int i = 0; i < req->num_headers; i++)
		if (http_streqcase(name, req->headers[i].name))
			return i;
	return -1;
}

static int
should_keep_alive(HTTP_Engine *eng)
{
	ASSERT(eng->state & HTTP_ENGINE_STATEBIT_PREP);

#if 0
	// If the parent system doesn't want us to reuse
	// the connection, we certainly can't keep alive.
	if ((eng->state & TINYHTTP_STREAM_REUSE) == 0)
		return 0;
#endif

	if (eng->numexch >= 100) // TODO: Make this a parameter
		return 0;

	HTTP_Request *req = &eng->result.req;

	// If the client is using HTTP/1.0, we can't
	// keep alive.
	if (req->minor == 0)
		return 0;

	// TODO: This assumes "Connection" can only hold a single token,
	//       but this is not true.
	int i = find_header(req, HTTP_STR("Connection"));
	if (i >= 0 && http_streqcase(req->headers[i].value, HTTP_STR("Close")))
		return 0;

	return 1;
}

static void process_incoming_request(HTTP_Engine *eng)
{
	ASSERT(eng->state == HTTP_ENGINE_STATE_SERVER_RECV_ACK
		|| eng->state == HTTP_ENGINE_STATE_SERVER_SEND_ACK
		|| eng->state == HTTP_ENGINE_STATE_SERVER_PREP_BODY
		|| eng->state == HTTP_ENGINE_STATE_SERVER_PREP_ERROR);

	char *src;
	int len;
	src = byte_queue_read_buf(&eng->input, &len);

	int ret = http_parse_request(src, len, &eng->result.req);

	if (ret == 0) {
		byte_queue_read_ack(&eng->input, 0);
		eng->state = HTTP_ENGINE_STATE_SERVER_RECV_BUF;
		return;
	}

	if (ret < 0) {
		byte_queue_read_ack(&eng->input, 0);
		byte_queue_write(&eng->output,
			"HTTP/1.1 400 Bad Request\r\n"
			"Connection: Close\r\n"
			"Content-Length: 0\r\n"
			"\r\n", -1
		);
		if (byte_queue_error(&eng->output))
			eng->state = HTTP_ENGINE_STATE_SERVER_CLOSED;
		else {
			eng->closing = 1;
			eng->state = HTTP_ENGINE_STATE_SERVER_SEND_BUF;
		}
		return;
	}

	ASSERT(ret > 0);

	eng->state = HTTP_ENGINE_STATE_SERVER_PREP_STATUS;
	eng->reqsize = ret;
	eng->keepalive = should_keep_alive(eng);
	eng->response_offset = byte_queue_offset(&eng->output);
}

void http_engine_recvack(HTTP_Engine *eng, int num)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_RECV_ACK) == 0)
		return;

	byte_queue_write_ack(&eng->input, num);

	if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT) {
		
		char *src;
		int len;
		src = byte_queue_read_buf(&eng->input, &len);

		int ret = http_parse_response(src, len, &eng->result.res);

		if (ret == 0) {
			byte_queue_read_ack(&eng->input, 0);
			eng->state = HTTP_ENGINE_STATE_CLIENT_RECV_BUF;
			return;
		}

		if (ret < 0) {
			eng->state = HTTP_ENGINE_STATE_CLIENT_CLOSED;
			return;
		}

		ASSERT(ret > 0);

		eng->state = HTTP_ENGINE_STATE_CLIENT_READY;

	} else {
		process_incoming_request(eng);
	}
}

char *http_engine_sendbuf(HTTP_Engine *eng, int *len)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_SEND_BUF) == 0) {
		*len = 0;
		return NULL;
	}

	eng->state &= ~HTTP_ENGINE_STATEBIT_SEND_BUF;
	eng->state |=  HTTP_ENGINE_STATEBIT_SEND_ACK;

	return byte_queue_read_buf(&eng->output, len);
}

void http_engine_sendack(HTTP_Engine *eng, int num)
{
	if (eng->state != HTTP_ENGINE_STATE_SERVER_SEND_ACK &&
		eng->state != HTTP_ENGINE_STATE_CLIENT_SEND_ACK)
		return;

	byte_queue_read_ack(&eng->output, num);

	if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT) {
		if (byte_queue_empty(&eng->output))
			eng->state = HTTP_ENGINE_STATE_CLIENT_RECV_BUF;
		else
			eng->state = HTTP_ENGINE_STATE_CLIENT_SEND_BUF;
	} else {
		if (byte_queue_empty(&eng->output)) {
			if (!eng->closing && eng->keepalive)
				process_incoming_request(eng);
			else
				eng->state = HTTP_ENGINE_STATE_SERVER_CLOSED;
		} else
			eng->state = HTTP_ENGINE_STATE_SERVER_SEND_BUF;
	}
}

HTTP_Request *http_engine_getreq(HTTP_Engine *eng)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_REQUEST) == 0)
		return NULL;
	return &eng->result.req;
}

HTTP_Response *http_engine_getres(HTTP_Engine *eng)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_RESPONSE) == 0)
		return NULL;
	return &eng->result.res;
}

void http_engine_url(HTTP_Engine *eng, HTTP_Method method, char *url, int minor)
{
	if (eng->state != HTTP_ENGINE_STATE_CLIENT_PREP_URL)
		return;

	int len = strlen(url);

	HTTP_URL parsed_url;
	int ret = http_parse_url(url, len, &parsed_url);
	if (ret != len) {
		eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_ERROR;
		return;
	}

	char *method_str = "???";
	switch (method) {
		case HTTP_METHOD_GET    : method_str = "GET";     break;
		case HTTP_METHOD_HEAD   : method_str = "HEAD";    break;
		case HTTP_METHOD_POST   : method_str = "POST";    break;
		case HTTP_METHOD_PUT    : method_str = "PUT";     break;
		case HTTP_METHOD_DELETE : method_str = "DELETE";  break;
		case HTTP_METHOD_CONNECT: method_str = "CONNECT"; break;
		case HTTP_METHOD_OPTIONS: method_str = "OPTIONS"; break;
		case HTTP_METHOD_TRACE  : method_str = "TRACE";   break;
		case HTTP_METHOD_PATCH  : method_str = "PATCH";   break;
	}

	HTTP_String path = parsed_url.path;
	if (path.len == 0)
		path = HTTP_STR("/");

	byte_queue_write_fmt(&eng->output,
		"%s %.*s%.*s HTTP/1.%d\r\n",
		method_str,
		path.len,
		path.ptr,
		parsed_url.query.len,
		parsed_url.query.ptr,
		minor
	);

	if (parsed_url.authority.port > 0)
		byte_queue_write_fmt(&eng->output,
			"Host: %.*s:%d\r\n",
			parsed_url.authority.host.text.len,
			parsed_url.authority.host.text.ptr,
			parsed_url.authority.port);
	else
		byte_queue_write_fmt(&eng->output,
			"Host: %.*s\r\n",
			parsed_url.authority.host.text.len,
			parsed_url.authority.host.text.ptr);

	eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_HEADER;
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

void http_engine_status(HTTP_Engine *eng, int status)
{
	if (eng->state != HTTP_ENGINE_STATE_SERVER_PREP_STATUS)
		return;

	byte_queue_write_fmt(&eng->output,
		"HTTP/1.1 %d %s\r\n",
		status, get_status_text(status));

	eng->state = HTTP_ENGINE_STATE_SERVER_PREP_HEADER;
}

void http_engine_header(HTTP_Engine *eng, const char *src, int len)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_PREP_HEADER) == 0)
		return;

	// TODO: Check that the header is valid

	byte_queue_write(&eng->output, src, len);
	byte_queue_write(&eng->output, "\r\n", 2);
}

void http_engine_header_fmt2(HTTP_Engine *eng, const char *fmt, va_list args)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_PREP_HEADER) == 0)
		return;

	// TODO: Check that the header is valid

	byte_queue_write_fmt2(&eng->output, fmt, args);
	byte_queue_write(&eng->output, "\r\n", 2);
}

void http_engine_header_fmt(HTTP_Engine *eng, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	http_engine_header_fmt2(eng, fmt, args);
	va_end(args);
}

static void
append_special_headers(HTTP_Engine *eng)
{
	ASSERT((eng->state & HTTP_ENGINE_STATEBIT_CLIENT) == 0);

	if (eng->keepalive)
		byte_queue_write(&eng->output, "Connection: Keep-Alive\r\n", -1);
	else
		byte_queue_write(&eng->output, "Connection: Close\r\n", -1);

	byte_queue_write(&eng->output, "Content-Length: ", -1);
	eng->content_length_value_offset = byte_queue_offset(&eng->output);
	byte_queue_write(&eng->output, TEN_SPACES "\r\n", -1);

	byte_queue_write(&eng->output, "\r\n", -1);
	eng->content_length_offset = byte_queue_offset(&eng->output);
}

void http_engine_body(HTTP_Engine *eng, void *src, int len)
{
	ASSERT(len >= 0);

	http_engine_bodycap(eng, len);
	int cap;
	char *buf = http_engine_bodybuf(eng, &cap);
	if (buf) {
		memcpy(buf, src, len);
		http_engine_bodyack(eng, len);
	}
}

static void ensure_body_entered(HTTP_Engine *eng)
{
	if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT) {

		if (eng->state == HTTP_ENGINE_STATE_CLIENT_PREP_HEADER) {
			byte_queue_write(&eng->output, "\r\n", 2);
			eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_BODY;
		}

	} else {

		if (eng->state == HTTP_ENGINE_STATE_SERVER_PREP_HEADER) {
			append_special_headers(eng);
			eng->state = HTTP_ENGINE_STATE_SERVER_PREP_BODY;
		}
	}
}

void http_engine_bodycap(HTTP_Engine *eng, int mincap)
{
	ensure_body_entered(eng);
	if (eng->state != HTTP_ENGINE_STATE_CLIENT_PREP_BODY &&
		eng->state != HTTP_ENGINE_STATE_SERVER_PREP_BODY)
		return;

	byte_queue_write_setmincap(&eng->output, mincap);
}

char *http_engine_bodybuf(HTTP_Engine *eng, int *cap)
{
	ensure_body_entered(eng);
	if (eng->state != HTTP_ENGINE_STATE_CLIENT_PREP_BODY &&
		eng->state != HTTP_ENGINE_STATE_SERVER_PREP_BODY) {
		*cap = 0;
		return NULL;
	}

	return byte_queue_write_buf(&eng->output, cap);
}

void http_engine_bodyack(HTTP_Engine *eng, int num)
{
	if (eng->state != HTTP_ENGINE_STATE_CLIENT_PREP_BODY &&
		eng->state != HTTP_ENGINE_STATE_SERVER_PREP_BODY)
		return;
	byte_queue_write_ack(&eng->output, num);
}

void http_engine_done(HTTP_Engine *eng)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_PREP) == 0)
		return;

	if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT) {

		if (eng->state == HTTP_ENGINE_STATE_CLIENT_PREP_URL) {
			eng->state = HTTP_ENGINE_STATE_CLIENT_CLOSED;
			return;
		}

		if (eng->state == HTTP_ENGINE_STATE_CLIENT_PREP_HEADER) {
			byte_queue_write(&eng->output, "\r\n", 2);
			eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_BODY;
		}

		if (eng->state == HTTP_ENGINE_STATE_CLIENT_PREP_BODY) {
			// TODO
		}

		if (eng->state == HTTP_ENGINE_STATE_CLIENT_PREP_ERROR) {
			// TODO
		}

		if (byte_queue_error(&eng->output)) {
			// TODO
		}

		eng->state = HTTP_ENGINE_STATE_CLIENT_SEND_BUF;

	} else {

		if (eng->state == HTTP_ENGINE_STATE_SERVER_PREP_HEADER) {
			append_special_headers(eng);
			eng->state = HTTP_ENGINE_STATE_SERVER_PREP_BODY;
		}

		if (eng->state == HTTP_ENGINE_STATE_SERVER_PREP_BODY) {

			unsigned int content_length = byte_queue_size_from_offset(&eng->output, eng->content_length_offset);

			if (content_length > UINT32_MAX) {
				// TODO
			}

			char tmp[10];

			tmp[0] = '0' + content_length / 1000000000; content_length %= 1000000000;
			tmp[1] = '0' + content_length / 100000000;  content_length %= 100000000;
			tmp[2] = '0' + content_length / 10000000;   content_length %= 10000000;
			tmp[3] = '0' + content_length / 1000000;    content_length %= 1000000;
			tmp[4] = '0' + content_length / 100000;     content_length %= 100000;
			tmp[5] = '0' + content_length / 10000;      content_length %= 10000;
			tmp[6] = '0' + content_length / 1000;       content_length %= 1000;
			tmp[7] = '0' + content_length / 100;        content_length %= 100;
			tmp[8] = '0' + content_length / 10;         content_length %= 10;
			tmp[9] = '0' + content_length;

			int i = 0;
			while (i < 9 && tmp[i] == '0')
				i++;

			byte_queue_patch(&eng->output, eng->content_length_value_offset, tmp + i, 10 - i);
		}

		if (eng->state == HTTP_ENGINE_STATE_SERVER_PREP_ERROR) {
			byte_queue_remove_from_offset(&eng->output, eng->response_offset);
			byte_queue_write(&eng->output,
				"HTTP/1.1 500 Internal Server Error\r\n"
				"Content-Length: 0\r\n"
				"Connection: Close\r\n"
				"\r\n",
				-1
			);
		}

		if (byte_queue_error(&eng->output)) {
			eng->state = HTTP_ENGINE_STATE_SERVER_CLOSED;
			return;
		}

		byte_queue_read_ack(&eng->input, eng->reqsize);
		eng->state = HTTP_ENGINE_STATE_SERVER_SEND_BUF;
	}
}

void http_engine_undo(HTTP_Engine *eng)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_PREP) == 0)
		return;

	byte_queue_remove_from_offset(&eng->output, eng->response_offset);

	if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT)
		eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_URL;
	else
		eng->state = HTTP_ENGINE_STATE_SERVER_PREP_STATUS;
}

#endif // HTTP_ENGINE
/////////////////////////////////////////////////////////////////////
// HTTP CLIENT AND SERVER
/////////////////////////////////////////////////////////////////////
#if HTTP_CLIENT || HTTP_SERVER

#ifdef _WIN32
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#define POLL WSAPoll
#define CLOSE_SOCKET closesocket
#else
#include <time.h>
#include <poll.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#define POLL poll
#define SOCKET int
#define INVALID_SOCKET -1
#define CLOSE_SOCKET close
#endif

static void *memfunc(HTTP_MemoryFuncTag tag, void *ptr, int len, void *data)
{
	(void) data;
	switch (tag) {

		case HTTP_MEMFUNC_MALLOC:
		return malloc(len);

		case HTTP_MEMFUNC_FREE:
		free(ptr);
		return NULL;
	}
	return NULL;
}

static int set_socket_blocking(SOCKET fd, int blocking)
{
#ifdef _WIN32
	unsigned long mode = blocking ? 0 : 1;
	return ioctlsocket(fd, FIONBIO, &mode) ? -1 : 0;
#else
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return -1;
	if (blocking) flags &= ~O_NONBLOCK;
	else          flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0)
		return -1;
	return 0;
#endif
}

static unsigned long long
get_current_time_ms(void)
{
#if defined(__linux__)

	struct timespec ts;
	int result = clock_gettime(CLOCK_REALTIME, &ts);
	if (result)
		return UINT64_MAX;
	return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;

#elif defined(_WIN32)

	FILETIME ft;
	GetSystemTimeAsFileTime(&ft);

	ULARGE_INTEGER uli;
	uli.LowPart = ft.dwLowDateTime;
	uli.HighPart = ft.dwHighDateTime;
					
	// Convert Windows file time (100ns since 1601-01-01) to 
	// Unix epoch time (seconds since 1970-01-01)
	// 116444736000000000 = number of 100ns intervals from 1601 to 1970
	return (uli.QuadPart - 116444736000000000ULL) / 10000ULL; // TODO: Make sure this is returning miliseconds
#endif
}

#endif // HTTP_CLIENT || HTTP_SERVER
/////////////////////////////////////////////////////////////////////
// HTTP CLIENT
/////////////////////////////////////////////////////////////////////
#if HTTP_CLIENT

#if !HTTP_ENGINE
#error "HTTP_CLIENT depends on HTTP_SERVER"
#endif

#if HTTP_CLIENT_TLS

#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct {
	SSL_CTX *ctx;
} HTTP_TLSContext_;
_Static_assert(sizeof(HTTP_TLSContext) >= sizeof(HTTP_TLSContext_));
_Static_assert(_Alignof(HTTP_TLSContext) >= _Alignof(HTTP_TLSContext_));

typedef struct {
	SSL *ssl;
} HTTP_TLSClientContext_;
_Static_assert(sizeof(HTTP_TLSClientContext) >= sizeof(HTTP_TLSClientContext_));
_Static_assert(_Alignof(HTTP_TLSClientContext) >= _Alignof(HTTP_TLSClientContext_));

void http_tls_global_init(void)
{
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
}

void http_tls_global_free(void)
{
	EVP_cleanup();
	ERR_free_strings();
}

int http_tls_init(HTTP_TLSContext *tls)
{
	HTTP_TLSContext_ *tls_ = (void*) tls;

	tls_->ctx = SSL_CTX_new(TLS_client_method());
	if (!tls_->ctx)
		return -1;

	SSL_CTX_set_verify(tls_->ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_default_verify_paths(tls_->ctx);
	return 0;
}

void http_tls_free(HTTP_TLSContext *tls)
{
	HTTP_TLSContext_ *tls_ = (void*) tls;

	SSL_CTX_free(tls_->ctx);
	tls_->ctx = NULL;
}

#else // HTTP_CLIENT_TLS

void http_tls_global_init(void) {}
void http_tls_global_free(void) {}
int  http_tls_init(HTTP_TLSContext *tls) { (void) tls; return 0; }
void http_tls_free(HTTP_TLSContext *tls) { (void) tls; }

#endif // !HTTP_CLIENT_TLS

void http_client_init(HTTP_Client *client)
{
	client->state = HTTP_STATE_CLIENT_IDLE;
}

void http_client_free(HTTP_Client *client)
{
	if (client->state != HTTP_STATE_CLIENT_IDLE) {
		// TODO
	}
}

static void client_connect(HTTP_Client *client, struct sockaddr *addr, int addrlen)
{
	int ret = connect((SOCKET) client->fd, addr, addrlen);
	if (ret == 0) {
		if (client->secure)
			client->state = HTTP_STATE_CLIENT_TLS_HANDSHAKE_SEND;
		else
			client->state = HTTP_STATE_CLIENT_SEND;
	} else {
		if (errno == EINPROGRESS)
			client->state = HTTP_STATE_CLIENT_CONNECT;
		else {
			client->code = HTTP_CLIENT_ERROR_FCONNECT;
			client->state = HTTP_STATE_CLIENT_CLOSED;
			return;
		}
	}
}

void http_client_startreq(
	HTTP_Client *client, HTTP_Method method,
	const char *url, HTTP_String *headers,
	int num_headers, char *body, int body_len,
	HTTP_TLSContext *tls)
{
#ifdef _WIN32
	WSADATA wd;
	if (WSAStartup(MAKEWORD(2, 2), &wd))
		return;
#endif

	HTTP_URL parsed_url;
	int ret = http_parse_url(url, strlen(url), &parsed_url);
	if (ret != strlen(url)) {
		client->code = HTTP_CLIENT_ERROR_INVURL;
		client->state = HTTP_STATE_CLIENT_CLOSED;
		return;
	}

	if (http_streq(parsed_url.scheme, HTTP_STR("https"))) {

#if !HTTP_CLIENT_TLS
		client->code = HTTP_CLIENT_ERROR_NOSYS;
		client->state = HTTP_STATE_CLIENT_CLOSED;
		return;
#else
		client->secure = 1;
#endif

	} else if (http_streq(parsed_url.scheme, HTTP_STR("http"))) {
		client->secure = 0;
	} else {
		client->code = HTTP_CLIENT_ERROR_INVPROTO;
		client->state = HTTP_STATE_CLIENT_CLOSED;
		return;
	}

	int port = parsed_url.authority.port;
	if (port == 0) {
		if (client->secure)
			port = 443;
		else
			port = 80;
	}

	client->fd = (HTTP_Socket) socket(AF_INET, SOCK_STREAM, 0);
	if ((SOCKET) client->fd == INVALID_SOCKET) {
		client->code = HTTP_CLIENT_ERROR_FSOCK;
		client->state = HTTP_STATE_CLIENT_CLOSED;
		return;
	}

	if (set_socket_blocking((SOCKET) client->fd, 0) < 0) {
		client->code = -100000; // TODO
		client->state = HTTP_STATE_CLIENT_CLOSED;
		return;
	}

	switch (parsed_url.authority.host.mode) {

		case HTTP_HOST_MODE_VOID:
		client->code = HTTP_CLIENT_ERROR_INVURL;
		client->state = HTTP_STATE_CLIENT_CLOSED;
		break;

		case HTTP_HOST_MODE_IPV4:
		{
			struct sockaddr_in addr_ipv4;
			addr_ipv4.sin_family = AF_INET;
			addr_ipv4.sin_port = htons(port);
			memcpy(&addr_ipv4.sin_addr, &parsed_url.authority.host.ipv4, 4);
			memset(&addr_ipv4.sin_zero, 0, sizeof(addr_ipv4.sin_zero));
			client_connect(client, (struct sockaddr*) &addr_ipv4, sizeof(addr_ipv4));
		}
		break;

		case HTTP_HOST_MODE_IPV6:
		{
			struct sockaddr_in6 addr_ipv6;
			addr_ipv6.sin6_family = AF_INET6;
			addr_ipv6.sin6_port = htons(port);
			memcpy(&addr_ipv6.sin6_addr, &parsed_url.authority.host.ipv6, 16);
			// TODO: Should the other fields be initialized?
			client_connect(client, (struct sockaddr*) &addr_ipv6, sizeof(addr_ipv6));
		}
		break;

		case HTTP_HOST_MODE_NAME:
		{
			char namestr[1<<10]; // TODO: Assuming this won't overflow
			memcpy(namestr,
				parsed_url.authority.host.name.ptr,
				parsed_url.authority.host.name.len);
			namestr[parsed_url.authority.host.name.len] = '\0';

			char portstr[1<<7];
			snprintf(portstr, sizeof(portstr), "%d", port);

			struct addrinfo *res;

			struct addrinfo hints;
			memset(&hints, 0, sizeof hints);
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;
			int ret = getaddrinfo(namestr, portstr, &hints, &res);
			if (ret) {
				client->code = HTTP_CLIENT_ERROR_DNS;
				client->state = HTTP_STATE_CLIENT_CLOSED;
			} else {
				for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
					client_connect(client, p->ai_addr, p->ai_addrlen);
					if (client->state != HTTP_STATE_CLIENT_CLOSED)
						break;
				}
				freeaddrinfo(res);
			}
		}
		break;
	}

	if (client->state == HTTP_STATE_CLIENT_CLOSED) {
		// TODO
		return;
	}

#if HTTP_CLIENT_TLS
	if (client->secure) {

		HTTP_TLSContext_ *glbtls = (void*) tls;
		HTTP_TLSClientContext_ *clitls = (void*) &client->tls;

		clitls->ssl = SSL_new(glbtls->ctx);
		if (clitls->ssl == NULL) {
			// TODO
			client->code = HTTP_CLIENT_ERROR_FSSLNEW;
			client->state = HTTP_STATE_CLIENT_CLOSED;
			return;
		}

		SSL_set_fd(clitls->ssl, (SOCKET) client->fd); // TODO: Error
	}
#endif // HTTP_CLIENT_TLS

	http_engine_init(&client->eng, 1, memfunc, NULL);
	http_engine_url(&client->eng, method, url, 1);
	for (int i = 0; i < num_headers; i++)
		http_engine_header(&client->eng, headers[i].ptr, headers[i].len);
	if (body_len > 0)
		http_engine_body(&client->eng, body, body_len);
	http_engine_done(&client->eng);
}

static void client_recv_plain(HTTP_Client *client)
{
	ASSERT(!client->secure);

	int cap;
	char *buf = http_engine_recvbuf(&client->eng, &cap);

	int ret = recv((SOCKET) client->fd, buf, cap, 0);
	if (ret < 0) {
		http_engine_recvack(&client->eng, 0);
		client->code = HTTP_CLIENT_ERROR_FRECV;
		client->state = HTTP_STATE_CLIENT_CLOSED;
		return;
	}
	if (ret == 0)
		http_engine_close(&client->eng);

	http_engine_recvack(&client->eng, ret);
}

static void client_recv_secure(HTTP_Client *client)
{
	ASSERT(client->secure);

#if !HTTP_CLIENT_TLS
	// TODO
#else
	HTTP_TLSClientContext_ *tls = (void*) &client->tls;
	SSL *ssl = tls->ssl;

	int cap;
	char *buf = http_engine_recvbuf(&client->eng, &cap);
	if (buf) {
		int ret = SSL_read(ssl, buf, cap);
		if (ret <= 0) {
			http_engine_recvack(&client->eng, 0);
			int err = SSL_get_error(ssl, ret);
			if (err == SSL_ERROR_WANT_READ) {
				client->state = HTTP_STATE_CLIENT_RECV;
				return;
			}
			if (err == SSL_ERROR_WANT_WRITE) {
				client->state = HTTP_STATE_CLIENT_SEND;
				return;
			}
			client->code = HTTP_CLIENT_ERROR_FSSLREAD;
			client->state = HTTP_STATE_CLIENT_CLOSED;
			http_engine_close(&client->eng);
			return;
		}
		http_engine_recvack(&client->eng, ret);
	}
#endif // HTTP_CLIENT_TLS
}

static void client_recv(HTTP_Client *client)
{
	if (client->secure) {
		client_recv_secure(client);
	} else {
		client_recv_plain(client);
	}
}

static void client_send_plain(HTTP_Client *client)
{
	int len;
	char *buf = http_engine_sendbuf(&client->eng, &len);
	if (buf) {
		int ret = send((SOCKET) client->fd, buf, len, 0);
		if (ret < 0) {
			http_engine_sendack(&client->eng, 0);
			client->code = HTTP_CLIENT_ERROR_FSEND;
			client->state = HTTP_STATE_CLIENT_CLOSED;
			return;
		}
		http_engine_sendack(&client->eng, ret);
	}
}

static void client_send_secure(HTTP_Client *client)
{
#if !HTTP_CLIENT_TLS
	// TODO
#else
	HTTP_TLSClientContext_ *tls = (void*) &client->tls;
	SSL *ssl = tls->ssl;

	int len;
	char *buf = http_engine_sendbuf(&client->eng, &len);
	if (buf == NULL) return;

	int ret = SSL_write(ssl, buf, len);
	if (ret <= 0) {
		http_engine_sendack(&client->eng, 0);
		int err = SSL_get_error(ssl, ret);
		if (err == SSL_ERROR_WANT_READ) {
			client->state = HTTP_STATE_CLIENT_RECV;
			return;
		}
		if (err == SSL_ERROR_WANT_WRITE) {
			client->state = HTTP_STATE_CLIENT_SEND;
			return;
		}
		client->code = HTTP_CLIENT_ERROR_FSSLWRITE;
		client->state = HTTP_STATE_CLIENT_CLOSED;
		http_engine_close(&client->eng);
		return;
	}

	http_engine_sendack(&client->eng, ret);
#endif // HTTP_CLIENT_TLS
}

static void client_send(HTTP_Client *client)
{
	if (client->secure)
		client_send_secure(client);
	else
		client_send_plain(client);
}

static void client_update(HTTP_Client *client)
{
#if HTTP_CLIENT_TLS
	HTTP_TLSClientContext_ *tlsclient_ = (void*) &client->tls;
	SSL *ssl = tlsclient_->ssl;
#endif

	if (client->state == HTTP_STATE_CLIENT_CONNECT) {

		int error;
		socklen_t errlen = sizeof(error);
		if (getsockopt((SOCKET) client->fd, SOL_SOCKET, SO_ERROR, (void*) &error, &errlen) < 0) {
			client->code = HTTP_CLIENT_ERROR_FGETSOCKOPT;
			client->state = HTTP_STATE_CLIENT_CLOSED;
			return;
		}
		if (error) {
			client->code = HTTP_CLIENT_ERROR_FCONNECT;
			client->state = HTTP_STATE_CLIENT_CLOSED;
			return;
		}

		if (client->secure)
			client->state = HTTP_STATE_CLIENT_TLS_HANDSHAKE_SEND;
		else
			client->state = HTTP_STATE_CLIENT_SEND;
	}

#if HTTP_CLIENT_TLS
	if (client->state == HTTP_STATE_CLIENT_TLS_HANDSHAKE_RECV ||
		client->state == HTTP_STATE_CLIENT_TLS_HANDSHAKE_SEND) {

		int ret = SSL_connect(ssl);
		if (ret <= 0) {
			int err = SSL_get_error(ssl, ret);
			if (0) {}
			else if (err == SSL_ERROR_WANT_READ)  client->state = HTTP_STATE_CLIENT_TLS_HANDSHAKE_RECV;
			else if (err == SSL_ERROR_WANT_WRITE) client->state = HTTP_STATE_CLIENT_TLS_HANDSHAKE_SEND;
			else {
				client->code = HTTP_CLIENT_ERROR_FSSLCONNECT;
				client->state = HTTP_STATE_CLIENT_CLOSED;
			}
			return;
		}

		client->state = HTTP_STATE_CLIENT_SEND;
	}
#endif // HTTP_CLIENT_TLS

	for (;;) {

		HTTP_EngineState engstate = http_engine_state(&client->eng);

		if (engstate == HTTP_ENGINE_STATE_CLIENT_SEND_BUF) {
			client_send(client);
			continue;
		}

		if (engstate == HTTP_ENGINE_STATE_CLIENT_RECV_BUF) {
			client_recv(client);
			continue;
		}

		switch (http_engine_state(&client->eng)) {

			case HTTP_ENGINE_STATE_CLIENT_SEND_BUF:
			client->state = HTTP_STATE_CLIENT_SEND;
			break;
	
			case HTTP_ENGINE_STATE_CLIENT_RECV_BUF:
			client->state = HTTP_STATE_CLIENT_RECV;
			break;
	
			case HTTP_ENGINE_STATE_CLIENT_READY:
			client->state = HTTP_STATE_CLIENT_READY;
			return;
	
			case HTTP_ENGINE_STATE_CLIENT_CLOSED:
			client->state = HTTP_STATE_CLIENT_CLOSED;
			return;

			default:
			UNREACHABLE;
			break;
		}
	}
}

int http_client_waitall(HTTP_Client **clients, int num_clients, int timeout)
{
	if (num_clients < 0) {
		num_clients = 0;
		while (clients[num_clients])
			num_clients++;
	}

	if (num_clients == 0 || num_clients > HTTP_CLIENT_WAIT_LIMIT)
		return -1;

	unsigned long long start_time;
	if (timeout < 0)
		start_time = -1ULL;
	else {
		start_time = get_current_time_ms();
		if (start_time == -1ULL)
			return -1;
	}

	HTTP_Client *remain[HTTP_CLIENT_WAIT_LIMIT];
	for (int i = 0; i < num_clients; i++)
		remain[i] = clients[i];
	int num_remain = num_clients;

	do {
		int timeout2;
		if (timeout < 0)
			timeout2 = -1;
		else {
			unsigned long long current_time = get_current_time_ms();
			if (current_time == -1ULL)
				return -1;
			ASSERT(current_time >= start_time);
			if (current_time - start_time > (unsigned long long) timeout)
				return 0;
			timeout2 = (int) (current_time - start_time);
		}

		int ret = http_client_waitany(remain, num_remain, timeout2);
		if (ret < 0) return -1;

		remain[ret] = remain[--num_remain];
	} while (num_remain > 0);

	return 0;
}

int http_client_waitany(HTTP_Client **clients, int num_clients, int timeout)
{
	if (num_clients < 0) {
		num_clients = 0;
		while (clients[num_clients])
			num_clients++;
	}

	if (num_clients == 0 || num_clients > HTTP_CLIENT_WAIT_LIMIT)
		return -1;

	unsigned long long start_time;
	if (timeout < 0)
		start_time = -1ULL;
	else {
		start_time = get_current_time_ms();
		if (start_time == -1ULL)
			return -1;
	}

	for (;;) {

		struct pollfd poll_array[HTTP_CLIENT_WAIT_LIMIT];
		int poll_count = 0;

		for (int i = 0; i < num_clients; i++) {

			int events = 0;
			switch (clients[i]->state) {
				case HTTP_STATE_CLIENT_CONNECT:
				events = POLLOUT;
				break;

				case HTTP_STATE_CLIENT_TLS_HANDSHAKE_RECV:
				events = POLLIN;
				break;

				case HTTP_STATE_CLIENT_TLS_HANDSHAKE_SEND:
				events = POLLOUT;
				break;

				case HTTP_STATE_CLIENT_RECV:
				events = POLLIN;
				break;

				case HTTP_STATE_CLIENT_SEND:
				events = POLLOUT;
				break;

				case HTTP_STATE_CLIENT_READY:
				case HTTP_STATE_CLIENT_CLOSED:
				return i;

				default:
				return -1;
			}

			poll_array[poll_count].fd = clients[i]->fd;
			poll_array[poll_count].events = events;
			poll_array[poll_count].revents = 0;
			poll_count++;
		}

		int timeout2;
		if (timeout < 0)
			timeout2 = -1;
		else {
			unsigned long long current_time = get_current_time_ms();
			if (current_time == -1ULL)
				return -1;
			ASSERT(current_time >= start_time);
			if (current_time - start_time > (unsigned long long) timeout)
				return 0;
			timeout2 = (int) (current_time - start_time);
		}

		int num = POLL(poll_array, poll_count, timeout2);
		// TODO: Handle error

		for (int i = 0; i < num_clients; i++)
			if (poll_array[i].revents) client_update(clients[i]);
	}

	return -1; // UNREACHABLE
}

int http_client_result(HTTP_Client *client, HTTP_Response **res)
{
	if (client->state != HTTP_STATE_CLIENT_READY) {
		*res = NULL;
		return client->code;
	}

	*res = http_engine_getres(&client->eng);
	return HTTP_CLIENT_OK;
}

const char *http_client_strerror(int code)
{
	switch (code) {
		case HTTP_CLIENT_OK: return "OK";
		case HTTP_CLIENT_ERROR_INVURL: return "Invalid URL";
		case HTTP_CLIENT_ERROR_NOSYS: return "Not compiled in";
		case HTTP_CLIENT_ERROR_INVPROTO: return "Invalid protocol";
		case HTTP_CLIENT_ERROR_FSOCK: return "socket() error";
		case HTTP_CLIENT_ERROR_FCONNECT: return "connect() error";
		case HTTP_CLIENT_ERROR_DNS: return "DNS resolution error";
		case HTTP_CLIENT_ERROR_FSSLNEW: return "SSL_new() error";
		case HTTP_CLIENT_ERROR_FRECV: return "recv() error";
		case HTTP_CLIENT_ERROR_FSSLREAD: return "SSL_read() error";
		case HTTP_CLIENT_ERROR_FSEND: return "send() error";
		case HTTP_CLIENT_ERROR_FSSLWRITE: return "SSL_write() error";
		case HTTP_CLIENT_ERROR_FGETSOCKOPT: return "getsockopt() error";
		case HTTP_CLIENT_ERROR_FSSLCONNECT: return "SSL_connect() error";
	}
	return "???";
}

#endif // HTTP_CLIENT
/////////////////////////////////////////////////////////////////////
// HTTP SERVER
/////////////////////////////////////////////////////////////////////
#if HTTP_SERVER

#if !HTTP_ENGINE
#error "HTTP_SERVER depends on HTTP_ENGINE"
#endif

static void bitset_init(HTTP_Bitset *set)
{
	memset(set, 0, sizeof(HTTP_Bitset));
}

static void bitset_set(HTTP_Bitset *set, int idx, int val)
{
	HTTP_BitsetWord *word = &set->data[idx / sizeof(HTTP_BitsetWord)];
	HTTP_BitsetWord  mask = (HTTP_BitsetWord) 1 << (idx % sizeof(HTTP_BitsetWord));
	if (val)
		*word |= mask;
	else
		*word &= ~mask;
}

static int bitset_get(HTTP_Bitset *set, int idx)
{
	HTTP_BitsetWord word = set->data[idx / sizeof(HTTP_BitsetWord)];
	HTTP_BitsetWord mask = (HTTP_BitsetWord) 1 << (idx % sizeof(HTTP_BitsetWord));
	return (word & mask) == mask;
}

static void int_queue_init(HTTP_IntQueue *q)
{
	q->head = 0;
	q->count = 0;
	bitset_init(&q->set);
}

static int int_queue_contains(HTTP_IntQueue *q, int val)
{
	return bitset_get(&q->set, val);
}

static void int_queue_push(HTTP_IntQueue *q, int val)
{
	if (int_queue_contains(q, val))
		return;

	q->items[(q->head + q->count) % HTTP_MAX_CLIENTS_PER_SERVER] = val;
	q->count++;

	bitset_set(&q->set, val, 1);
}

static int int_queue_pop(HTTP_IntQueue *q)
{
	if (q->count == 0)
		return -1;

	int val = q->items[q->head % HTTP_MAX_CLIENTS_PER_SERVER];
	q->head = (q->head + 1) % HTTP_MAX_CLIENTS_PER_SERVER;

	q->count--;
	bitset_set(&q->set, val, 0);
	return val;
}

static void int_queue_remove(HTTP_IntQueue *q, int val)
{
	if (!int_queue_contains(q, val))
		return;

	int i = 0;
	while (q->items[(q->head + i) % HTTP_MAX_CLIENTS_PER_SERVER] != val)
		i++;

	while (i < q->count-1) {
		q->items[(q->head + i) % HTTP_MAX_CLIENTS_PER_SERVER]
			= q->items[(q->head + i + 1) % HTTP_MAX_CLIENTS_PER_SERVER];
		i++;
	}

	q->count--;
	bitset_set(&q->set, val, 0);
}

int http_server_init(HTTP_Server *server, const char *addr, int port)
{
#ifdef _WIN32
	WSADATA wd;
	if (WSAStartup(MAKEWORD(2, 2), &wd))
		return -1;
#endif

	SOCKET listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd == INVALID_SOCKET)
		return -1;

	if (set_socket_blocking(listen_fd, 0) < 0) {
		CLOSE_SOCKET(listen_fd);
		return -1;
	}

	int reuse = 1;
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (void*) &reuse, sizeof(reuse));

	struct in_addr bind_addr_buf;
	if (inet_pton(AF_INET, addr, &bind_addr_buf) != 1) {
		CLOSE_SOCKET(listen_fd);
		return -1;
	}

	struct sockaddr_in bind_all_buf;
	bind_all_buf.sin_family = AF_INET;
	bind_all_buf.sin_port   = htons(port);
	bind_all_buf.sin_addr   = bind_addr_buf;
	if (bind(listen_fd, (struct sockaddr*) &bind_all_buf, sizeof(bind_all_buf)) < 0) {
		CLOSE_SOCKET(listen_fd);
		return -1;
	}

	if (listen(listen_fd, 32) < 0) {
		CLOSE_SOCKET(listen_fd);
		return -1;
	}

	int_queue_init(&server->ready);
	server->listen_fd = listen_fd;
	server->num_conns = 0;
	for (int i = 0; i < HTTP_MAX_CLIENTS_PER_SERVER; i++) {
		server->conns[i].fd = INVALID_SOCKET;
		server->conns[i].gen = 1;
	}

	return 0;
}

void http_server_free(HTTP_Server *server)
{
	for (int i = 0; i < HTTP_MAX_CLIENTS_PER_SERVER; i++)
		if ((SOCKET) server->conns[i].fd != INVALID_SOCKET) {
			http_engine_free(&server->conns[i].eng);
			CLOSE_SOCKET((SOCKET) server->conns[i].fd);
		}
	CLOSE_SOCKET((SOCKET) server->listen_fd);
}

static HTTP_ResponseHandle
conn2handle(HTTP_Server *server, HTTP_ServerConnection *conn)
{
	return (HTTP_ResponseHandle) { server, conn - server->conns, conn->gen };
}

static HTTP_ServerConnection*
handle2conn(HTTP_ResponseHandle handle)
{
	HTTP_Server *server = handle.ptr;
	if (handle.idx >= HTTP_MAX_CLIENTS_PER_SERVER)
		return NULL;
	HTTP_ServerConnection *conn = &server->conns[handle.idx];
	if (conn->gen != handle.gen)
		return NULL;
	return conn;
}

int http_server_wait(HTTP_Server *server, HTTP_Request **req,
	HTTP_ResponseHandle *res, int timeout)
{
	unsigned long long start_time;
	if (timeout < 0)
		start_time = -1ULL;
	else {
		start_time = get_current_time_ms();
		if (start_time == -1ULL)
			return -1;
	}

	int popped;
	while ((popped = int_queue_pop(&server->ready)) < 0) {

		int poll_count = 0;
		int poll_indices[HTTP_MAX_CLIENTS_PER_SERVER];
		struct pollfd poll_array[HTTP_MAX_CLIENTS_PER_SERVER + 1];

		for (int i = 0, j = 0; j < server->num_conns; i++) {

			HTTP_ServerConnection *conn = &server->conns[i];
			if ((SOCKET) conn->fd == INVALID_SOCKET)
				continue;

			HTTP_EngineState state = http_engine_state(&conn->eng);

			int events = 0;
			if (0) {}
			else if (state == HTTP_ENGINE_STATE_SERVER_RECV_BUF) events = POLLIN;
			else if (state == HTTP_ENGINE_STATE_SERVER_SEND_BUF) events = POLLOUT;

			if (events) {
				poll_array[poll_count].fd = conn->fd;
				poll_array[poll_count].events = events;
				poll_array[poll_count].revents = 0;
				poll_indices[poll_count] = i;
				poll_count++;
			}

			j++;
		}

		if (server->num_conns < HTTP_MAX_CLIENTS_PER_SERVER) {
			poll_array[poll_count].fd = server->listen_fd;
			poll_array[poll_count].events = POLLIN;
			poll_array[poll_count].revents = 0;
			poll_count++;
		}

		int timeout2;
		if (timeout < 0)
			timeout2 = -1;
		else {
			unsigned long long current_time = get_current_time_ms();
			if (current_time == -1ULL)
				return -1;
			ASSERT(current_time >= start_time);
			if (current_time - start_time > (unsigned long long) timeout)
				return 0;
			timeout2 = (int) (current_time - start_time);
		}

		int num = POLL(poll_array, poll_count, timeout2);
		if (num < 0) {
			// TODO
		}

		if (server->num_conns < HTTP_MAX_CLIENTS_PER_SERVER) {
			if (poll_array[poll_count-1].revents) do {
				SOCKET accepted_fd = accept(server->listen_fd, NULL, NULL);
				if (accepted_fd == INVALID_SOCKET)
					break;

				int i = 0;
				while ((SOCKET) server->conns[i].fd != INVALID_SOCKET)
					i++;
				HTTP_ServerConnection *conn = &server->conns[i];

				conn->fd = accepted_fd;
				http_engine_init(&conn->eng, 0, memfunc, NULL);

				server->num_conns++;

			} while (server->num_conns < HTTP_MAX_CLIENTS_PER_SERVER);
			poll_count--;
		}

		for (int i = 0; i < poll_count; i++) {

			int j = poll_indices[i];
			int revents = poll_array[i].revents;

			HTTP_ServerConnection *conn = &server->conns[j];
			ASSERT((SOCKET) conn->fd != INVALID_SOCKET);

			HTTP_EngineState state;
			for (;;) {
				state = http_engine_state(&conn->eng);

				if (state == HTTP_ENGINE_STATE_SERVER_RECV_BUF && (revents & POLLIN)) {
					int max;
					char *buf = http_engine_recvbuf(&conn->eng, &max);
					int ret = recv(conn->fd, buf, max, 0);
					if (ret <= 0) {
						if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
							revents = ~POLLIN;
						else
							http_engine_close(&conn->eng);
						ret = 0;
					}
					http_engine_recvack(&conn->eng, ret);
					continue;
				}

				if (state == HTTP_ENGINE_STATE_SERVER_SEND_BUF && (revents & POLLOUT)) {
					int max;
					char *buf = http_engine_sendbuf(&conn->eng, &max);
					int ret = send(conn->fd, buf, max, 0);
					if (ret <= 0) {
						if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
							revents = ~POLLOUT;
						else
							http_engine_close(&conn->eng);
						ret = 0;
					}
					http_engine_sendack(&conn->eng, ret);
					continue;
				}

				break;
			}

			if (state == HTTP_ENGINE_STATE_SERVER_PREP_STATUS)
				int_queue_push(&server->ready, j);

			if (state == HTTP_ENGINE_STATE_SERVER_CLOSED) {

				http_engine_free(&conn->eng);

				CLOSE_SOCKET(conn->fd);
				conn->fd = INVALID_SOCKET;

				conn->gen++;
				if (conn->gen == 0 || conn->gen == UINT16_MAX)
					conn->gen = 1;

				int_queue_remove(&server->ready, j);

				server->num_conns--;
			}
		}
	}

	HTTP_ServerConnection *conn = &server->conns[popped];
	*req = http_engine_getreq(&conn->eng);
	*res = conn2handle(server, conn);
	return 1;
}

void http_response_status(HTTP_ResponseHandle res, int status)
{
	HTTP_ServerConnection *conn = handle2conn(res);
	if (conn == NULL)
		return;

	http_engine_status(&conn->eng, status);
}

void http_response_header(HTTP_ResponseHandle res, const char *fmt, ...)
{
	HTTP_ServerConnection *conn = handle2conn(res);
	if (conn == NULL)
		return;

	va_list args;
	va_start(args, fmt);
	http_engine_header_fmt2(&conn->eng, fmt, args);
	va_end(args);
}

void http_response_body(HTTP_ResponseHandle res, char *src, int len)
{
	HTTP_ServerConnection *conn = handle2conn(res);
	if (conn == NULL)
		return;

	if (len < 0)
		len = strlen(src);

	http_engine_body(&conn->eng, src, len);
}

void http_response_bodycap(HTTP_ResponseHandle res, int mincap)
{
	HTTP_ServerConnection *conn = handle2conn(res);
	if (conn == NULL)
		return;

	http_engine_bodycap(&conn->eng, mincap);
}

char *http_response_bodybuf(HTTP_ResponseHandle res, int *cap)
{
	HTTP_ServerConnection *conn = handle2conn(res);
	if (conn == NULL) {
		*cap = 0;
		return NULL;
	}

	return http_engine_bodybuf(&conn->eng, cap);
}

void http_response_bodyack(HTTP_ResponseHandle res, int num)
{
	HTTP_ServerConnection *conn = handle2conn(res);
	if (conn == NULL)
		return;

	http_engine_bodyack(&conn->eng, num);
}

void http_response_undo(HTTP_ResponseHandle res)
{
	HTTP_ServerConnection *conn = handle2conn(res);
	if (conn == NULL)
		return;

	http_engine_undo(&conn->eng);
}

void http_response_done(HTTP_ResponseHandle res)
{
	HTTP_Server *server = res.ptr;
	HTTP_ServerConnection *conn = handle2conn(res);
	if (conn == NULL)
		return;

	http_engine_done(&conn->eng);

	conn->gen++;
	if (conn->gen == 0 || conn->gen == UINT16_MAX)
		conn->gen = 1;

	HTTP_EngineState state = http_engine_state(&conn->eng);

	if (state == HTTP_ENGINE_STATE_SERVER_PREP_STATUS)
		int_queue_push(&server->ready, res.idx);

	if (state == HTTP_ENGINE_STATE_SERVER_CLOSED) {

		http_engine_free(&conn->eng);

		CLOSE_SOCKET(conn->fd);
		conn->fd = INVALID_SOCKET;

		int_queue_remove(&server->ready, res.idx);

		server->num_conns--;
	}
}

#endif // HTTP_SERVER
/////////////////////////////////////////////////////////////////////
// HTTP ROUTER
/////////////////////////////////////////////////////////////////////
#if HTTP_ROUTER

#if !HTTP_SERVER
#error "HTTP_ROUTER depends on HTTP_SERVER"
#endif

#ifndef _WIN32
#include <sys/stat.h>
#endif

typedef enum {
	ROUTE_STATIC_DIR,
	ROUTE_DYNAMIC,
} RouteType;

typedef struct {
	RouteType type;
	HTTP_String endpoint;
	HTTP_String path;
	HTTP_RouterFunc func;
	void *ptr;
} Route;

struct HTTP_Router {
	int num_routes;
	int max_routes;
	Route routes[];
};

HTTP_Router *http_router_init(void)
{
	int max_routes = 32;
	HTTP_Router *router = malloc(max_routes * sizeof(HTTP_Router));
	if (router == NULL)
		return NULL;
	router->max_routes = max_routes;
	router->num_routes = 0;
	return router;
}

void http_router_free(HTTP_Router *router)
{
	free(router);
}

void http_router_dir(HTTP_Router *router, HTTP_String endpoint, HTTP_String path)
{
	if (router->num_routes == router->max_routes)
		abort();
	Route *route = &router->routes[router->num_routes++];
	route->type = ROUTE_STATIC_DIR;
	route->endpoint = endpoint;
	route->path = path;
}

void http_router_func(HTTP_Router *router, HTTP_Method method,
	HTTP_String endpoint, HTTP_RouterFunc func, void *ptr)
{
	if (router->num_routes == router->max_routes)
		abort();
	Route *route = &router->routes[router->num_routes++];
	// TODO: Don't ignore the method
	route->type = ROUTE_DYNAMIC;
	route->endpoint = endpoint;
	route->func = func;
	route->ptr  = ptr;
}

static int valid_component_char(char c)
{
	return is_alpha(c) || is_digit(c) || c == '-' || c == '_' || c == '.'; // TODO
}

static int parse_and_sanitize_path(HTTP_String path, HTTP_String *comps, int max_comps)
{
	// We treat relative and absolute paths the same
	if (path.len > 0 && path.ptr[0] == '/') {
		path.ptr++;
		path.len--;
		if (path.len == 0)
			return 0;
	}

	int num = 0;
	int cur = 0;
	for (;;) {
		if (cur == path.len || !valid_component_char(path.ptr[cur]))
			return -1; // Empty component
		int start = cur;
		do
			cur++;
		while (cur < path.len && valid_component_char(path.ptr[cur]));
		HTTP_String comp = { path.ptr + start, cur - start };

		if (http_streq(comp, HTTP_STR(".."))) {
			if (num == 0)
				return -1;
			num--;
		} else if (!http_streq(comp, HTTP_STR("."))) {
			if (num == max_comps)
				return -1;
			comps[num++] = comp;
		}

		if (cur < path.len) {
			if (path.ptr[cur] != '/')
				return -1;
			cur++;
		}

		if (cur == path.len)
			break;
	}

	return num;
}

static int
serialize_parsed_path(HTTP_String *comps, int num_comps, char *dst, int max)
{
	int len = 0;
	for (int i = 0; i < num_comps; i++)
		len += comps[i].len + 1;

	if (len >= max)
		return -1;

	int copied = 0;
	for (int i = 0; i < num_comps; i++) {

		if (i > 0)
			dst[copied++] = '/';

		memcpy(dst + copied,
			comps[i].ptr,
			comps[i].len);

		copied += comps[i].len;
	}

	dst[copied] = '\0';
	return copied;
}

#define MAX_COMPS 32

static int sanitize_path(HTTP_String path, char *dst, int max)
{
	HTTP_String comps[MAX_COMPS];
	int num_comps = parse_and_sanitize_path(path, comps, MAX_COMPS);
	if (num_comps < 0) return -1;

	return serialize_parsed_path(comps, num_comps, dst, max);
}

static int swap_parents(HTTP_String original_parent_path, HTTP_String new_parent_path, HTTP_String path, char *mem, int max)
{
	int num_original_parent_path_comps;
	HTTP_String  original_parent_path_comps[MAX_COMPS];

	int num_new_parent_path_comps;
	HTTP_String  new_parent_path_comps[MAX_COMPS];

	int num_path_comps;
	HTTP_String  path_comps[MAX_COMPS];

	num_original_parent_path_comps = parse_and_sanitize_path(original_parent_path, original_parent_path_comps, MAX_COMPS);
	num_new_parent_path_comps      = parse_and_sanitize_path(new_parent_path,      new_parent_path_comps,      MAX_COMPS);
	num_path_comps                 = parse_and_sanitize_path(path,                 path_comps,                 MAX_COMPS);
	if (num_original_parent_path_comps < 0 || num_new_parent_path_comps < 0 || num_path_comps < 0)
		return -1;

	int match = 1;
	if (num_path_comps < num_original_parent_path_comps)
		match = 0;
	else {
		for (int i = 0; i < num_original_parent_path_comps; i++)
			if (!http_streq(original_parent_path_comps[i], path_comps[i])) {
				match = 0;
				break;
			}
	}
	if (!match)
		return 0;

	int num_result_comps = num_new_parent_path_comps + num_path_comps - num_original_parent_path_comps;
	if (num_result_comps < 0 || num_result_comps > MAX_COMPS)
		return -1;
	
	HTTP_String result_comps[MAX_COMPS];
	for (int i = 0; i < num_new_parent_path_comps; i++)
		result_comps[i] = new_parent_path_comps[i];
	
	for (int i = 0; i < num_path_comps; i++)
		result_comps[num_new_parent_path_comps + i] = path_comps[num_original_parent_path_comps + i];

	return serialize_parsed_path(result_comps, num_result_comps, mem, max);
}

#if _WIN32
typedef HANDLE File;
#else
typedef int File;
#endif

static int file_open(const char *path, File *handle, int *size)
{
#ifdef _WIN32
	*handle = CreateFileA(
		path,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (*handle == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError();
		if (error == ERROR_FILE_NOT_FOUND)
			return 1;
		if (error == ERROR_ACCESS_DENIED)
			return 1;
		return -1;
	}
	LARGE_INTEGER fileSize;
	if (!GetFileSizeEx(*handle, &fileSize)) {
		CloseHandle(*handle);
		return -1;
	}
	if (fileSize.QuadPart > INT_MAX) {
		CloseHandle(*handle);
		return -1;
	}
	*size = (int) fileSize.QuadPart;
	return 0;
#else
	*handle = open(path, O_RDONLY);
	if (*handle < 0) {
		if (errno == ENOENT)
			return 1;
		return -1;
	}
	struct stat info;
	if (fstat(*handle, &info) < 0) {
		close(*handle);
		return -1;
	}
	if (S_ISDIR(info.st_mode)) {
		close(*handle);
		return 1;
	}
	if (info.st_size > INT_MAX) {
		close(*handle);
		return -1;
	}
	*size = (int) info.st_size;
	return 0;
#endif
}

static void file_close(File file)
{
#ifdef _WIN32
	CloseHandle(file);
#else
	close(file);
#endif
}

static int file_read(File file, char *dst, int max)
{
#ifdef _WIN32
	DWORD num;
	BOOL ok = ReadFile(file, dst, max, &num, NULL);
	if (!ok)
		return -1;
	return (int) num;
#else
	return read(file, dst, max);
#endif
}

static int serve_file_or_index(HTTP_ResponseHandle res, HTTP_String base_endpoint, HTTP_String base_path, HTTP_String endpoint)
{
	char mem[1<<12];
	int ret = swap_parents(base_endpoint, base_path, endpoint, mem, sizeof(mem));
	if (ret <= 0)
		return ret;
	HTTP_String path = {mem, ret}; // Note that this is zero terminated

	int size;
	File file;
	ret = file_open(path.ptr, &file, &size);
	if (ret == -1) {
		http_response_status(res, 500);
		http_response_done(res);
		return 1;
	}
	if (ret == 1) {

		// File missing

		char index[] = "index.html";
		if (path.len + sizeof(index) + 1 > sizeof(mem)) {
			http_response_status(res, 500);
			http_response_done(res);
			return 1;
		}
		path.ptr[path.len++] = '/';
		memcpy(path.ptr + path.len, index, sizeof(index));
		path.len += sizeof(index)-1;

		ret = file_open(path.ptr, &file, &size);
		if (ret == -1) {
			http_response_status(res, 500);
			http_response_done(res);
			return 1;
		}
		if (ret == 1)
			return 0; // File missing
	}
	ASSERT(ret == 0);

	int cap;
	char *dst;
	http_response_status(res, 200);
	http_response_bodycap(res, size);
	dst = http_response_bodybuf(res, &cap);
	if (dst) {
		int copied = 0;
		while (copied < size) {
			int ret = file_read(file, dst + copied, size - copied);
			if (ret < 0) goto err;
			if (ret == 0) break;
			copied += ret;
		}
		if (copied < size) goto err;
		http_response_bodyack(res, size);
	}
	http_response_done(res);
	file_close(file);
	return 1;
err:
	http_response_bodyack(res, 0);
	http_response_undo(res);
	http_response_status(res, 500);
	http_response_done(res);
	file_close(file);
	return 1;
}

static int serve_dynamic_route(Route *route, HTTP_Request *req, HTTP_ResponseHandle res)
{
	char path_mem[1<<12];
	int path_len = sanitize_path(req->url.path, path_mem, (int) sizeof(path_mem));
	if (path_len < 0) {
		http_response_status(res, 400);
		http_response_body(res, "Invalid path", -1);
		http_response_done(res);
		return 1;
	}
	HTTP_String path = {path_mem, path_len};

	if (!http_streq(path, route->endpoint))
		return 0;

	route->func(req, res, route->ptr);
	return 1;
}

void http_router_resolve(HTTP_Router *router, HTTP_Request *req, HTTP_ResponseHandle res)
{
	for (int i = 0; i < router->num_routes; i++) {
		Route *route = &router->routes[i];
		switch (route->type) {
		case ROUTE_STATIC_DIR:
			if (serve_file_or_index(res,
				route->endpoint,
				route->path,
				req->url.path))
				return;
			break;

		case ROUTE_DYNAMIC:
			if (serve_dynamic_route(route, req, res))
				return;
			break;

		default:
			http_response_status(res, 500);
			http_response_done(res);
			return;
		}
	}
	http_response_status(res, 404);
	http_response_done(res);
}

int http_serve(const char *addr, int port, HTTP_Router *router)
{
	int ret;

	HTTP_Server server;
	ret = http_server_init(&server, addr, port);
	if (ret < 0) {
		http_router_free(router);
		return -1;
	}

	for (;;) {
		HTTP_Request *req;
		HTTP_ResponseHandle res;
		ret = http_server_wait(&server, &req, &res, -1);
		if (ret < 0) {
			http_server_free(&server);
			http_router_free(router);
			return -1;
		}
		if (ret == 0)
			continue;
		http_router_resolve(router, req, res);
	}

	http_server_free(&server);
	http_router_free(router);
	return 0;
}

#endif // HTTP_ROUTER
/////////////////////////////////////////////////////////////////////
// THE END
/////////////////////////////////////////////////////////////////////