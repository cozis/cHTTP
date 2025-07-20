/*
 * HTTP Library - Amalgamated Source
 * Generated automatically - do not edit manually
 */

#include "http.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

//////////////////////////////////////////////////////////////////////
// src/cert.h
//////////////////////////////////////////////////////////////////////

int http_create_test_certificate(HTTP_String C, HTTP_String O, HTTP_String CN,
    HTTP_String cert_file, HTTP_String key_file);

//////////////////////////////////////////////////////////////////////
// src/socket.h
//////////////////////////////////////////////////////////////////////

// This is a socket abstraction module for non-blocking TCP and TLS sockets.
//
// Sockets may be in a number of states based on if they are plain TCP or TLS
// sockets. Users generally only care about when the connection is established
// or is terminated.
//
// Sockets can be created by connecting to a server using one of these:
//
//   socket_connect
//   socket_connect_ipv4
//   socket_connect_ipv6
//
// They allow connecting to a remote host by specifying its name, of IP address.
// Or by interning a socket accepted by a listening socket:
//
//   socket_accept
//
// after creation, the event field will hold one of the values:
//
//   SOCKET_WANT_READ
//   SOCKET_WANT_WRITE
//
// Which respectively mean that the socket object needs to read or write
// from the underlying socket, and to do so non-blockingly, the caller needs
// to wait for the socket being ready for that operation. This is one way
// to do it:
//
//   // Translate the socket event field to poll() flags
//   int events;
//   if (sock.event == SOCKET_WANT_READ)
//     events = POLLIN;
//   else if (sock.event == SOCKET_WANT_WRITE)
//     events = POLLOUT;
//
//   // block until the socket is ready
//   struct pollfd buf;
//   buf.fd = sock.fd;
//   buf.events = events;
//   buf.revents = 0;
//   poll(&buf, 1, -1);
//
// whenever a socket is ready, the user must call the socket_update
// function. Then, if the socket is in the SOCKET_STATE_ESTABLISHED_READY
// state, the user can call one of
//
//   socket_close
//   socket_read
//   socket_write
//
// At any point the socket could reach the SOCKET_STATE_DIED state,
// which means the user needs to call socket_free to free the socket
// as it's not unusable.



typedef struct {
    int is_ipv6;
    union {
        HTTP_IPv4 ipv4;
        HTTP_IPv6 ipv6;
    } addr;
} AddrInfo;

typedef enum {
    SOCKET_STATE_PENDING,
    SOCKET_STATE_CONNECTING,
    SOCKET_STATE_CONNECTED,
    SOCKET_STATE_ACCEPTED,
    SOCKET_STATE_ESTABLISHED_WAIT,
    SOCKET_STATE_ESTABLISHED_READY,
    SOCKET_STATE_SHUTDOWN,
    SOCKET_STATE_DIED
} SocketState;

typedef enum {
    SOCKET_WANT_NONE,
    SOCKET_WANT_READ,
    SOCKET_WANT_WRITE,
} SocketWantEvent;

typedef struct {
    SocketState state;
    SocketWantEvent event;
    int fd;
    SSL *ssl;
    SSL_CTX *ssl_ctx;
    AddrInfo *addr_list;
    int addr_count;
    int addr_cursor;
    char *hostname;
    uint16_t port;
} Socket;

typedef struct {
    char name[128];
    SSL_CTX *ssl_ctx;
} Domain;

typedef struct {
    SSL_CTX *ssl_ctx;
    int num_domains;
    int max_domains;
    Domain *domains;
} SocketGroup;

void        socket_global_init  (void);
void        socket_global_free  (void);
int         socket_group_init   (SocketGroup *group);
int         socket_group_init_server(SocketGroup *group, HTTP_String cert_file, HTTP_String key_file);
int         socket_group_add_domain(SocketGroup *group, HTTP_String domain, HTTP_String cert_key, HTTP_String private_key);
void        socket_group_free   (SocketGroup *group);
SocketState socket_state        (Socket *sock);
void        socket_accept       (Socket *sock, SocketGroup *group, int fd);
void        socket_connect      (Socket *sock, SocketGroup *group, HTTP_String host, uint16_t port);
void        socket_connect_ipv4 (Socket *sock, SocketGroup *group, HTTP_IPv4   addr, uint16_t port);
void        socket_connect_ipv6 (Socket *sock, SocketGroup *group, HTTP_IPv6   addr, uint16_t port);
void        socket_update       (Socket *sock);
int         socket_read         (Socket *sock, char *dst, int max);
int         socket_write        (Socket *sock, char *src, int len);
void        socket_close        (Socket *sock);
void        socket_free         (Socket *sock);
int         socket_wait         (Socket **socks, int num_socks);

//////////////////////////////////////////////////////////////////////
// src/basic.c
//////////////////////////////////////////////////////////////////////

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

static bool is_printable(char c)
{
    return c >= ' ' && c <= '~';
}

void print_bytes(HTTP_String prefix, HTTP_String src)
{
    if (src.len == 0)
        return;

    FILE *stream = stdout;

    bool new_line = true;
    int cur = 0;
    for (;;) {
        int start = cur;

        while (cur < src.len && is_printable(src.ptr[cur]))
            cur++;

        if (new_line) {
            fwrite(prefix.ptr, 1, prefix.len, stream);
            new_line = false;
        }

        fwrite(src.ptr + start, 1, cur - start, stream);

        if (cur == src.len)
            break;

        if (src.ptr[cur] == '\n') {
            putc('\\', stream);
            putc('n',  stream);
            putc('\n', stream);
            new_line = true;
        } else if (src.ptr[cur] == '\r') {
            putc('\\', stream);
            putc('r',  stream);
        } else {
            putc('.', stream);
        }
        cur++;
    }
    putc('\n', stream);
}//////////////////////////////////////////////////////////////////////
// src/parse.c
//////////////////////////////////////////////////////////////////////

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
}//////////////////////////////////////////////////////////////////////
// src/engine.c
//////////////////////////////////////////////////////////////////////

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

	HTTP_ASSERT((queue->flags & BYTE_QUEUE_READ) == 0);
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
	HTTP_ASSERT(num >= 0);

	if (queue->flags & BYTE_QUEUE_ERROR)
		return;

	if ((queue->flags & BYTE_QUEUE_READ) == 0)
		return;

	queue->flags &= ~BYTE_QUEUE_READ;

	HTTP_ASSERT((unsigned int) num <= queue->used);
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

	HTTP_ASSERT((queue->flags & BYTE_QUEUE_WRITE) == 0);
	queue->flags |= BYTE_QUEUE_WRITE;

	unsigned int ucap = queue->size - (queue->head + queue->used);
	if (ucap > INT_MAX) ucap = INT_MAX;

	*cap = (int) ucap;
	return queue->data + (queue->head + queue->used);
}

static void
byte_queue_write_ack(HTTP_ByteQueue *queue, int num)
{
	HTTP_ASSERT(num >= 0);

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
	HTTP_ASSERT(mincap >= 0);
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

	HTTP_ASSERT((queue->flags & BYTE_QUEUE_WRITE) == 0);

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
	if (queue->flags & BYTE_QUEUE_ERROR)
		return;

	// Check that the offset is in range
	HTTP_ASSERT(off >= queue->curs && off - queue->curs < queue->used);

	// Check that the length is in range
	HTTP_ASSERT(len <= queue->used - (off - queue->curs));

	// Perform the patch
	char *dst = queue->data + queue->head + (off - queue->curs);
	memcpy(dst, src, len);
}

static void
byte_queue_remove_from_offset(HTTP_ByteQueue *queue, HTTP_ByteQueueOffset offset)
{
	if (queue->flags & BYTE_QUEUE_ERROR)
		return;

	unsigned long long num = (queue->curs + queue->used) - offset;
	HTTP_ASSERT(num <= queue->used);

	queue->used -= num;
}

static void
byte_queue_write(HTTP_ByteQueue *queue, const char *str, int len)
{
    if (str == NULL) str = "";
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

const char* http_engine_statestr(HTTP_EngineState state) { // TODO: remove
    switch (state) {
        case HTTP_ENGINE_STATE_NONE: return "NONE";
        case HTTP_ENGINE_STATE_CLIENT_PREP_URL: return "CLIENT_PREP_URL";
        case HTTP_ENGINE_STATE_CLIENT_PREP_HEADER: return "CLIENT_PREP_HEADER";
        case HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF: return "CLIENT_PREP_BODY_BUF";
        case HTTP_ENGINE_STATE_CLIENT_PREP_BODY_ACK: return "CLIENT_PREP_BODY_ACK";
        case HTTP_ENGINE_STATE_CLIENT_PREP_ERROR: return "CLIENT_PREP_ERROR";
        case HTTP_ENGINE_STATE_CLIENT_SEND_BUF: return "CLIENT_SEND_BUF";
        case HTTP_ENGINE_STATE_CLIENT_SEND_ACK: return "CLIENT_SEND_ACK";
        case HTTP_ENGINE_STATE_CLIENT_RECV_BUF: return "CLIENT_RECV_BUF";
        case HTTP_ENGINE_STATE_CLIENT_RECV_ACK: return "CLIENT_RECV_ACK";
        case HTTP_ENGINE_STATE_CLIENT_READY: return "CLIENT_READY";
        case HTTP_ENGINE_STATE_CLIENT_CLOSED: return "CLIENT_CLOSED";
        case HTTP_ENGINE_STATE_SERVER_RECV_BUF: return "SERVER_RECV_BUF";
        case HTTP_ENGINE_STATE_SERVER_RECV_ACK: return "SERVER_RECV_ACK";
        case HTTP_ENGINE_STATE_SERVER_PREP_STATUS: return "SERVER_PREP_STATUS";
        case HTTP_ENGINE_STATE_SERVER_PREP_HEADER: return "SERVER_PREP_HEADER";
        case HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF: return "SERVER_PREP_BODY_BUF";
        case HTTP_ENGINE_STATE_SERVER_PREP_BODY_ACK: return "SERVER_PREP_BODY_ACK";
        case HTTP_ENGINE_STATE_SERVER_PREP_ERROR: return "SERVER_PREP_ERROR";
        case HTTP_ENGINE_STATE_SERVER_SEND_BUF: return "SERVER_SEND_BUF";
        case HTTP_ENGINE_STATE_SERVER_SEND_ACK: return "SERVER_SEND_ACK";
        case HTTP_ENGINE_STATE_SERVER_CLOSED: return "SERVER_CLOSED";
        default: return "UNKNOWN";
    }
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
		if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT)
			eng->state = HTTP_ENGINE_STATE_CLIENT_CLOSED;
		else
			eng->state = HTTP_ENGINE_STATE_SERVER_CLOSED;
		return NULL;
	}

	return byte_queue_write_buf(&eng->input, cap);
}

static int
should_keep_alive(HTTP_Engine *eng)
{
	HTTP_ASSERT(eng->state & HTTP_ENGINE_STATEBIT_PREP);

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
	int i = http_find_header(req->headers, req->num_headers, HTTP_STR("Connection"));
	if (i >= 0 && http_streqcase(req->headers[i].value, HTTP_STR("Close")))
		return 0;

	return 1;
}

static void process_incoming_request(HTTP_Engine *eng)
{
	HTTP_ASSERT(eng->state == HTTP_ENGINE_STATE_SERVER_RECV_ACK
		|| eng->state == HTTP_ENGINE_STATE_SERVER_SEND_ACK
		|| eng->state == HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF
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

	HTTP_ASSERT(ret > 0);

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

		HTTP_ASSERT(ret > 0);

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

void http_engine_url(HTTP_Engine *eng, HTTP_Method method, HTTP_String url, int minor)
{
	if (eng->state != HTTP_ENGINE_STATE_CLIENT_PREP_URL)
		return;

	eng->response_offset = byte_queue_offset(&eng->output); // TODO: rename response_offset to something that makes sense for clients

	HTTP_URL parsed_url;
	int ret = http_parse_url(url.ptr, url.len, &parsed_url);
	if (ret != url.len) {
		eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_ERROR;
		return;
	}

	HTTP_String method_and_space = HTTP_STR("???");
	switch (method) {
		case HTTP_METHOD_GET    : method_and_space = HTTP_STR("GET ");     break;
		case HTTP_METHOD_HEAD   : method_and_space = HTTP_STR("HEAD ");    break;
		case HTTP_METHOD_POST   : method_and_space = HTTP_STR("POST ");    break;
		case HTTP_METHOD_PUT    : method_and_space = HTTP_STR("PUT ");     break;
		case HTTP_METHOD_DELETE : method_and_space = HTTP_STR("DELETE ");  break;
		case HTTP_METHOD_CONNECT: method_and_space = HTTP_STR("CONNECT "); break;
		case HTTP_METHOD_OPTIONS: method_and_space = HTTP_STR("OPTIONS "); break;
		case HTTP_METHOD_TRACE  : method_and_space = HTTP_STR("TRACE ");   break;
		case HTTP_METHOD_PATCH  : method_and_space = HTTP_STR("PATCH ");   break;
	}

	HTTP_String path = parsed_url.path;
	if (path.len == 0)
		path = HTTP_STR("/");

	byte_queue_write(&eng->output, method_and_space.ptr, method_and_space.len);
	byte_queue_write(&eng->output, path.ptr, path.len);
	byte_queue_write(&eng->output, parsed_url.query.ptr, parsed_url.query.len);
	byte_queue_write(&eng->output, minor ? " HTTP/1.1\r\nHost: " : " HTTP/1.0\r\nHost: ", -1);
	byte_queue_write(&eng->output, parsed_url.authority.host.text.ptr, parsed_url.authority.host.text.len);
	if (parsed_url.authority.port > 0)
		byte_queue_write_fmt(&eng->output, "%d", parsed_url.authority.port);
	byte_queue_write(&eng->output, "\r\n", 2);

	eng->keepalive = 1; // TODO

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

	if (len < 0) len = strlen(src);

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
complete_message_head(HTTP_Engine *eng)
{
	if (eng->keepalive) byte_queue_write(&eng->output, "Connection: Keep-Alive\r\n", -1);
	else                byte_queue_write(&eng->output, "Connection: Close\r\n", -1);

	byte_queue_write(&eng->output, "Content-Length: ", -1);
	eng->content_length_value_offset = byte_queue_offset(&eng->output);
	byte_queue_write(&eng->output, TEN_SPACES "\r\n", -1);

	byte_queue_write(&eng->output, "\r\n", -1);
	eng->content_length_offset = byte_queue_offset(&eng->output);
}

static void complete_message_body(HTTP_Engine *eng)
{
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

void http_engine_body(HTTP_Engine *eng, void *src, int len)
{
	if (len < 0) len = strlen(src);

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
			complete_message_head(eng);
			eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF;
		}

	} else {

		if (eng->state == HTTP_ENGINE_STATE_SERVER_PREP_HEADER) {
			complete_message_head(eng);
			eng->state = HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF;
		}
	}
}

void http_engine_bodycap(HTTP_Engine *eng, int mincap)
{
	ensure_body_entered(eng);
	if (eng->state != HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF &&
		eng->state != HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF)
		return;

	byte_queue_write_setmincap(&eng->output, mincap);
}

char *http_engine_bodybuf(HTTP_Engine *eng, int *cap)
{
	ensure_body_entered(eng);
	if (eng->state != HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF &&
		eng->state != HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF) {
		*cap = 0;
		return NULL;
	}

	if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT)
		eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_BODY_ACK;
	else
		eng->state = HTTP_ENGINE_STATE_SERVER_PREP_BODY_ACK;

	return byte_queue_write_buf(&eng->output, cap);
}

void http_engine_bodyack(HTTP_Engine *eng, int num)
{
	if (eng->state != HTTP_ENGINE_STATE_CLIENT_PREP_BODY_ACK &&
		eng->state != HTTP_ENGINE_STATE_SERVER_PREP_BODY_ACK)
		return;

	byte_queue_write_ack(&eng->output, num);

	if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT)
		eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF;
	else
		eng->state = HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF;
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
			complete_message_head(eng);
			eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF;
		}

		if (eng->state == HTTP_ENGINE_STATE_CLIENT_PREP_BODY_BUF)
			complete_message_body(eng);

		if (eng->state == HTTP_ENGINE_STATE_CLIENT_PREP_ERROR) {
			eng->state = HTTP_ENGINE_STATE_CLIENT_CLOSED;
			return;
		}

		if (byte_queue_error(&eng->output)) {
			eng->state = HTTP_ENGINE_STATE_CLIENT_CLOSED;
			return;
		}

		eng->state = HTTP_ENGINE_STATE_CLIENT_SEND_BUF;

	} else {

		if (eng->state == HTTP_ENGINE_STATE_SERVER_PREP_HEADER) {
			complete_message_head(eng);
			eng->state = HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF;
		}

		if (eng->state == HTTP_ENGINE_STATE_SERVER_PREP_BODY_BUF)
			complete_message_body(eng);

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

	byte_queue_write_ack(&eng->output, 0);
	byte_queue_remove_from_offset(&eng->output, eng->response_offset);

	if (eng->state & HTTP_ENGINE_STATEBIT_CLIENT)
		eng->state = HTTP_ENGINE_STATE_CLIENT_PREP_URL;
	else
		eng->state = HTTP_ENGINE_STATE_SERVER_PREP_STATUS;
}//////////////////////////////////////////////////////////////////////
// src/socket.c
//////////////////////////////////////////////////////////////////////

void socket_global_init(void)
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

void socket_global_free(void)
{
    EVP_cleanup();
    ERR_free_strings();
}

int socket_group_init(SocketGroup *group)
{
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        fprintf(stderr, "Unable to create SSL context\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Set minimum TLS version (optional - for better security)
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
    
    // Set certificate verification mode
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
    
    // Load default trusted certificate store
    if (SSL_CTX_set_default_verify_paths(ssl_ctx) != 1) {
        fprintf(stderr, "Failed to set default verify paths\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ssl_ctx);
        return -1;
    }

    group->ssl_ctx = ssl_ctx;
    group->domains = NULL;
    group->num_domains = 0;
    group->max_domains = 0;
    return 0;
}

static int servername_callback(SSL *ssl, int *ad, void *arg)
{
    SocketGroup *group = arg;

    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (servername == NULL)
        return SSL_TLSEXT_ERR_NOACK;
    
    for (int i = 0; i < group->num_domains; i++) {
        Domain *domain = &group->domains[i];
        if (!strcmp(domain->name, servername)) {
            SSL_set_SSL_CTX(ssl, domain->ssl_ctx);
            return SSL_TLSEXT_ERR_OK;
        }
    }

    return SSL_TLSEXT_ERR_NOACK;
}

int socket_group_init_server(SocketGroup *group, HTTP_String cert_file, HTTP_String key_file)
{
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) {
        fprintf(stderr, "Unable to create server SSL context\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Set minimum TLS version (optional - for better security)
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
    
    // Copy certificate file path to static buffer
    static char cert_buffer[1024];
    if (cert_file.len >= (int) sizeof(cert_buffer)) {
        fprintf(stderr, "Certificate file path too long\n");
        SSL_CTX_free(ssl_ctx);
        return -1;
    }
    memcpy(cert_buffer, cert_file.ptr, cert_file.len);
    cert_buffer[cert_file.len] = '\0';
    
    // Copy private key file path to static buffer
    static char key_buffer[1024];
    if (key_file.len >= (int) sizeof(key_buffer)) {
        fprintf(stderr, "Private key file path too long\n");
        SSL_CTX_free(ssl_ctx);
        return -1;
    }
    memcpy(key_buffer, key_file.ptr, key_file.len);
    key_buffer[key_file.len] = '\0';
    
    // Load certificate and private key
    if (SSL_CTX_use_certificate_file(ssl_ctx, cert_buffer, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Failed to load certificate file: %s\n", cert_buffer);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ssl_ctx);
        return -1;
    }
    
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_buffer, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Failed to load private key file: %s\n", key_buffer);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ssl_ctx);
        return -1;
    }
    
    // Verify that the private key matches the certificate
    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
        fprintf(stderr, "Private key does not match certificate\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ssl_ctx);
        return -1;
    }

    SSL_CTX_set_tlsext_servername_callback(group->ssl_ctx, servername_callback);
    SSL_CTX_set_tlsext_servername_arg(group->ssl_ctx, group);

    group->ssl_ctx = ssl_ctx;
    group->domains = NULL;
    group->num_domains = 0;
    group->max_domains = 0;
    return 0;
}

void socket_group_free(SocketGroup *group)
{
    SSL_CTX_free(group->ssl_ctx);
}

int socket_group_add_domain(SocketGroup *group, HTTP_String domain, HTTP_String cert_file, HTTP_String key_file)
{
    if (group->num_domains == group->max_domains) {

        int new_max_domains = 2 * group->max_domains;
        if (new_max_domains == 0)
            new_max_domains = 4;

        Domain *new_domains = malloc(new_max_domains * sizeof(Domain));
        if (new_domains == NULL)
            return -1;

        if (group->max_domains > 0) {
            for (int i = 0; i < group->num_domains; i++)
                new_domains[i] = group->domains[i];
            free(group->domains);
        }

        group->domains = new_domains;
        group->max_domains = new_max_domains;
    }

    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) {
        fprintf(stderr, "Unable to create server SSL context\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Set minimum TLS version (optional - for better security)
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
    
    // Copy certificate file path to static buffer
    static char cert_buffer[1024];
    if (cert_file.len >= (int) sizeof(cert_buffer)) {
        fprintf(stderr, "Certificate file path too long\n");
        SSL_CTX_free(ssl_ctx);
        return -1;
    }
    memcpy(cert_buffer, cert_file.ptr, cert_file.len);
    cert_buffer[cert_file.len] = '\0';
    
    // Copy private key file path to static buffer
    static char key_buffer[1024];
    if (key_file.len >= (int) sizeof(key_buffer)) {
        fprintf(stderr, "Private key file path too long\n");
        SSL_CTX_free(ssl_ctx);
        return -1;
    }
    memcpy(key_buffer, key_file.ptr, key_file.len);
    key_buffer[key_file.len] = '\0';
    
    // Load certificate and private key
    if (SSL_CTX_use_certificate_file(ssl_ctx, cert_buffer, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Failed to load certificate file: %s\n", cert_buffer);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ssl_ctx);
        return -1;
    }
    
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_buffer, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Failed to load private key file: %s\n", key_buffer);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ssl_ctx);
        return -1;
    }
    
    // Verify that the private key matches the certificate
    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
        fprintf(stderr, "Private key does not match certificate\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ssl_ctx);
        return -1;
    }

    Domain *domain_info = &group->domains[group->num_domains];
    if (domain.len >= (int) sizeof(domain_info->name)) {
        SSL_CTX_free(ssl_ctx);
        return -1;
    }
    memcpy(domain_info->name, domain.ptr, domain.len);
    domain_info->name[domain.len] = '\0';
    domain_info->ssl_ctx = ssl_ctx;
    group->num_domains++;
    return 0;
}

SocketState socket_state(Socket *sock)
{
    return sock->state;
}

void socket_accept(Socket *sock, SocketGroup *group, int fd)
{
    // Initialize socket for server-side TLS handshake
    sock->state = SOCKET_STATE_ACCEPTED;  // TCP connection already established
    sock->event = SOCKET_WANT_NONE;
    sock->fd = fd;
    sock->ssl = NULL;
    sock->ssl_ctx = group ? group->ssl_ctx : NULL;
    sock->addr_list = NULL;
    sock->addr_count = 0;
    sock->addr_cursor = 0;
    sock->hostname = NULL;
    sock->port = 0;
    
    // Set non-blocking mode for the accepted socket
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    
    // Start the TLS handshake process
    socket_update(sock);
}

void socket_connect(Socket *sock, SocketGroup *group, HTTP_String host, uint16_t port) {
    sock->state = SOCKET_STATE_PENDING;
    sock->event = SOCKET_WANT_NONE;
    sock->fd = -1;
    sock->ssl = NULL;
    sock->ssl_ctx = group ? group->ssl_ctx : NULL;
    sock->addr_list = NULL;
    sock->addr_count = 0;
    sock->addr_cursor = 0;
    sock->port = port;
    sock->hostname = (char*)malloc(host.len + 1);
    memcpy(sock->hostname, host.ptr, host.len);
    sock->hostname[host.len] = '\0';
    // DNS query
    struct addrinfo hints = {0}, *res = NULL, *rp = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", port);
    if (getaddrinfo(sock->hostname, portstr, &hints, &res) != 0) {
        sock->state = SOCKET_STATE_DIED;
        return;
    }
    // Count addresses
    int count = 0;
    for (rp = res; rp; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET || rp->ai_family == AF_INET6) count++;
    }
    if (count == 0) {
        freeaddrinfo(res);
        sock->state = SOCKET_STATE_DIED;
        return;
    }
    sock->addr_list = (AddrInfo*)malloc(sizeof(AddrInfo) * count);
    sock->addr_count = count;
    sock->addr_cursor = 0;
    int i = 0;
    for (rp = res; rp; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET) {
            sock->addr_list[i].is_ipv6 = 0;
            memcpy(&sock->addr_list[i].addr.ipv4, &((struct sockaddr_in*)rp->ai_addr)->sin_addr, sizeof(HTTP_IPv4));
            i++;
        } else if (rp->ai_family == AF_INET6) {
            sock->addr_list[i].is_ipv6 = 1;
            memcpy(&sock->addr_list[i].addr.ipv6, &((struct sockaddr_in6*)rp->ai_addr)->sin6_addr, sizeof(HTTP_IPv6));
            i++;
        }
    }
    freeaddrinfo(res);
    // Set event/state and call update
    sock->event = SOCKET_WANT_NONE;
    sock->state = SOCKET_STATE_PENDING;
    socket_update(sock);
}

void socket_connect_ipv4(Socket *sock, SocketGroup *group, HTTP_IPv4 addr, uint16_t port) {
    sock->state = SOCKET_STATE_PENDING;
    sock->event = SOCKET_WANT_NONE;
    sock->fd = -1;
    sock->ssl = NULL;
    sock->ssl_ctx = group ? group->ssl_ctx : NULL;
    sock->addr_list = NULL;
    sock->addr_count = 0;
    sock->addr_cursor = 0;
    sock->hostname = NULL;
    sock->port = port;
    sock->addr_list = (AddrInfo*)malloc(sizeof(AddrInfo));
    sock->addr_list[0].is_ipv6 = 0;
    memcpy(&sock->addr_list[0].addr.ipv4, &addr, sizeof(HTTP_IPv4));
    sock->addr_count = 1;
    sock->addr_cursor = 0;
    sock->event = SOCKET_WANT_NONE;
    sock->state = SOCKET_STATE_PENDING;
    socket_update(sock);
}

void socket_connect_ipv6(Socket *sock, SocketGroup *group, HTTP_IPv6 addr, uint16_t port) {
    sock->state = SOCKET_STATE_PENDING;
    sock->event = SOCKET_WANT_NONE;
    sock->fd = -1;
    sock->ssl = NULL;
    sock->ssl_ctx = group ? group->ssl_ctx : NULL;
    sock->addr_list = NULL;
    sock->addr_count = 0;
    sock->addr_cursor = 0;
    sock->hostname = NULL;
    sock->port = port;
    sock->addr_list = (AddrInfo*)malloc(sizeof(AddrInfo));
    sock->addr_list[0].is_ipv6 = 1;
    memcpy(&sock->addr_list[0].addr.ipv6, &addr, sizeof(HTTP_IPv6));
    sock->addr_count = 1;
    sock->addr_cursor = 0;
    sock->event = SOCKET_WANT_NONE;
    sock->state = SOCKET_STATE_PENDING;
    socket_update(sock);
}

void socket_update(Socket *sock)
{
    sock->event = SOCKET_WANT_NONE;

    bool again;
    do {

        again = false;

        switch (sock->state) {
        case SOCKET_STATE_PENDING:
        {
            if (sock->ssl) {
                SSL_free(sock->ssl);
                sock->ssl = NULL;
            }

            if (sock->fd != -1)
                close(sock->fd);

            // If cursor reached the end, die
            if (sock->addr_cursor >= sock->addr_count) {
                sock->event = SOCKET_WANT_NONE;
                sock->state = SOCKET_STATE_DIED;
                break;
            }

            // Take current address
            AddrInfo *ai = &sock->addr_list[sock->addr_cursor];
            int family = ai->is_ipv6 ? AF_INET6 : AF_INET;
            int fd = socket(family, SOCK_STREAM, 0);
            if (fd < 0) {
                // Try next address
                sock->addr_cursor++;
                sock->event = SOCKET_WANT_NONE;
                sock->state = SOCKET_STATE_PENDING;
                again = true;
                break;
            }

            // Set non-blocking
            int flags = fcntl(fd, F_GETFL, 0);
            if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK); // TODO: Handle error by setting the socket to DIED

            // Prepare sockaddr
            int ret;
            if (ai->is_ipv6) {
                struct sockaddr_in6 sa6 = {0};
                sa6.sin6_family = AF_INET6;
                memcpy(&sa6.sin6_addr, &ai->addr.ipv6, sizeof(HTTP_IPv6));
                sa6.sin6_port = htons(sock->port);
                ret = connect(fd, (struct sockaddr*)&sa6, sizeof(sa6));
            } else {
                struct sockaddr_in sa4 = {0};
                sa4.sin_family = AF_INET;
                memcpy(&sa4.sin_addr, &ai->addr.ipv4, sizeof(HTTP_IPv4));
                sa4.sin_port = htons(sock->port);
                ret = connect(fd, (struct sockaddr*)&sa4, sizeof(sa4));
            }

            if (ret == 0) {
                // Connected immediately
                sock->fd = fd;
                sock->event = SOCKET_WANT_NONE;
                sock->state = SOCKET_STATE_CONNECTED;
                again = true;
                break;
            }
            
            if (ret < 0 && errno == EINPROGRESS) {
                // Connection pending
                sock->fd = fd;
                sock->event = SOCKET_WANT_WRITE;
                sock->state = SOCKET_STATE_CONNECTING;
                break;
            }

            // Connect failed
            // If remote peer not working, try next address
            if (errno == ECONNREFUSED || errno == ETIMEDOUT || errno == ENETUNREACH || errno == EHOSTUNREACH) {
                sock->addr_cursor++;
                sock->event = SOCKET_WANT_NONE;
                sock->state = SOCKET_STATE_PENDING;
                again = true;
            } else {
                sock->event = SOCKET_WANT_NONE;
                sock->state = SOCKET_STATE_DIED;
            }
        }
        break;

        case SOCKET_STATE_CONNECTING:
        {
            // Check connect result
            int err = 0;
            socklen_t len = sizeof(err);
            if (getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
                close(sock->fd);
                // If remote peer not working, try next address
                if (err == ECONNREFUSED || err == ETIMEDOUT || err == ENETUNREACH || err == EHOSTUNREACH) {
                    sock->addr_cursor++;
                    sock->event = SOCKET_WANT_NONE;
                    sock->state = SOCKET_STATE_PENDING;
                    again = true;
                } else {
                    sock->event = SOCKET_WANT_NONE;
                    sock->state = SOCKET_STATE_DIED;
                }
                break;
            }

            // Connect succeeded
            sock->event = SOCKET_WANT_NONE;
            sock->state = SOCKET_STATE_CONNECTED;
            again = true;
            break;
        }
        break;

        case SOCKET_STATE_CONNECTED:
        {
            if (sock->ssl_ctx == NULL) {
                sock->event = SOCKET_WANT_NONE;
                sock->state = SOCKET_STATE_ESTABLISHED_READY;
            } else {

                // Start SSL handshake
                if (!sock->ssl) {
                    sock->ssl = SSL_new(sock->ssl_ctx);
                    SSL_set_fd(sock->ssl, sock->fd); // TODO: handle error?
                    if (sock->hostname) SSL_set_tlsext_host_name(sock->ssl, sock->hostname);
                }

                int ret = SSL_connect(sock->ssl);
                if (ret == 1) {
                    // Handshake done
                    free(sock->addr_list); sock->addr_list = NULL;
                    sock->event = SOCKET_WANT_NONE;
                    sock->state = SOCKET_STATE_ESTABLISHED_READY;
                    break;
                }

                int err = SSL_get_error(sock->ssl, ret);
                if (err == SSL_ERROR_WANT_READ) {
                    sock->event = SOCKET_WANT_READ;
                    break;
                }

                if (err == SSL_ERROR_WANT_WRITE) {
                    sock->event = SOCKET_WANT_WRITE;
                    break;
                }

                sock->addr_cursor++;
                sock->event = SOCKET_WANT_NONE;
                sock->state = SOCKET_STATE_PENDING;
                again = true;
            }
        }
        break;

        case SOCKET_STATE_ACCEPTED:
        {
            if (sock->ssl_ctx == NULL) {
                sock->event = SOCKET_WANT_NONE;
                sock->state = SOCKET_STATE_ESTABLISHED_READY;
            } else {

                // Start server-side SSL handshake
                if (!sock->ssl) {
                    sock->ssl = SSL_new(sock->ssl_ctx);
                    SSL_set_fd(sock->ssl, sock->fd); // TODO: handle error?
                }

                int ret = SSL_accept(sock->ssl);
                if (ret == 1) {
                    // Handshake done
                    sock->event = SOCKET_WANT_NONE;
                    sock->state = SOCKET_STATE_ESTABLISHED_READY;
                    break;
                }

                int err = SSL_get_error(sock->ssl, ret);
                if (err == SSL_ERROR_WANT_READ) {
                    sock->event = SOCKET_WANT_READ;
                    break;
                }

                if (err == SSL_ERROR_WANT_WRITE) {
                    sock->event = SOCKET_WANT_WRITE;
                    break;
                }

                // Server socket error - close the connection
                sock->event = SOCKET_WANT_NONE;
                sock->state = SOCKET_STATE_DIED;
            }
        }
        break;

        case SOCKET_STATE_ESTABLISHED_WAIT:
        {
            sock->event = SOCKET_WANT_NONE;
            sock->state = SOCKET_STATE_ESTABLISHED_READY;
        }
        break;

        case SOCKET_STATE_SHUTDOWN:
        {
            if (sock->ssl_ctx == NULL) {
                sock->event = SOCKET_WANT_NONE;
                sock->state = SOCKET_STATE_DIED;
            } else {

                int ret = SSL_shutdown(sock->ssl);
                if (ret == 1) {
                    sock->event = SOCKET_WANT_NONE;
                    sock->state = SOCKET_STATE_DIED;
                    break;
                }

                int err = SSL_get_error(sock->ssl, ret);
                if (err == SSL_ERROR_WANT_READ) {
                    sock->event = SOCKET_WANT_READ;
                    break;
                }
                
                if (err == SSL_ERROR_WANT_WRITE) {
                    sock->event = SOCKET_WANT_WRITE;
                    break;
                }

                sock->event = SOCKET_WANT_NONE;
                sock->state = SOCKET_STATE_DIED;
            }
        }
        break;

        default:
            // Do nothing
            break;
        }

    } while (again);
}

int socket_read(Socket *sock, char *dst, int max) {
    // If not ESTABLISHED, set state to DIED and return
    if (sock->state != SOCKET_STATE_ESTABLISHED_READY) {
        sock->event = SOCKET_WANT_NONE;
        sock->state = SOCKET_STATE_DIED;
        return -1;
    }

    if (sock->ssl_ctx == NULL) {
        int ret = read(sock->fd, dst, max);
        if (ret == 0) {
            sock->event = SOCKET_WANT_NONE;
            sock->state = SOCKET_STATE_DIED;
        } else {
            if (ret < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    sock->event = SOCKET_WANT_READ;
                    sock->state = SOCKET_STATE_ESTABLISHED_WAIT;
                } else {
                    if (errno != EINTR) {
                        sock->event = SOCKET_WANT_NONE;
                        sock->state = SOCKET_STATE_DIED;
                    }
                }
                ret = 0;
            }
        }
        return ret;
    } else {
        int ret = SSL_read(sock->ssl, dst, max);
        if (ret <= 0) {
            int err = SSL_get_error(sock->ssl, ret);
            if (err == SSL_ERROR_WANT_READ) {
                sock->event = SOCKET_WANT_READ;
                sock->state = SOCKET_STATE_ESTABLISHED_WAIT;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                sock->event = SOCKET_WANT_WRITE;
                sock->state = SOCKET_STATE_ESTABLISHED_WAIT;
            } else {
                fprintf(stderr, "OpenSSL error in socket_read: ");
                ERR_print_errors_fp(stderr);
                sock->event = SOCKET_WANT_NONE;
                sock->state = SOCKET_STATE_DIED;
            }
            ret = 0;
        }
        return ret;
    }
}

int socket_write(Socket *sock, char *src, int len) {
    // If not ESTABLISHED, set state to DIED and return
    if (sock->state != SOCKET_STATE_ESTABLISHED_READY) {
        sock->event = SOCKET_WANT_NONE;
        sock->state = SOCKET_STATE_DIED;
        return 0;
    }

    if (sock->ssl_ctx == NULL) {
        int ret = write(sock->fd, src, len);
        if (ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                sock->event = SOCKET_WANT_WRITE;
                sock->state = SOCKET_STATE_ESTABLISHED_WAIT;
            } else {
                if (errno != EINTR) {
                    sock->event = SOCKET_WANT_NONE;
                    sock->state = SOCKET_STATE_DIED;
                }
            }
            ret = 0;
        }
        return ret;
    } else {
        int ret = SSL_write(sock->ssl, src, len);
        if (ret <= 0) {
            int err = SSL_get_error(sock->ssl, ret);
            if (err == SSL_ERROR_WANT_READ) {
                sock->event = SOCKET_WANT_READ;
                sock->state = SOCKET_STATE_ESTABLISHED_WAIT;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                sock->event = SOCKET_WANT_WRITE;
                sock->state = SOCKET_STATE_ESTABLISHED_WAIT;
            } else {
                fprintf(stderr, "OpenSSL error in socket_write: ");
                ERR_print_errors_fp(stderr);
                sock->event = SOCKET_WANT_NONE;
                sock->state = SOCKET_STATE_DIED;
            }
            ret = 0;
        }
        return ret;
    }
}

void socket_close(Socket *sock) {
    // Set state to SHUTDOWN and call update
    sock->event = SOCKET_WANT_NONE;
    sock->state = SOCKET_STATE_SHUTDOWN;
    socket_update(sock);
}

void socket_free(Socket *sock) {
    // Release all resources associated to the socket
    if (sock->ssl) {
        SSL_free(sock->ssl);
        sock->ssl = NULL;
    }
    if (sock->fd >= 0) {
        close(sock->fd);
        sock->fd = -1;
    }
    if (sock->hostname) {
        free(sock->hostname);
        sock->hostname = NULL;
    }
    if (sock->addr_list) {
        free(sock->addr_list);
        sock->addr_list = NULL;
    }
}

#define COUNT(X) (sizeof(X) / sizeof((X)[0]))

int socket_wait(Socket **socks, int num_socks)
{
    if (num_socks <= 0)
        return -1;

    struct pollfd polled[100]; // TODO: make this value configurable
    if (num_socks > (int) COUNT(polled))
        return -1;

    for (;;) {

        for (int i = 0; i < num_socks; i++) {

            int events = 0;
            switch (socks[i]->event) {
                case SOCKET_WANT_READ : events = POLLIN;  break;
                case SOCKET_WANT_WRITE: events = POLLOUT; break;
                case SOCKET_WANT_NONE : return i;
                default: HTTP_ASSERT(0); break;
            }

            polled[i].fd = socks[i]->fd;
            polled[i].events = events;
            polled[i].revents = 0;
        }

        int ret = poll(polled, num_socks, -1);
        if (ret < 0)
            return -1;

        // Update socket states based on poll results
        for (int i = 0; i < num_socks; i++) {

            if (polled[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                socks[i]->event = SOCKET_WANT_NONE;
                socks[i]->state = SOCKET_STATE_DIED;
                return i;
            }

            if (polled[i].revents & (POLLIN | POLLOUT)) {
                socks[i]->event = SOCKET_WANT_NONE;
                socket_update(socks[i]);
            }
        }
    }

    return -1;
}//////////////////////////////////////////////////////////////////////
// src/client.c
//////////////////////////////////////////////////////////////////////

// TODO
#define ERROR printf("error at %s:%d\n", __FILE__, __LINE__);

#define CLIENT_MAX_CONNS 256

typedef enum {
    CLIENT_CONNECTION_FREE,
    CLIENT_CONNECTION_INIT,
    CLIENT_CONNECTION_WAIT,
    CLIENT_CONNECTION_DONE,
} ClientConnectionState;

typedef struct {
    ClientConnectionState state;
    uint16_t        gen;
    Socket          socket;
    HTTP_Engine     engine;
    bool            trace;
} ClientConnection;

struct HTTP_Client {
    SocketGroup group;
    int num_conns;
    ClientConnection conns[CLIENT_MAX_CONNS];

    int ready_head;
    int ready_count;
    int ready[CLIENT_MAX_CONNS];
};

// Rename the memory function
static void* client_memfunc(HTTP_MemoryFuncTag tag, void *ptr, int len, void *data) {
    (void)data;
    switch (tag) {
        case HTTP_MEMFUNC_MALLOC:
            return malloc(len);
        case HTTP_MEMFUNC_FREE:
            free(ptr);
            return NULL;
    }
    return NULL;
}

void http_global_init(void)
{
    socket_global_init();
}

void http_global_free(void)
{
    socket_global_free();
}

HTTP_Client *http_client_init(void)
{
    HTTP_Client *client = malloc(sizeof(HTTP_Client));
    if (client == NULL)
        return NULL;

    if (socket_group_init(&client->group) < 0) {
        free(client);
        return NULL;
    }

    for (int i = 0; i < CLIENT_MAX_CONNS; i++) {
        client->conns[i].state = CLIENT_CONNECTION_FREE;
        client->conns[i].gen  = 1;
    }

    client->num_conns = 0;
    client->ready_head = 0;
    client->ready_count = 0;

    return client;
}

void http_client_free(HTTP_Client *client)
{
    for (int i = 0, j = 0; j < client->num_conns; i++) {

        if (client->conns[i].state == CLIENT_CONNECTION_FREE)
            continue;
        j++;

        // TODO
    }

    socket_group_free(&client->group);
    free(client);
}

int http_client_request(HTTP_Client *client, HTTP_RequestHandle *handle)
{
    if (client->num_conns == CLIENT_MAX_CONNS)
        return -1;

    int i = 0;
    while (client->conns[i].state != CLIENT_CONNECTION_FREE)
        i++;

    client->conns[i].trace = false;
    client->conns[i].state = CLIENT_CONNECTION_INIT;
    http_engine_init(&client->conns[i].engine, 1, client_memfunc, NULL);

    client->num_conns++;

    *handle = (HTTP_RequestHandle) { client, i, client->conns[i].gen };
    return 0;
}

static void client_connection_update(ClientConnection *conn)
{
    HTTP_ASSERT(conn->state == CLIENT_CONNECTION_WAIT);

    socket_update(&conn->socket);

    while (socket_state(&conn->socket) == SOCKET_STATE_ESTABLISHED_READY) {

        HTTP_EngineState engine_state;
        
        engine_state = http_engine_state(&conn->engine);

        if (engine_state == HTTP_ENGINE_STATE_CLIENT_RECV_BUF) {
            int len;
            char *buf;
            buf = http_engine_recvbuf(&conn->engine, &len);
            if (buf) {
                int ret = socket_read(&conn->socket, buf, len);
                if (conn->trace)
                    print_bytes(HTTP_STR(">> "), (HTTP_String) { buf, ret });
                http_engine_recvack(&conn->engine, ret);
            }
        } else if (engine_state == HTTP_ENGINE_STATE_CLIENT_SEND_BUF) {
            int len;
            char *buf;
            buf = http_engine_sendbuf(&conn->engine, &len);
            if (buf) {
                int ret = socket_write(&conn->socket, buf, len);
                if (conn->trace)
                    print_bytes(HTTP_STR("<< "), (HTTP_String) { buf, ret });
                http_engine_sendack(&conn->engine, ret);
            }
        }

        engine_state = http_engine_state(&conn->engine);

        if (engine_state == HTTP_ENGINE_STATE_CLIENT_CLOSED ||
            engine_state == HTTP_ENGINE_STATE_CLIENT_READY)
            socket_close(&conn->socket);
    }

    if (socket_state(&conn->socket) == SOCKET_STATE_DIED)
        conn->state = CLIENT_CONNECTION_DONE;
}

int http_client_wait(HTTP_Client *client, HTTP_RequestHandle *handle)
{
    while (client->ready_count == 0) {

        int num_polled = 0;
        int indices[CLIENT_MAX_CONNS];
        struct pollfd polled[CLIENT_MAX_CONNS];

        for (int i = 0, j = 0; j < client->num_conns; i++) {

            HTTP_ASSERT(i < CLIENT_MAX_CONNS);
            ClientConnection *conn = &client->conns[i];

            if (conn->state == CLIENT_CONNECTION_FREE)
                continue;
            j++;

            int events = 0;
            if (conn->state == CLIENT_CONNECTION_WAIT) {
                switch (conn->socket.event) {
                    case SOCKET_WANT_READ : events = POLLIN;  break;
                    case SOCKET_WANT_WRITE: events = POLLOUT; break;
                    case SOCKET_WANT_NONE : events = 0;       break;
                }
            }

            if (events) {
                indices[num_polled] = i;
                polled[num_polled].fd = conn->socket.fd;
                polled[num_polled].events = events;
                polled[num_polled].revents = 0;
                num_polled++;
            }
        }

        if (num_polled == 0)
            return -1;

        poll(polled, num_polled, -1);

        for (int i = 0; i < num_polled; i++) {

            int connidx = indices[i];
            ClientConnection *conn = &client->conns[connidx];

            if (conn->state != CLIENT_CONNECTION_WAIT)
                continue;

            if (polled[i].revents == 0)
                continue;

            // TODO: handle error revents

            client_connection_update(conn);

            if (conn->state == CLIENT_CONNECTION_DONE) {
                int tail = (client->ready_head + client->ready_count) % CLIENT_MAX_CONNS;
                client->ready[tail] = connidx;
                client->ready_count++;
            }
        }
    }

    int index = client->ready[client->ready_head];
    client->ready_head = (client->ready_head + 1) % CLIENT_MAX_CONNS;
    client->ready_count--;
    *handle = (HTTP_RequestHandle) { client, index, client->conns[index].gen };
    return 0;
}

static ClientConnection *handle2clientconn(HTTP_RequestHandle handle)
{
    if (handle.data0 == NULL)
        return NULL;

    HTTP_Client *client = handle.data0;

    if (handle.data1 >= CLIENT_MAX_CONNS)
        return NULL;

    ClientConnection *conn = &client->conns[handle.data1];

    if (handle.data2 != conn->gen)
        return NULL;

    return conn;
}

void http_request_trace(HTTP_RequestHandle handle, bool trace)
{
    ClientConnection *conn = handle2clientconn(handle);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT)
        return;

    conn->trace = trace;
}

void http_request_line(HTTP_RequestHandle handle, HTTP_Method method, HTTP_String url)
{
    ClientConnection *conn = handle2clientconn(handle);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT)
        return;

    HTTP_Client *client = handle.data0;

    HTTP_URL parsed_url;
    int ret = http_parse_url(url.ptr, url.len, &parsed_url);
    if (ret != url.len) {
        // TODO
        ERROR;
        return;
    }

    bool secure = false;
    if (http_streq(parsed_url.scheme, HTTP_STR("https"))) {
        secure = true;
    } else if (!http_streq(parsed_url.scheme, HTTP_STR("http"))) {
        // TODO
        ERROR;
        return;
    }

    int port = parsed_url.authority.port;
    if (port == 0) {
        if (secure)
            port = 443;
        else
            port = 80;
    }

    SocketGroup *group = secure ? &client->group : NULL;
    switch (parsed_url.authority.host.mode) {
        case HTTP_HOST_MODE_IPV4: socket_connect_ipv4(&conn->socket, group, parsed_url.authority.host.ipv4, port); break;
        case HTTP_HOST_MODE_IPV6: socket_connect_ipv6(&conn->socket, group, parsed_url.authority.host.ipv6, port); break;
        case HTTP_HOST_MODE_NAME: socket_connect     (&conn->socket, group, parsed_url.authority.host.name, port); break;

        case HTTP_HOST_MODE_VOID:
        // TODO
        ERROR;
        return;
    }

    http_engine_url(&conn->engine, method, url, 1);
}

void http_request_header(HTTP_RequestHandle handle, char *header, int len)
{
    ClientConnection *conn = handle2clientconn(handle);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT)
        return;

    http_engine_header(&conn->engine, header, len);
}

void http_request_body(HTTP_RequestHandle handle, char *body, int len)
{
    ClientConnection *conn = handle2clientconn(handle);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT)
        return;

    http_engine_body(&conn->engine, body, len);
}

void http_request_submit(HTTP_RequestHandle handle)
{
    ClientConnection *conn = handle2clientconn(handle);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT)
        return;

    http_engine_done(&conn->engine);
    conn->state = CLIENT_CONNECTION_WAIT;
}

HTTP_Response *http_request_result(HTTP_RequestHandle handle)
{
    ClientConnection *conn = handle2clientconn(handle);
    if (conn == NULL)
        return NULL;
    if (conn->state != CLIENT_CONNECTION_DONE)
        return NULL;
    HTTP_EngineState engine_state = http_engine_state(&conn->engine);
    if (engine_state != HTTP_ENGINE_STATE_CLIENT_READY)
        return NULL;
    return http_engine_getres(&conn->engine);
}

void http_request_free(HTTP_RequestHandle handle)
{
    HTTP_Client *client = handle.data0;
    ClientConnection *conn = handle2clientconn(handle);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_DONE)
        return;
    http_engine_free(&conn->engine);
    socket_free(&conn->socket);
    conn->state = CLIENT_CONNECTION_FREE;
    client->num_conns--;
}//////////////////////////////////////////////////////////////////////
// src/server.c
//////////////////////////////////////////////////////////////////////

#define MAX_CONNS (1<<10)

typedef struct {
    bool        used;
    uint16_t    gen;
    Socket      socket;
    HTTP_Engine engine;
} Connection;

struct HTTP_Server {
    SocketGroup group;

    int listen_fd;
    int secure_fd;

    int num_conns;
    Connection conns[MAX_CONNS];

    int ready_head;
    int ready_count;
    int ready[MAX_CONNS];
};

static int listen_socket(HTTP_String addr, uint16_t port, bool reuse_addr, int backlog)
{
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0)
        return -1;

    {
        int flags = fcntl(listen_fd, F_GETFL, 0);
        if (flags < 0) {
            close(listen_fd);
            return -1;
        }

        if (fcntl(listen_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            close(listen_fd);
            return -1;
        }
    }

    if (reuse_addr) {
        int one = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    }

    struct in_addr addr_buf;
    if (addr.len == 0)
        addr_buf.s_addr = htonl(INADDR_ANY);
    else {

        _Static_assert(sizeof(struct in_addr) == sizeof(HTTP_IPv4));
        if (http_parse_ipv4(addr.ptr, addr.len, (HTTP_IPv4*) &addr_buf) < 0) {
            close(listen_fd);
            return -1;
        }
    }

    struct sockaddr_in bind_buf;
    bind_buf.sin_family = AF_INET;
    bind_buf.sin_addr   = addr_buf;
    bind_buf.sin_port   = htons(port);
    if (bind(listen_fd, (struct sockaddr*) &bind_buf, sizeof(bind_buf)) < 0) {
        close(listen_fd);
        return -1;
    }

    if (listen(listen_fd, backlog) < 0) {
        close(listen_fd);
        return -1;
    }

    return listen_fd;
}

HTTP_Server *http_server_init(HTTP_String addr, uint16_t port)
{
    return http_server_init_ex(addr, port, 0, HTTP_STR(""), HTTP_STR(""));
}

HTTP_Server *http_server_init_ex(HTTP_String addr, uint16_t port,
    uint16_t secure_port, HTTP_String cert_key, HTTP_String private_key)
{
    HTTP_Server *server = malloc(sizeof(HTTP_Server));
    if (server == NULL)
        return NULL;

    int backlog = 32;
    bool reuse_addr = true;

    if (port == 0 && secure_port == 0) {
        // You must have at least one!
        free(server);
        return NULL;
    }

    if (port == 0)
        server->listen_fd = -1;
    else {
        server->listen_fd = listen_socket(addr, port, reuse_addr, backlog);
        if (server->listen_fd < 0) {
            free(server);
            return NULL;
        }
    }

    if (secure_port == 0)
        server->secure_fd = -1;
    else {

        if (socket_group_init_server(&server->group, cert_key, private_key) < 0) {
            close(server->listen_fd);
            free(server);
            return NULL;
        }

        server->secure_fd = listen_socket(addr, secure_port, reuse_addr, backlog);
        if (server->secure_fd < 0) {
            socket_group_free(&server->group);
            close(server->listen_fd);
            free(server);
            return NULL;
        }
    }

    server->num_websites = 0;
    server->num_conns = 0;
    server->ready_head = 0;
    server->ready_count = 0;

    for (int i = 0; i < MAX_CONNS; i++) {
        server->conns[i].used = false;
        server->conns[i].gen = 1;
    }

    return server;
}

void http_server_free(HTTP_Server *server)
{
    for (int i = 0, j = 0; j < server->num_conns; i++) {

        if (!server->conns[i].used)
            continue;
        j++;

        // TODO
    }

    close(server->secure_fd);
    close(server->listen_fd);
    if (server->secure_fd != -1)
        socket_group_free(&server->group);
    free(server);
}

int http_server_website(HTTP_Server *server, HTTP_String domain, HTTP_String cert_file, HTTP_String key_file)
{
    return socket_group_add_domain(&server->group, domain, cert_file, key_file);
}

static void* server_memfunc(HTTP_MemoryFuncTag tag, void *ptr, int len, void *data) {
    (void)data;
    switch (tag) {
        case HTTP_MEMFUNC_MALLOC:
            return malloc(len);
        case HTTP_MEMFUNC_FREE:
            free(ptr);
            return NULL;
    }
    return NULL;
}

int http_server_wait(HTTP_Server *server, HTTP_Request **req, HTTP_ResponseHandle *handle)
{
    while (server->ready_count == 0) {

        int num_polled = 0;
        struct pollfd polled[MAX_CONNS+2];
        int          indices[MAX_CONNS+2];

        if (server->num_conns < MAX_CONNS) {

            if (server->listen_fd != -1) {
                polled[num_polled].fd = server->listen_fd;
                polled[num_polled].events = POLLIN;
                polled[num_polled].revents = 0;
                indices[num_polled] = -1;
                num_polled++;
            }

            if (server->secure_fd != -1) {
                polled[num_polled].fd = server->secure_fd;
                polled[num_polled].events = POLLIN;
                polled[num_polled].revents = 0;
                indices[num_polled] = -1;
                num_polled++;
            }
        }

        for (int i = 0, j = 0; i < server->num_conns; i++) {

            if (!server->conns[i].used)
                continue;
            j++;

            int events = 0;

            if (server->conns[i].socket.ssl_ctx)
                events = server->conns[i].socket.event;
            else {
                switch (http_engine_state(&server->conns[i].engine)) {
                    case HTTP_ENGINE_STATE_SERVER_RECV_BUF: events = POLLIN;  break;
                    case HTTP_ENGINE_STATE_SERVER_SEND_BUF: events = POLLOUT; break;
                    default:break;
                }
            }

            if (events) {
                polled[num_polled].fd = server->conns[i].socket.fd;
                polled[num_polled].events = events;
                polled[num_polled].revents = 0;
                indices[num_polled] = i;
                num_polled++;
            }
        }

        int timeout = -1;
        poll(polled, num_polled, timeout);

        for (int i = 0; i < num_polled; i++) {

            if (polled[i].fd == server->listen_fd || polled[i].fd == server->secure_fd) {

                bool secure = false;
                if (polled[i].fd == server->secure_fd)
                    secure = true;

                if ((polled[i].revents & POLLIN) && server->num_conns < MAX_CONNS) {

                    int new_fd = accept(polled[i].fd, NULL, NULL);

                    int k = 0;
                    while (server->conns[k].used)
                        k++;

                    server->conns[k].used = true;
                    socket_accept(&server->conns[k].socket, secure ? &server->group : NULL, new_fd);
                    http_engine_init(&server->conns[k].engine, 0, server_memfunc, NULL);
                    server->num_conns++;
                }

            } else {

                int connidx = indices[i];
                Connection *conn = &server->conns[connidx];

                socket_update(&conn->socket);

                if (socket_state(&conn->socket) == SOCKET_STATE_ESTABLISHED_READY) {

                    switch (http_engine_state(&conn->engine)) {

                        int len;
                        char *buf;

                        case HTTP_ENGINE_STATE_SERVER_RECV_BUF:
                        buf = http_engine_recvbuf(&conn->engine, &len);
                        if (buf) {
                            int ret = socket_read(&conn->socket, buf, len);
                            http_engine_recvack(&conn->engine, ret);
                        }
                        break;

                        case HTTP_ENGINE_STATE_SERVER_SEND_BUF:
                        buf = http_engine_sendbuf(&conn->engine, &len);
                        if (buf) {
                            int ret = socket_write(&conn->socket, buf, len);
                            http_engine_sendack(&conn->engine, ret);
                        }
                        break;

                        default:
                        break;
                    }

                    switch (http_engine_state(&conn->engine)) {

                        int tail;

                        case HTTP_ENGINE_STATE_SERVER_PREP_STATUS:
                        tail = (server->ready_head + server->ready_count) % MAX_CONNS;
                        server->ready[tail] = connidx;
                        server->ready_count++;
                        break;

                        case HTTP_ENGINE_STATE_SERVER_CLOSED:
                        socket_close(&conn->socket);
                        break;

                        default:
                        break;

                    }
                }

                if (socket_state(&conn->socket) == SOCKET_STATE_DIED) {
                    socket_free(&conn->socket);
                    http_engine_free(&conn->engine);
                    conn->used = false;
                    server->num_conns--;
                }
            }
        }
    }

    int index = server->ready[server->ready_head];
    server->ready_head = (server->ready_head + 1) % MAX_CONNS;
    server->ready_count--;

    *req = http_engine_getreq(&server->conns[index].engine);
    *handle = (HTTP_ResponseHandle) { server, index, server->conns[index].gen };
    return 0;
}

static Connection*
handle2conn(HTTP_ResponseHandle handle)
{
	HTTP_Server *server = handle.data0;
	if (handle.data1 >= MAX_CONNS)
		return NULL;

	Connection *conn = &server->conns[handle.data1];
	if (conn->gen != handle.data2)
		return NULL;

	return conn;
}

void http_response_status(HTTP_ResponseHandle res, int status)
{
	Connection *conn = handle2conn(res);
	if (conn == NULL)
		return;

	http_engine_status(&conn->engine, status);
}

void http_response_header(HTTP_ResponseHandle res, const char *fmt, ...)
{
	Connection *conn = handle2conn(res);
	if (conn == NULL)
		return;

	va_list args;
	va_start(args, fmt);
	http_engine_header_fmt2(&conn->engine, fmt, args);
	va_end(args);
}

void http_response_body(HTTP_ResponseHandle res, char *src, int len)
{
	Connection *conn = handle2conn(res);
	if (conn == NULL)
		return;

	if (len < 0)
		len = strlen(src);

	http_engine_body(&conn->engine, src, len);
}

void http_response_bodycap(HTTP_ResponseHandle res, int mincap)
{
	Connection *conn = handle2conn(res);
	if (conn == NULL)
		return;

	http_engine_bodycap(&conn->engine, mincap);
}

char *http_response_bodybuf(HTTP_ResponseHandle res, int *cap)
{
	Connection *conn = handle2conn(res);
	if (conn == NULL) {
		*cap = 0;
		return NULL;
	}

	return http_engine_bodybuf(&conn->engine, cap);
}

void http_response_bodyack(HTTP_ResponseHandle res, int num)
{
	Connection *conn = handle2conn(res);
	if (conn == NULL)
		return;

	http_engine_bodyack(&conn->engine, num);
}

void http_response_undo(HTTP_ResponseHandle res)
{
	Connection *conn = handle2conn(res);
	if (conn == NULL)
		return;

	http_engine_undo(&conn->engine);
}

void http_response_done(HTTP_ResponseHandle res)
{
    HTTP_Server *server = res.data0;
    Connection *conn = handle2conn(res);
    if (conn == NULL)
        return;

    http_engine_done(&conn->engine);

    conn->gen++;
    if (conn->gen == 0 || conn->gen == UINT16_MAX)
        conn->gen = 1;

    HTTP_EngineState state = http_engine_state(&conn->engine);

    if (state == HTTP_ENGINE_STATE_SERVER_PREP_STATUS) {
        int tail = (server->ready_head + server->ready_count) % MAX_CONNS;
        server->ready[tail] = res.data1;
        server->ready_count++;
    }

    if (state == HTTP_ENGINE_STATE_SERVER_CLOSED) {
        socket_close(&conn->socket);
        http_engine_free(&conn->engine);
        server->num_conns--;
    }
}//////////////////////////////////////////////////////////////////////
// src/router.c
//////////////////////////////////////////////////////////////////////

#ifndef _WIN32
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
	HTTP_ASSERT(ret == 0);

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

int http_serve(char *addr, int port, HTTP_Router *router)
{
	int ret;

	HTTP_Server *server = http_server_init((HTTP_String) { addr, strlen(addr) }, port, 0, (HTTP_String) {}, (HTTP_String) {});
	if (server == NULL) {
		http_router_free(router);
		return -1;
	}

	for (;;) {
		HTTP_Request *req;
		HTTP_ResponseHandle res;
		ret = http_server_wait(server, &req, &res);
		if (ret < 0) {
			http_server_free(server);
			http_router_free(router);
			return -1;
		}
		if (ret == 0)
			continue;
		http_router_resolve(router, req, res);
	}

	http_server_free(server);
	http_router_free(router);
	return 0;
}