#ifndef HTTP_NOINCLUDE
#include "chttp.h"
#endif

////////////////////////////////////////////////////////////////////////////////////////
// src/sec.h
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/sec.h"
#ifndef SEC_INCLUDED
#define SEC_INCLUDED


#ifndef HTTP_AMALGAMATION
#include "basic.h"
#endif

#ifndef HTTPS_ENABLED

typedef struct {
} SecureContext;

#else

#define MAX_CERTS 10

#include <stdbool.h>

#include <openssl/ssl.h>

typedef struct {
    char domain[128];
    SSL_CTX *ctx;
} CertData;

typedef struct {

    bool is_server;

    SSL_CTX *ctx;

    // Only used when server
    int num_certs;
    CertData certs[MAX_CERTS];

} SecureContext;

#endif

void secure_context_global_init(void);
void secure_context_global_free(void);

int secure_context_init_as_client(SecureContext *sec);

int secure_context_init_as_server(SecureContext *sec,
    HTTP_String cert_file, HTTP_String key_file);

int secure_context_add_cert(SecureContext *sec,
    HTTP_String domain, HTTP_String cert_file,
    HTTP_String key_file);

void secure_context_free(SecureContext *sec);

#endif // SEC_INCLUDED

////////////////////////////////////////////////////////////////////////////////////////
// src/socket_raw.h
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/socket_raw.h"
#ifndef SOCKET_RAW_INCLUDED
#define SOCKET_RAW_INCLUDED

#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
#include <winsock2.h>
#define RAW_SOCKET SOCKET
#define BAD_SOCKET INVALID_SOCKET
#define POLL WSAPoll
#define CLOSE_SOCKET closesocket
#endif

#ifdef __linux__
#include <poll.h>
#include <unistd.h>
#define RAW_SOCKET int
#define BAD_SOCKET -1
#define POLL poll
#define CLOSE_SOCKET close
#endif

#ifndef HTTP_AMALGAMATION
#include "basic.h"
#endif

int  socket_raw_global_init(void);
void socket_raw_global_free(void);

int set_socket_blocking(RAW_SOCKET sock, bool value);

RAW_SOCKET listen_socket(HTTP_String addr, uint16_t port, bool reuse_addr, int backlog);

#endif // SOCKET_RAW_INCLUDED

////////////////////////////////////////////////////////////////////////////////////////
// src/socket.h
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/socket.h"
#ifndef SOCKET_INCLUDED
#define SOCKET_INCLUDED

// This module implements the socket state machine to encapsulate
// the complexity of non-blocking TCP and TLS sockets.
//
// A socket is represented by the "Socket" structure, which may
// be in a number of states. As far as an user of the interface
// is concerned, the socket may be DIED, READY, or in an internal
// state that requires waiting for an event. Therefore, if the
// socket is not DIED or READY, the user needs to wait for the
// events specified in the [socket->events] field, then call the
// socket_update function. At some point the socket will become
// either READY or DIED.
//
// When the socket reaches the DIED state, the user must call
// socket_free.
//
// If the socket is ESTABLISHED_READY, the user may call socket_read,
// socket_write, or socket_close on it.

#ifndef HTTP_AMALGAMATION
#include "sec.h"
#include "parse.h"
#include "socket_raw.h"
#endif

typedef struct PendingConnect PendingConnect;

// These should only be relevant to socket.c
typedef enum {
    SOCKET_STATE_FREE,
    SOCKET_STATE_DIED,
    SOCKET_STATE_ESTABLISHED_WAIT,
    SOCKET_STATE_ESTABLISHED_READY,
    SOCKET_STATE_PENDING,
    SOCKET_STATE_ACCEPTED,
    SOCKET_STATE_CONNECTED,
    SOCKET_STATE_CONNECTING,
    SOCKET_STATE_SHUTDOWN,
} SocketState;

typedef struct {
    SocketState state;

    RAW_SOCKET raw;
    int events;

    void *user_data;
    PendingConnect *pending_connect;

#ifdef HTTPS_ENABLED
    SSL *ssl;
#endif

    SecureContext *sec;

} Socket;

void  socket_connect(Socket *sock, SecureContext *sec, HTTP_String hostname, uint16_t port, void *user_data);
void  socket_connect_ipv4(Socket *sock, SecureContext *sec, HTTP_IPv4 addr, uint16_t port, void *user_data);
void  socket_connect_ipv6(Socket *sock, SecureContext *sec, HTTP_IPv6 addr, uint16_t port, void *user_data);
void  socket_accept(Socket *sock, SecureContext *sec, RAW_SOCKET raw);
void  socket_update(Socket *sock);
void  socket_close(Socket *sock);
bool  socket_ready(Socket *sock);
bool  socket_died(Socket *sock);
int   socket_read(Socket *sock, char *dst, int max);
int   socket_write(Socket *sock, char *src, int len);
void  socket_free(Socket *sock);
bool  socket_secure(Socket *sock);
void  socket_set_user_data(Socket *sock, void *user_data);
void* socket_get_user_data(Socket *sock);

#endif // SOCKET_INCLUDED

////////////////////////////////////////////////////////////////////////////////////////
// src/socket_pool.h
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/socket_pool.h"
#ifndef SOCKET_POOL_INCLUDED
#define SOCKET_POOL_INCLUDED

#ifndef HTTP_AMALGAMATION
#include "basic.h"
#include "socket.h"
#include "socket_raw.h"
#endif

typedef struct SocketPool SocketPool;

typedef int SocketHandle;

typedef enum {
    SOCKET_EVENT_DIED,
    SOCKET_EVENT_READY,
    SOCKET_EVENT_ERROR,
    SOCKET_EVENT_SIGNAL,
} SocketEventType;

typedef struct {
    SocketEventType type;
    SocketHandle handle;
    void *user_data;
} SocketEvent;

int  socket_pool_global_init(void);
void socket_pool_global_free(void);

SocketPool *socket_pool_init(HTTP_String addr,
    uint16_t port, uint16_t secure_port, int max_socks,
    bool reuse_addr, int backlog, HTTP_String cert_file,
    HTTP_String key_file);

void socket_pool_free(SocketPool *pool);

int socket_pool_add_cert(SocketPool *pool, HTTP_String domain, HTTP_String cert_file, HTTP_String key_file);

SocketEvent socket_pool_wait(SocketPool *pool);

void socket_pool_set_user_data(SocketPool *pool, SocketHandle handle, void *user_data);

void socket_pool_close(SocketPool *pool, SocketHandle handle);

int socket_pool_connect(SocketPool *pool, bool secure,
    HTTP_String addr, uint16_t port, void *user_data);

int socket_pool_connect_ipv4(SocketPool *pool, bool secure,
    HTTP_IPv4 addr, uint16_t port, void *user_data);

int socket_pool_connect_ipv6(SocketPool *pool, bool secure,
    HTTP_IPv6 addr, uint16_t port, void *user_data);

int socket_pool_read(SocketPool *pool, SocketHandle handle, char *dst, int len);

int socket_pool_write(SocketPool *pool, SocketHandle handle, char *src, int len);

bool socket_pool_secure(SocketPool *pool, SocketHandle handle);

#endif // SOCKET_POOL_INCLUDED

////////////////////////////////////////////////////////////////////////////////////////
// src/basic.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/basic.c"
#include <stddef.h>
#include <string.h>

#ifndef HTTP_AMALGAMATION
#include "basic.h"
#endif

bool http_streq(HTTP_String s1, HTTP_String s2)
{
	if (s1.len != s2.len)
		return false;

    for (int i = 0; i < s1.len; i++)
		if (s1.ptr[i] != s2.ptr[i])
			return false;

	return true;
}

static char to_lower(char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A' + 'a';
	return c;
}

bool http_streqcase(HTTP_String s1, HTTP_String s2)
{
	if (s1.len != s2.len)
		return false;

	for (int i = 0; i < s1.len; i++)
		if (to_lower(s1.ptr[i]) != to_lower(s2.ptr[i]))
			return false;

	return true;
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

#include <stdio.h>
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
}

////////////////////////////////////////////////////////////////////////////////////////
// src/parse.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/parse.c"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <limits.h>

#ifndef HTTP_AMALGAMATION
#include "parse.h"
#include "basic.h"
#endif

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
    HTTP_ASSERT(token.len > 0);

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

    bool body_expected = true;
    if (req->method == HTTP_METHOD_GET || req->method == HTTP_METHOD_DELETE) // TODO: maybe other methods?
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

    bool body_expected = true; // TODO

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
    // TODO: best-effort implementation

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

static bool is_digit(char c)
{
    return c >= '0' && c <= '9';
}

int http_get_param_i(HTTP_String body, HTTP_String str)
{
    char buf[128];
    HTTP_String out = http_get_param(body, str, buf, SIZEOF(buf));
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

////////////////////////////////////////////////////////////////////////////////////////
// src/engine.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/engine.c"
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h> // TODO: remove some of these headers
#include <stddef.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#ifndef HTTP_AMALGAMATION
#include "basic.h"
#include "engine.h"
#endif

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

void http_engine_header(HTTP_Engine *eng, HTTP_String str)
{
	if ((eng->state & HTTP_ENGINE_STATEBIT_PREP_HEADER) == 0)
		return;

	// TODO: Check that the header is valid

	byte_queue_write(&eng->output, str.ptr, str.len);
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

void http_engine_body(HTTP_Engine *eng, HTTP_String str)
{
	http_engine_bodycap(eng, str.len);
	int cap;
	char *buf = http_engine_bodybuf(eng, &cap);
	if (buf) {
		memcpy(buf, str.ptr, str.len);
		http_engine_bodyack(eng, str.len);
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
}

////////////////////////////////////////////////////////////////////////////////////////
// src/cert.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/cert.c"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HTTPS_ENABLED
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#endif

#ifndef HTTP_AMALGAMATION
#include "cert.h"
#endif

#ifdef HTTPS_ENABLED

static EVP_PKEY *generate_rsa_key_pair(int key_bits)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
        return NULL;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_bits) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static X509 *create_certificate(EVP_PKEY *pkey, HTTP_String C, HTTP_String O, HTTP_String CN, int days)
{
    X509 *x509 = X509_new();
    if (!x509)
        return NULL;

    // Set version (version 3)
    X509_set_version(x509, 2);
    
    // Set serial number
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    
    // Set validity period
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L * days); // days * seconds_per_year

    // Set public key
    X509_set_pubkey(x509, pkey);

    // Set subject name
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char*) C.ptr,  C.len,  -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char*) O.ptr,  O.len,  -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*) CN.ptr, CN.len, -1, 0);

    // Set issuer name (same as subject for self-signed)
    X509_set_issuer_name(x509, name);

    if (!X509_sign(x509, pkey, EVP_sha256())) {
        X509_free(x509);
        return NULL;
    }

    return x509;
}

static int save_private_key(EVP_PKEY *pkey, HTTP_String file)
{
    char copy[1<<10];
    if (file.len >= (int) sizeof(copy))
        return -1;
    memcpy(copy, file.ptr, file.len);
    copy[file.len] = '\0';

    FILE *fp = fopen(copy, "wb");
    if (!fp)
        return -1;

    // Write private key in PEM format
    if (!PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL)) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

static int save_certificate(X509 *x509, HTTP_String file)
{
    char copy[1<<10];
    if (file.len >= (int) sizeof(copy))
        return -1;
    memcpy(copy, file.ptr, file.len);
    copy[file.len] = '\0';

    FILE *fp = fopen(copy, "wb");
    if (!fp)
        return -1;

    // Write certificate in PEM format
    if (!PEM_write_X509(fp, x509)) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

int http_create_test_certificate(HTTP_String C, HTTP_String O, HTTP_String CN,
    HTTP_String cert_file, HTTP_String key_file)
{
    EVP_PKEY *pkey = generate_rsa_key_pair(2048);
    if (pkey == NULL)
        return -1;

    X509 *x509 = create_certificate(pkey, C, O, CN, 1);
    if (x509 == NULL) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (save_private_key(pkey, key_file) < 0) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (save_certificate(x509, cert_file) < 0) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return -1;
    }

    X509_free(x509);
    EVP_PKEY_free(pkey);
    return 0;
}

#else

int http_create_test_certificate(HTTP_String C, HTTP_String O, HTTP_String CN,
    HTTP_String cert_file, HTTP_String key_file)
{
    (void) C;
    (void) O;
    (void) CN;
    (void) cert_file;
    (void) key_file;
    return -1;
}

#endif

////////////////////////////////////////////////////////////////////////////////////////
// src/sec.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/sec.c"
#ifndef HTTP_AMALGAMATION
#include "sec.h"
#endif

#ifndef HTTPS_ENABLED

void secure_context_global_init(void)
{
}

void secure_context_global_free(void)
{
}

int secure_context_init_as_client(SecureContext *sec)
{
    (void) sec;
    return 0;
}

int secure_context_init_as_server(SecureContext *sec,
    HTTP_String cert_file, HTTP_String key_file)
{
    (void) sec;
    (void) cert_file;
    (void) key_file;
    return 0;
}

int secure_context_add_cert(SecureContext *sec,
    HTTP_String domain, HTTP_String cert_file,
    HTTP_String key_file)
{
    (void) sec;
    (void) domain;
    (void) cert_file;
    (void) key_file;
    return -1;
}

void secure_context_free(SecureContext *sec)
{
    (void) sec;
}

#else

void secure_context_global_init(void)
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

void secure_context_global_free(void)
{
    EVP_cleanup();
}

int secure_context_init_as_client(SecureContext *sec)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        return -1;

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    
    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        SSL_CTX_free(ctx);
        return -1;
    }

    sec->is_server = false;
    sec->ctx = ctx;
    sec->num_certs = 0;
    return 0;
}

static int servername_callback(SSL *ssl, int *ad, void *arg)
{
    SecureContext *sec = arg;

    (void) ad; // TODO: use this?

    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (servername == NULL)
        return SSL_TLSEXT_ERR_NOACK;
    
    for (int i = 0; i < sec->num_certs; i++) {
        CertData *cert = &sec->certs[i];
        if (!strcmp(cert->domain, servername)) {
            SSL_set_SSL_CTX(ssl, cert->ctx);
            return SSL_TLSEXT_ERR_OK;
        }
    }

    return SSL_TLSEXT_ERR_NOACK;
}

int secure_context_init_as_server(SecureContext *sec,
    HTTP_String cert_file, HTTP_String key_file)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
        return -1;

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    char cert_buffer[1024];
    if (cert_file.len >= (int) sizeof(cert_buffer)) {
        SSL_CTX_free(ctx);
        return -1;
    }
    memcpy(cert_buffer, cert_file.ptr, cert_file.len);
    cert_buffer[cert_file.len] = '\0';
    
    // Copy private key file path to static buffer
    char key_buffer[1024];
    if (key_file.len >= (int) sizeof(key_buffer)) {
        SSL_CTX_free(ctx);
        return -1;
    }
    memcpy(key_buffer, key_file.ptr, key_file.len);
    key_buffer[key_file.len] = '\0';
    
    // Load certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, cert_buffer, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ctx);
        return -1;
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, key_buffer, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ctx);
        return -1;
    }
    
    // Verify that the private key matches the certificate
    if (SSL_CTX_check_private_key(ctx) != 1) {
        SSL_CTX_free(ctx);
        return -1;
    }

    SSL_CTX_set_tlsext_servername_callback(ctx, servername_callback);
    SSL_CTX_set_tlsext_servername_arg(ctx, sec);

    sec->is_server = true;
    sec->ctx = ctx;
    sec->num_certs = 0;
    return 0;
}

void secure_context_free(SecureContext *sec)
{
    SSL_CTX_free(sec->ctx);
    for (int i = 0; i < sec->num_certs; i++)
        SSL_CTX_free(sec->certs[i].ctx);
}

int secure_context_add_cert(SecureContext *sec,
    HTTP_String domain, HTTP_String cert_file,
    HTTP_String key_file)
{
    if (!sec->is_server)
        return -1;

    if (sec->num_certs == MAX_CERTS)
        return -1;

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
        return -1;

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    char cert_buffer[1024];
    if (cert_file.len >= (int) sizeof(cert_buffer)) {
        SSL_CTX_free(ctx);
        return -1;
    }
    memcpy(cert_buffer, cert_file.ptr, cert_file.len);
    cert_buffer[cert_file.len] = '\0';
    
    char key_buffer[1024];
    if (key_file.len >= (int) sizeof(key_buffer)) {
        SSL_CTX_free(ctx);
        return -1;
    }
    memcpy(key_buffer, key_file.ptr, key_file.len);
    key_buffer[key_file.len] = '\0';
    
    if (SSL_CTX_use_certificate_file(ctx, cert_buffer, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ctx);
        return -1;
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, key_buffer, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ctx);
        return -1;
    }
    
    if (SSL_CTX_check_private_key(ctx) != 1) {
        SSL_CTX_free(ctx);
        return -1;
    }

    CertData *cert = &sec->certs[sec->num_certs];
    if (domain.len >= (int) sizeof(cert->domain)) {
        SSL_CTX_free(ctx);
        return -1;
    }
    memcpy(cert->domain, domain.ptr, domain.len);
    cert->domain[domain.len] = '\0';
    cert->ctx = ctx;
    sec->num_certs++;
    return 0;
}

#endif

////////////////////////////////////////////////////////////////////////////////////////
// src/socket_raw.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/socket_raw.c"
#include <string.h>

#ifdef _WIN32
#include <ws2tcpip.h>
#endif

#ifdef __linux__
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#ifndef HTTP_AMALGAMATION
#include "socket_raw.h"
#endif

int socket_raw_global_init(void)
{
#ifdef _WIN32
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0)
        return 1;
#endif
    return 0;
}

void socket_raw_global_free(void)
{
#ifdef _WIN32
    WSACleanup();
#endif
}

int set_socket_blocking(RAW_SOCKET sock, bool value)
{
#ifdef _WIN32
    u_long mode = !value;
    if (ioctlsocket(sock, FIONBIO, &mode) == SOCKET_ERROR)
        return -1;
#endif

#ifdef __linux__
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0)
        return -1;
    if (value) flags &= ~O_NONBLOCK;
    else       flags |= O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) < 0)
        return -1;
#endif
    
    return 0;
}

RAW_SOCKET listen_socket(HTTP_String addr, uint16_t port, bool reuse_addr, int backlog)
{
    RAW_SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == BAD_SOCKET)
        return BAD_SOCKET;

    if (set_socket_blocking(sock, false) < 0) {
        CLOSE_SOCKET(sock);
        return BAD_SOCKET;
    }

    if (reuse_addr) {
        int one = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void*) &one, sizeof(one));
    }

    struct in_addr addr_buf;
    if (addr.len == 0)
        addr_buf.s_addr = htonl(INADDR_ANY);
    else {

        char copy[100];
        if (addr.len >= (int) sizeof(copy)) {
            CLOSE_SOCKET(sock);
            return BAD_SOCKET;
        }
        memcpy(copy, addr.ptr, addr.len);
        copy[addr.len] = '\0';

        if (inet_pton(AF_INET, copy, &addr_buf) < 0) {
            CLOSE_SOCKET(sock);
            return BAD_SOCKET;
        }
    }

    struct sockaddr_in bind_buf;
    bind_buf.sin_family = AF_INET;
    bind_buf.sin_addr   = addr_buf;
    bind_buf.sin_port   = htons(port);
    if (bind(sock, (struct sockaddr*) &bind_buf, sizeof(bind_buf)) < 0) { // TODO: how does bind fail on windows?
        CLOSE_SOCKET(sock);
        return BAD_SOCKET;
    }

    if (listen(sock, backlog) < 0) { // TODO: how does listen fail on windows?
        CLOSE_SOCKET(sock);
        return BAD_SOCKET;
    }

    return sock;
}

////////////////////////////////////////////////////////////////////////////////////////
// src/socket.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/socket.c"
#include <stdio.h> // snprintf
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <ws2tcpip.h>
#endif

#ifdef __linux__
#include <netdb.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#ifdef HTTPS_ENABLED
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#ifndef HTTP_AMALGAMATION
#include "basic.h"
#include "socket.h"
#endif

typedef struct {
    bool is_ipv4;
    union {
        HTTP_IPv4 ipv4;
        HTTP_IPv6 ipv6;
    };
} PendingConnectAddr;

struct PendingConnect {
    uint16_t port;
    int      cursor;
    int      num_addrs;
    int      max_addrs;
    PendingConnectAddr *addrs;
    char*    hostname; // null-terminated
    int      hostname_len;
};

static PendingConnect*
pending_connect_init(HTTP_String hostname, uint16_t port, int max_addrs)
{
    PendingConnect *pending_connect = malloc(sizeof(PendingConnect) + max_addrs * sizeof(PendingConnectAddr) + hostname.len + 1);
    if (pending_connect == NULL)
        return NULL;
    pending_connect->port = port;
    pending_connect->cursor = 0;
    pending_connect->num_addrs = 0;
    pending_connect->max_addrs = max_addrs;
    pending_connect->addrs = (PendingConnectAddr*) (pending_connect + 1);
    pending_connect->hostname = (char*) (pending_connect->addrs + max_addrs);
    memcpy(pending_connect->hostname, hostname.ptr, hostname.len);
    pending_connect->hostname[hostname.len] = '\0';
    pending_connect->hostname_len = hostname.len;
    return pending_connect;
}

static void
pending_connect_free(PendingConnect *pending_connect)
{
    free(pending_connect);
}

static void
pending_connect_add_ipv4(PendingConnect *pending_connect, HTTP_IPv4 ipv4)
{
    if (pending_connect->num_addrs == pending_connect->max_addrs)
        return;
    pending_connect->addrs[pending_connect->num_addrs++] = (PendingConnectAddr) { .is_ipv4=true, .ipv4=ipv4 };
}

static void
pending_connect_add_ipv6(PendingConnect *pending_connect, HTTP_IPv6 ipv6)
{
    if (pending_connect->num_addrs == pending_connect->max_addrs)
        return;
    pending_connect->addrs[pending_connect->num_addrs++] = (PendingConnectAddr) { .is_ipv4=false, .ipv6=ipv6 };
}

static int
next_connect_addr(PendingConnect *pending_connect, PendingConnectAddr *addr)
{
    if (pending_connect->cursor == pending_connect->num_addrs)
        return -1;
    *addr = pending_connect->addrs[pending_connect->cursor++];
    return 0;
}

// Initializes a FREE socket with the information required to
// connect to specified host name. The resulting socket state
// is DIED if an error occurred or PENDING.
void socket_connect(Socket *sock, SecureContext *sec,
    HTTP_String hostname, uint16_t port, void *user_data)
{
    PendingConnect *pending_connect;

    int max_addrs = 30;
    pending_connect = pending_connect_init(hostname, port, max_addrs);
    if (pending_connect == NULL) {
        sock->state = SOCKET_STATE_DIED;
        sock->events = 0;
        return;
    }

    char portstr[16];
    int len = snprintf(portstr, sizeof(portstr), "%u", port);
    if (len < 0 || len >= (int) sizeof(portstr)) {
        pending_connect_free(pending_connect);
        sock->state = SOCKET_STATE_DIED;
        sock->events = 0;
        return;
    }

    // DNS query
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int ret = getaddrinfo(pending_connect->hostname, portstr, &hints, &res);
    if (ret != 0) {
        pending_connect_free(pending_connect);
        sock->state = SOCKET_STATE_DIED;
        sock->events = 0;
        return;
    }

    for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET) {
            HTTP_IPv4 *ipv4 = (void*) &((struct sockaddr_in*)rp->ai_addr)->sin_addr;
            pending_connect_add_ipv4(pending_connect, *ipv4);
        } else if (rp->ai_family == AF_INET6) {
            HTTP_IPv6 *ipv6 = (void*) &((struct sockaddr_in6*)rp->ai_addr)->sin6_addr;
            pending_connect_add_ipv6(pending_connect, *ipv6);
        }
    }

    freeaddrinfo(res);

    sock->state = SOCKET_STATE_PENDING;
    sock->events = 0;

    sock->raw = BAD_SOCKET;
    sock->user_data = user_data;
    sock->pending_connect = pending_connect;
    sock->sec = sec;

#ifdef HTTPS_ENABLED
    sock->ssl = NULL;
#endif

    socket_update(sock);
}

// Just like socket_connect, but the raw IPv4 address is specified
void socket_connect_ipv4(Socket *sock, SecureContext *sec,
    HTTP_IPv4 addr, uint16_t port, void *user_data)
{
    PendingConnect *pending_connect;
    
    pending_connect = pending_connect_init(HTTP_STR(""), port, 1);
    if (pending_connect == NULL) {
        sock->state = SOCKET_STATE_DIED;
        sock->events = 0;
        return;
    }

    pending_connect_add_ipv4(pending_connect, addr);

    sock->state = SOCKET_STATE_PENDING;
    sock->events = 0;

    sock->raw = BAD_SOCKET;
    sock->user_data = user_data;
    sock->pending_connect = pending_connect;
    sock->sec = sec;

#ifdef HTTPS_ENABLED
    sock->ssl = NULL;
#endif

    socket_update(sock);
}

// Just like socket_connect, but the raw IPv6 address is specified
void socket_connect_ipv6(Socket *sock, SecureContext *sec,
    HTTP_IPv6 addr, uint16_t port, void *user_data)
{
    PendingConnect *pending_connect;
    
    pending_connect = pending_connect_init(HTTP_STR(""), port, 1);
    if (pending_connect == NULL) {
        sock->state = SOCKET_STATE_DIED;
        sock->events = 0;
        return;
    }

    pending_connect_add_ipv6(pending_connect, addr);

    sock->state = SOCKET_STATE_PENDING;
    sock->events = 0;

    sock->raw = BAD_SOCKET;
    sock->user_data = user_data;
    sock->pending_connect = pending_connect;
    sock->sec = sec;

#ifdef HTTPS_ENABLED
    sock->ssl = NULL;
#endif

    socket_update(sock);
}

void socket_accept(Socket *sock, SecureContext *sec, RAW_SOCKET raw)
{
    sock->state = SOCKET_STATE_ACCEPTED;
    sock->raw = raw;
    sock->events = 0;
    sock->user_data = NULL;
    sock->pending_connect = NULL;
    sock->sec = sec;

#ifdef HTTPS_ENABLED
    sock->ssl = NULL;
#endif

    if (set_socket_blocking(raw, false) < 0) {
        sock->state  = SOCKET_STATE_DIED;
        sock->events = 0;
        return;
    }

    socket_update(sock);
}

void socket_close(Socket *sock)
{
    // TODO: maybe we don't want to always set to SHUTDOWN. What if the socket is DIED for instance?
    sock->state  = SOCKET_STATE_SHUTDOWN;
    sock->events = 0;
    socket_update(sock);
}

bool socket_ready(Socket *sock)
{
    return sock->state == SOCKET_STATE_ESTABLISHED_READY;
}

bool socket_died(Socket *sock)
{
    return sock->state == SOCKET_STATE_DIED;
}

// TODO: when is the pending_connect data freed?

static bool connect_pending(void)
{
#ifdef _WIN32
    return WSAGetLastError() == WSAEWOULDBLOCK;
#else
    return errno == EINPROGRESS;
#endif
}

static bool
connect_failed_because_or_peer_2(int err)
{
#ifdef _WIN32
    return err == WSAECONNREFUSED
        || err == WSAETIMEDOUT
        || err == WSAENETUNREACH
        || err == WSAEHOSTUNREACH;
#else
    return err == ECONNREFUSED
        || err == ETIMEDOUT
        || err == ENETUNREACH
        || err == EHOSTUNREACH;
#endif
}

static bool
connect_failed_because_or_peer(void)
{
#ifdef _WIN32
    int err = WSAGetLastError();
#else
    int err = errno;
#endif
    return connect_failed_because_or_peer_2(err);
}

// Processes the socket until it's either ready, died, or would block
void socket_update(Socket *sock)
{
    sock->events = 0;

    bool again;
    do {

        again = false;

        switch (sock->state) {
        case SOCKET_STATE_PENDING:
        {
            // In this state we need to pop an address from the pending connect
            // data and try connect to it. This state is reached when a socket
            // is initialized using one of the socket_connect functions or by
            // failing to connect before the established state is reached.

            // If this isn't the first connection attempt we may have old
            // descriptors that need freeing before trying again.
            {
#ifdef HTTPS_ENABLED
                if (sock->ssl) {
                    SSL_free(sock->ssl);
                    sock->ssl = NULL;
                }
#endif
                if (sock->raw != BAD_SOCKET)
                    CLOSE_SOCKET(sock->raw);
            }

            // Pop the next address from the pending connect data
            PendingConnectAddr addr;
            if (next_connect_addr(sock->pending_connect, &addr) < 0) {
                sock->state  = SOCKET_STATE_DIED;
                sock->events = 0;
                break;
            }
            uint16_t port = sock->pending_connect->port;

            // Create a kernel socket object
            int family = addr.is_ipv4 ? AF_INET : AF_INET6;
            RAW_SOCKET raw = socket(family, SOCK_STREAM, 0);
            if (raw == BAD_SOCKET) {
                sock->state  = SOCKET_STATE_PENDING;
                sock->events = 0;
                again = true;
                break;
            }

            // Configure it
            if (set_socket_blocking(raw, false) < 0) {
                CLOSE_SOCKET(raw);
                sock->state  = SOCKET_STATE_DIED;
                sock->events = 0;
                break;
            }

            // Now perform the connect

            struct sockaddr_in  connect_buf_4;
            struct sockaddr_in6 connect_buf_6;
            struct sockaddr*    connect_buf;
            int    connect_buf_len;

            if (addr.is_ipv4) {

                connect_buf = (struct sockaddr*) &connect_buf_4;
                connect_buf_len = sizeof(connect_buf_4);

                connect_buf_4.sin_family = AF_INET;
                connect_buf_4.sin_port = htons(port);
                memcpy(&connect_buf_4.sin_addr, &addr.ipv4, sizeof(HTTP_IPv4));

            } else {

                connect_buf = (struct sockaddr*) &connect_buf_6;
                connect_buf_len = sizeof(connect_buf_6);

                connect_buf_6.sin6_family = AF_INET6;
                connect_buf_6.sin6_port = htons(port);
                memcpy(&connect_buf_6.sin6_addr, &addr.ipv6, sizeof(HTTP_IPv6));
            }

            int ret = connect(raw, connect_buf, connect_buf_len);

            // We divide the connect() results in four categories:
            //
            //   1) The connect resolved immediately. I'm not sure how this can happen,
            //      but we may as well handle it. This allows us to skip a step.
            //
            //   2) The connect operation is pending. This is what we expect most of the time.
            //
            //   3) The connect operation failed because the target address wasn't good
            //      for some reason. It make sense to try connecting to a different address
            //
            //   4) The connect operation failed for unknown reasons. There isn't much we
            //      can do at this point.

            if (ret == 0) {
                // Connected immediately
                sock->raw    = raw;
                sock->state  = SOCKET_STATE_CONNECTED;
                sock->events = 0;
                again = true;
                break;
            }

            if (connect_pending()) { // TODO: I'm pretty sure all the error numbers need to be changed for windows
                // Connection pending
                sock->raw = raw;
                sock->state = SOCKET_STATE_CONNECTING;
                sock->events = POLLOUT;
                break;
            }

            // Connect failed

            // If remote peer not working, try next address
            if (connect_failed_because_or_peer()) {
                sock->state = SOCKET_STATE_PENDING;
                sock->events = 0;
                again = true;
            } else {
                sock->state = SOCKET_STATE_DIED;
                sock->events = 0;
            }
        }
        break;

        case SOCKET_STATE_CONNECTING:
        {
            // We reach this point when a connect() operation on the
            // socket started and then the descriptor was marked as
            // ready for output. This means the operation is complete.

            int err = 0;
            socklen_t len = sizeof(err);

            if (getsockopt(sock->raw, SOL_SOCKET, SO_ERROR, (void*) &err, &len) < 0 || err != 0) {

                // If remote peer not working, try next address
                if (connect_failed_because_or_peer_2(err)) {
                    sock->state = SOCKET_STATE_PENDING;
                    sock->events = 0;
                    again = true;
                    break;
                }

                sock->state = SOCKET_STATE_DIED;
                sock->events = 0;
                break;
            }

            // Connect succeeded
            sock->state = SOCKET_STATE_CONNECTED;
            sock->events = 0;
            again = true;
        }
        break;

        case SOCKET_STATE_CONNECTED:
        {
            if (!socket_secure(sock)) {

                pending_connect_free(sock->pending_connect);
                sock->pending_connect = NULL;

                sock->events = 0;
                sock->state = SOCKET_STATE_ESTABLISHED_READY;

            } else {
#ifdef HTTPS_ENABLED
                // Start SSL handshake

                if (sock->ssl == NULL) {
                    sock->ssl = SSL_new(sock->sec->ctx);
                    if (sock->ssl == NULL) {
                        ERR_print_errors_fp(stderr); // TODO: remove
                        sock->state  = SOCKET_STATE_DIED;
                        sock->events = 0;
                        break;
                    }

                    if (SSL_set_fd(sock->ssl, sock->raw) != 1) {
                        sock->state  = SOCKET_STATE_DIED;
                        sock->events = 0;
                        break;
                    }

                    char *hostname = NULL;
                    if (sock->pending_connect->hostname[0])
                        hostname = sock->pending_connect->hostname;

                    if (hostname)
                        SSL_set_tlsext_host_name(sock->ssl, hostname);
                }

                int ret = SSL_connect(sock->ssl);
                if (ret == 1) {
                    // Handshake done

                    pending_connect_free(sock->pending_connect);
                    sock->pending_connect = NULL;

                    sock->state  = SOCKET_STATE_ESTABLISHED_READY;
                    sock->events = 0;
                    break;
                }

                int err = SSL_get_error(sock->ssl, ret);
                if (err == SSL_ERROR_WANT_READ) {
                    sock->events = POLLIN;
                    break;
                }

                if (err == SSL_ERROR_WANT_WRITE) {
                    sock->events = POLLOUT;
                    break;
                }

                sock->state  = SOCKET_STATE_PENDING;
                sock->events = 0;
                again = true;
#else
                assert(0);
#endif
            }
        }
        break;

        case SOCKET_STATE_ACCEPTED:
        {
            if (!socket_secure(sock)) {
                sock->state  = SOCKET_STATE_ESTABLISHED_READY;
                sock->events = 0;
            } else {
#ifdef HTTPS_ENABLED
                // Start server-side SSL handshake
                if (!sock->ssl) {

                    sock->ssl = SSL_new(sock->sec->ctx);
                    if (sock->ssl == NULL) {
                        sock->state  = SOCKET_STATE_DIED;
                        sock->events = 0;
                        break;
                    }

                    if (SSL_set_fd(sock->ssl, sock->raw) != 1) {
                        sock->state  = SOCKET_STATE_DIED;
                        sock->events = 0;
                        break;
                    }
                }

                int ret = SSL_accept(sock->ssl);
                if (ret == 1) {
                    // Handshake done
                    sock->state = SOCKET_STATE_ESTABLISHED_READY;
                    sock->events = 0;
                    break;
                }

                int err = SSL_get_error(sock->ssl, ret);
                if (err == SSL_ERROR_WANT_READ) {
                    sock->events = POLLIN;
                    break;
                }

                if (err == SSL_ERROR_WANT_WRITE) {
                    sock->events = POLLOUT;
                    break;
                }

                // Server socket error - close the connection
                sock->state  = SOCKET_STATE_DIED;
                sock->events = 0;
#else
               assert(0);
#endif
            }
        }
        break;

        case SOCKET_STATE_ESTABLISHED_WAIT:
        {
            sock->state = SOCKET_STATE_ESTABLISHED_READY;
            sock->events = 0;
        }
        break;

        case SOCKET_STATE_SHUTDOWN:
        {
            if (!socket_secure(sock)) {
                sock->state = SOCKET_STATE_DIED;
                sock->events = 0;
            } else {
#ifdef HTTPS_ENABLED
                int ret = SSL_shutdown(sock->ssl);
                if (ret == 1) {
                    sock->state  = SOCKET_STATE_DIED;
                    sock->events = 0;
                    break;
                }

                int err = SSL_get_error(sock->ssl, ret);
                if (err == SSL_ERROR_WANT_READ) {
                    sock->events = POLLIN;
                    break;
                }
                
                if (err == SSL_ERROR_WANT_WRITE) {
                    sock->events = POLLOUT;
                    break;
                }

                sock->state  = SOCKET_STATE_DIED;
                sock->events = 0;
#else
                assert(0);
#endif
            }
        }
        break;

        default:
            // Do nothing
            break;
        }

    } while (again);
}

static bool would_block(void)
{
#ifdef _WIN32
    int err = WSAGetLastError();
    return err == WSAEWOULDBLOCK;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK;
#endif
}

static bool interrupted(void)
{
#ifdef _WIN32
    return false;
#else
    return errno == EINTR;
#endif
}

int socket_read(Socket *sock, char *dst, int max)
{
    // If not ESTABLISHED, set state to DIED and return
    if (sock->state != SOCKET_STATE_ESTABLISHED_READY) {
        sock->state = SOCKET_STATE_DIED;
        sock->events = 0;
        return 0;
    }

    if (!socket_secure(sock)) {
        int ret = recv(sock->raw, dst, max, 0);
        if (ret == 0) {
            sock->state  = SOCKET_STATE_DIED;
            sock->events = 0;
        } else {
            if (ret < 0) {
                if (would_block()) {
                    sock->state  = SOCKET_STATE_ESTABLISHED_WAIT;
                    sock->events = POLLIN;
                } else {
                    if (!interrupted()) {
                        sock->state  = SOCKET_STATE_DIED;
                        sock->events = 0;
                    }
                }
                ret = 0;
            }
        }
        return ret;
    } else {
#ifdef HTTPS_ENABLED
        int ret = SSL_read(sock->ssl, dst, max);
        if (ret <= 0) {
            int err = SSL_get_error(sock->ssl, ret);
            if (err == SSL_ERROR_WANT_READ) {
                sock->state  = SOCKET_STATE_ESTABLISHED_WAIT;
                sock->events = POLLIN;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                sock->state = SOCKET_STATE_ESTABLISHED_WAIT;
                sock->events = POLLOUT;
            } else {
                fprintf(stderr, "OpenSSL error in socket_read: ");
                ERR_print_errors_fp(stderr);
                sock->state  = SOCKET_STATE_DIED;
                sock->events = 0;
            }
            ret = 0;
        }
        return ret;
#else
        assert(0);
        return -1;
#endif
    }
}

int socket_write(Socket *sock, char *src, int len)
{
    // If not ESTABLISHED, set state to DIED and return
    if (sock->state != SOCKET_STATE_ESTABLISHED_READY) {
        sock->state  = SOCKET_STATE_DIED;
        sock->events = 0;
        return 0;
    }

    if (!socket_secure(sock)) {
        int ret = send(sock->raw, src, len, 0);
        if (ret < 0) {
            if (would_block()) {
                sock->state  = SOCKET_STATE_ESTABLISHED_WAIT;
                sock->events = POLLOUT;
            } else {
                if (!interrupted()) {
                    sock->state = SOCKET_STATE_DIED;
                    sock->events = 0;
                }
            }
            ret = 0;
        }
        return ret;
    } else {
#ifdef HTTPS_ENABLED
        int ret = SSL_write(sock->ssl, src, len);
        if (ret <= 0) {
            int err = SSL_get_error(sock->ssl, ret);
            if (err == SSL_ERROR_WANT_READ) {
                sock->state  = SOCKET_STATE_ESTABLISHED_WAIT;
                sock->events = POLLIN;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                sock->state  = SOCKET_STATE_ESTABLISHED_WAIT;
                sock->events = POLLOUT;
            } else {
                fprintf(stderr, "OpenSSL error in socket_write: ");
                ERR_print_errors_fp(stderr);
                sock->state  = SOCKET_STATE_DIED;
                sock->events = 0;
            }
            ret = 0;
        }
        return ret;
#else
        assert(0);
#endif
    }
}

bool socket_secure(Socket *sock)
{
#ifdef HTTPS_ENABLED
    return sock->sec != NULL;
#else
    (void) sock;
    return false;
#endif
}

void socket_free(Socket *sock)
{
    if (sock->pending_connect != NULL)
        pending_connect_free(sock->pending_connect);

    if (sock->raw != BAD_SOCKET)
        CLOSE_SOCKET(sock->raw);

#ifdef HTTPS_ENABLED
    if (sock->ssl)
        SSL_free(sock->ssl);
#endif

    sock->state = SOCKET_STATE_FREE;
}

void socket_set_user_data(Socket *sock, void *user_data)
{
    sock->user_data = user_data;
}

void *socket_get_user_data(Socket *sock)
{
    return sock->user_data;
}

////////////////////////////////////////////////////////////////////////////////////////
// src/socket_pool.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/socket_pool.c"
#include <assert.h>
#include <stdlib.h>

#ifdef __linux__
#include <errno.h>
#include <sys/socket.h>
#endif

#ifndef HTTP_AMALGAMATION
#include "socket_pool.h"
#endif

#define SOCKET_HARD_LIMIT (1<<10)
#define MAX_CERTS 10

struct SocketPool {

    SecureContext sec;

    RAW_SOCKET listen_sock;
    RAW_SOCKET secure_sock;

    int num_socks;
    int max_socks;
    Socket socks[];
};

int socket_pool_global_init(void)
{
    int ret = socket_raw_global_init();
    if (ret < 0)
        return -1;

    secure_context_global_init();
    return 0;
}

void socket_pool_global_free(void)
{
    secure_context_global_free();
    socket_raw_global_free();
}

SocketPool *socket_pool_init(HTTP_String addr,
    uint16_t port, uint16_t secure_port, int max_socks,
    bool reuse_addr, int backlog, HTTP_String cert_file,
    HTTP_String key_file)
{
    if (max_socks > SOCKET_HARD_LIMIT)
        return NULL;

    SocketPool *pool = malloc(sizeof(SocketPool) + max_socks * sizeof(Socket));
    if (pool == NULL)
        return NULL;

    pool->num_socks = 0;
    pool->max_socks = max_socks;

    for (int i = 0; i < pool->max_socks; i++)
        pool->socks[i].state = SOCKET_STATE_FREE;

    if (port == 0)
        pool->listen_sock = BAD_SOCKET;
    else {
        pool->listen_sock = listen_socket(addr, port, reuse_addr, backlog);
        if (pool->listen_sock == BAD_SOCKET) {
            free(pool);
            return NULL;
        }
    }

    if (secure_port == 0)
        pool->secure_sock = BAD_SOCKET;
    else {
#ifndef HTTPS_ENABLED
        (void) cert_file;
        (void) key_file;
        if (pool->listen_sock != BAD_SOCKET)
            CLOSE_SOCKET(pool->listen_sock);
        free(pool);
        return NULL;
#else
        if (secure_context_init_as_server(&pool->sec, cert_file, key_file) < 0) {
            if (pool->listen_sock != BAD_SOCKET)
                CLOSE_SOCKET(pool->listen_sock);
            free(pool);
            return NULL;
        }

        pool->secure_sock = listen_socket(addr, secure_port, reuse_addr, backlog);
        if (pool->secure_sock == BAD_SOCKET) {
            if (pool->listen_sock != BAD_SOCKET) CLOSE_SOCKET(pool->listen_sock);
            free(pool);
            return NULL;
        }
#endif
    }

#ifdef HTTPS_ENABLED
    if (port == 0 && secure_port == 0) {
        if (secure_context_init_as_client(&pool->sec) < 0) {
            if (pool->listen_sock != BAD_SOCKET) CLOSE_SOCKET(pool->listen_sock);
            if (pool->secure_sock != BAD_SOCKET) CLOSE_SOCKET(pool->secure_sock);
            free(pool);
            return NULL;
        }
    }
#endif

    for (int i = 0; i < max_socks; i++)
        pool->socks[i].state = SOCKET_STATE_FREE;

    return pool;
}

void socket_pool_free(SocketPool *pool)
{
    for (int i = 0, j = 0; j < pool->num_socks; i++) {

        Socket *sock = &pool->socks[i];

        if (sock->state == SOCKET_STATE_FREE)
            continue;
        j++;

        socket_free(sock);
    }

    secure_context_free(&pool->sec);

    if (pool->secure_sock != BAD_SOCKET) CLOSE_SOCKET(pool->secure_sock);
    if (pool->listen_sock != BAD_SOCKET) CLOSE_SOCKET(pool->listen_sock);
}

int socket_pool_add_cert(SocketPool *pool, HTTP_String domain, HTTP_String cert_file, HTTP_String key_file)
{
    return secure_context_add_cert(&pool->sec, domain, cert_file, key_file);
}

void socket_pool_set_user_data(SocketPool *pool, SocketHandle handle, void *user_data)
{
    Socket *sock = &pool->socks[handle];
    socket_set_user_data(sock, user_data);
}

void socket_pool_close(SocketPool *pool, SocketHandle handle)
{
    Socket *sock = &pool->socks[handle];
    socket_close(sock);
}

static Socket *find_free_socket(SocketPool *pool)
{
    if (pool->num_socks == pool->max_socks)
        return NULL;

    int i = 0;
    while (pool->socks[i].state != SOCKET_STATE_FREE)
        i++;

    return &pool->socks[i];
}

int socket_pool_connect(SocketPool *pool, bool secure,
    HTTP_String addr, uint16_t port, void *user_data)
{
    Socket *sock = find_free_socket(pool);
    if (sock == NULL)
        return -1;

    socket_connect(sock, secure ? &pool->sec : NULL, addr, port, user_data);

    if (socket_died(sock)) {
        socket_free(sock);
        return -1;
    }

    pool->num_socks++;
    return 0;
}

int socket_pool_connect_ipv4(SocketPool *pool, bool secure,
    HTTP_IPv4 addr, uint16_t port, void *user_data)
{
    Socket *sock = find_free_socket(pool);
    if (sock == NULL)
        return -1;

    socket_connect_ipv4(sock, secure ? &pool->sec : NULL, addr, port, user_data);

    if (socket_died(sock)) {
        socket_free(sock);
        return -1;
    }

    pool->num_socks++;
    return 0;
}

int socket_pool_connect_ipv6(SocketPool *pool, bool secure,
    HTTP_IPv6 addr, uint16_t port, void *user_data)
{
    Socket *sock = find_free_socket(pool);
    if (sock == NULL)
        return -1;

    socket_connect_ipv6(sock, secure ? &pool->sec : NULL, addr, port, user_data);

    if (socket_died(sock)) {
        socket_free(sock);
        return -1;
    }

    pool->num_socks++;
    return 0;
}

#include <stdio.h> // TODO: remove

SocketEvent socket_pool_wait(SocketPool *pool)
{
    for (;;) {

        // First, iterate over all sockets to find one that
        // died or is ready.

        for (int i = 0, j = 0; j < pool->num_socks; i++) {

            Socket *sock = &pool->socks[i];

            if (sock->state == SOCKET_STATE_FREE)
                continue;
            j++;

            if (socket_died(sock)) {
                void *user_data = socket_get_user_data(sock);
                socket_free(sock);
                pool->num_socks--;
                return (SocketEvent) { SOCKET_EVENT_DIED, -1, user_data };
            }

            if (socket_ready(sock))
                return (SocketEvent) { SOCKET_EVENT_READY, i, socket_get_user_data(sock) };

            assert(sock->events);
        }

        // If we reached this point, we either have no sockets
        // or all sockets need to wait for some event. Waiting
        // when no sockets are available is only allowed when
        // the pool is in server mode.

        int indices[SOCKET_HARD_LIMIT+2];
        struct pollfd polled[SOCKET_HARD_LIMIT+2];
        int num_polled = 0;

        if (pool->num_socks < pool->max_socks) {

            if (pool->listen_sock != BAD_SOCKET) {
                indices[num_polled] = -1;
                polled[num_polled].fd = pool->listen_sock;
                polled[num_polled].events = POLLIN;
                polled[num_polled].revents = 0;
                num_polled++;
            }

            if (pool->secure_sock != BAD_SOCKET) {
                indices[num_polled] = -1;
                polled[num_polled].fd = pool->secure_sock;
                polled[num_polled].events = POLLIN;
                polled[num_polled].revents = 0;
                num_polled++;
            }
        }

        for (int i = 0, j = 0; j < pool->num_socks; i++) {

            Socket *sock = &pool->socks[i];

            if (sock->state == SOCKET_STATE_FREE)
                continue;
            j++;

            indices[num_polled] = i;
            polled[num_polled].fd = sock->raw;
            polled[num_polled].events = sock->events;
            polled[num_polled].revents = 0;
            num_polled++;
        }

        if (num_polled == 0)
            return (SocketEvent) { SOCKET_EVENT_ERROR, -1, NULL };

        int ret = POLL(polled, num_polled, -1);
        if (ret < 0) {

            if (errno == EINTR)
                return (SocketEvent) { SOCKET_EVENT_SIGNAL, -1, NULL };

            return (SocketEvent) { SOCKET_EVENT_ERROR, -1, NULL };
        }

        for (int i = 0; i < num_polled; i++) {

            Socket *sock;
            
            if (polled[i].fd == pool->listen_sock || polled[i].fd == pool->secure_sock) {

                bool secure = false;
                if (polled[i].fd == pool->secure_sock)
                    secure = true;

                Socket *sock = find_free_socket(pool);
                if (sock == NULL)
                    continue;

                RAW_SOCKET raw = accept(polled[i].fd, NULL, NULL);
                if (raw == BAD_SOCKET)
                    continue;

                socket_accept(sock, secure ? &pool->sec : NULL, raw);

                if (socket_died(sock)) {
                    socket_free(sock);
                    continue;
                }

                pool->num_socks++;

            } else {
                int j = indices[i];
                sock = &pool->socks[j];

                if (polled[i].revents)
                    socket_update(sock);
            }
        }
    }

    // This branch is unreachable
    return (SocketEvent) { SOCKET_EVENT_ERROR, -1, NULL };
}

int socket_pool_read(SocketPool *pool, SocketHandle handle, char *dst, int len)
{
    return socket_read(&pool->socks[handle], dst, len);
}

int socket_pool_write(SocketPool *pool, SocketHandle handle, char *src, int len)
{
    return socket_write(&pool->socks[handle], src, len);
}

bool socket_pool_secure(SocketPool *pool, SocketHandle handle)
{
    return socket_secure(&pool->socks[handle]);
}

////////////////////////////////////////////////////////////////////////////////////////
// src/client.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/client.c"
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#define POLL WSAPoll
#endif

#ifdef __linux__
#include <poll.h>
#define POLL poll
#endif

#ifndef HTTP_AMALGAMATION
#include "client.h"
#include "engine.h"
#include "socket_pool.h"
#endif

#define CLIENT_MAX_CONNS 256

typedef enum {
    CLIENT_CONNECTION_FREE,
    CLIENT_CONNECTION_INIT,
    CLIENT_CONNECTION_INIT_ERROR,
    CLIENT_CONNECTION_WAIT,
    CLIENT_CONNECTION_DONE,
} ClientConnectionState;

typedef struct {
    ClientConnectionState state;
    uint16_t     gen;
    SocketHandle sock;
    HTTP_Engine  eng;
    bool         trace;
    void*        user_data;
} ClientConnection;

struct HTTP_Client {

    SocketPool *socket_pool;

    int num_conns;
    ClientConnection conns[CLIENT_MAX_CONNS];

    int ready_head;
    int ready_count;
    int ready[CLIENT_MAX_CONNS];
};

int http_global_init(void)
{
    int ret = socket_pool_global_init();
    if (ret < 0)
        return -1;
    return 0;
}

void http_global_free(void)
{
    socket_pool_global_free();
}

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

HTTP_Client *http_client_init(void)
{
    HTTP_Client *client = malloc(sizeof(HTTP_Client));
    if (client == NULL)
        return NULL;

    int max_socks = 100;
    SocketPool *socket_pool = socket_pool_init(HTTP_STR(""), 0, 0, max_socks, false, 0, HTTP_STR(""), HTTP_STR(""));
    if (socket_pool == NULL) {
        free(client);
        return NULL;
    }
    client->socket_pool = socket_pool;

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

    socket_pool_free(client->socket_pool);
    free(client);
}

int http_client_get_builder(HTTP_Client *client, HTTP_RequestBuilder *builder)
{
    if (client->num_conns == CLIENT_MAX_CONNS)
        return -1;

    int i = 0;
    while (client->conns[i].state != CLIENT_CONNECTION_FREE)
        i++;

    client->conns[i].sock = -1;
    client->conns[i].user_data = NULL;
    client->conns[i].trace = false;
    client->conns[i].state = CLIENT_CONNECTION_INIT;
    http_engine_init(&client->conns[i].eng, 1, client_memfunc, NULL);

    client->num_conns++;

    *builder = (HTTP_RequestBuilder) { client, i, client->conns[i].gen };
    return 0;
}

int http_client_wait(HTTP_Client *client, HTTP_Response **result, void **user_data)
{
    while (client->ready_count == 0) {

        SocketEvent event = socket_pool_wait(client->socket_pool);
        switch (event.type) {

            case SOCKET_EVENT_DIED:
            {
                ClientConnection *conn = event.user_data;
                conn->state = CLIENT_CONNECTION_DONE;

                int tail = (client->ready_head + client->ready_count) % CLIENT_MAX_CONNS;
                client->ready[tail] = conn - client->conns;
                client->ready_count++;
            }
            break;

            case SOCKET_EVENT_READY:
            {
                ClientConnection *conn = event.user_data;

                if (conn->sock == -1)
                    conn->sock = event.handle;

                HTTP_EngineState engine_state;
                engine_state = http_engine_state(&conn->eng);

                if (engine_state == HTTP_ENGINE_STATE_CLIENT_RECV_BUF) {
                    int len;
                    char *buf;
                    buf = http_engine_recvbuf(&conn->eng, &len);
                    if (buf) {
                        int ret = socket_pool_read(client->socket_pool, conn->sock, buf, len);
                        if (conn->trace)
                            print_bytes(HTTP_STR(">> "), (HTTP_String) { buf, ret });
                        http_engine_recvack(&conn->eng, ret);
                    }
                } else if (engine_state == HTTP_ENGINE_STATE_CLIENT_SEND_BUF) {
                    int len;
                    char *buf;
                    buf = http_engine_sendbuf(&conn->eng, &len);
                    if (buf) {
                        int ret = socket_pool_write(client->socket_pool, conn->sock, buf, len);
                        if (conn->trace)
                            print_bytes(HTTP_STR("<< "), (HTTP_String) { buf, ret });
                        http_engine_sendack(&conn->eng, ret);
                    }
                }

                engine_state = http_engine_state(&conn->eng);

                if (engine_state == HTTP_ENGINE_STATE_CLIENT_CLOSED ||
                    engine_state == HTTP_ENGINE_STATE_CLIENT_READY)
                    socket_pool_close(client->socket_pool, conn->sock);
            }
            break;

            case SOCKET_EVENT_ERROR:
            return -1;

            case SOCKET_EVENT_SIGNAL:
            return 1;
        }
    }

    int index = client->ready[client->ready_head];
    client->ready_head = (client->ready_head + 1) % CLIENT_MAX_CONNS;
    client->ready_count--;

    ClientConnection *conn = &client->conns[index];

    HTTP_Response *result2 = http_engine_getres(&conn->eng);

    if (result)
        *result = result2;

    if (user_data)
        *user_data = conn->user_data;

    if (result2 == NULL) {
        http_engine_free(&conn->eng);
        conn->state = CLIENT_CONNECTION_FREE;
        client->num_conns--;
    } else {
        result2->context = client;
    }

    return 0;
}

static ClientConnection *client_builder_to_conn(HTTP_RequestBuilder handle)
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

void http_request_builder_user_data(HTTP_RequestBuilder builder, void *user_data)
{
    ClientConnection *conn = client_builder_to_conn(builder);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT)
        return;

    conn->user_data = user_data;
}

void http_request_builder_trace(HTTP_RequestBuilder builder, bool trace)
{
    ClientConnection *conn = client_builder_to_conn(builder);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT)
        return;

    conn->trace = trace;
}

void http_request_builder_line(HTTP_RequestBuilder builder, HTTP_Method method, HTTP_String url)
{
    ClientConnection *conn = client_builder_to_conn(builder);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT)
        return;

    HTTP_Client *client = builder.data0;

    HTTP_URL parsed_url;
    int ret = http_parse_url(url.ptr, url.len, &parsed_url);
    if (ret != url.len) {
        conn->state = CLIENT_CONNECTION_INIT_ERROR;
        return;
    }

    bool secure = false;
    if (http_streq(parsed_url.scheme, HTTP_STR("https"))) {
        secure = true;
    } else if (!http_streq(parsed_url.scheme, HTTP_STR("http"))) {
        conn->state = CLIENT_CONNECTION_INIT_ERROR;
        return;
    }

    int port = parsed_url.authority.port;
    if (port == 0) {
        if (secure)
            port = 443;
        else
            port = 80;
    }

    switch (parsed_url.authority.host.mode) {
        case HTTP_HOST_MODE_IPV4: ret = socket_pool_connect_ipv4(client->socket_pool, secure, parsed_url.authority.host.ipv4, port, conn); break;
        case HTTP_HOST_MODE_IPV6: ret = socket_pool_connect_ipv6(client->socket_pool, secure, parsed_url.authority.host.ipv6, port, conn); break;
        case HTTP_HOST_MODE_NAME: ret = socket_pool_connect     (client->socket_pool, secure, parsed_url.authority.host.name, port, conn); break;
        case HTTP_HOST_MODE_VOID: ret = -1; return;
    }

    if (ret < 0) {
        conn->state = CLIENT_CONNECTION_INIT_ERROR;
        return;
    }

    http_engine_url(&conn->eng, method, url, 1);
}

void http_request_builder_header(HTTP_RequestBuilder handle, HTTP_String str)
{
    ClientConnection *conn = client_builder_to_conn(handle);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT)
        return;

    http_engine_header(&conn->eng, str);
}

void http_request_builder_body(HTTP_RequestBuilder handle, HTTP_String str)
{
    ClientConnection *conn = client_builder_to_conn(handle);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT)
        return;

    http_engine_body(&conn->eng, str);
}

void http_request_builder_submit(HTTP_RequestBuilder handle)
{
    HTTP_Client *client = handle.data0;
    ClientConnection *conn = client_builder_to_conn(handle);
    if (conn == NULL)
        return;
    if (conn->state != CLIENT_CONNECTION_INIT &&
        conn->state != CLIENT_CONNECTION_INIT_ERROR)
        return;

    // TODO: invalidate the handle

    if (conn->state == CLIENT_CONNECTION_INIT_ERROR) {

        conn->state = CLIENT_CONNECTION_DONE;

        int tail = (client->ready_head + client->ready_count) % CLIENT_MAX_CONNS;
        client->ready[tail] = conn - client->conns;
        client->ready_count++;

    } else {
        http_engine_done(&conn->eng);
        conn->state = CLIENT_CONNECTION_WAIT;
    }
}

void http_response_free(HTTP_Response *res)
{
    if (res == NULL)
        return;

    HTTP_Client *client = res->context;

    ClientConnection *conn = NULL;
    for (int i = 0, j = 0; j < client->num_conns; i++) {

        if (client->conns[i].state == CLIENT_CONNECTION_FREE)
            continue;
        j++;

        if (client->conns[i].state != CLIENT_CONNECTION_DONE)
            continue;

        if (http_engine_getres(&client->conns[i].eng) == res) {
            conn = &client->conns[i];
            break;
        }
    }

    HTTP_ASSERT(conn);

    http_engine_free(&conn->eng);
    conn->state = CLIENT_CONNECTION_FREE;
    client->num_conns--;
}

static HTTP_Client *default_client___; // TODO: deinitialize the default client when http_global_free is called

static HTTP_Client *get_default_client(void)
{
    if (default_client___ == NULL)
        default_client___ = http_client_init();
    return default_client___;
}

HTTP_Response *http_get(HTTP_String url, HTTP_String *headers, int num_headers)
{
    HTTP_Client *client = get_default_client();
    if (client == NULL)
        return NULL;

    HTTP_RequestBuilder builder;
    int ret = http_client_get_builder(client, &builder);
    if (ret < 0)
        return NULL;
    http_request_builder_line(builder, HTTP_METHOD_GET, url);
    for (int i = 0; i < num_headers; i++)
        http_request_builder_header(builder, headers[i]);
    http_request_builder_submit(builder);

    HTTP_Response *res;
    ret = http_client_wait(client, &res, NULL); // TODO: it's assumed there is only one request pending
    if (ret < 0)
        return NULL;

    return res;
}

HTTP_Response *http_post(HTTP_String url, HTTP_String *headers, int num_headers, HTTP_String body)
{
    HTTP_Client *client = get_default_client();
    if (client == NULL)
        return NULL;

    HTTP_RequestBuilder builder;
    int ret = http_client_get_builder(client, &builder);
    if (ret < 0)
        return NULL;
    http_request_builder_line(builder, HTTP_METHOD_POST, url);
    for (int i = 0; i < num_headers; i++)
        http_request_builder_header(builder, headers[i]);
    http_request_builder_body(builder, body);
    http_request_builder_submit(builder);

    HTTP_Response *res;
    ret = http_client_wait(client, &res, NULL); // TODO: it's assumed there is only one request pending
    if (ret < 0)
        return NULL;

    return res;
}

////////////////////////////////////////////////////////////////////////////////////////
// src/server.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/server.c"
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>

#ifndef HTTP_AMALGAMATION
#include "engine.h"
#include "server.h"
#include "socket_pool.h"
#endif

#define MAX_CONNS (1<<10)

typedef struct {
    bool         used;
    uint16_t     gen;
    HTTP_Engine  engine;
    SocketHandle sock;
} Connection;

struct HTTP_Server {

    SocketPool *socket_pool;

    int num_conns;
    Connection conns[MAX_CONNS];

    int ready_head;
    int ready_count;
    int ready[MAX_CONNS];
};

HTTP_Server *http_server_init(HTTP_String addr, uint16_t port)
{
    return http_server_init_ex(addr, port, 0, HTTP_STR(""), HTTP_STR(""));
}

HTTP_Server *http_server_init_ex(HTTP_String addr, uint16_t port,
    uint16_t secure_port, HTTP_String cert_file, HTTP_String key_file)
{
    HTTP_Server *server = malloc(sizeof(HTTP_Server));
    if (server == NULL)
        return NULL;

    int backlog = 32;
    bool reuse_addr = true;
    SocketPool *socket_pool = socket_pool_init(addr, port, secure_port, MAX_CONNS, reuse_addr, backlog, cert_file, key_file);
    if (socket_pool == NULL) {
        free(server);
        return NULL;
    }

    server->socket_pool = socket_pool;
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

    socket_pool_free(server->socket_pool);
    free(server);
}

int http_server_add_website(HTTP_Server *server, HTTP_String domain, HTTP_String cert_file, HTTP_String key_file)
{
    return socket_pool_add_cert(server->socket_pool, domain, cert_file, key_file);
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

int http_server_wait(HTTP_Server *server, HTTP_Request **req, HTTP_ResponseBuilder *builder)
{
    while (server->ready_count == 0) {

        SocketEvent event = socket_pool_wait(server->socket_pool);
        switch (event.type) {

            case SOCKET_EVENT_DIED:
            {
                Connection *conn = event.user_data;
                HTTP_ASSERT(conn);

                http_engine_free(&conn->engine);
                conn->used = false;
                conn->gen++;
                server->num_conns--;
            }
            break;

            case SOCKET_EVENT_READY:
            {
                Connection *conn = event.user_data;
                if (conn == NULL) {

                    // Connection was just accepted

                    if (server->num_conns == MAX_CONNS) {
                        socket_pool_close(server->socket_pool, event.handle);
                        break;
                    }

                    int i = 0;
                    while (server->conns[i].used)
                        i++;

                    conn = &server->conns[i];
                    conn->used = true;
                    conn->sock = event.handle;
                    http_engine_init(&conn->engine, 0, server_memfunc, NULL);
                    socket_pool_set_user_data(server->socket_pool, event.handle, conn);
                    server->num_conns++;
                }

                switch (http_engine_state(&conn->engine)) {

                    int len;
                    char *buf;

                    case HTTP_ENGINE_STATE_SERVER_RECV_BUF:
                    buf = http_engine_recvbuf(&conn->engine, &len);
                    if (buf) {
                        int ret = socket_pool_read(server->socket_pool, conn->sock, buf, len);
                        http_engine_recvack(&conn->engine, ret);
                    }
                    break;

                    case HTTP_ENGINE_STATE_SERVER_SEND_BUF:
                    buf = http_engine_sendbuf(&conn->engine, &len);
                    if (buf) {
                        int ret = socket_pool_write(server->socket_pool, conn->sock, buf, len);
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
                    server->ready[tail] = conn - server->conns;
                    server->ready_count++;
                    break;

                    case HTTP_ENGINE_STATE_SERVER_CLOSED:
                    socket_pool_close(server->socket_pool, conn->sock);
                    break;

                    default:
                    break;
                }
            }
            break;

            case SOCKET_EVENT_ERROR:
            return -1;

            case SOCKET_EVENT_SIGNAL:
            return 1;
        }
    }

    int index = server->ready[server->ready_head];
    server->ready_head = (server->ready_head + 1) % MAX_CONNS;
    server->ready_count--;

    *req = http_engine_getreq(&server->conns[index].engine);
    (*req)->secure = socket_pool_secure(server->socket_pool, server->conns[index].sock);

    *builder = (HTTP_ResponseBuilder) { server, index, server->conns[index].gen };
    return 0;
}

static Connection*
server_builder_to_conn(HTTP_ResponseBuilder builder)
{
	HTTP_Server *server = builder.data0;
	if (builder.data1 >= MAX_CONNS)
		return NULL;

	Connection *conn = &server->conns[builder.data1];
	if (conn->gen != builder.data2)
		return NULL;

	return conn;
}

void http_response_builder_status(HTTP_ResponseBuilder res, int status)
{
	Connection *conn = server_builder_to_conn(res);
	if (conn == NULL)
		return;

	http_engine_status(&conn->engine, status);
}

void http_response_builder_header(HTTP_ResponseBuilder res, HTTP_String str)
{
	Connection *conn = server_builder_to_conn(res);
	if (conn == NULL)
		return;

	http_engine_header(&conn->engine, str);
}

void http_response_builder_body(HTTP_ResponseBuilder res, HTTP_String str)
{
	Connection *conn = server_builder_to_conn(res);
	if (conn == NULL)
		return;

	http_engine_body(&conn->engine, str);
}

void http_response_builder_bodycap(HTTP_ResponseBuilder res, int mincap)
{
	Connection *conn = server_builder_to_conn(res);
	if (conn == NULL)
		return;

	http_engine_bodycap(&conn->engine, mincap);
}

char *http_response_builder_bodybuf(HTTP_ResponseBuilder res, int *cap)
{
	Connection *conn = server_builder_to_conn(res);
	if (conn == NULL) {
		*cap = 0;
		return NULL;
	}

	return http_engine_bodybuf(&conn->engine, cap);
}

void http_response_builder_bodyack(HTTP_ResponseBuilder res, int num)
{
	Connection *conn = server_builder_to_conn(res);
	if (conn == NULL)
		return;

	http_engine_bodyack(&conn->engine, num);
}

void http_response_builder_undo(HTTP_ResponseBuilder res)
{
	Connection *conn = server_builder_to_conn(res);
	if (conn == NULL)
		return;

	http_engine_undo(&conn->engine);
}

void http_response_builder_done(HTTP_ResponseBuilder res)
{
    HTTP_Server *server = res.data0;
    Connection *conn = server_builder_to_conn(res);
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

    if (state == HTTP_ENGINE_STATE_SERVER_CLOSED)
        socket_pool_close(server->socket_pool, conn->sock);
}

////////////////////////////////////////////////////////////////////////////////////////
// src/router.c
////////////////////////////////////////////////////////////////////////////////////////

#line 1 "src/router.c"
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef __linux__
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#endif

#ifndef HTTP_AMALGAMATION
#include "router.h"
#endif

#ifndef HTTP_AMALGAMATION
bool is_alpha(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
bool is_digit(char c)
{
	return c >= '0' && c <= '9';
}
#endif // HTTP_AMALGAMATION

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
	HTTP_Router *router = malloc(sizeof(HTTP_Router) + max_routes * sizeof(Route));
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
	(void) method; // TODO: Don't ignore the method
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

static int serve_file_or_index(HTTP_ResponseBuilder res, HTTP_String base_endpoint, HTTP_String base_path, HTTP_String endpoint)
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
		http_response_builder_status(res, 500);
		http_response_builder_done(res);
		return 1;
	}
	if (ret == 1) {

		// File missing

		char index[] = "index.html";
		if (path.len + sizeof(index) + 1 > sizeof(mem)) {
			http_response_builder_status(res, 500);
			http_response_builder_done(res);
			return 1;
		}
		path.ptr[path.len++] = '/';
		memcpy(path.ptr + path.len, index, sizeof(index));
		path.len += sizeof(index)-1;

		ret = file_open(path.ptr, &file, &size);
		if (ret == -1) {
			http_response_builder_status(res, 500);
			http_response_builder_done(res);
			return 1;
		}
		if (ret == 1)
			return 0; // File missing
	}
	HTTP_ASSERT(ret == 0);

	int cap;
	char *dst;
	http_response_builder_status(res, 200);
	http_response_builder_bodycap(res, size);
	dst = http_response_builder_bodybuf(res, &cap);
	if (dst) {
		int copied = 0;
		while (copied < size) {
			int ret = file_read(file, dst + copied, size - copied);
			if (ret < 0) goto err;
			if (ret == 0) break;
			copied += ret;
		}
		if (copied < size) goto err;
		http_response_builder_bodyack(res, size);
	}
	http_response_builder_done(res);
	file_close(file);
	return 1;
err:
	http_response_builder_bodyack(res, 0);
	http_response_builder_undo(res);
	http_response_builder_status(res, 500);
	http_response_builder_done(res);
	file_close(file);
	return 1;
}

static int serve_dynamic_route(Route *route, HTTP_Request *req, HTTP_ResponseBuilder res)
{
	char path_mem[1<<12];
	int path_len = sanitize_path(req->url.path, path_mem, (int) sizeof(path_mem));
	if (path_len < 0) {
		http_response_builder_status(res, 400);
		http_response_builder_body(res, HTTP_STR("Invalid path"));
		http_response_builder_done(res);
		return 1;
	}
	HTTP_String path = {path_mem, path_len};

	if (!http_streq(path, route->endpoint))
		return 0;

	route->func(req, res, route->ptr);
	return 1;
}

void http_router_resolve(HTTP_Router *router, HTTP_Request *req, HTTP_ResponseBuilder res)
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
			http_response_builder_status(res, 500);
			http_response_builder_done(res);
			return;
		}
	}
	http_response_builder_status(res, 404);
	http_response_builder_done(res);
}

int http_serve(char *addr, int port, HTTP_Router *router)
{
	int ret;

	HTTP_Server *server = http_server_init_ex((HTTP_String) { addr, strlen(addr) }, port, 0, (HTTP_String) {}, (HTTP_String) {});
	if (server == NULL) {
		http_router_free(router);
		return -1;
	}

	for (;;) {
		HTTP_Request *req;
		HTTP_ResponseBuilder res;
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
