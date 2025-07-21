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

int set_socket_blocking(RAW_SOCKET sock, bool value);

RAW_SOCKET listen_socket(HTTP_String addr, uint16_t port, bool reuse_addr, int backlog);

#endif // SOCKET_RAW_INCLUDED