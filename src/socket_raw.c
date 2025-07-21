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
