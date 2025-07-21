#include <assert.h> // TODO: organize these includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define POLL WSAPoll
#endif

#ifdef __linux__
#include <poll.h>
#include <netdb.h>
#include <fcntl.h>
#define POLL poll
#endif

#ifdef HTTPS_ENABLED
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#endif

#ifndef HTTP_AMALGAMATION
#include "socket.h"
#endif

static int set_socket_blocking(SOCKET_TYPE sock, bool value)
{
#ifdef _WIN32
    u_long mode = !value;
    if (ioctlsocket(sock, FIONBIO, &mode) == SOCKET_ERROR)
        return -1;
#endif

#ifdef __linux__
    int flags = fcntl(listen_fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    if (fcntl(listen_fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return BAD_SOCKET;
#endif
    
    return 0;
}

SOCKET_TYPE listen_socket(HTTP_String addr, uint16_t port, bool reuse_addr, int backlog)
{
    SOCKET_TYPE listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd == BAD_SOCKET)
        return BAD_SOCKET;

    if (set_socket_blocking(listen_fd, false) < 0) {
        CLOSE_SOCKET(listen_fd);
        return BAD_SOCKET;
    }

    if (reuse_addr) {
        int one = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (void*) &one, sizeof(one));
    }

    struct in_addr addr_buf;
    if (addr.len == 0)
        addr_buf.s_addr = htonl(INADDR_ANY);
    else {

        _Static_assert(sizeof(struct in_addr) == sizeof(HTTP_IPv4));
        if (http_parse_ipv4(addr.ptr, addr.len, (HTTP_IPv4*) &addr_buf) < 0) {
            CLOSE_SOCKET(listen_fd);
            return BAD_SOCKET;
        }
    }

    struct sockaddr_in bind_buf;
    bind_buf.sin_family = AF_INET;
    bind_buf.sin_addr   = addr_buf;
    bind_buf.sin_port   = htons(port);
    if (bind(listen_fd, (struct sockaddr*) &bind_buf, sizeof(bind_buf)) < 0) { // TODO: how does bind fail on windows?
        CLOSE_SOCKET(listen_fd);
        return BAD_SOCKET;
    }

    if (listen(listen_fd, backlog) < 0) { // TODO: how does listen fail on windows?
        CLOSE_SOCKET(listen_fd);
        return BAD_SOCKET;
    }

    return listen_fd;
}


void socket_global_init(void)
{
#ifdef HTTPS_ENABLED
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#endif
}

void socket_global_free(void)
{
#ifdef HTTPS_ENABLED
    EVP_cleanup();
    ERR_free_strings();
#endif
}

int socket_group_init(SocketGroup *group)
{
#ifdef HTTPS_ENABLED
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
#else
    (void) group;
#endif
    return 0;
}

#ifdef HTTPS_ENABLED
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
#endif

int socket_group_init_server(SocketGroup *group, HTTP_String cert_file, HTTP_String key_file)
{
#ifdef HTTPS_ENABLED
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
#else
    (void) group;
    if (cert_file.len > 0 || key_file.len > 0)
        return -1;
#endif

    return 0;
}

void socket_group_free(SocketGroup *group)
{
#ifdef HTTPS_ENABLED
    SSL_CTX_free(group->ssl_ctx);
#else
    (void) group;
#endif
}

int socket_group_add_domain(SocketGroup *group, HTTP_String domain, HTTP_String cert_file, HTTP_String key_file)
{
#ifdef HTTPS_ENABLED
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
#else
    (void) group;
    (void) domain;
    (void) cert_file;
    (void) key_file;
    return -1;
#endif
}

SocketState socket_state(Socket *sock)
{
    return sock->state;
}

void socket_accept(Socket *sock, SocketGroup *group, SOCKET_TYPE fd)
{
#ifdef HTTPS_ENABLED
    sock->ssl = NULL;
    sock->ssl_ctx = group ? group->ssl_ctx : NULL;
#else
    if (group) {
        sock->state = SOCKET_STATE_DIED;
        return;
    }
#endif

    // Initialize socket for server-side TLS handshake
    sock->state = SOCKET_STATE_ACCEPTED;  // TCP connection already established
    sock->event = SOCKET_WANT_NONE;
    sock->fd = fd;
    sock->addr_list = NULL;
    sock->addr_count = 0;
    sock->addr_cursor = 0;
    sock->hostname = NULL;
    sock->port = 0;

    if (set_socket_blocking(fd, false) < 0) {
        sock->state = SOCKET_STATE_DIED;
        return;
    }

    // Start the TLS handshake process
    socket_update(sock);
}

void socket_connect(Socket *sock, SocketGroup *group, HTTP_String host, uint16_t port)
{
#ifdef HTTPS_ENABLED
    sock->ssl = NULL;
    sock->ssl_ctx = group ? group->ssl_ctx : NULL;
#else
    if (group) {
        sock->state = SOCKET_STATE_DIED;
        return;
    }
#endif
    sock->state = SOCKET_STATE_PENDING;
    sock->event = SOCKET_WANT_NONE;
    sock->fd = -1;
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

void socket_connect_ipv4(Socket *sock, SocketGroup *group, HTTP_IPv4 addr, uint16_t port)
{
#ifdef HTTPS_ENABLED
    sock->ssl = NULL;
    sock->ssl_ctx = group ? group->ssl_ctx : NULL;
#else
    if (group) {
        sock->state = SOCKET_STATE_DIED;
        return;
    }
#endif
    sock->state = SOCKET_STATE_PENDING;
    sock->event = SOCKET_WANT_NONE;
    sock->fd = -1;
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

void socket_connect_ipv6(Socket *sock, SocketGroup *group, HTTP_IPv6 addr, uint16_t port)
{
#ifdef HTTPS_ENABLED
    sock->ssl = NULL;
    sock->ssl_ctx = group ? group->ssl_ctx : NULL;
#else
    if (group) {
        sock->state = SOCKET_STATE_DIED;
        return;
    }
#endif
    sock->state = SOCKET_STATE_PENDING;
    sock->event = SOCKET_WANT_NONE;
    sock->fd = -1;
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

bool socket_secure(Socket *sock)
{
#ifdef HTTPS_ENABLED
    return sock->ssl_ctx != NULL;
#else
    (void) sock;
    return false;
#endif
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
#ifdef HTTPS_ENABLED
            if (sock->ssl) {
                SSL_free(sock->ssl);
                sock->ssl = NULL;
            }
#endif

            if (sock->fd != BAD_SOCKET)
                CLOSE_SOCKET(sock->fd);

            // If cursor reached the end, die
            if (sock->addr_cursor >= sock->addr_count) {
                sock->event = SOCKET_WANT_NONE;
                sock->state = SOCKET_STATE_DIED;
                break;
            }

            // Take current address
            AddrInfo *ai = &sock->addr_list[sock->addr_cursor];
            int family = ai->is_ipv6 ? AF_INET6 : AF_INET;
            SOCKET_TYPE fd = socket(family, SOCK_STREAM, 0);
            if (fd == BAD_SOCKET) {
                // Try next address
                sock->addr_cursor++;
                sock->event = SOCKET_WANT_NONE;
                sock->state = SOCKET_STATE_PENDING;
                again = true;
                break;
            }

            if (set_socket_blocking(fd, false) < 0) {
                CLOSE_SOCKET(fd);
                sock->event = SOCKET_WANT_NONE;
                sock->state = SOCKET_STATE_DIED;
                break;
            }

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
            
            if (ret < 0 && errno == EINPROGRESS) { // TODO: I'm pretty sure all the error numbers need to be changed for windows
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
            if (getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, (void*) &err, &len) < 0 || err != 0) {
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
            if (!socket_secure(sock)) {
                sock->event = SOCKET_WANT_NONE;
                sock->state = SOCKET_STATE_ESTABLISHED_READY;
            } else {
#ifdef HTTPS_ENABLED
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
#else
                HTTP_ASSERT(0);
#endif
            }
        }
        break;

        case SOCKET_STATE_ACCEPTED:
        {
            if (!socket_secure(sock)) {
                sock->event = SOCKET_WANT_NONE;
                sock->state = SOCKET_STATE_ESTABLISHED_READY;
            } else {
#ifdef HTTPS_ENABLED
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
#else
               HTTP_ASSERT(0);
#endif
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
            if (!socket_secure(sock)) {
                sock->event = SOCKET_WANT_NONE;
                sock->state = SOCKET_STATE_DIED;
            } else {
#ifdef HTTPS_ENABLED
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
#else
                HTTP_ASSERT(0);
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

int socket_read(Socket *sock, char *dst, int max) {
    // If not ESTABLISHED, set state to DIED and return
    if (sock->state != SOCKET_STATE_ESTABLISHED_READY) {
        sock->event = SOCKET_WANT_NONE;
        sock->state = SOCKET_STATE_DIED;
        return -1;
    }

    if (!socket_secure(sock)) {
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
#ifdef HTTPS_ENABLED
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
#else
        HTTP_ASSERT(0);
        return -1;
#endif
    }
}

int socket_write(Socket *sock, char *src, int len) {
    // If not ESTABLISHED, set state to DIED and return
    if (sock->state != SOCKET_STATE_ESTABLISHED_READY) {
        sock->event = SOCKET_WANT_NONE;
        sock->state = SOCKET_STATE_DIED;
        return 0;
    }

    if (!socket_secure(sock)) {
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
#ifdef HTTPS_ENABLED
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
#else
        HTTP_ASSERT(0);
#endif
    }
}

void socket_close(Socket *sock) {
    // Set state to SHUTDOWN and call update
    sock->event = SOCKET_WANT_NONE;
    sock->state = SOCKET_STATE_SHUTDOWN;
    socket_update(sock);
}

void socket_free(Socket *sock)
{
#ifdef HTTPS_ENABLED
    if (sock->ssl)
        SSL_free(sock->ssl);
#endif

    if (sock->fd != BAD_SOCKET) {
        CLOSE_SOCKET(sock->fd);
        sock->fd = BAD_SOCKET;
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

int socket_wait(Socket **socks, int num_socks) // TODO: is this used?
{
    if (num_socks <= 0)
        return -1;

    struct pollfd polled[100]; // TODO: make this value configurable
    if (num_socks > (int) HTTP_COUNT(polled))
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

        int ret = POLL(polled, num_socks, -1);
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
}