#ifndef SEC_INCLUDED
#define SEC_INCLUDED

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

int secure_context_init_as_client(SecureContext *sec);

int secure_context_init_as_server(SecureContext *sec,
    char *cert_file, int cert_file_len,
    char *key_file, int key_file_len);

int secure_context_add_cert(SecureContext *sec,
    char *domain, int domain_len, char *cert_file,
    int cert_file_len, char *key_file, int key_file_len);

void secure_context_free(SecureContext *sec);

#endif // SEC_INCLUDED