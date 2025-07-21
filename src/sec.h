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