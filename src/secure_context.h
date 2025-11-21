
#ifndef SERVER_CERTIFICATE_LIMIT
// Maximum number of certificates that can be
// associated to a TLS server. This doesn't include
// the default certificate.
#define SERVER_CERTIFICATE_LIMIT 8
#endif

int global_secure_context_init(void);
int global_secure_context_free(void);

typedef struct {
#ifdef HTTPS_ENABLED
    SSL_CTX *p;
#endif
} ClientSecureContext;

int  client_secure_context_init(ClientSecureContext *ctx);
void client_secure_context_free(ClientSecureContext *ctx);

typedef struct {
#ifdef HTTPS_ENABLED
    char domain[128];
    SSL_CTX *ctx;
#endif
} ServerCertificate;

typedef struct {
#ifdef HTTPS_ENABLED
    SSL_CTX *p;
    int num_certs;
    ServerCertificate certs[SERVER_CERTIFICATE_LIMIT];
#endif
} ServerSecureContext;

int server_secure_context_init(ServerSecureContext *ctx,
    HTTP_String cert_file, HTTP_String key_file);
void server_secure_context_free(ServerSecureContext *ctx);
int  server_secure_context_add_certificate(ServerSecureContext *ctx,
    HTTP_String domain, HTTP_String cert_file, HTTP_String key_file);
