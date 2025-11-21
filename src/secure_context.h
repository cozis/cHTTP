
int global_secure_context_init(void);
int global_secure_context_free(void);

typedef struct {
#ifdef HTTPS_ENABLED
    // TODO
    SSL_CTX *p;
#endif
} ClientSecureContext;

int client_secure_context_init(ClientSecureContext *ctx);
int client_secure_context_free(ClientSecureContext *ctx);

typedef struct {

} SecureDomain;

typedef struct {
#ifdef HTTPS_ENABLED
    // TODO
    SSL_CTX *p;
#endif
} ServerSecureContext;

int server_secure_context_init(ServerSecureContext *ctx);
int server_secure_context_free(ServerSecureContext *ctx);
int server_secure_context_add_certificate(ServerSecureContext *ctx,
    HTTP_String domain, HTTP_String cert_file, HTTP_String key_file);
