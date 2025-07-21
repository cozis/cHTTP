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
    char *cert_file, int cert_file_len,
    char *key_file, int key_file_len)
{
    (void) sec;
    (void) cert_file;
    (void) cert_file_len;
    (void) key_file;
    (void) key_file_len;
    return 0;
}

int secure_context_add_cert(SecureContext *sec,
    char *domain, int domain_len, char *cert_file,
    int cert_file_len, char *key_file, int key_file_len)
{
    (void) sec;
    (void) domain;
    (void) domain_len;
    (void) cert_file;
    (void) cert_file_len;
    (void) key_file;
    (void) key_file_len;
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
    ERR_free_strings();
}

int secure_context_init_as_client(SecureContext *sec)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        return -1;

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    
    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        SSL_CTX_free(ctx);
        return -1;

    sec->is_server = false;
    sec->ctx = ctx;
    sec->num_certs = 0;
    return 0;
}

static int servername_callback(SSL *ssl, int *ad, void *arg)
{
    SecureContext *sec = arg;

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
    char *cert_file, int cert_file_len,
    char *key_file, int key_file_len)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
        return -1;

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    static char cert_buffer[1024];
    if (cert_file_len >= (int) sizeof(cert_buffer)) {
        SSL_CTX_free(ctx);
        return -1;
    }
    memcpy(cert_buffer, cert_file, cert_file_len);
    cert_buffer[cert_file_len] = '\0';
    
    // Copy private key file path to static buffer
    static char key_buffer[1024];
    if (key_file_len >= (int) sizeof(key_buffer)) {
        SSL_CTX_free(ctx);
        return -1;
    }
    memcpy(key_buffer, key_file, key_file_len);
    key_buffer[key_file_len] = '\0';
    
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
    char *domain, int domain_len, char *cert_file,
    int cert_file_len, char *key_file, int key_file_len)
{
    if (!sec->is_server)
        return -1;

    if (sec->num_certs == MAX_CERTS)
        return -1;

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
        return -1;

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    static char cert_buffer[1024];
    if (cert_file_len >= (int) sizeof(cert_buffer)) {
        SSL_CTX_free(ctx);
        return -1;
    }
    memcpy(cert_buffer, cert_file, cert_file_len);
    cert_buffer[cert_file_len] = '\0';
    
    static char key_buffer[1024];
    if (key_file_len >= (int) sizeof(key_buffer)) {
        SSL_CTX_free(ctx);
        return -1;
    }
    memcpy(key_buffer, key_file, key_file_len);
    key_buffer[key_file_len] = '\0';
    
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
    if (domain_len >= (int) sizeof(cert->domain)) {
        SSL_CTX_free(ctx);
        return -1;
    }
    memcpy(cert->domain, domain, domain_len);
    cert->domain[domain_len] = '\0';
    cert->ctx = ctx;
    sec->num_certs++;
    return 0;
}

#endif