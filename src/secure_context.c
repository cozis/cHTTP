
int global_secure_context_init(void)
{
#ifdef HTTPS_ENABLED
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#endif
    return 0;
}

int global_secure_context_free(void)
{
#ifdef HTTPS_ENABLED
    EVP_cleanup();
#endif
    return 0;
}

int client_secure_context_init(ClientSecureContext *ctx)
{
#ifdef HTTPS_ENABLED
    SSL_CTX *p = SSL_CTX_new(TLS_client_method());
    if (!p)
        return -1;

    SSL_CTX_set_min_proto_version(p, TLS1_2_VERSION);

    SSL_CTX_set_verify(p, SSL_VERIFY_PEER, NULL);

    if (SSL_CTX_set_default_verify_paths(p) != 1) {
        SSL_CTX_free(p);
        return -1;
    }

    ctx->p = p;
    return 0;
#else
    (void) ctx;
    return -1;
#endif
}

void client_secure_context_free(ClientSecureContext *ctx)
{
#ifdef HTTPS_ENABLED
    SSL_CTX_free(ctx->p);
#else
    (void) ctx;
#endif
}

#ifdef HTTPS_ENABLED
static int servername_callback(SSL *ssl, int *ad, void *arg)
{
    ServerSecureContext *ctx = arg;

    // The 'ad' parameter is used to set the alert description when returning
    // SSL_TLSEXT_ERR_ALERT_FATAL. Since we only return OK or NOACK, it's unused.
    (void) ad;

    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (servername == NULL)
        return SSL_TLSEXT_ERR_NOACK;

    for (int i = 0; i < ctx->num_certs; i++) {
        ServerCertificate *cert = &ctx->certs[i];
        if (!strcmp(cert->domain, servername)) {
            SSL_set_SSL_CTX(ssl, cert->ctx);
            return SSL_TLSEXT_ERR_OK;
        }
    }

    return SSL_TLSEXT_ERR_NOACK;
}
#endif

int server_secure_context_init(ServerSecureContext *ctx,
    CHTTP_String cert_file, CHTTP_String key_file)
{
#ifdef HTTPS_ENABLED
    SSL_CTX *p = SSL_CTX_new(TLS_server_method());
    if (!p)
        return -1;

    SSL_CTX_set_min_proto_version(p, TLS1_2_VERSION);

    char cert_buffer[1024];
    if (cert_file.len >= (int) sizeof(cert_buffer)) {
        SSL_CTX_free(p);
        return -1;
    }
    memcpy(cert_buffer, cert_file.ptr, cert_file.len);
    cert_buffer[cert_file.len] = '\0';

    // Copy private key file path to static buffer
    char key_buffer[1024];
    if (key_file.len >= (int) sizeof(key_buffer)) {
        SSL_CTX_free(p);
        return -1;
    }
    memcpy(key_buffer, key_file.ptr, key_file.len);
    key_buffer[key_file.len] = '\0';

    // Load certificate and private key
    if (SSL_CTX_use_certificate_chain_file(p, cert_buffer) != 1) {
        SSL_CTX_free(p);
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(p, key_buffer, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(p);
        return -1;
    }

    // Verify that the private key matches the certificate
    if (SSL_CTX_check_private_key(p) != 1) {
        SSL_CTX_free(p);
        return -1;
    }

    SSL_CTX_set_tlsext_servername_callback(p, servername_callback);
    SSL_CTX_set_tlsext_servername_arg(p, ctx);

    ctx->p = p;
    ctx->num_certs = 0;
    return 0;
#else
    (void) ctx;
    (void) cert_file;
    (void) key_file;
    return -1;
#endif
}

void server_secure_context_free(ServerSecureContext *ctx)
{
#ifdef HTTPS_ENABLED
    SSL_CTX_free(ctx->p);
    for (int i = 0; i < ctx->num_certs; i++)
        SSL_CTX_free(ctx->certs[i].ctx);
#else
    (void) ctx;
#endif
}

int server_secure_context_add_certificate(ServerSecureContext *ctx,
    CHTTP_String domain, CHTTP_String cert_file, CHTTP_String key_file)
{
#ifdef HTTPS_ENABLED
    if (ctx->num_certs == SERVER_CERTIFICATE_LIMIT)
        return -1;

    SSL_CTX *p = SSL_CTX_new(TLS_server_method());
    if (!p)
        return -1;

    SSL_CTX_set_min_proto_version(p, TLS1_2_VERSION);

    char cert_buffer[1024];
    if (cert_file.len >= (int) sizeof(cert_buffer)) {
        SSL_CTX_free(p);
        return -1;
    }
    memcpy(cert_buffer, cert_file.ptr, cert_file.len);
    cert_buffer[cert_file.len] = '\0';

    char key_buffer[1024];
    if (key_file.len >= (int) sizeof(key_buffer)) {
        SSL_CTX_free(p);
        return -1;
    }
    memcpy(key_buffer, key_file.ptr, key_file.len);
    key_buffer[key_file.len] = '\0';

    if (SSL_CTX_use_certificate_chain_file(p, cert_buffer) != 1) {
        SSL_CTX_free(p);
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(p, key_buffer, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(p);
        return -1;
    }

    if (SSL_CTX_check_private_key(p) != 1) {
        SSL_CTX_free(p);
        return -1;
    }

    ServerCertificate *cert = &ctx->certs[ctx->num_certs];
    if (domain.len >= (int) sizeof(cert->domain)) {
        SSL_CTX_free(p);
        return -1;
    }
    memcpy(cert->domain, domain.ptr, domain.len);
    cert->domain[domain.len] = '\0';
    cert->ctx = p;
    ctx->num_certs++;
    return 0;
#else
    (void) ctx;
    (void) domain;
    (void) cert_file;
    (void) key_file;
    return -1;
#endif
}
