
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
