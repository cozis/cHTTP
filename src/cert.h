// This is an utility to create self-signed certificates
// useful when testing HTTPS servers locally. This is only
// meant to be used by people starting out with a library
// and simplifying the zero to one phase.
//
// The C, O, and CN are respectively country name, organization name,
// and common name of the certificate. For instance:
//
//   C="IT"
//   O="My Organization"
//   CN="my_website.com"
//
// The output is a certificate file in PEM format and a private
// key file with the key used to sign the certificate.
int chttp_create_test_certificate(CHTTP_String C, CHTTP_String O, CHTTP_String CN,
    CHTTP_String cert_file, CHTTP_String key_file);
