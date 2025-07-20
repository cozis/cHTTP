#ifndef CERT_INCLUDED
#define CERT_INCLUDED

#include "basic.h"

int http_create_test_certificate(HTTP_String C, HTTP_String O, HTTP_String CN,
    HTTP_String cert_file, HTTP_String key_file);

#endif // CERT_INCLUDED