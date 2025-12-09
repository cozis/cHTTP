#include <stddef.h>

#include "../chttp.h"

// This is an example of how to serve different websites
// over a single HTTPS server instance.

int setup_test_certificates(void);

int main(void)
{
    // To test this program you need to add the following
    // lines to your hosts file:
    //
    //   127.0.0.1    websiteA.com
    //   127.0.0.1    websiteB.com
    //   127.0.0.1    websiteC.com
    //
    // That you can find at /etc/hosts on Linux and
    // C:\Windows\System32\drivers\etc\hosts on Windows

    // First, create three certificates for the domains:
    //
    //   websiteA.com
    //   websiteB.com
    //   websiteC.com
    //
    // This will create a number of certificate files
    // and private key files
    //
    //   websiteA_cert.pem   websiteA_key.pem
    //   websiteB_cert.pem   websiteB_key.pem
    //   websiteC_cert.pem   websiteC_key.pem
    //
    // Of course this is just for testing. It is expected
    // you have your own.
    int ret = setup_test_certificates();
    if (ret < 0)
        return -1;

    CHTTP_Server server;
    ret = chttp_server_init(&server);
    if (ret < 0) {
        fprintf(stderr, "Couldn't initialize server (%s)\n", chttp_strerror(ret));
        return -1;
    }

    chttp_server_set_reuse_addr(&server, true);
    chttp_server_set_trace_bytes(&server, true);


    // First, set up an HTTPS server instance with one
    // of the certificate. This will act as default certificate
    // when ecrypted connections don't target a specific domain.

    CHTTP_String local_addr = CHTTP_STR("127.0.0.1");
    uint16_t    local_port = 8443;

    CHTTP_String cert_file  = CHTTP_STR("websiteA_cert.pem");
    CHTTP_String key_file   = CHTTP_STR("websiteA_key.pem");

    ret = chttp_server_listen_tls(&server, local_addr, local_port, cert_file, key_file);
    if (ret < 0) {
        fprintf(stderr, "Couldn't start listening (%s)\n", chttp_strerror(ret));
        return -1;
    }

    // Then we can add an arbitrary number of additional
    // certificates using the add_website function

    ret = chttp_server_add_certificate(&server,
        CHTTP_STR("websiteB.com"),
        CHTTP_STR("websiteB_cert.pem"),
        CHTTP_STR("websiteB_key.pem"));
    if (ret < 0)
        return -1;

    ret = chttp_server_add_certificate(&server,
        CHTTP_STR("websiteC.com"),
        CHTTP_STR("websiteC_cert.pem"),
        CHTTP_STR("websiteC_key.pem"));
    if (ret < 0)
        return -1;

    // Now the server is ready to accept incoming HTTP
    // or HTTPS connections.
    //
    // Note that the add_website function is only used
    // to serve the correct certificate to the client.
    // The HTTP request itself may very well hold a
    // different domain name in the host header:
    //
    // [client]                           [server]
    //    |                                  |
    //    |   TLS hanshake to domain1.com    |
    //    | -------------------------------> |
    //    |                                  |
    //    |       cert for domain1.com       |
    //    | <------------------------------- |
    //    |                                  |
    //    |    HTTP request to domain2.com   |
    //    |   over the encrypted connection  |
    //    |   established with domain1.com   |
    //    | -------------------------------> |
    //    |                                  |
    //    |      response as domain2.com     |
    //    | <------------------------------- |
    //    |                                  |

    for (;;) {

        CHTTP_Request *req;
        CHTTP_ResponseBuilder builder;
        chttp_server_wait_request(&server, &req, &builder);

        if (chttp_match_host(req, CHTTP_STR("websiteB.com"), 8080) ||
            chttp_match_host(req, CHTTP_STR("websiteB.com"), 8443)) {

            chttp_response_builder_status(builder, 200);
            chttp_response_builder_body(builder, CHTTP_STR("Hello from websiteB.com!"));
            chttp_response_builder_send(builder);

        } else if (chttp_match_host(req, CHTTP_STR("websiteC.com"), 8080) ||
                   chttp_match_host(req, CHTTP_STR("websiteC.com"), 8443)) {

            chttp_response_builder_status(builder, 200);
            chttp_response_builder_body(builder, CHTTP_STR("Hello from websiteC.com!"));
            chttp_response_builder_send(builder);

        } else {

            // Serve websiteA.com by default to be consistent
            // with the certificate setup

            chttp_response_builder_status(builder, 200);
            chttp_response_builder_body(builder, CHTTP_STR("Hello from websiteA.com!"));
            chttp_response_builder_send(builder);
        }
    }

    chttp_server_free(&server);
    return 0;
}

int setup_test_certificates(void)
{
    int ret = chttp_create_test_certificate(
        CHTTP_STR("IT"),
        CHTTP_STR("Organization A"),
        CHTTP_STR("websiteA.com"),
        CHTTP_STR("websiteA_cert.pem"),
        CHTTP_STR("websiteA_key.pem")
    );
    if (ret < 0)
        return -1;

    ret = chttp_create_test_certificate(
        CHTTP_STR("IT"),
        CHTTP_STR("Organization B"),
        CHTTP_STR("websiteB.com"),
        CHTTP_STR("websiteB_cert.pem"),
        CHTTP_STR("websiteB_key.pem")
    );
    if (ret < 0)
        return -1;

    ret = chttp_create_test_certificate(
        CHTTP_STR("IT"),
        CHTTP_STR("Organization C"),
        CHTTP_STR("websiteC.com"),
        CHTTP_STR("websiteC_cert.pem"),
        CHTTP_STR("websiteC_key.pem")
    );
    if (ret < 0)
        return -1;

    return 0;
}
