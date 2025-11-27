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

    HTTP_Server server;
    ret = http_server_init(&server);
    if (ret < 0) {
        fprintf(stderr, "Couldn't initialize server (%s)\n", http_strerror(ret));
        return -1;
    }

    http_server_set_reuse_addr(&server, true);
    http_server_set_trace_bytes(&server, true);


    // First, set up an HTTPS server instance with one
    // of the certificate. This will act as default certificate
    // when ecrypted connections don't target a specific domain.

    HTTP_String local_addr = HTTP_STR("127.0.0.1");
    uint16_t    local_port = 8443;

    HTTP_String cert_file  = HTTP_STR("websiteA_cert.pem");
    HTTP_String key_file   = HTTP_STR("websiteA_key.pem");

    ret = http_server_listen_tls(&server, local_addr, local_port, cert_file, key_file);
    if (ret < 0) {
        fprintf(stderr, "Couldn't start listening (%s)\n", http_strerror(ret));
        return -1;
    }

    // Then we can add an arbitrary number of additional
    // certificates using the add_website function

    ret = http_server_add_certificate(&server,
        HTTP_STR("websiteB.com"),
        HTTP_STR("websiteB_cert.pem"),
        HTTP_STR("websiteB_key.pem"));
    if (ret < 0)
        return -1;

    ret = http_server_add_certificate(&server,
        HTTP_STR("websiteC.com"),
        HTTP_STR("websiteC_cert.pem"),
        HTTP_STR("websiteC_key.pem"));
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

        HTTP_Request *req;
        HTTP_ResponseBuilder builder;
        http_server_wait_request(&server, &req, &builder);

        if (http_match_host(req, HTTP_STR("websiteB.com"), 8080) ||
            http_match_host(req, HTTP_STR("websiteB.com"), 8443)) {

            http_response_builder_status(builder, 200);
            http_response_builder_body(builder, HTTP_STR("Hello from websiteB.com!"));
            http_response_builder_send(builder);

        } else if (http_match_host(req, HTTP_STR("websiteC.com"), 8080) ||
                   http_match_host(req, HTTP_STR("websiteC.com"), 8443)) {

            http_response_builder_status(builder, 200);
            http_response_builder_body(builder, HTTP_STR("Hello from websiteC.com!"));
            http_response_builder_send(builder);

        } else {

            // Serve websiteA.com by default to be consistent
            // with the certificate setup

            http_response_builder_status(builder, 200);
            http_response_builder_body(builder, HTTP_STR("Hello from websiteA.com!"));
            http_response_builder_send(builder);
        }
    }

    http_server_free(&server);
    return 0;
}

int setup_test_certificates(void)
{
    int ret = http_create_test_certificate(
        HTTP_STR("IT"),
        HTTP_STR("Organization A"),
        HTTP_STR("websiteA.com"),
        HTTP_STR("websiteA_cert.pem"),
        HTTP_STR("websiteA_key.pem")
    );
    if (ret < 0)
        return -1;

    ret = http_create_test_certificate(
        HTTP_STR("IT"),
        HTTP_STR("Organization B"),
        HTTP_STR("websiteB.com"),
        HTTP_STR("websiteB_cert.pem"),
        HTTP_STR("websiteB_key.pem")
    );
    if (ret < 0)
        return -1;

    ret = http_create_test_certificate(
        HTTP_STR("IT"),
        HTTP_STR("Organization C"),
        HTTP_STR("websiteC.com"),
        HTTP_STR("websiteC_cert.pem"),
        HTTP_STR("websiteC_key.pem")
    );
    if (ret < 0)
        return -1;

    return 0;
}
