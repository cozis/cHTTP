#include <http.h>

// This is an example of how to serve different websites
// over a single HTTPS server instance.

int setup_test_certificates(void);

int main(void)
{
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

    // First, set up an HTTPS server instance with one
    // of the certificate. This will act as default certificate
    // when ecrypted connections don't target a specific domain.
    HTTP_Server *server = http_server_init(
        HTTP_STR("127.0.0.1"), 8080, 8443,
        HTTP_STR("websiteA_cert.pem"),
        HTTP_STR("websiteA_key.pem")
    );
    if (server == NULL)
        return -1;

    // Then we can add an arbitrary number of additional
    // certificates using the add_website function

    ret = http_server_add_website(server,
        HTTP_STR("websiteB_cert.pem"),
        HTTP_STR("websiteB_key.pem")
    );
    if (ret < 0)
        return -1;

    ret = http_server_add_website(server,
        HTTP_STR("websiteC_cert.pem"),
        HTTP_STR("websiteC_key.pem")
    );
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
        HTTP_ResponseHandle res;
        ret = http_server_wait(server, &req, &res);
        if (ret < 0)
            break;

        int idx = http_find_header(req->headers, req->num_headers, HTTP_STR("Host"));
        HTTP_ASSERT(idx != -1); // Requests without the host header are always rejected
        HTTP_String host = req->headers[idx].value;

        if (http_streq(host, HTTP_STR("websiteB.com"))) {

            http_response_status(res, 200);
            http_response_body(res, "Hello from websiteB.com!");
            http_response_done(res);

        } else if (http_streq(host, HTTP_STR("websiteC.com"))) {

            http_response_status(res, 200);
            http_response_body(res, "Hello from websiteC.com!");
            http_response_done(res);

        } else {

            // Serve websiteA.com by default to be consistent
            // with the certificate setup

            http_response_status(res, 200);
            http_response_body(res, "Hello from websiteA.com!");
            http_response_done(res);
        }
    }

    http_server_free(server);
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
