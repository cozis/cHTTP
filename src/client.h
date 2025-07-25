#ifndef CLIENT_INCLUDED
#define CLIENT_INCLUDED

#include <stdbool.h>

#ifndef HTTP_AMALGAMATION
#include "parse.h"
#endif

// Initialize the global state of cHTTP.
//
// cHTTP tries to avoid global state. What this function
// does is call the global initialization functions of
// its dependencies (OpenSSL and Winsock)
int http_global_init(void);

// Free the global state of cHTTP.
void http_global_free(void);

// Opaque type describing an "HTTP client". Any request
// that is started must always be associated to an HTTP
// client object.
typedef struct HTTP_Client HTTP_Client;

// Handle for a pending request. This should be considered
// opaque. Don't read or modify its fields!
typedef struct {
    void *data0;
    int   data1;
    int   data2;
} HTTP_RequestBuilder;

// Initialize a client object. If something goes wrong,
// NULL is returned.
HTTP_Client *http_client_init(void);

// Deinitialize a client object
void http_client_free(HTTP_Client *client);

// Create a request object associated to the given client.
// On success, 0 is returned and the handle is initialized.
// On error, -1 is returned.
int http_client_get_builder(HTTP_Client *client, HTTP_RequestBuilder *builder);

void http_request_builder_user_data(HTTP_RequestBuilder builder, void *user_data);

// Enable/disable I/O tracing for the specified request.
// This must be done when the request is in the initialization
// phase.
void http_request_builder_trace(HTTP_RequestBuilder builder, bool trace);

// Set the method and URL of the specified request object.
// This must be the first thing you do after http_client_request
// is called (you may http_request_trace before, but nothing
// else!)
void http_request_builder_line(HTTP_RequestBuilder builder, HTTP_Method method, HTTP_String url);

// Append a header to the specified request. You must call
// this after http_request_line and may do so multiple times.
void http_request_builder_header(HTTP_RequestBuilder builder, HTTP_String str);

// Append some data to the request's body. You must call
// this after either http_request_line or http_request_header.
void http_request_builder_body(HTTP_RequestBuilder builder, HTTP_String str);

// Mark the initialization of the request as completed and
// perform the request.
void http_request_builder_submit(HTTP_RequestBuilder builder);

// Free resources associated to a request. This must be called
// after the request has completed.
//
// TODO: allow aborting pending requests
void http_response_free(HTTP_Response *res);

// Wait for the completion of one request associated to
// the client. The handle of the resolved request is returned
// through the handle output parameter. If you're not
// interested in which request completed (like when you
// have only one pending request), you can pass NULL.
//
// On error -1 is retutned, else 0 is returned and the
// handle is initialized.
//
// Note that calling this function when no requests are
// pending is considered an error. 
int http_client_wait(HTTP_Client *client, HTTP_Response **res, void **user_data);

// TODO: comment
HTTP_Response *http_get(HTTP_String url,
    HTTP_String *headers, int num_headers);

// TODO: comment
HTTP_Response *http_post(HTTP_String url,
    HTTP_String *headers, int num_headers,
    HTTP_String body);

#endif // CLIENT_INCLUDED