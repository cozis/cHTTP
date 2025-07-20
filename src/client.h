#ifndef CLIENT_INCLUDED
#define CLIENT_INCLUDED

#include <stdbool.h>
#include "parse.h"

// Initialize the global state of cHTTP.
//
// cHTTP tries to avoid global state. What this function
// does is call the global initialization functions of
// its dependencies (OpenSSL and Winsock)
void http_global_init(void);

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
} HTTP_RequestHandle;

// Initialize a client object. If something goes wrong,
// NULL is returned.
HTTP_Client *http_client_init(void);

// Deinitialize a client object
void http_client_free(HTTP_Client *client);

// Create a request object associated to the given client.
// On success, 0 is returned and the handle is initialized.
// On error, -1 is returned.
int http_client_request(HTTP_Client *client, HTTP_RequestHandle *handle);

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
int http_client_wait(HTTP_Client *client, HTTP_RequestHandle *handle);

// Enable/disable I/O tracing for the specified request.
// This must be done when the request is in the initialization
// phase.
void http_request_trace(HTTP_RequestHandle handle, bool trace);

// Set the method and URL of the specified request object.
// This must be the first thing you do after http_client_request
// is called (you may http_request_trace before, but nothing
// else!)
void http_request_line(HTTP_RequestHandle handle, HTTP_Method method, HTTP_String url);

// Append a header to the specified request. You must call
// this after http_request_line and may do so multiple times.
//
// TODO: use HTTP_String instead of char*+int
void http_request_header(HTTP_RequestHandle handle, char *header, int len);

// Append some data to the request's body. You must call
// this after either http_request_line or http_request_header.
//
// TODO: use HTTP_String instead of char*+int
void http_request_body(HTTP_RequestHandle handle, char *body, int len);

// Mark the initialization of the request as completed and
// perform the request.
void http_request_submit(HTTP_RequestHandle handle);

// Retrieve the response to the specified request. If the
// request hasn't completed or it couldn't be performed
// due to an error, NULL is returned. If the request completed,
// the parsed response object is returned.
//
// Note that responses 4xx and 5xx code responses are still
// considered as successes from cHTTP's perspective.
HTTP_Response *http_request_result(HTTP_RequestHandle handle);

// Free resources associated to a request. This must be called
// after the request has completed.
//
// TODO: allow aborting pending requests
void http_request_free(HTTP_RequestHandle handle);

#endif // CLIENT_INCLUDED