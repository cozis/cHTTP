#include <string.h>
#include <chttp.h>

// This example shows how to generate response bodies
// using the zero-copy API.

int main(void)
{
    // All the setup is identical to the previous example.
    // The only thing that changes where "http_response_body"
    // is called.

    HTTP_Server *server = http_server_init(HTTP_STR("127.0.0.1"), 8080);
    if (server == NULL)
        return -1;

    for (;;) {

        HTTP_Request *req;
        HTTP_ResponseHandle res;

        int ret = http_server_wait(server, &req, &res);
        if (ret < 0) return -1;

        http_response_status(res, 200);
        http_response_header(res, "Content-Type: text/plain");

        // The previous example used the *_body function to
        // write the response body in chunks:
        //
        //   http_response_body(res, HTTP_STR("Hello"));
        //   http_response_body(res, HTTP_STR(", world!"));
        //
        // This function reads from an user buffer and copies
        // the data in the connection's output buffer. If the
        // data is not in a contiguous region that's fine as
        // the function can be called repeatedly on separate
        // chunks.
        //
        // This function assumes the user is holding in memory
        // the data to be sent beforehand, but this may not
        // be true. If for instance the data comes from a file,
        // the user will need to read from the file, copy in
        // memory and then write to the response body.
        //
        // The zero-copy API allows copying directly from the
        // source of the data (such as the read() system call
        // on a file descriptor) to the server's output buffer

        char example_data[] = "I'm some example data!";
        int  example_data_len = sizeof(example_data)-1;

        // Tell the server how much data we are going to write
        http_response_bodycap(res, example_data_len);

        int cap;
        char *dst;
        
        // Get a pointer to the server's output buffer. The
        // output parameter [cap] is the capacity of the region
        // and is equal or larger than the data we requested
        // with *_bodycap
        dst = http_response_bodybuf(res, &cap);

        // Write the data directly into the output buffer. In
        // this example we are copying from memory, but you could
        // read from a file or a socket
        if (dst) {
            memcpy(dst, example_data, example_data_len);
        }

        // Tell the server how much bytes we have written to
        // the provided region.
        http_response_bodyack(res, example_data_len);

        // The reason we had to guard the [memcpy] by checking the
        // [dst] pointer is that if an error occurred internally
        // then *_bodybuf will return NULL. This will cause the
        // server to either return an internally generated error
        // response or drop the connection. The correct thing to
        // do in that situation is not access the pointer and do
        // as nothing bad happened.

        // As usual, mark the response as complete
        http_response_done(res);

        // If we're being being honest, this is not a zero-copy
        // interface. It's more like an N-1 copy interface as in
        // it just avoids one copy from userspace to userspace!
    }

    http_server_free(server);
    return 0;
}
