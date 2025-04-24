# TinyHTTP

TinyHTTP is a C library for implementing web servers. It offers two interfaces:
1. stream interface
1. server interface

The stream interface is a lower level interface to TinyHTTP's HTTP state machine. It's completely stand-alone and performs no internal I/O, making it ideal for embedding in applications with custom constraints. The only dependency are freestanding libc headers.

The server interface is based on the stream interface and adds to it a platform-dependant I/O system. It uses the most performant I/O model available on the platform it's compiled for, but is single-threaded. The design goal of the server interface is ease of use and reasonable performance. It does also depend on libc.

## Table of Contents

1. Stream Interface
	1. Initialize a Stream
	1. Stream I/O
	1. Response Builer API
		1. Basic Usage
		1. Special Headers
		1. Zero-Copy Response Building
		1. Error Management
	1. The State Bitset
	1. Embedding in Custom Event Loops
		1. Ready-based Event Loops
		1. Completion-based Event Loops

## Stream Interface

The stream interface is based on the `TinyHTTPStream` object, which abstracts the communication between the server and one client. Generally, a non-blocking web server will hold an array of stream objects.

Applications must feed input bytes from the network into the stream and flush any bytes from the stream to the network. When the stream becomes "ready", the application creates a response using the response builder interface and submits it to the stream. If at any point something goes wrong, the stream is marked as DIED.

Since the stream object doesn't perform read/write operations on the socket directly but waits for the application to provide I/O bytes, it is trivial to add HTTPS support. Before bytes are read/written into the stream, applications can perform a TLS encryption/decryption step.

### Initialize a Stream

The only resources held by the stream object are the input and output buffers, which are contiguous buffers resized as needed. Therefore the only thing the stream depends on is a general purpose allocator. To keep the core of TinyHTTP dependency-free, allocation is done through a callback:

```c
static void *memfunc(TinyHTTPMemoryFuncTag tag,
	void *ptr, int len, void *data)
{
	(void) data;
	switch (tag) {

	case TINYHTTP_MEM_MALLOC:
		// ptr is null
		// len contains the allocation size
		return malloc(len);

		case TINYHTTP_MEM_FREE:
		// ptr is the previous allocation
		// len contains the size of the allocation (as requested during malloc)
		free(ptr);
		return NULL;
	}
	return NULL;
}

int main(void)
{
	TinyHTTPStream stream;
	tinyhttp_stream_init(&stream, memfunc, NULL);

	// ...
}
```

in most cases this will be a wrapper of malloc/free.

### Stream I/O

When the stream is ready to receive bytes, applications can use the `tinyhttp_stream_recv_buf` to start a receive operation. This function will return a pointer into the stream's input buffer where data can be written from the network. The function returns from an output argument the capacity of the returned region. No more bytes than the capacity must be written.

When the write input the input buffer is complete, applications must call the `tinyhttp_stream_recv_ack` to complete the operation and let the stream object know how many bytes were written into the buffer.

It's not possible to start multiple recv operations at once. In other words, once you call `tinyhttp_stream_recv_buf`, you can't call it again until `tinyhttp_stream_recv_ack` is called.

Here's an example:

```c
ptrdiff_t cap;
char *dst;

// Get the input buffer's pointer
dst = tinyhttp_stream_recv_buf(stream, &cap);

// Write to the buffer
int num = recv(socket_fd, dst, cap, 0);
if (num < 0) {
	// ... error ...
}
if (num == 0) {
	// ... peer disconnected ...
}

// Tell the stream there are new bytes available
tinyhttp_stream_recv_ack(stream, num);
```

Flushing data from the stream works the same exact way, except you copy data out of the returned pointer instead of writing to it:

```c
ptrdiff_t len;
char *src;

// Get the output buffer's pointer
src = tinyhttp_stream_send_buf(stream, &len);

// Write to the buffer
int num = send(socket_fd, src, len, 0);
if (num < 0) {
	// ... error ...
}

// Tell the stream how many bytes were flushed
tinyhttp_stream_send_ack(stream, num);
```

Note that if an error occurred and the stream is in the DIED state (more on that later), the `tinyhttp_stream_recv_buf` and `tinyhttp_stream_send_buf` will return a null pointer and a zero length/capacity. In this scenario, it doesn't matter what you do since an unrecoverable error occurred in the stream which will be shortly freed.

### Response Builder API

#### Basic Usage

When the stream reaches the "ready" state, applications can use the response builder interface to generate a response:

```c
TinyHTTPRequest *req = tinyhttp_stream_request(stream);
if (req == NULL) {
	// Not ready yet
} else {
	// Ready!

	// Get the parsed request
	TinyHTTPRequest *request = tinyhttp_stream_request(stream);

	// .. read the request ..

	tinyhttp_stream_response_status(stream, 200);
	tinyhttp_stream_response_header(stream, "Some-header: %d", 100);
	tinyhttp_stream_response_header(stream, "Other-header: %s", "hello");
	tinyhttp_stream_response_body(stream, "Hello, world!", -1);
	tinyhttp_stream_response_send(stream);
}
```

The `tinyhttp_stream_request` function returns the parsed version of the buffered request. You must always access request information through the returned pointer and not copy and pointers from it since they may be invalidated if the stream decides to move data in the input buffer.

These response functions follow a strict state machine. You must first call the status function one time, then the header functions zero or more times, then the body functions zero or more times, and finally the send function. At any point you can drop the response and start from scratch by using the undo function:

```c
tinyhttp_stream_response_status(stream, 200);
if (error_occurred) {
	tinyhttp_stream_response_undo(stream);
	tinyhttp_stream_response_status(stream, 500);
}
tinyhttp_stream_response_send(stream);
```

#### Special Headers

TinyHTTP adds some special headers under the hood:

* Content-Length
* Transfer-Encoding
* Connection

so you should avoid adding these manually.

#### Zero-Copy Response Building

TODO: Talk about body_buf/ack/setmincap

#### Error Management

The response builder interface also uses sticky errors to lift the burdain of error management from the application.

If an error occurs while building the response, tinyhttp either sends a code 500 response or sets the DIED state. Either way, this is totally transparent to the application.

### The State Bitset

To know which operations are allowed on a stream at any given time, applications can use the `tinyhttp_stream_state` function:

```c
int state = tinyhttp_stream_state(stream);

if (state & TINYHTTP_STREAM_RECV) {
	// stream is ready for input bytes
}

if (state & TINYHTTP_STREAM_SEND) {
	// stream is ready for output
}

if (state & TINYHTTP_STREAM_RECV_STARTED) {
	// A recv operation is in progress
}

if (state & TINYHTTP_STREAM_SEND_STARTED) {
	// A send operation is in progress
}

if (state & TINYHTTP_STREAM_READY) {
	// Request was buffered so it's now possible
	// to build a response
}

if (state & TINYHTTP_STREAM_DIED) {
	// The stream died
}
```

The `TINYHTTP_STREAM_RECV` and `TINYHTTP_STREAM_SEND` flags tell the application when it should call `tinyhttp_stream_recv_buf` or `tinyhttp_stream_send_buf`.

The `TINYHTTP_STREAM_RECV_STARTED` and `TINYHTTP_STREAM_SEND_STARTED` tell the application when calls to `tinyhttp_stream_recv_ack` or `tinyhttp_stream_send_ack` are expected due to previous calls to `tinyhttp_stream_recv_buf` or `tinyhttp_stream_send_buf`.

The `TINYHTTP_STREAM_READY` tells the application a request was buffered and it is now possible to build a response. The parsed request can by accessed with `tinyhttp_stream_request`.

The `TINYHTTP_STREAM_DIED` flag indicates an unreacoverable error occurred and all resources associated to the stream and the stream itself should be freed. DIED connections keep their input and output buffers intact to allow any pending asynchronous operations reading or writing to the stream's buffers to complete safely. When no one is using the stream's buffers, applications should free the stream. If you are handling states with a chain of if statements, you should handle the DIED state last since the code before it may cause the stream to go into the DIED state.

### Embedding in Custom Event Loops
In this sections there are some pseudocode examples of how one would use stream objects with various event loop models.

#### Ready-based Event Loops
Ready-based event loops are those which report that an operation can be performed on a given resource in a non-blocking way. Examples of ready-based event loops are those based on epoll, poll, and select.

TODO

#### Completion-based Event Loops
Completion-based event loops are an other way of referring to asynchronous I/O. With the completion-based model, when a thread performs a read or write operation on a resource, it does not wait for its completion. Instead, it continues running by doing other stuff. When no more work can be performed until an read/write operation completes, it waits until the next completion. Examples of this model are Windows's I/O completion ports and Linux's io_uring.

TODO