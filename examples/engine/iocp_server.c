#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <chttp.h>

#define MAX_CLIENTS (1<<10)

// Callback used by the engine to manage dynamic memory
static void *memfunc(HTTP_MemoryFuncTag tag,
	void *ptr, int len, void *data)
{
	(void) data;
	switch (tag) {

		case HTTP_MEMFUNC_MALLOC:
		return malloc(len);

		case HTTP_MEMFUNC_FREE:
		free(ptr);
		return NULL;
	}
	return NULL;
}

static SOCKET start_accept(LPFN_ACCEPTEX AcceptEx, SOCKET listen_fd, OVERLAPPED *accept_ov, char *buf, int bufsize)
{
	SOCKET accept_target = socket(AF_INET, SOCK_STREAM, 0);
	if (accept_target == INVALID_SOCKET)
		return INVALID_SOCKET;

	unsigned long num;
	memset(accept_ov, 0, sizeof(OVERLAPPED));
	BOOL ok = AcceptEx(listen_fd, accept_target, buf, bufsize - ((sizeof(struct sockaddr_in) + 16) * 2),
		sizeof(struct sockaddr_in) + 16,
		sizeof(struct sockaddr_in) + 16,
		&num, accept_ov);
	if (!ok && WSAGetLastError() != ERROR_IO_PENDING) {
		closesocket(accept_target);
		return INVALID_SOCKET;
	}

	return accept_target;
}

static void start_recv_or_send(SOCKET sock, OVERLAPPED *recv_ov, OVERLAPPED *send_ov, HTTP_Engine *eng)
{
	HTTP_EngineState state = http_engine_state(eng);

	if (state == HTTP_ENGINE_STATE_SERVER_RECV_BUF) {

		int cap;
		char *dst = http_engine_recvbuf(eng, &cap);

		memset(recv_ov, 0, sizeof(OVERLAPPED));
		int ok = ReadFile((HANDLE) sock, dst, cap, NULL, recv_ov);
		if (!ok && GetLastError() != ERROR_IO_PENDING)
			http_engine_close(eng);

	} else if (state == HTTP_ENGINE_STATE_SERVER_SEND_BUF) {

		int len;
		char *src = http_engine_sendbuf(eng, &len);

		memset(send_ov, 0, sizeof(OVERLAPPED));
		int ok = WriteFile((HANDLE) sock, src, len, NULL, send_ov);
		if (!ok && GetLastError() != ERROR_IO_PENDING)
			http_engine_close(eng);
	}
}

int main(void)
{
	// Interface and port the server will be listening on.
	char *addr = "127.0.0.1";
	int port = 8080;

	// Initialize the winsock subsystem
	WSADATA wd;
	if (WSAStartup(MAKEWORD(2, 2), &wd))
		return -1;

	// Create the I/O completion port object
	HANDLE iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
	if (iocp == INVALID_HANDLE_VALUE)
		return -1;

	// Create the listening socket
	SOCKET listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd == INVALID_SOCKET)
		return -1;

	// Register the socket into the IOCP
	if (CreateIoCompletionPort((HANDLE) listen_fd, iocp, 0, 0) == NULL)
		return -1;

	// Ignore the cooldown time for the bound interface to
	// avoid that annoying "address in use" error
	int reuse = 1;
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (void*) &reuse, sizeof(reuse));

	// Fill out the address struct
	struct sockaddr_in bind_buf;
	{
		struct in_addr addr_buf;
		if (inet_pton(AF_INET, addr, &addr_buf) != 1)
			return -1;

		bind_buf.sin_family = AF_INET;
		bind_buf.sin_port   = htons(port);
		bind_buf.sin_addr   = addr_buf;
		memset(&bind_buf.sin_zero, 0, sizeof(bind_buf.sin_zero));
	}

	// Associate the listening socket to the interface
	if (bind(listen_fd, (struct sockaddr*) &bind_buf, sizeof(bind_buf)) < 0)
		return -1;

	// Allow incoming connections
	if (listen(listen_fd, 32) < 0)
		return -1;

	// Get the AcceptEx function pointer
	LPFN_ACCEPTEX AcceptEx = NULL;
	GUID GuidAcceptEx = WSAID_ACCEPTEX;
	unsigned long num;
	int ret = WSAIoctl(listen_fd,
		SIO_GET_EXTENSION_FUNCTION_POINTER,
		&GuidAcceptEx, sizeof(GuidAcceptEx),
		&AcceptEx, sizeof(AcceptEx),
		&num, NULL, NULL);
	if (ret == SOCKET_ERROR)
		return -1;

	OVERLAPPED accept_ov;
	char accept_buf[2 * (sizeof(struct sockaddr_in) + 16)];
	SOCKET accept_target = start_accept(AcceptEx, listen_fd, &accept_ov, accept_buf, (int) sizeof(accept_buf));
	if (accept_target == INVALID_SOCKET)
		return -1;

	OVERLAPPED recv_overlapped[MAX_CLIENTS];
	OVERLAPPED send_overlapped[MAX_CLIENTS];
	SOCKET sockets[MAX_CLIENTS];
	HTTP_Engine engs[MAX_CLIENTS];

	for (int i = 0; i < MAX_CLIENTS; i++)
		sockets[i] = INVALID_SOCKET;

	for (;;) {
		DWORD timeout = INFINITE;
		
		DWORD transferred;
		ULONG_PTR key; 
		OVERLAPPED *overlapped;
		BOOL result = GetQueuedCompletionStatus(iocp, &transferred, &key, &overlapped, timeout);
		if (!result && overlapped == NULL) {
			if (GetLastError() == WAIT_TIMEOUT)
				continue; // Go back to waiting
			return -1; // Error
		}

		if (overlapped == &accept_ov) {
			// A new client connected

			int i = 0;
			while (i < MAX_CLIENTS && sockets[i] != INVALID_SOCKET)
				i++;
			
			if (i == MAX_CLIENTS)
				closesocket(accept_target); // Server limit reached
			else {

				sockets[i] = accept_target;
				http_engine_init(&engs[i], 0, memfunc, NULL);

				// Register the socket into the IOCP
				if (CreateIoCompletionPort((HANDLE) sockets[i], iocp, i, 0) == NULL)
					return -1;

				start_recv_or_send(sockets[i], &recv_overlapped[i], &send_overlapped[i], &engs[i]);

				// Check that the recv or send operation was started.
				// If now, remove the connection
				if (http_engine_state(&engs[i]) == HTTP_ENGINE_STATE_CLIENT_CLOSED) {
					closesocket(sockets[i]);
					sockets[i] = INVALID_SOCKET;
					http_engine_free(&engs[i]);
				}
			}

			accept_target = start_accept(AcceptEx, listen_fd, &accept_ov, accept_buf, (int) sizeof(accept_buf));
			if (accept_target == INVALID_SOCKET)
				return -1;

			// Go back to waiting
			continue;
		}

		// Complete the current operation
		if (0) {}
		else if (overlapped == &recv_overlapped[key]) http_engine_recvack(&engs[key], transferred);
		else if (overlapped == &send_overlapped[key]) http_engine_sendack(&engs[key], transferred);

		if (http_engine_state(&engs[key]) == HTTP_ENGINE_STATE_SERVER_PREP_STATUS) {

			// See blocking_server_with_engine.c to learn about how to
			// build a response
			http_engine_status(&engs[key], 200);
			http_engine_body(&engs[key], "Hello, world!", -1);
			http_engine_done(&engs[key]);
		}

		start_recv_or_send(sockets[key],
			&recv_overlapped[key],
			&send_overlapped[key],
			&engs[key]);

		if (http_engine_state(&engs[key]) == HTTP_ENGINE_STATE_SERVER_CLOSED) {
			http_engine_free(&engs[key]);
			closesocket(sockets[key]);
			sockets[key] = INVALID_SOCKET;
		}
	}
	
	return 0;
}