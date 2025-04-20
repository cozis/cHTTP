#include "../tinyhttp.h"

// TODO: Complete this example

int main(void)
{
	SOCKET listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd == INVALID_SOCKET)
		return -1;

	for (;;) {

		SOCKET client_fd = accept(listen_fd, NULL, NULL);
		if (client_fd == INVALID_SOCKET)
			continue;

		TinyHTTPStream stream;
		tinyhttp_stream_init(&stream, memfunc, NULL);

		int state = tinyhttp_stream_state(&stream);
		while (!(state & TINYHTTP_STREAM_READY)) {

			ASSERT(state & TINYHTTP_STREAM_RECV);

			char *dst;
			ptrdiff_t cap;

			dst = tinyhttp_stream_recv_buf(&stream, &cap);

			int ret = recv(client_fd, dst, cap, 0);
			if (ret < 0) {
				// TODO
			}

			tinyhttp_stream_recv_ack(&stream, ret);
			state = tinyhttp_stream_state(&stream);
		}

		TinyHTTPRequest *request = tinyhttp_stream_request(&stream);

		tinyhttp_stream_response_status(&stream, 200);
		tinyhttp_stream_response_body(&stream, "Hello, world!", -1);
		tinyhttp_stream_response_send(&stream);

		while (state & TINYHTTP_STREAM_SEND) {

			char *src;
			ptrdiff_t len;

			src = tinyhttp_stream_send_buf(&stream, &len);

			int ret = send(client_fd, src, len, 0);
			if (ret < 0) {
				// TODO
			}

			tinyhttp_stream_send_ack(&stream, ret);
			state = tinyhttp_stream_state(&stream);
		}

		tinyhttp_stream_free(&stream);
		CLOSESOCKET(client_fd);
	}

	CLOSESOCKET(listen_fd);
	return 0;
}