#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>

// This is a bare-bones epoll HTTP server to get a practical
// req/sec limit.
//
// Compile:
//   gcc fast_epoll.c -o fast_epoll -Wall -Wextra -O2 -DNDEBUG

int main()
{
	int epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		perror("epoll_create1");
		return -1;
	}

	int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd == -1) {
		perror("socket");
		return -1;
	}

	{
		int flags = fcntl(listen_fd, F_GETFL, 0);
		if (flags < 0) {
			perror("fcntl");
			return -1;
		}
		flags |= O_NONBLOCK;
		if (fcntl(listen_fd, F_SETFL, flags) < 0) {
			perror("fcntl");
			return -1;
		}
	}

	int one = 1;
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (char*) &one, sizeof(one)) < 0) {
		perror("setsockopt");
		close(listen_fd);
		return -1;
	}

	struct sockaddr_in bind_buf;
	bind_buf.sin_family = AF_INET;
	bind_buf.sin_port = htons(3333);
	bind_buf.sin_addr.s_addr = inet_addr("127.0.0.1");
	if (bind(listen_fd, (struct sockaddr*) &bind_buf, sizeof(bind_buf)) < 0) {
		perror("bind");
		close(listen_fd);
		return -1;
	}

	if (listen(listen_fd, 32) < 0) {
		perror("listen");
		close(listen_fd);
		return -1;
	}

	struct epoll_event epoll_buf;
	epoll_buf.data.fd = -1;
	epoll_buf.events = EPOLLIN;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &epoll_buf) < 0) {
		perror("epoll_ctl");
		return -1;
	}

	#define CAPACITY (1<<9)
	#define IBUFCAP (1<<9)
	#define OBUFCAP (1<<9)
	#define MAXEXCH 100

	int num_fds = 0;
	int fds[CAPACITY];
	int free_idx[CAPACITY];

	char ibufs[CAPACITY][IBUFCAP];
	char obufs[CAPACITY][OBUFCAP];
	int  sent[CAPACITY];
	int  received[CAPACITY];
	int  exchanged[CAPACITY];

	for (int i = 0; i < CAPACITY; i++)
		free_idx[i] = i;

	for (;;) {

		struct epoll_event batch[CAPACITY];
		int num = epoll_wait(epoll_fd, batch, CAPACITY, -1);

		for (int i = 0; i < num; i++) {

			if (batch[i].data.fd < 0) {
				while (num_fds < CAPACITY) {
					int accepted_fd = accept4(listen_fd, NULL, NULL, SOCK_NONBLOCK);
					if (accepted_fd < 0) {
						if (errno == EINTR)
							continue;
						if (errno == EAGAIN || errno == EWOULDBLOCK)
							break;
						__builtin_trap();
					}

					int num_free = CAPACITY - num_fds;
					int idx = free_idx[num_free-1];

					struct epoll_event epoll_buf;
					epoll_buf.data.fd = idx;
					epoll_buf.events = EPOLLIN;
					if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, accepted_fd, &epoll_buf)) {
						perror("epoll_ctl");
						__builtin_trap();
					}

					fds[idx] = accepted_fd;
					sent[idx] = 0;
					received[idx] = 0;
					exchanged[idx] = 0;

					num_fds++;
				}
			} else {

				int flags = batch[i].events;
				int idx = batch[i].data.fd;
				int fd = fds[idx];

				char *ibuf = ibufs[idx];
				char *obuf = obufs[idx];

				int remove = 0;
				if (flags & EPOLLIN) {

					for (;;) {
						if (received[idx] == IBUFCAP)
							__builtin_trap();
						int ret = recv(fd, ibuf + received[idx], IBUFCAP - received[idx], 0);
						if (ret < 0) {
							if (errno == EINTR)
								continue;
							if (errno == EAGAIN || errno == EWOULDBLOCK)
								break;
							remove = 1;
							break;
						}
						if (ret == 0) {
							remove = 1;
							break;
						}
						received[idx] += ret;
					}

					if (!remove) {
						int found = -1;
						for (int i = 0; i < received[idx]; i++) {
							if (3 < received[idx] - i
								&& ibuf[i+0] == '\r'
								&& ibuf[i+1] == '\n'
								&& ibuf[i+2] == '\r'
								&& ibuf[i+3] == '\n') {
								found = i;
								break;
							}
						}
						if (found > -1) {
							
							char resp[] = "HTTP/1.1 204 OK\r\nConnection: Keep-Alive\r\n\r\n";
							memcpy(obuf + sent[idx], resp, sizeof(resp)-1);
							sent[idx] += sizeof(resp)-1;

							int head_len = found+4;
							memcpy(ibuf, ibuf + received[idx], received[idx] - head_len);
							received[idx] -= head_len;

							struct epoll_event epoll_buf;
							epoll_buf.data.fd = idx;
							epoll_buf.events = EPOLLOUT;
							if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &epoll_buf) < 0) {
								perror("epoll_ctl");
								__builtin_trap();
							}
						}
					}
				}

				if (!remove && (flags & EPOLLOUT)) {
					int flushed = 0;
					do {
						int ret = send(fd, obuf + flushed, sent[idx] - flushed, 0);
						if (ret < 0) {
							if (errno == EINTR)
								continue;
							if (errno == EAGAIN || errno == EWOULDBLOCK)
								break;
							__builtin_trap();
						}
						if (ret == 0)
							__builtin_trap();
						flushed += ret;
					} while (flushed < sent[idx]);

					memmove(obuf, obuf + flushed, sent[idx] - flushed);
					sent[idx] -= flushed;

					if (sent[idx] == 0) {
						struct epoll_event epoll_buf;
						epoll_buf.data.fd = idx;
						epoll_buf.events = EPOLLIN;
						if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &epoll_buf) < 0) {
							perror("epoll_ctl");
							__builtin_trap();
						}
					}
					exchanged[idx]++;
					if (exchanged[idx] == MAXEXCH)
						remove = 1;
				}

				if (remove) {
					close(fds[idx]);
					fds[idx] = -1;
					int num_free = CAPACITY - num_fds;
					free_idx[num_free] = idx;
					num_fds--;
				}
			}
		}
	}

	close(epoll_fd);
}
