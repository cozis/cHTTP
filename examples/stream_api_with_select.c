// A program using the stream interface may look like this:
//
//   void respond(TinyHTTPStream *stream)
//   {
//     TinyHTTPRequest *req = tinyhttp_stream_request(stream);
//     if (req->method != TINYHTTP_METHOD_GET)
//       tinyhttp_stream_status(stream, 405);
//     else
//       tinyhttp_stream_status(stream, 200);
//     tinyhttp_stream_send(stream);
//   }
//
//   int main(void)
//   {
//     int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
//
//     struct sockaddr_in buf;
//     buf.sin_family = AF_INET;
//     buf.sin_port   = htons(port);
//     buf.sin_addr.s_addr = htonl(INADDR_ANY);
//     bind(listen_fd, (struct sockaddr*) &buf, sizeof(buf));
//
//     listen(listen_fd, 32);
//
//     int num_conns = 0;
//     int fds[1000];
//     TinyHTTPStream streams[1000];
//
//     for (int i = 0; i < 1000; i++)
//       fds[i] = -1;
//
//     for (;;) {
//       // TODO: timeouts
//
//       fd_set readset;
//       fd_set writeset;
//       FD_ZERO(&readset);
//       FD_ZERO(&writeset);
//
//       FD_SET(&readset);
//       int max_fd = listen_fd;
//       for (int i = 0; i < 1000; i++) {
//         if (fds[i] == -1) continue;
//         int state = tinyhttp_stream_state(&streams[i]);
//         if (state & TINYHTTP_STREAM_RECV)
//           FD_SET(fds[i], &readset);
//         if (state & TINYHTTP_STREAM_SEND)
//           FD_SET(fds[i], &writeset);
//         if (state & (TINYHTTP_STREAM_RECV | TINYHTTP_STREAM_SEND))
//           if (max_fd < fds[i]) max_fd = fds[i];
//       }
//
//       int num = select(max_fd+1, &readset, &writeset, NULL, NULL);
//
//       if (FD_ISSET(liste_fd, &readset)) {
//         // TODO
//       }
//
//       int ready_queue[1000];
//       int ready_head = 0;
//       int ready_count = 0;
//       for (int i = 0; i < 1000; i++) {
//         // TODO
//       }
//
//       while (ready_count > 0) {
//
//         int idx = ready_queue[ready_head];
//         TinyHTTPStream *stream = &streams[idx];
//
//         TinyHTTPRequest *req = tinyhttp_stream_request(stream);
//         assert(req);
//
//         respond(stream);
//
//         ready_head = (ready_head + 1) % 1000;
//         ready_count--;
//         if (tinyhttp_stream_request(stream)) {
//           ready_queue[(ready_head + ready_count) % 1000] = idx;
//           ready_count++;
//         }
//       }
//     }
//
//     close(listen_fd);
//     return 0;
//   }
//
// Note that this example does not keep track of timeouts.
//
// The recv_buf/recv_ack and send_buf/send_ack interface is very handy as it's
// compatible both with readyness-based event loops (epoll, poll, select) and
// completion-based event loops (iocp, io_uring). Since the stream object does
// not read from the socket directly, you can easily implement HTTPS by providing
// it with TLS-encoded data instead of data directly from the socket.
