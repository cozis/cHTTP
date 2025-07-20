# chttp

chttp is an HTTP client & server library for C.

## Why another HTTP library?

This is my attempt at solving the "HTTP problem" for the C language. Writing C programs that behave as or interact with web services is always more painful than necessary in C. You either need to use `libcurl` which is overkill in most situations or link a large scale web servers to serve simple pages. This library targets smaller scale use-cases and tries to be as nice as possible to work with. Even then, it is fast. No performance is left on the table unless there is a specific reason. And if you do want to work at larger scales by using more sophisticate I/O systems (io_uring, I/O completion ports, etc) you can reuse the core state machine of the library that is I/O independant.

I would be comfortable with chttp handling up to 1000 simultaneous connections. For anything more than that I would reuse chttp's I/O independant state machine with my own multi-threaded and more scalable I/O.

## Features & Limitations
* HTTP/1.1 server & client
* Cross-platform (Windows & Linux)
* TLS (HTTPS) support using OpenSSL
* Minimal dependencies (libc and OpenSSL)
* Non-blocking design based on `poll()`
* I/O independant core reusable with more sophisticated I/O models
* Virtual hosts
* Single-threaded
