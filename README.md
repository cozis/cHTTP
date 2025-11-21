# cHTTP
This is an HTTP library for C, featuring an HTTP(S) server, HTTP(S) client, and much more!

## Contributing

Contributions are welcome! The following are some notes on how to work with the codebase. Don't worry if you get something wrong. I will remind you.

The source code in the `src/` directory is intended to be be amalgamated into a single file before compilation. The amalgamation is not only intended as a distribution method, but also as easy-access documentation, and therefore need to be readable. For this reasons:
1. You never need need to include other cHTTP source files
2. All inclusions of third-party headers are to be placed inside `src/includes.h`
3. All files must start with a single empty line, unless they start with an overview comment of the file, in which case they must have no empty lines at the beginning of the file.
4. All files must end with a single empty line.
