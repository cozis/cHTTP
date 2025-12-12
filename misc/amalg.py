class Amalgamator:
    def __init__(self):
        self.out = ""

    def append_text(self, text):
        self.out += text

    def append_file(self, file):
        self.out += "\n"
        self.out += "////////////////////////////////////////////////////////////////////////////////////////\n"
        self.out += "// " + file + "\n"
        self.out += "////////////////////////////////////////////////////////////////////////////////////////\n"
        self.out += open(file).read()

        if len(self.out) > 0 and self.out[len(self.out) - 1] != "\n":
            self.out += "\n"

    def save(self, file):
        open(file, "w").write(self.out)


desc = """// cHTTP, an HTTP client and server library!
//
// This file was generated automatically. Do not modify directly.
//
// Refer to the end of this file for the license"""

license = """
////////////////////////////////////////////////////////////////////////////////////////
// Copyright 2025 Francesco Cozzuto
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom
// the Software is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice shall
// be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
////////////////////////////////////////////////////////////////////////////////////////
"""

header = Amalgamator()
header.append_text("#ifndef CHTTP_INCLUDED\n")
header.append_text("#define CHTTP_INCLUDED\n")
header.append_text(desc)
header.append_file("src/includes.h")
header.append_file("src/basic.h")
header.append_file("src/parse.h")
header.append_file("src/time.h")
header.append_file("src/secure_context.h")
header.append_file("src/socket.h")
header.append_file("src/byte_queue.h")
header.append_file("src/cert.h")
header.append_file("src/client.h")
header.append_file("src/server.h")
header.append_text(license)
header.append_text("#endif // CHTTP_INCLUDED\n")
header.save("chttp.h")

source = Amalgamator()
source.append_text(desc)
source.append_text("\n")
source.append_text("#ifndef CHTTP_DONT_INCLUDE\n")
source.append_text('#include "chttp.h"\n')
source.append_text("#endif\n")
source.append_file("src/basic.c")
source.append_file("src/parse.c")
source.append_file("src/time.c")
source.append_file("src/secure_context.c")
source.append_file("src/socket.c")
source.append_file("src/byte_queue.c")
source.append_file("src/cert.c")
source.append_file("src/client.c")
source.append_file("src/server.c")
source.append_text(license)
source.save("chttp.c")
