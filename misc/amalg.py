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
        self.out += "\n"
        self.out += "#line 1 \"" + file + "\"\n"
        self.out += open(file).read()

        if len(self.out) > 0 and self.out[len(self.out)-1] != '\n':
            self.out += "\n"

    def save(self, file):
        open(file, 'w').write(self.out)

desc = """
// This file was generated automatically. Do not modify directly!
"""

header = Amalgamator()
header.append_text("#ifndef HTTP_AMALGAMATION\n")
header.append_text("#define HTTP_AMALGAMATION\n")
header.append_text(desc)
header.append_file("src/basic.h")
header.append_file("src/parse.h")
header.append_file("src/engine.h")
header.append_file("src/cert.h")
header.append_file("src/client.h")
header.append_file("src/server.h")
header.append_text("#endif // HTTP_AMALGAMATION\n")
header.save("chttp.h")

source = Amalgamator()

source.append_text("#ifndef HTTP_NOINCLUDE\n")
source.append_text("#include \"chttp.h\"\n")
source.append_text("#endif\n")

source.append_file("src/sec.h")
source.append_file("src/socket_raw.h")
source.append_file("src/socket.h")
source.append_file("src/socket_pool.h")
source.append_file("src/basic.c")
source.append_file("src/parse.c")
source.append_file("src/engine.c")
source.append_file("src/cert.c")
source.append_file("src/sec.c")
source.append_file("src/socket_raw.c")
source.append_file("src/socket.c")
source.append_file("src/socket_pool.c")
source.append_file("src/client.c")
source.append_file("src/server.c")
source.save("chttp.c")
