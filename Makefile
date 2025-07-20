
CC = gcc
CFLAGS = -I. -Wall -Wextra -O0 -g3
LFLAGS = -lssl -lcrypto
AR = ar

CFILES = $(shell find src -name "*.c")
HFILES = $(shell find src -name "*.h")
OFILES = $(patsubst %.c,%.o,$(CFILES))

# Library names
LIBNAME = chttp
STATIC_LIB = lib$(LIBNAME).a
SHARED_LIB = lib$(LIBNAME).so

# Detect OS and set executable extension
ifeq ($(OS),Windows_NT)
    EXT = .exe
    SHARED_LIB = $(LIBNAME).dll
else
    EXT = .out
endif

# Installation directories
PREFIX ?= /usr/local
LIBDIR = $(PREFIX)/lib
INCDIR = $(PREFIX)/include

EXAMPLES_CLIENT_SRC := $(shell ls examples/client/*.c 2>/dev/null)
EXAMPLES_SERVER_SRC := $(shell ls examples/server/*.c 2>/dev/null)
EXAMPLES_ENGINE_SRC := $(shell ls examples/engine/*.c 2>/dev/null)

EXAMPLES_CLIENT := $(patsubst %.c,%$(EXT),$(EXAMPLES_CLIENT_SRC))
EXAMPLES_SERVER := $(patsubst %.c,%$(EXT),$(EXAMPLES_SERVER_SRC))
EXAMPLES_ENGINE := $(patsubst %.c,%$(EXT),$(EXAMPLES_ENGINE_SRC))

all: chttp.c chttp.h examples lib

lib: $(STATIC_LIB) $(SHARED_LIB)

chttp.c chttp.h: $(HFILES) $(CFILES)
	python misc/amalg.py

# Object files from source files
%.o: %.c $(HFILES)
	$(CC) $(CFLAGS) -c $< -o $@

# Static library
$(STATIC_LIB): $(OFILES)
	$(AR) rcs $@ $^

# Shared library
$(SHARED_LIB): $(OFILES)
	$(CC) -shared -o $@ $^ $(LFLAGS)

examples: $(EXAMPLES_CLIENT) $(EXAMPLES_SERVER) $(EXAMPLES_ENGINE)

examples/client/%$(EXT): examples/client/%.c chttp.c chttp.h
	$(CC) $(CFLAGS) $< chttp.c -o $@ $(LFLAGS)

examples/server/%$(EXT): examples/server/%.c chttp.c chttp.h
	$(CC) $(CFLAGS) $< chttp.c -o $@ $(LFLAGS)

examples/engine/%$(EXT): examples/engine/%.c chttp.c chttp.h
	$(CC) $(CFLAGS) $< chttp.c -o $@ $(LFLAGS)

# Installation targets
install: install-lib install-headers

install-lib: $(STATIC_LIB) $(SHARED_LIB)
	install -d $(LIBDIR)
	install -m 644 $(STATIC_LIB) $(LIBDIR)/
	install -m 755 $(SHARED_LIB) $(LIBDIR)/

install-headers: chttp.h
	install -d $(INCDIR)
	install -m 644 chttp.h $(INCDIR)/

uninstall:
	rm -f $(LIBDIR)/$(STATIC_LIB)
	rm -f $(LIBDIR)/$(SHARED_LIB)
	rm -f $(INCDIR)/chttp.h

clean:
	rm -f client_example server_example
	rm -f examples/client/*$(EXT) examples/server/*$(EXT) examples/engine/*$(EXT)
	rm -f $(OFILES)
	rm -f $(STATIC_LIB) $(SHARED_LIB)
	rm -f chttp.c chttp.h

.PHONY: all lib examples install install-lib install-headers uninstall clean
