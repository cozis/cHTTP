
CC = gcc
CFLAGS = -I. -Wall -Wextra -O0 -g3
LFLAGS =
AR = ar

CFILES = $(shell find src -name "*.c")
HFILES = $(shell find src -name "*.h")
OFILES = $(patsubst %.c,%.o,$(CFILES))

# Library names
LIBNAME = chttp
STATIC_LIB = lib$(LIBNAME).a

# Detect OS and set executable extension
ifeq ($(OS),Windows_NT)
    EXT = .exe
	LFLAGS = -lws2_32
else
    EXT = .out
	LFLAGS += -lssl -lcrypto
endif

HTTPS = 1
ifeq ($(HTTPS),1)
	CFLAGS += -DHTTPS_ENABLED
	LFLAGS += -lssl -lcrypto
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

lib: $(STATIC_LIB)

chttp.c chttp.h: $(HFILES) $(CFILES)
	python misc/amalg.py

# Object files from source files
%.o: %.c $(HFILES)
	$(CC) $(CFLAGS) -c $< -o $@

# Static library
$(STATIC_LIB): $(OFILES)
	$(AR) rcs $@ $^

examples: $(EXAMPLES_CLIENT) $(EXAMPLES_SERVER) $(EXAMPLES_ENGINE)

examples/client/%$(EXT): examples/client/%.c chttp.c chttp.h
	$(CC) $(CFLAGS) $< chttp.c -o $@ $(LFLAGS)

examples/server/%$(EXT): examples/server/%.c chttp.c chttp.h
	$(CC) $(CFLAGS) $< chttp.c -o $@ $(LFLAGS)

examples/engine/%$(EXT): examples/engine/%.c chttp.c chttp.h
	$(CC) $(CFLAGS) $< chttp.c -o $@ $(LFLAGS)

clean:
	rm -f client_example server_example
	rm -f examples/client/*$(EXT) examples/server/*$(EXT) examples/engine/*$(EXT)
	rm -f $(OFILES)
	rm -f $(STATIC_LIB)
	rm -f chttp.c chttp.h

.PHONY: all lib examples install install-lib install-headers uninstall clean
