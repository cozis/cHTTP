
CC = gcc
CFLAGS = -I. -Wall -Wextra -O0 -g3
LFLAGS = -lssl -lcrypto

CFILES = $(shell find src -name "*.c")
HFILES = $(shell find src -name "*.h")

EXAMPLES_CLIENT := $(basename $(shell ls examples/client/*.c 2>/dev/null))
EXAMPLES_SERVER := $(basename $(shell ls examples/server/*.c 2>/dev/null))
EXAMPLES_ENGINE := $(basename $(shell ls examples/engine/*.c 2>/dev/null))

all: chttp.c chttp.h examples

chttp.c chttp.h: $(HFILES) $(CFILES)
	python misc/amalg.py

examples: $(EXAMPLES_CLIENT) $(EXAMPLES_SERVER) $(EXAMPLES_ENGINE)

examples/client/%: examples/client/%.c chttp.c chttp.h
	$(CC) $(CFLAGS) $< chttp.c -o $@ $(LFLAGS)

examples/server/%: examples/server/%.c chttp.c chttp.h
	$(CC) $(CFLAGS) $< chttp.c -o $@ $(LFLAGS)

examples/engine/%: examples/engine/%.c chttp.c chttp.h
	$(CC) $(CFLAGS) $< chttp.c -o $@ $(LFLAGS)

clean:
	rm -f client_example server_example
	rm -f examples/client/* examples/server/* examples/engine/*
