
CC = gcc
CFLAGS = -I. -Wall -Wextra -O0 -g3
LFLAGS = -lssl -lcrypto

CFILES = $(shell find src -name "*.c")
HFILES = $(shell find src -name "*.h")

all: chttp.c chttp.h

chttp.c chttp.h: $(HFILES) $(CFILES)
	python misc/amalg.py

clean:
	rm -f client_example server_example
