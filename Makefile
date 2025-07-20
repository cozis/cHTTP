
CC = gcc
CFLAGS = -I. -Wall -Wextra -O0 -g3
LFLAGS = -lssl -lcrypto

CFILES = $(shell find src -name "*.c")
HFILES = $(shell find src -name "*.h")

all: client_example server_example http.c http.h

http.c http.h: $(HFILES) $(CFILES)
	python misc/amalg.py

client_example: examples/client_example.c http.c http.h
	$(CC) examples/client_example.c http.c $(CFLAGS) -o $@ $(LFLAGS)
	
server_example: examples/server_example.c http.c http.h
	$(CC) examples/server_example.c http.c $(CFLAGS) -o $@ $(LFLAGS)

clean:
	rm -f client_example server_example
