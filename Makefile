
CFLAGS = -ggdb
LFLAGS =

ifeq ($(shell uname -s),Linux)
	EXT =
else
	EXT = .exe
	LFLAGS += -lws2_32
endif

HTTPS ?= 0
ifneq ($(HTTPS),0)
	CFLAGS += -DHTTPS_ENABLED
	LFLAGS += -lcrypto -lssl
endif

.PHONY: all clean example

all: chttp.c chttp.h simple_client$(EXT) simple_server$(EXT)

chttp.c chttp.h: $(wildcard src/*.c src/*.h) misc/amalg.py Makefile
	python misc/amalg.py

%$(EXT): examples/%.c chttp.c chttp.h
	gcc $< chttp.c -o $@ $(CFLAGS) $(LFLAGS)

clean:
	rm chttp.c chttp.h simple_client simple_client.exe simple_server simple_server.exe
