
CFLAGS = -ggdb -Wall -Wextra
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

all: chttp.c chttp.h 000_simple_client$(EXT) 001_simple_server$(EXT) 002_proxy$(EXT) 003_virtual_hosts$(EXT) 004_https_server$(EXT) 005_virtual_hosts_over_https$(EXT)

chttp.c chttp.h: $(wildcard src/*.c src/*.h) misc/amalg.py Makefile
	python misc/amalg.py

%$(EXT): examples/%.c chttp.c chttp.h
	gcc $< chttp.c -o $@ $(CFLAGS) $(LFLAGS)

clean:
	rm chttp.c chttp.h 000_simple_client 000_simple_client.exe 001_simple_server 001_simple_server.exe 002_proxy 002_proxy.exe 003_virtual_hosts 003_virtual_hosts.exe  004_https_server 004_https_server.exe 005_virtual_hosts_over_https 005_virtual_hosts_over_https.exe
