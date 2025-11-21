.PHONY: all clean example

all: chttp.c chttp.h simple_client simple_server

chttp.c chttp.h: $(wildcard src/*.c src/*.h) misc/amalg.py Makefile
	python misc/amalg.py

%: examples/%.c chttp.c chttp.h
	gcc $< chttp.c -o $@ -ggdb

clean:
	rm chttp.c chttp.h
