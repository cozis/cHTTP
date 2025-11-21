.PHONY: all clean example

all: chttp.c chttp.h example

chttp.c chttp.h: $(wildcard src/*.c src/*.h) misc/amalg.py Makefile
	python misc/amalg.py

example: main.c chttp.c chttp.h
	gcc main.c chttp.c -o example.exe

clean:
	rm chttp.c chttp.h
