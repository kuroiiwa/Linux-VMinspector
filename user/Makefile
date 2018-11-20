CC = gcc
CFLAGS = -g -O2 -Wall

.PHONY: all clean

all: test

test: test.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f test
