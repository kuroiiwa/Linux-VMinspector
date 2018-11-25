CC = gcc
CFLAGS = -g -O2 -Wall

.PHONY: all clean

all: test vm_inspector

test: test.c
	$(CC) $(CFLAGS) -o $@ $<

test: vm_inspector.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f test vm_inspector
