CC = gcc
CFLAGS = -g -O2 -Wall

.PHONY: all clean

all: vm_inspector

vm_inspector: vm_inspector.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f vm_inspector
