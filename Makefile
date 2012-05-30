
CC=gcc
CFLAGS=-g -Wall
OUT=-o wguppy

all: wireguppy.c
	$(CC) $(CFLAGS) $(OUT) wireguppy.c

clean:
	rm wguppy
	rm -rf wguppy.*
