
CC=gcc
CFLAGS=-g -Wall
OUT=-o wireg

all: wireguppy.c
	$(CC) $(CFLAGS) $(OUT) wireguppy.c

clean:
	rm wireg
	rm -rf wireg.*
