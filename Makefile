CFLAGS=-std=c99 -Wall -g3 -I/opt/local/include
CC=clang
LDFLAGS=-L/opt/local/lib -lgcrypt

default: all

all: test

%.o: %.c 
	$(CC) $(CFLAGS) -o $@ -c $<

test: test.o crypt.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean: 
	rm -f *.o test

.PHONY: default all clean
