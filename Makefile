CFLAGS=-std=c99 -Wall -Wextra -pedantic -g3 -I/opt/local/include
CC=clang
LDFLAGS=-L/opt/local/lib -lgcrypt

default: all

all: test uoenc uodec

%.o: %.c 
	$(CC) $(CFLAGS) -o $@ -c $<

test: test.o crypt.o
	$(CC) -o $@ $^ $(LDFLAGS)

uoenc: uoenc.o crypt.o uoutil.o
	$(CC) -o $@ $^ $(LDFLAGS)

uodec: uodec.o crypt.o uoutil.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean: 
	rm -f *.o test uoenc uodec

.PHONY: default all clean
