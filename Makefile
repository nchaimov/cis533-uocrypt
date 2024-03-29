# Use c99 will all warnings and debug symbols enabled
CFLAGS=-std=gnu99 -Wall -Wextra -g3 -I/opt/local/include

# Use GCC by default; clang also works
CC=gcc

# Use libgcrypt
LDFLAGS=-L/opt/local/lib -lgcrypt

default: all

all: test uoenc uodec

%.o: %.c 
	$(CC) $(CFLAGS) -o $@ -c $<

test: test.o uocrypt.o
	$(CC) -o $@ $^ $(LDFLAGS)

uoenc: uoenc.o uocrypt.o uoio.o
	$(CC) -o $@ $^ $(LDFLAGS)

uodec: uodec.o uocrypt.o uoio.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean: 
	rm -f *.o test uoenc uodec

.PHONY: default all clean
