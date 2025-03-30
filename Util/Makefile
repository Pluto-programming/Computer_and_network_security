CC=gcc
CFLAGS=-Wall -Werror

.PHONY: all clean

all: keygen

keygen: keygen.o
	$(CC) $(CFLAGS) -o $@ $< -lssl -lcrypto

keygen.o: main.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f keygen.o keygen