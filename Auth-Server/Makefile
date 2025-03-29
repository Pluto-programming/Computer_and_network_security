CC=gcc
CFLAGS=-Wall -Werror

.PHONY: all clean

all: auth-server

auth-server: auth-server.o
	$(CC) $(CFLAGS) -o $@ $<

auth-server.o: main.cpp
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f auth-server.o auth-server