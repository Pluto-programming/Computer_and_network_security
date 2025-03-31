CC=g++
CFLAGS=-Wall -Werror -g

.PHONY: all clean

all: auth-server

auth-server: auth-server.o
	$(CC) $(CFLAGS) -o $@ $< -lssl -lcrypto

auth-server.o: main.cpp
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f auth-server.o auth-server