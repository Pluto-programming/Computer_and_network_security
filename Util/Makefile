#CC=g++
#CFLAGS=-Wall -Werror -g
#
#.PHONY: all clean
#
#all: keygen
#
#keygen: main.o
#	$(CC) $(CFLAGS) -o $@ $<
#
#main.o: main.cpp
#	$(CC) $(CFLAGS) -c main.cpp
#
#clean:
#	rm -f *.o keygen

CC=g++
CFLAGS=-Wall -Werror -g -I/opt/homebrew/opt/openssl@3/include
LDFLAGS=-L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto

all: keygen

keygen: main.o
	$(CC) $(CFLAGS) -o keygen main.o $(LDFLAGS)

main.o: main.cpp
	$(CC) $(CFLAGS) -c main.cpp

clean:
	rm -f *.o keygen
