# Compiler and flags
CC = g++
CFLAGS = -Wall -Werror -g -std=c++17 -I../Include
LDFLAGS = -lssl -lcrypto -lpthread  # Added -lpthread here

# Source and object files
SRCS = main.cpp
OBJS = auth-server.o ../Src/aes_utils.o ../Src/logger.o ../Src/shared.o

# Output binary
TARGET = auth-server

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

auth-server.o: main.cpp
	$(CC) $(CFLAGS) -c $< -o $@

../Src/%.o: ../Src/%.cpp
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o ../Src/*.o $(TARGET)
