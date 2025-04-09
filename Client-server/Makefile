CXX = g++
CXXFLAGS = -Wall -Werror -g -std=c++17 -I../Include -I/opt/homebrew/opt/openssl@3/include
LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto -lpthread

SRCS = main.cpp ../Src/aes_utils.cpp ../Src/logger.cpp ../Src/shared.cpp
OBJS = $(SRCS:.cpp=.o)

all: client-server

client-server: $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f client-server $(OBJS)
