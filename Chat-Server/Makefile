CXX = g++
CXXFLAGS = -Wall -Werror -std=c++11 -g -I../Include -I/opt/homebrew/opt/openssl@3/include
LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto -lpthread

SRC_DIR = ../Src
OBJS = main.o $(SRC_DIR)/logger.o $(SRC_DIR)/attack_detection.o $(SRC_DIR)/shared.o $(SRC_DIR)/aes_utils.o

all: chat-server

chat-server: $(OBJS)
	$(CXX) $(CXXFLAGS) -o chat-server $(OBJS) $(LDFLAGS)

main.o: main.cpp
	$(CXX) $(CXXFLAGS) -c main.cpp

$(SRC_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f *.o $(SRC_DIR)/*.o chat-server
