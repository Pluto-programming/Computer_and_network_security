# Compiler and Flags
CXX = g++
OPENSSL_INC = -I/opt/homebrew/opt/openssl@3/include
OPENSSL_LIB = -L/opt/homebrew/opt/openssl@3/lib
CXXFLAGS = -Wall -Werror -g -std=c++17 $(OPENSSL_INC)
LDFLAGS = $(OPENSSL_LIB) -lssl -lcrypto -lpthread

# Directories
SRC_DIR = Src
INCLUDE_DIR = Include
BIN_DIR = bin
AUTH_DIR = Auth-Server
CLIENT_DIR = Client-server
CHAT_DIR = Chat-Server

# Shared Object Files
OBJS = \
	$(SRC_DIR)/aes_utils.o \
	$(SRC_DIR)/logger.o \
	$(SRC_DIR)/shared.o \
	$(SRC_DIR)/attack_detection.o

# Final Executables
AUTH_EXE = $(BIN_DIR)/auth-server
CLIENT_EXE = $(BIN_DIR)/client-server
CHAT_EXE = $(BIN_DIR)/chat-server

.PHONY: all clean

all: $(AUTH_EXE) $(CLIENT_EXE) $(CHAT_EXE)

# Auth Server
$(AUTH_EXE): $(AUTH_DIR)/main.cpp $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Client Server
$(CLIENT_EXE): $(CLIENT_DIR)/main.cpp $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Chat Server
$(CHAT_EXE): $(CHAT_DIR)/main.cpp $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Compile any object in Src/
$(SRC_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(BIN_DIR) $(SRC_DIR)/*.o

