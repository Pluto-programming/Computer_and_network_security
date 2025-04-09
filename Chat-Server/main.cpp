#include <algorithm>
#include <iostream>
#include <thread>
#include <vector>
#include <mutex>
#include <fstream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include "../Include/shared.h"
#include "../Include/aes_utils.h"

#define CHAT_PORT 6666
#define CHAT_KEY_PATH "../Certs/chat_server_key.bin"

std::vector<int> clients;
std::mutex clients_mutex;
std::vector<unsigned char> session_key;

void broadcast(const std::vector<unsigned char>& packet, int sender_fd) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (int client : clients) {
        if (client != sender_fd) {
            send(client, packet.data(), packet.size(), 0);
        }
    }
}

void handle_client(int client_fd) {
    char buffer[2048];
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int len = recv(client_fd, buffer, sizeof(buffer), 0);
        if (len <= 0) {
            close(client_fd);
            std::lock_guard<std::mutex> lock(clients_mutex);
            clients.erase(std::remove(clients.begin(), clients.end(), client_fd), clients.end());
            break;
        }

        unsigned char iv[12], tag[16], *plaintext = nullptr;
        memcpy(iv, buffer, 12);
        memcpy(tag, buffer + 12, 16);

        aes_decrypt_gcm((unsigned char*)buffer + 28, len - 28, session_key.data(), iv, tag, &plaintext);
        std::cout << "[Client " << client_fd << "]: " << plaintext << std::endl;
        free(plaintext);

        std::vector<unsigned char> packet(buffer, buffer + len);
        broadcast(packet, client_fd);
    }
}

int main() {
    std::ifstream f(CHAT_KEY_PATH, std::ios::binary);
    session_key.resize(32);
    f.read((char*)session_key.data(), session_key.size());
    f.close();

    int server_fd = create_socket(CHAT_PORT);
    std::cout << "[*] Chat Server Running on port " << CHAT_PORT << "..." << std::endl;

    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) continue;

        {
            std::lock_guard<std::mutex> lock(clients_mutex);
            clients.push_back(client_fd);
        }

        std::thread t([client_fd]() { handle_client(client_fd); });
        t.detach();
    }

    close(server_fd);
    return 0;
}
