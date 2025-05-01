#include <cstring>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <thread>
#include <csignal>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "../Include/aes_utils.h"
#include "../Include/shared.h"
#include "../Auth-Server/auth-var.h"

// SSL
#include <openssl/ssl.h> // TLS
#include <openssl/err.h> // Error 
#include <openssl/rand.h> // AES Key Generation (SYM)
#include <openssl/evp.h> // Symmetric Key
#ifdef OPNSSL3
#include <openssl/core_names.h> // Defines
#endif

#define AUTH_PORT 8081
#define CHAT_PORT 6666
#define USER_KEY_PATH "../Certs/usr_key.bin"
#define CHAT_KEY_PATH "../Certs/chat_server_key.bin"

int chat_sock = -1;

std::vector<std::string> split(const std::string& str, char delim) {
    std::vector<std::string> out;
    std::stringstream ss(str);
    std::string token;
    while (std::getline(ss, token, delim)) {
        out.push_back(token);
    }
    return out;
}

void signal_handler(int signum) {
    if (chat_sock != -1) close(chat_sock);
    std::cout << "\n[Client] Exiting gracefully." << std::endl;
    exit(0);
}

SSL_CTX* create_client_context() {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

// Get User registration info, send to auth, and get key
void register_user(char key[32], std::string username, std::string pass){
    

    // Setup SSL
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    SSL_CTX* ctx = create_client_context();
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8081);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(server_fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("Connection failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    SSL* ssl;
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server_fd);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        std::cout << "SSL connection established." << std::endl;

        // Send registration message (username,password)
        std::string register_message = username + "," + pass;

        SSL_write(ssl, register_message.c_str(), register_message.length());

        // Receive AES key (expecting 32 bytes for AES-256)
        unsigned char aes_key[32] = {0};
        int received = SSL_read(ssl, aes_key, sizeof(aes_key));

        if (received == 32) {
            std::cout << "Received AES-256 key: ";
            for (int i = 0; i < 32; ++i)
                printf("%02x", aes_key[i]);
            std::cout << std::endl;

        
        } else {
            // If not exactly 32 bytes, server might have sent an error message
            char error_msg[4096] = {0};
            memcpy(error_msg, aes_key, received);
            std::cout << "Server response: " << error_msg << std::endl;
        }

    }
    // Shutdown SSL connection and return
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(server_fd);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return;
}



void request_session_key_from_auth(std::vector<unsigned char>& session_key) {
    std::cout << "[Client] Connecting to auth-server..." << std::endl;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(AUTH_PORT);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Ask user to register or login
    std::cout << "Would you like to login or register a new user?";
    std::cout << "(type 'r' for register, 'l' for login)" << std::endl;
    std::string input;
    std::cin >> input;

    char key[32];
    std::string username;
    std::string pass;

    // get key from login or registration
    if (!input.empty() && input[0] == 'r'){ //register
        // Get username and password
        std::cout << "\nRegistering the user . . ."<<std::endl;
        std::cout << "Username: ";
        std::cin >> username;
        std::cout << "Password: ";
        std::cin >> pass;
        std::cout << std::endl;

        register_user(key, username, pass);
        std::cout << "Done Registering the user\n"<<std::endl;
    }

    // login
    // Get username and password if not logged in
    std::cout << "Logging in . . ."<<std::endl;
    std::cout << "Username: ";
    std::cin >> username;
    std::cout << std::endl << "Password: ";
    std::cin >> pass;
    std::cout << std::endl;
    connect(sock, (sockaddr*)&addr, sizeof(addr));
    std::string log_msg = username + ',' + pass;
    send(sock, log_msg.c_str(), sizeof(log_msg.c_str()), 0);                          // Username and password

    char buffer[2048] = {0};
    int len = recv(sock, buffer, sizeof(buffer), 0);
    std::string full(buffer, len);

    std::cout << "[Client] Received total payload (" << len << " bytes):" << full << std::endl;

    std::vector<std::string> parts = split(full, ',');
    if (parts.size() != 6) {
        std::cerr << "[Client] ERROR: Expected 6 comma-separated parts" << std::endl;
        exit(1);
    }

    unsigned char user_key[32], chat_key[32];
    std::string usr_key_path = "../Certs/" + username + ".bin";
    std::ifstream ukey(usr_key_path.c_str(), std::ios::binary);
    
    if (!ukey.read((char*)user_key, sizeof(user_key))) {
        std::cerr << "[Client] ERROR: Failed to load user key\n";
        exit(1);
    }
    ukey.close();

    std::ifstream ckey(CHAT_KEY_PATH, std::ios::binary);
    if (!ckey.read((char*)chat_key, sizeof(chat_key))) {
        std::cerr << "[Client] ERROR: Failed to load chat key\n";
        exit(1);
    }
    ckey.close();

    auto b64_to_bytes = [](const std::string& in) {
        std::vector<unsigned char> out(in.length());
        int len = EVP_DecodeBlock(out.data(), (const unsigned char*)in.c_str(), in.length());
        out.resize(len);
        return out;
    };

    auto msg1 = b64_to_bytes(parts[0]);
    auto iv1  = b64_to_bytes(parts[1]);
    auto tag1 = b64_to_bytes(parts[2]);
    auto msg2 = b64_to_bytes(parts[3]);
    auto iv2  = b64_to_bytes(parts[4]);
    auto tag2 = b64_to_bytes(parts[5]);

    unsigned char* out1 = nullptr;
    unsigned char* out2 = nullptr;
    aes_decrypt_gcm(msg1.data(), msg1.size(), user_key, iv1.data(), tag1.data(), &out1);
    aes_decrypt_gcm(msg2.data(), msg2.size(), chat_key, iv2.data(), tag2.data(), &out2);

    std::string decrypted1((char*)out1);
    std::string decrypted2((char*)out2);
    std::cout << "[Client] Client-decrypted: " << decrypted1 << std::endl;
    std::cout << "[Client] Chat-decrypted:   " << decrypted2 << std::endl;

    free(out1);
    free(out2);

    auto fields = split(decrypted1, ',');
    if (fields.size() != 4) {
        std::cerr << "[Client] ERROR: Decrypted message from auth-server does not have 4 fields." << std::endl;
        exit(1);
    }

    std::string session_key_b64 = fields[3];
    session_key.resize(32);
    EVP_DecodeBlock(session_key.data(), (const unsigned char*)session_key_b64.c_str(), session_key_b64.length());
}

void chat_loop(const std::vector<unsigned char>& session_key) {
    chat_sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(CHAT_PORT);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    connect(chat_sock, (sockaddr*)&addr, sizeof(addr));
    std::cout << "[Client] Connected to chat server." << std::endl;

    std::thread reader([&]() {
        char buffer[2048];
        while (true) {
            memset(buffer, 0, sizeof(buffer));
            int len = recv(chat_sock, buffer, sizeof(buffer), 0);
            if (len <= 0) break;

            unsigned char* plaintext = nullptr;
            unsigned char iv[12], tag[16];
            memcpy(iv, buffer, 12);
            memcpy(tag, buffer + 12, 16);
            aes_decrypt_gcm((unsigned char*)buffer + 28, len - 28, session_key.data(), iv, tag, &plaintext);
            std::cout << "\r[Message] " << plaintext << "\n> " << std::flush;
            free(plaintext);
        }
    });

    std::string line;
    while (true) {
        std::cout << "> " << std::flush;
        std::getline(std::cin, line);

        unsigned char ciphertext[2048], tag[16], iv[12];
        RAND_bytes(iv, sizeof(iv));
        int len;
        aes_encrypt_gcm((unsigned char*)line.c_str(), line.size(), session_key.data(), iv, ciphertext, &len, tag);

        std::vector<unsigned char> packet;
        packet.insert(packet.end(), iv, iv + 12);
        packet.insert(packet.end(), tag, tag + 16);
        packet.insert(packet.end(), ciphertext, ciphertext + len);

        send(chat_sock, packet.data(), packet.size(), 0);
    }

    reader.join();
}


int main() {
    std::signal(SIGINT, signal_handler);
    std::cout << "[Client] Starting main()" << std::endl;



    std::vector<unsigned char> session_key;
    request_session_key_from_auth(session_key);
    std::cout << "[Client] Session key retrieved successfully." << std::endl;

    chat_loop(session_key);
    return 0;
}
