#ifndef SHARED_H
#define SHARED_H

#include <string>
#include <netinet/in.h>

int create_socket(int port);

void aes_encrypt(const std::string& plaintext, std::string& ciphertext, const unsigned char* key);
void aes_decrypt(const std::string& ciphertext, std::string& plaintext, const unsigned char* key);

#endif
