#ifndef AES_UTILS_H
#define AES_UTILS_H

#include <openssl/evp.h>

int aes_encrypt_gcm(
    const unsigned char* plaintext, int plaintext_len,
    const unsigned char* key,
    const unsigned char* iv,
    unsigned char* ciphertext,
    int* ciphertext_len,
    unsigned char* tag
);

int aes_decrypt_gcm(
    const unsigned char* ciphertext, int ciphertext_len,
    const unsigned char* key,
    const unsigned char* iv,
    const unsigned char* tag,
    unsigned char** plaintext
);

#endif // AES_UTILS_H

