#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>
#include <cstdlib>
#include "../Include/aes_utils.h"

int aes_encrypt_gcm(
    const unsigned char* plaintext, int plaintext_len,
    const unsigned char* key,
    const unsigned char* iv,
    unsigned char* ciphertext,
    int* ciphertext_len,
    unsigned char* tag
) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    *ciphertext_len = 0;

    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto error;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto error;

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
        goto error;

    *ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
        goto error;

    *ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
        goto error;

    EVP_CIPHER_CTX_free(ctx);
    return 1;

error:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int aes_decrypt_gcm(
    const unsigned char* ciphertext, int ciphertext_len,
    const unsigned char* key,
    const unsigned char* iv,
    const unsigned char* tag,
    unsigned char** plaintext
) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    int plaintext_len;
    int ret = -1;

    *plaintext = (unsigned char*)malloc(ciphertext_len + 1);
    if (!*plaintext) return -1;

    if (!ctx) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto error;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto error;

    if (EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len) != 1)
        goto error;

    plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag);

    if (EVP_DecryptFinal_ex(ctx, *plaintext + len, &len) <= 0)
        goto error;

    plaintext_len += len;
    (*plaintext)[plaintext_len] = '\0';
    ret = plaintext_len;

error:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

