#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>


#define AES_256_KEY_SIZE 32

int main(void) {
    unsigned char key[AES_256_KEY_SIZE];

    if (RAND_bytes(key, sizeof(key)) != 1) {
        fprintf(stderr, "Error Generating Random Key");
        return 1;
    }

    FILE* fp = fopen("usr_key.bin", "w");

    if (!fp) {
        perror("Error Opening File");
        return 1;
    }

    fwrite(key, sizeof(key[0]), AES_256_KEY_SIZE, fp);

    fclose(fp);
    return 0;
}
