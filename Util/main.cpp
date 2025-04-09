#include <iostream>
#include <fstream>
#include <openssl/rand.h>

int main() {
    unsigned char key[32];
    if (!RAND_bytes(key, sizeof(key))) {
        std::cerr << "Error generating key" << std::endl;
        return 1;
    }
    std::ofstream out("../Certs/usr_key.bin", std::ios::binary);
    out.write(reinterpret_cast<char*>(key), sizeof(key));
    std::cout << "Key generated and saved to ../Certs/usr_key.bin" << std::endl;
    return 0;
}
