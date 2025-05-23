// Predefined Constants
#define PORT 8081
#define INIT_BUFFER 1024 // starting buffer size
#define TLS_HELLO 5
#define MAX_LEN 2048   // Max message length
#define MAX_USR_LEN 64 // Max length of Username
#define MAX_PASS_LEN 64 // Max length of Password
#define MSG_BUFF_MAX 8192
#define NONCE_BYTE 64
#define DELIM ','
// Server Key Paths
#define CRT_PATH "../Certs/as-c.pem"
#define KEY_PATH "../Certs/as-k.pem"
// Chat-Clinet Auth Key
#define CLIENT_KEY "../Certs/chat_server_key.bin"
//#define CLIENT_KEY "/home/mharper/Dropbox/GitHub/Computer_and_network_security/Certs/chat_server_key.bin"

// AES https://github.com/aws-samples/aws-cloudhsm-pkcs11-examples/blob/master/src/encrypt/aes.h#L25
#define AES_256_KEY_SIZE 32
#define AES_GCM_IV_SIZE 12
#define AES_GCM_TAG_SIZE 16

// Error Messages
const char* srv_fault = "Sever Fault, Exception Thrown";

// Control What is compiled
// Using OpenSSL Versoin 3+
#define OPNSSL1
//#define OPNSSL3
