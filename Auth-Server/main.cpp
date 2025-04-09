// Standard Library Functions
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// File
#include <fcntl.h>

// TIme
#include <time.h>

// Socket
#include <sys/socket.h> // Sockets (General)
#include <netinet/in.h> // Internet Sockets

// Linux POSIX API
#include <unistd.h>
// Threading
#include <pthread.h>
#include <thread>

// Custom
#include "auth-var.h"

// SSL
#include <openssl/ssl.h> // TLS
#include <openssl/err.h> // Error 
#include <openssl/rand.h> // AES Key Generation (SYM)
#include <openssl/evp.h> // Symmetric Key
#ifdef OPNSSL3
#include <openssl/core_names.h> // Defines
#endif



// Custom Functions -- Separate into separate file later
void conn_handler(int conn_socket, SSL_CTX* ctx);
void handle_ssl(int conn_socket, SSL_CTX* ctx);
void handle_custom_auth(int conn_socket);
int load_chat_key(unsigned char* key_buff, unsigned size);
int handle_usr_1(int conn_sock, char* msgbuff, char* username, unsigned char* nonce);
int parse_csv_line(char* buff, int buff_len, unsigned char* trgt);
int lookup_user_key(unsigned char* key, char* usrname);

// OpenSSL Functions -- Separate Later -- https://wiki.openssl.org/index.php/Simple_TLS_Server
SSL_CTX *create_context();
unsigned configure_context(SSL_CTX* ctx);

// AES Functions
int aes_gcm_enc(unsigned char* plaintext, unsigned int p_len, unsigned char* key, unsigned char* iv, unsigned char* dest, int* dest_len, unsigned char* tag);

// Base 64 Wrapper
void b64_encode(const unsigned char* input,  unsigned char* output, int len);
void b64_decode(const unsigned char* input,  unsigned char* output, int len);

int main(int argc, char** argv)
{
    // Socket FD
    int sock_fd = 0, tsock = 0;
    //Struct for socket
    struct sockaddr_in auth_sock;
    // Length of Socket Struct
    socklen_t addrlen = sizeof(auth_sock);
    // Options Number for setsockopt
    int opts = 1;

    // SSL Socket Context
    SSL_CTX* ctx = NULL;

    // AF_INET (Internet Socket), SOCK_STREAM (TCP), 0 == Internet Protocol
    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Unable to Create Socket (socket)");
        goto exit;
    }

    // setsocketop can be used to ensure we get the correct port
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opts, sizeof(opts)) == -1) {
        perror("Unable to set socket options (setsockopt)");
        goto exit;

    }

    // Configure Socket Settings
    auth_sock.sin_family = AF_INET; // IPv4
    auth_sock.sin_addr.s_addr = INADDR_ANY; // IPv4 Any '0.0.0.0'
    auth_sock.sin_port = htons(PORT); // Host To Network Short (Network always in big endian)

    // Bind to Socket (Claim it)
    if (bind(sock_fd, (struct sockaddr*)&auth_sock, sizeof(auth_sock)) == -1) {
        perror("Unable to Bind Socket (bind)");
        goto exit;
    }

    // Setup Listening (Max clients accepted, etc)
    if (listen(sock_fd, 10) == -1) {
        perror("Failed to Listen (listen)");
        goto close_exit;
    }

    // Configure SSL Context
    ctx = create_context();

    // If we fail to create a context
    // We need to clean up and exit
    if (!ctx)
        goto close_exit;

    if(!configure_context(ctx)) {
        fprintf(stderr, "Failure to Configure Context");
        goto ssl_exit;
    }

    // Infinate Loop
    while(1) {

        tsock = accept(sock_fd, (struct sockaddr*)&auth_sock, &addrlen);
        if (tsock == -1) {
            perror("Failure on Accept (accept)");
            goto ssl_exit;
        }
        // Create Thread or Fork. Fork will be simpler... With thread we will need to kill threads before cleanup.
// Launch a new thread per connection
        std::thread([tsock, ctx]() {
            conn_handler(tsock, ctx);
        }).detach(); // detached: cleans up after itself
    }

ssl_exit:
    SSL_CTX_free(ctx);
close_exit:
    close(sock_fd);
exit:
    return EXIT_FAILURE;
}

// Custom Functions
void conn_handler(int conn_socket, SSL_CTX* ctx)
{
    // We have accepted a connection, determine if it is a TLS
    int rcv_cnt = 0;
    char data[6];


    // Something Went Wrong with the RCV Free and Exit (No MSG)
    if ((rcv_cnt = recv(conn_socket, data, TLS_HELLO, MSG_PEEK)) == -1)
        goto close_exit_ch;

    // Check if TLS
    if (rcv_cnt && data[0] == 0x16 && data[1] == 0x03) {
        // We only use SSL for registration. So if we get
        // a non-registration message over SSL, we will
        // Ignore it.
        handle_ssl(conn_socket, ctx);
    } else {
        handle_custom_auth(conn_socket);
    }
close_exit_ch:
    close(conn_socket);
}

void handle_ssl(int conn_socket, SSL_CTX* ctx)
{
    // Create SSL Socket
    SSL *ssl = SSL_new(ctx);

    // Set socket to use SSL context
    SSL_set_fd(ssl, conn_socket);

    // Check if connection will be accepted
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        goto exit_ssl;
    }

    // b_64(username),b_64(key)
    // Handle User Registration
    SSL_write(ssl, "Hi\n", 3);

    // Cleanup SSL connection
exit_ssl:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(conn_socket);
}

void handle_custom_auth(int conn_socket)
{
    // Variables used for Encryption
    unsigned char msg_out[MSG_BUFF_MAX] = {0};
    unsigned char key[AES_256_KEY_SIZE] = {0};
    unsigned char key_c_s[AES_256_KEY_SIZE] = {0};
    unsigned char tag_c[AES_GCM_TAG_SIZE + 1] = {0};
    unsigned char iv_c[AES_GCM_IV_SIZE + 1] = {0};
    unsigned char iv_s[AES_GCM_IV_SIZE + 1] = {0};
    int enc_len;

    // User Message Parsing
    char usrname[MAX_USR_LEN];
    unsigned char nonce[NONCE_BYTE];
    unsigned char msg_buff[MAX_LEN] = {0};

    // Get Time
    time_t currtime = time(NULL);
    if (currtime == ((time_t)-1)) {
        perror("time");
        goto ret_err;
    }

    // Handle First User Message
    handle_usr_1(conn_socket, (char*)msg_buff, usrname, nonce);

    // Generate IVs and Session Key
    if (RAND_bytes(iv_c, AES_GCM_IV_SIZE) != 1 ||
        RAND_bytes(iv_s, AES_GCM_IV_SIZE) != 1 ||
        RAND_bytes(key_c_s, AES_256_KEY_SIZE) != 1) {
        fprintf(stderr, "Error generating IVs or session key\n");
        goto ret_err;
    }

    if (!lookup_user_key(key, usrname)) {
        goto ret_err;
    }

    // First Encrypted Message (Client Side)
    snprintf((char*)msg_buff, sizeof(msg_buff), "%s,%s,%ld,%s",
             usrname, nonce, currtime, key_c_s);
    aes_gcm_enc(msg_buff, strlen((char*)msg_buff), key, iv_s, msg_out, &enc_len, tag_c);

    unsigned char b64_msg1[2048], b64_iv1[64], b64_tag1[64];
    b64_encode(msg_out, b64_msg1, enc_len);
    b64_encode(iv_s, b64_iv1, AES_GCM_IV_SIZE);
    b64_encode(tag_c, b64_tag1, AES_GCM_TAG_SIZE);

    // Second Encrypted Message (Chat Server Side)
    if (!load_chat_key(key, AES_256_KEY_SIZE)) {
        goto ret_err;
    }

    snprintf((char*)msg_buff, sizeof(msg_buff), "%s,%s,%ld",
             usrname, key_c_s, currtime);
    aes_gcm_enc(msg_buff, strlen((char*)msg_buff), key, iv_c, msg_out, &enc_len, tag_c);

    unsigned char b64_msg2[2048], b64_iv2[64], b64_tag2[64];
    b64_encode(msg_out, b64_msg2, enc_len);
    b64_encode(iv_c, b64_iv2, AES_GCM_IV_SIZE);
    b64_encode(tag_c, b64_tag2, AES_GCM_TAG_SIZE);

    // Final Full Message (6-part payload)
    snprintf((char*)msg_out, MSG_BUFF_MAX, "%s,%s,%s,%s,%s,%s",
             b64_msg1, b64_iv1, b64_tag1,
             b64_msg2, b64_iv2, b64_tag2);

    send(conn_socket, msg_out, strlen((char*)msg_out), 0);
    printf("%s\n", (char*)msg_out);

ret_err:
    return;
}
int load_chat_key(unsigned char* key_buff, unsigned size)
{
    int fd;
    fd = open(CLIENT_KEY, O_RDONLY);

    if (fd < 0) {
        perror("Error Opening Client Key File");
        return 0;
    }

    size_t read_res = read(fd, key_buff, size);

    if (read_res != AES_256_KEY_SIZE) {
        perror("Error Extracting From Key File");
        close(fd);
        return 0;
    }

    // printf("Loaded key: ");
    // for (int i = 0; i < AES_256_KEY_SIZE; i++) {
    //     printf("%02x", key_buff[i]);
    // }
    // printf("\n");

    close(fd);
    return 1;
}

// Recieve and Parse user's first message.
// Extract Username and Nonce.
int handle_usr_1(int conn_sock, char* msgbuff, char* username, unsigned char* nonce)
{
    int res = 0;

    // Only handle 4096 max len message
    res = recv(conn_sock, msgbuff, MSG_BUFF_MAX, 0);

    // Parse Out Username
    res = parse_csv_line(msgbuff, MAX_USR_LEN, (unsigned char*)username);
    if (res == 0)
        return 1;

    write(1, username, res);
    write(1, "\n", 1);

    //Parse out Nonce (res + 1) to get to start of next field
    res = parse_csv_line(msgbuff + (res + 1), NONCE_BYTE, (unsigned char*)nonce);
    if (res == 0)
        return 1;

    write(1, nonce, res);
    write(1, "\n", 1);

    return 0;
}

// Messages will be sent with commas separating content
// Example: USR,NONCE
int parse_csv_line(char* buff, int buff_len, unsigned char* trgt)
{
    // Length Var
    int len = 0;
    // Clear out trgt buffer
    trgt[0] = '\0';
    for(len = 0; len < buff_len; len++) {
        if (buff[len] == DELIM || buff[len] == '\n' || buff[len] == '\r') // Not checking on carrage return means we overwrite our stuff.
            break;

        // Would be linear no need for separate trgt index
        trgt[len] = buff[len];
    }

    return len;
}

// Lookup User Key (Leaving this to others since I am lazy)
// During the running of the program we store use keys in a hash map.
// Save use, key to a file
// or multiple files.
int lookup_user_key(unsigned char* key, char* usrname) {
    int fd = open("../Certs/usr_key.bin", O_RDONLY);

    if (fd < 0) {
        perror("open");
        return 0;
    }

    ssize_t read_bytes = read(fd, key, AES_256_KEY_SIZE);
    if (read_bytes != AES_256_KEY_SIZE) {
        perror("read");
        close(fd);
        return 0;
    }

    close(fd);
    return 1;
}

// SSL Functions
SSL_CTX *create_context()
{
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    // Init OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Request TLS Server Methods (Context creation)
    method = TLS_server_method();

    ctx = SSL_CTX_new(method);

    if (!ctx) {
        ERR_print_errors_fp(stderr);
        perror("Error Creating SSL Context (create_context)");
    }
    return ctx; // Handle ctx == null cleanup in main.
}
unsigned configure_context(SSL_CTX* ctx)
{
    // Configure Context with Key and whatnot
    if (SSL_CTX_use_certificate_file(ctx, CRT_PATH, SSL_FILETYPE_PEM) <=0) {
        ERR_print_errors_fp(stderr);    return 0; // handle cleanup in main
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_PATH, SSL_FILETYPE_PEM) <=0) {
        ERR_print_errors_fp(stderr);   return 0;
    }
    return 1;
}

#ifdef OPNSSL3
// AES Functions, based on https://github.com/openssl/openssl/blob/master/demos/cipher/aesgcm.c

static OSSL_LIB_CTX *libctx = NULL;
static const char *propq = NULL;

int aes_gcm_enc(unsigned char* plaintext, unsigned int p_len, unsigned char* key, unsigned char* iv, unsigned char* dest, int* dest_len, unsigned char* tag)
{
    int tmp_dest;

    size_t iv_size = AES_GCM_IV_SIZE;

    // Statically Size the Buffer
    OSSL_PARAM params[2] = {
        OSSL_PARAM_END, OSSL_PARAM_END // Two Placeholders
    };

    // Create Context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return 1;

    EVP_CIPHER* cipher = EVP_CIPHER_fetch(libctx, "AES-256-GCM", propq);
    if (!cipher) {
        perror("Error Fetching Cipher");
        goto cipher_error;
    }

    // Set IV Length Paramiter
    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, &iv_size);


    if (!EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL)) { // Init Context for AES GCM Encryption
        perror("Error Init AES Context w/ Cipher");
        goto cipher_error;
    }

    // Encrypt Plaintext
    if (!EVP_EncryptUpdate(ctx, dest, dest_len, plaintext, p_len)) {
        perror("Error Encrypting Plaintext");
        goto cipher_error;
    }

    // Must call Final before we can get tag!
    if (!EVP_EncryptFinal_ex(ctx, dest, &tmp_dest))
        goto cipher_error;

    *dest_len = *dest_len + tmp_dest;

    // Extract TAG
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag) != 1) {
        perror("Error extracting tag");
        goto cipher_error;
    }

cipher_error:
    // Cleanup
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);

    return 0;

}
#endif

#ifdef OPNSSL1
// Modifications made to OPNSSL3 version based on https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
int aes_gcm_enc(unsigned char* plaintext, unsigned int p_len, unsigned char* key, unsigned char* iv, unsigned char* dest, int* dest_len, unsigned char* tag)
{
    int tmp_dest;

    // Create Context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return 1;

    // Init Cipher
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) { // Init Context for AES GCM Encryption
        perror("Error Init AES Context w/ Cipher");
        goto cipher_error;
    }

    // Configure IV Length
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_SIZE, NULL)) {
        perror("Error Init AES IV Length");
        goto cipher_error;
    }

    // Init Cipher with Key and IV
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) { // Init Context for AES GCM Encryption
        perror("Error Init AES Context w/ Key and IV");
        goto cipher_error;
    }

    // Encrypt Plaintext
    if (!EVP_EncryptUpdate(ctx, dest, dest_len, plaintext, p_len)) {
        perror("Error Encrypting Plaintext");
        goto cipher_error;
    }

    // Must call Final before we can get tag!
    if (!EVP_EncryptFinal_ex(ctx, dest, &tmp_dest))
        goto cipher_error;

    *dest_len = *dest_len + tmp_dest;

    // Extract TAG
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag) != 1) {
        perror("Error extracting tag");
        goto cipher_error;
    }

cipher_error:
    // Cleanup
    EVP_CIPHER_CTX_free(ctx);

    return 0;

}
#endif

void b64_encode(const unsigned char* input,  unsigned char* output, int len)
{
    // Base 64 Encode
    int encode_len = EVP_EncodeBlock(output, input, len);
    output[encode_len] = '\0'; // Null Terminate
    return;
}


void b64_decode(const unsigned char* input,  unsigned char* output, int len)
{
    // Base 64 Encode
    int encode_len = EVP_DecodeBlock(output, input, len);
    output[encode_len] = '\0'; // Null Terminate
    return;
}
