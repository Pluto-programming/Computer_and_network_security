
// Standard Library Functions
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Socket
#include <sys/socket.h> // Sockets (General)
#include <netinet/in.h> // Internet Sockets

// Linux POSIX API
#include <unistd.h>
// Threading
#include <pthread.h>

// SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

// Custom
#include "auth-var.h"


// Custom Functions -- Separate into separate file later
void conn_handler(int conn_socket, SSL_CTX* ctx);
void handle_ssl(int conn_socket, SSL_CTX* ctx);
void handle_custom_auth(int conn_socket);


// OpenSSL Functions -- Separate Later -- https://wiki.openssl.org/index.php/Simple_TLS_Server
SSL_CTX *create_context();
unsigned configure_context(SSL_CTX* ctx);

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
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR | SO_KEEPALIVE, &opts, sizeof(opts)) == -1) {
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

    // Handle User Registration


    // Cleanup SSL connection
exit_ssl:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(conn_socket);
}
void handle_custom_auth(int conn_socket)
{
    // Determine Auth Scheme
}

// SSL Functions

SSL_CTX *create_context()
{
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    // Request TLS Server Methods (Context creation)
    method = TLS_server_method();

    ctx = SSL_CTX_new(method);

    if (!ctx)
        perror("Error Creating SSL Context (create_context)");
    return ctx; // Handle ctx == null cleanup in main.
}
unsigned configure_context(SSL_CTX* ctx)
{
    // Configure Context with Key and whatnot
    if (SSL_CTX_use_certificate_file(ctx, CRT_PATH, SSL_FILETYPE_PEM) <=0)
        return 0; // handle cleanup in main

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_PATH, SSL_FILETYPE_PEM) <=0)
        return 0;

    return 1;
}