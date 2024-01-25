#ifndef TLS_H
#define TLS_H

#include <openssl/ssl.h>

void configure_server_context(SSL_CTX *ctx);

void configure_client_context(SSL_CTX *ctx);

SSL_CTX *create_server_context();

SSL_CTX *create_client_context();

#endif