#ifndef SSL_H
#define SSL_H

SSL_CTX *create_context();

void configure_context(SSL_CTX *ctx);

#endif