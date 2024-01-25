#include <stdio.h>
#include <sys/socket.h>
#include <openssl/ssl.h>

#include "vpn.h"
#include "tls.h"

#define SERVER 1

int main(int argc, char **argv)
{
    int tun_fd;
    if ((tun_fd = tun_alloc()) < 0)
    {
        return 1;
    }

    ifconfig_server();
    setup_route_table_server();
    cleanup_when_sig_exit(SERVER);

    int socket_fd;
    struct sockaddr_storage client_addr;
    socklen_t client_addrlen = sizeof(client_addr);

    // TCP: Zamiast udp_bind używamy tcp_server_bind lub tcp_client_connect
    if ((socket_fd = tcp_server_bind((struct sockaddr *)&client_addr, &client_addrlen, BIND_IP, PORT)) < 0)
    {
        return 1;
    }

    // OPENSSL TLS
    SSL_CTX *ctx;
    ctx = create_server_context();
    configure_server_context(ctx);

    SSL *ssl;
    ssl = SSL_new(ctx);

    char tun_buf[MTU], tcp_buf[MTU];
    bzero(tun_buf, MTU);
    bzero(tcp_buf, MTU);

    int client_fd = accept(socket_fd, (struct sockaddr *)&client_addr, &client_addrlen);

    SSL_set_fd(ssl, client_fd);

    // Handshake
    if (SSL_accept(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    while (1)
    {
        fd_set readset;
        FD_ZERO(&readset);
        FD_SET(tun_fd, &readset);
        FD_SET(client_fd, &readset);
        int max_fd = max(tun_fd, client_fd) + 1;

        if (-1 == select(max_fd, &readset, NULL, NULL, NULL))
        {
            perror("select error");
            break;
        }

        int r;
        if (FD_ISSET(tun_fd, &readset))
        {
            r = read(tun_fd, tun_buf, MTU);
            if (r < 0)
            {
                perror("read from tun_fd error");
                break;
            }

            memcpy(tcp_buf, tun_buf, r);
            printf("Writing to TCP %d bytes ...\n", r);

            r = SSL_write(ssl, tcp_buf, r);
            if (r < 0)
            {
                perror("send error");
                break;
            }
        }

        if (FD_ISSET(client_fd, &readset))
        {
            r = SSL_read(ssl, tcp_buf, MTU);
            if (r < 0)
            {
                perror("recv error");
                break;
            }

            memcpy(tun_buf, tcp_buf, r);
            printf("Writing to tun %d bytes ...\n", r);

            r = write(tun_fd, tun_buf, r);
            if (r < 0)
            {
                perror("write tun_fd error");
                break;
            }
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);

    close(tun_fd);
    close(client_fd);
    close(socket_fd);

    SSL_CTX_free(ctx);
    cleanup_route_table_server();

    return 0;
}