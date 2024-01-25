#ifndef VPN_H
#define VPN_H

#include <sys/socket.h>

#define MTU 1500
#define PORT 6553

#define SERVER_HOST "192.168.0.105"
#define BIND_IP "0.0.0.0"

int tun_alloc();

int max(int a, int b);

void run(char *cmd);

void ifconfig_client();

void ifconfig_server();

void setup_route_table_client();

void setup_route_table_server();

void cleanup_route_table_client();

void cleanup_route_table_server();

int tcp_server_bind(struct sockaddr *addr, socklen_t *addrlen, const char *server_host, int port);

int tcp_client_connect(struct sockaddr *addr, socklen_t *addrlen, const char *server_host, int port);

void cleanup_client(int signo);

void cleanup_server(int signo);

void cleanup_when_sig_exit(int client_flag);

#endif /* VPN_H */
