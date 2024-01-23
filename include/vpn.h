#ifndef VPN_H
#define VPN_H

#define PORT 54344
#define MTU 1400
#define BIND_HOST "0.0.0.0"

// Function declarations
int max(int a, int b);
int tun_alloc();
void run(char *cmd);
void ifconfig();
void setup_route_table();
void cleanup_route_table();
int tcp_bind(struct sockaddr *addr, socklen_t *addrlen);
void cleanup(int signo);
void cleanup_when_sig_exit();
void encrypt(char *plaintext, char *ciphertext, int len);
void decrypt(char *ciphertext, char *plaintext, int len);

#endif