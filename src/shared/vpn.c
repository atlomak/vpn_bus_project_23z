#include "vpn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/socket.h>

int max(int a, int b)
{
    return a > b ? a : b;
}

int tun_alloc()
{
    struct ifreq ifr;
    int fd, e;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
    {
        perror("Cannot open /dev/net/tun");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, "tun0", IFNAMSIZ);

    if ((e = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0)
    {
        perror("ioctl[TUNSETIFF]");
        close(fd);
        return e;
    }

    return fd;
}

void run(char *cmd)
{
    printf("Execute `%s`\n", cmd);
    if (system(cmd))
    {
        perror(cmd);
        exit(1);
    }
}

void ifconfig_client()
{
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "ifconfig tun0 10.8.0.2/16 mtu %d up", MTU);
    run(cmd);
}

void ifconfig_server()
{
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "ifconfig tun0 10.8.0.1/16 mtu %d up", MTU);
    run(cmd);
}

void setup_route_table_client()
{
    run("sysctl -w net.ipv4.ip_forward=1");

    run("iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE");
    run("iptables -I FORWARD 1 -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT");
    run("iptables -I FORWARD 1 -o tun0 -j ACCEPT");
    char cmd[1024];
    // snprintf(cmd, sizeof(cmd), "ip route add %s via $(ip route show 0/0 | sed -e 's/.* via \([^ ]*\).*/\1/')", SERVER_HOST);
    // run(cmd);
    run("ip route add 0/1 dev tun0");
    run("ip route add 128/1 dev tun0");
}

void setup_route_table_server()
{
    run("sysctl -w net.ipv4.ip_forward=1");

    run("iptables -t nat -A POSTROUTING -s 10.8.0.0/16 ! -d 10.8.0.0/16 -m comment --comment 'vpndemo' -j MASQUERADE");
    run("iptables -A FORWARD -s 10.8.0.0/16 -m state --state RELATED,ESTABLISHED -j ACCEPT");
    run("iptables -A FORWARD -d 10.8.0.0/16 -j ACCEPT");
}

void cleanup_route_table_client()
{
    run("iptables -t nat -D POSTROUTING -o tun0 -j MASQUERADE");
    run("iptables -D FORWARD -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT");
    run("iptables -D FORWARD -o tun0 -j ACCEPT");
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "ip route del %s", SERVER_HOST);
    run(cmd);
    run("ip route del 0/1");
    run("ip route del 128/1");
}

void cleanup_route_table_server()
{
    run("iptables -t nat -D POSTROUTING -s 10.8.0.0/16 ! -d 10.8.0.0/16 -m comment --comment 'vpndemo' -j MASQUERADE");
    run("iptables -D FORWARD -s 10.8.0.0/16 -m state --state RELATED,ESTABLISHED -j ACCEPT");
    run("iptables -D FORWARD -d 10.8.0.0/16 -j ACCEPT");
}

int tcp_server_bind(struct sockaddr *addr, socklen_t *addrlen, const char *bind_host, int port)
{
    struct addrinfo hints;
    struct addrinfo *result;
    int sock, flags;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM; // TCP
    hints.ai_protocol = IPPROTO_TCP; // TCP

    if (0 != getaddrinfo(bind_host, NULL, &hints, &result))
    {
        perror("getaddrinfo error");
        return -1;
    }

    if (result->ai_family == AF_INET)
        ((struct sockaddr_in *)result->ai_addr)->sin_port = htons(port);
    else if (result->ai_family == AF_INET6)
        ((struct sockaddr_in6 *)result->ai_addr)->sin6_port = htons(port);
    else
    {
        fprintf(stderr, "unknown ai_family %d", result->ai_family);
        freeaddrinfo(result);
        return -1;
    }
    memcpy(addr, result->ai_addr, result->ai_addrlen);
    *addrlen = result->ai_addrlen;

    if (-1 == (sock = socket(result->ai_family, SOCK_STREAM, IPPROTO_TCP)))
    {
        perror("Cannot create socket");
        freeaddrinfo(result);
        return -1;
    }

    if (0 != bind(sock, result->ai_addr, result->ai_addrlen))
    {
        perror("Cannot bind");
        close(sock);
        freeaddrinfo(result);
        return -1;
    }

    // Listen for incoming connections (specific to TCP)
    if (listen(sock, 1) == -1)
    {
        perror("listen");
        close(sock);
        return -1;
    }

    // if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1)
    // {
    //     perror("fcntl F_SETFL error");
    //     close(sock);
    //     freeaddrinfo(result);
    //     return -1;
    // }

    freeaddrinfo(result);

    return sock;
}

int tcp_client_connect(struct sockaddr *addr, socklen_t *addrlen, const char *server_host, int port)
{
    struct addrinfo hints;
    struct addrinfo *result;
    int sock, flags;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM; // TCP
    hints.ai_protocol = IPPROTO_TCP; // TCP

    if (0 != getaddrinfo(server_host, NULL, &hints, &result))
    {
        perror("getaddrinfo error");
        return -1;
    }

    if (result->ai_family == AF_INET)
        ((struct sockaddr_in *)result->ai_addr)->sin_port = htons(port);
    else if (result->ai_family == AF_INET6)
        ((struct sockaddr_in6 *)result->ai_addr)->sin6_port = htons(port);
    else
    {
        fprintf(stderr, "unknown ai_family %d", result->ai_family);
        freeaddrinfo(result);
        return -1;
    }
    memcpy(addr, result->ai_addr, result->ai_addrlen);
    *addrlen = result->ai_addrlen;

    if (-1 == (sock = socket(result->ai_family, SOCK_STREAM, IPPROTO_TCP)))
    {
        perror("Cannot create socket");
        freeaddrinfo(result);
        return -1;
    }

    // if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1)
    // {
    //     perror("fcntl F_SETFL error");
    //     close(sock);
    //     freeaddrinfo(result);
    //     return -1;
    // }

    if (connect(sock, result->ai_addr, result->ai_addrlen) == -1)
    {
        perror("connect error");
        close(sock);
        freeaddrinfo(result);
        return -1;
    }

    freeaddrinfo(result);

    return sock;
}

void cleanup_client(int signo)
{
    printf("CLEANUP....\n");
    if (signo == SIGHUP || signo == SIGINT || signo == SIGTERM)
    {
        cleanup_route_table_client();
        exit(0);
    }
}

void cleanup_server(int signo)
{
    printf("CLEANUP....\n");
    if (signo == SIGHUP || signo == SIGINT || signo == SIGTERM)
    {
        cleanup_route_table_server();
        exit(0);
    }
}

void cleanup_when_sig_exit(int client_flag)
{
    struct sigaction sa;
    if (client_flag)
    {
        sa.sa_handler = &cleanup_client;
    }
    else
    {
        sa.sa_handler = &cleanup_server;
    }
    sa.sa_flags = SA_RESTART;
    sigfillset(&sa.sa_mask);

    if (sigaction(SIGHUP, &sa, NULL) < 0)
    {
        perror("Cannot handle SIGHUP");
    }
    if (sigaction(SIGINT, &sa, NULL) < 0)
    {
        perror("Cannot handle SIGINT");
    }
    if (sigaction(SIGTERM, &sa, NULL) < 0)
    {
        perror("Cannot handle SIGTERM");
    }
}