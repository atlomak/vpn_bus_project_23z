#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/select.h>

#include "vpn.h"
#include "client.h"


int max(int a, int b)
{
    return a > b ? a : b;
}

/*
 * Create VPN interface /dev/tun0 and return a fd
 */
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

/*
 * Execute commands
 */
void run(char *cmd)
{
    printf("Execute `%s`\n", cmd);
    if (system(cmd))
    {
        perror(cmd);
        exit(1);
    }
}

/*
 * Configure IP address and MTU of VPN interface /dev/tun0
 */
void ifconfig()
{
    char cmd[1024];

#ifdef AS_CLIENT
    snprintf(cmd, sizeof(cmd), "ifconfig tun0 10.8.0.2/16 mtu %d up", MTU);
#else
    snprintf(cmd, sizeof(cmd), "ifconfig tun0 10.8.0.1/16 mtu %d up", MTU);
#endif
    run(cmd);
}

/*
 * Setup route table via `iptables` & `ip route`
 */
void setup_route_table()
{
    run("sysctl -w net.ipv4.ip_forward=1");

#ifdef AS_CLIENT
    run("iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE");
    run("iptables -I FORWARD 1 -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT");
    run("iptables -I FORWARD 1 -o tun0 -j ACCEPT");
    char cmd[1024];
    run(cmd);
    run("ip route add 0/1 dev tun0");
    run("ip route add 128/1 dev tun0");
#else
    run("iptables -t nat -A POSTROUTING -s 10.8.0.0/16 ! -d 10.8.0.0/16 -m comment --comment 'vpndemo' -j MASQUERADE");
    run("iptables -A FORWARD -s 10.8.0.0/16 -m state --state RELATED,ESTABLISHED -j ACCEPT");
    run("iptables -A FORWARD -d 10.8.0.0/16 -j ACCEPT");
#endif
}

/*
 * Cleanup route table
 */
void cleanup_route_table()
{
#ifdef AS_CLIENT
    run("iptables -t nat -D POSTROUTING -o tun0 -j MASQUERADE");
    run("iptables -D FORWARD -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT");
    run("iptables -D FORWARD -o tun0 -j ACCEPT");
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "ip route del %s", SERVER_HOST);
    run(cmd);
    run("ip route del 0/1");
    run("ip route del 128/1");
#else
    run("iptables -t nat -D POSTROUTING -s 10.8.0.0/16 ! -d 10.8.0.0/16 -m comment --comment 'vpndemo' -j MASQUERADE");
    run("iptables -D FORWARD -s 10.8.0.0/16 -m state --state RELATED,ESTABLISHED -j ACCEPT");
    run("iptables -D FORWARD -d 10.8.0.0/16 -j ACCEPT");
#endif
}

/*
 * Bind TCP port
 */
int tcp_bind(struct sockaddr *addr, socklen_t *addrlen)
{
    struct addrinfo hints;
    struct addrinfo *result;
    int sock, flags;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

#ifdef AS_CLIENT
    const char *host = SERVER_HOST;
#else
    const char *host = BIND_HOST;
#endif
    if (0 != getaddrinfo(host, NULL, &hints, &result))
    {
        perror("getaddrinfo error");
        return -1;
    }

    if (result->ai_family == AF_INET)
        ((struct sockaddr_in *)result->ai_addr)->sin_port = htons(PORT);
    else if (result->ai_family == AF_INET6)
        ((struct sockaddr_in6 *)result->ai_addr)->sin6_port = htons(PORT);
    else
    {
        fprintf(stderr, "unknown ai_family %d", result->ai_family);
        freeaddrinfo(result);
        return -1;
    }
    memcpy(addr, result->ai_addr, result->ai_addrlen);
    *addrlen = result->ai_addrlen;

    if (-1 == (sock = socket(result->ai_family, SOCK_STREAM, 0)))
    {
        perror("Cannot create socket");
        freeaddrinfo(result);
        return -1;
    }

#ifndef AS_CLIENT
    if (0 != bind(sock, result->ai_addr, result->ai_addrlen))
    {
        perror("Cannot bind");
        close(sock);
        freeaddrinfo(result);
        return -1;
    }
#endif

    freeaddrinfo(result);

    flags = fcntl(sock, F_GETFL, 0);
    if (flags != -1)
    {
        if (-1 != fcntl(sock, F_SETFL, flags | O_NONBLOCK))
            return sock;
    }
    perror("fcntl error");

    close(sock);
    return -1;
}

/*
 * Catch Ctrl-C and `kill`s, make sure route table gets cleaned before this process exit
 */
void cleanup(int signo)
{
    printf("Goodbye, cruel world....\n");
    if (signo == SIGHUP || signo == SIGINT || signo == SIGTERM)
    {
        cleanup_route_table();
        exit(0);
    }
}

void cleanup_when_sig_exit()
{
    struct sigaction sa;
    sa.sa_handler = &cleanup;
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

/*
 * For a real-world VPN, traffic inside UDP tunnel is encrypted
 * A comprehensive encryption is not easy and not the point for this demo
 * I'll just leave the stubs here
 */
void encrypt(char *plantext, char *ciphertext, int len)
{
    memcpy(ciphertext, plantext, len);
}

void decrypt(char *ciphertext, char *plantext, int len)
{
    memcpy(plantext, ciphertext, len);
}