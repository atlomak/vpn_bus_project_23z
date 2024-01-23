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
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "vpn.h"

int create_socket_client(const char *server_ip, int port)
{
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == -1)
  {
    perror("socket");
    return -1;
  }

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  server_addr.sin_addr.s_addr = inet_addr(server_ip);

  if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
  {
    perror("connect");
    close(sock);
    return -1;
  }

  // Connection is successful
  return sock;
}

int main(int argc, char **argv)
{
  int tun_fd;
  if ((tun_fd = tun_alloc()) < 0)
  {
    return 1;
  }

  ifconfig();
  setup_route_table();
  cleanup_when_sig_exit();

  int sock;
  SSL_CTX *ctx;

  /* Ignore broken pipe signals */
  signal(SIGPIPE, SIG_IGN);

  ctx = SSL_CTX_new(TLS_client_method());
  SSL_CTX_use_certificate_file(ctx, "/home/atlomak/Projects/vpn_bus_project_23z/dummy_certs/cert.pem", SSL_FILETYPE_PEM);

  sock = create_socket_client(SERVER_HOST, PORT);

  /*
   * tun_buf - memory buffer read from/write to tun dev - is always plain
   * tcp_buf - memory buffer read from/write to udp fd - is always encrypted
   */
  char tun_buf[MTU], tcp_buf[MTU];
  bzero(tun_buf, MTU);
  bzero(tcp_buf, MTU);

  struct sockaddr_in addr;
  unsigned int len = sizeof(addr);
  SSL *ssl;

  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, sock);

  if (SSL_connect(ssl) <= 0)
  {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }


  while (1)
  {
    fd_set readset;
    FD_ZERO(&readset);
    FD_SET(tun_fd, &readset);
    FD_SET(sock, &readset);
    int max_fd = max(tun_fd, sock) + 1;

    int r;

    if (-1 == select(max_fd, &readset, NULL, NULL, NULL))
    {
      perror("select error");
      break;
    }

    if (FD_ISSET(tun_fd, &readset))
    {
      r = read(tun_fd, tun_buf, MTU);
      if (r < 0)
      {
        perror("read from tun_fd error");
        break;
      }

      printf("Writing to TCP %d bytes ...\n", r);

      r = SSL_write(ssl, tun_buf, r);
      if (r < 0)
      {
        perror("sendto tcp_fd error");
        break;
      }
    }

    if (FD_ISSET(sock, &readset))
    {
      // r = recvfrom(tcp_fd, tcp_buf, MTU, 0, (struct sockaddr *)&client_addr, &client_addrlen);
      r = SSL_read(ssl, tcp_buf, MTU);
      if (r < 0)
      {
        // TODO: ignore some errno
        perror("recvfrom tcp_fd error");
        break;
      }

      printf("Writing to tun %d bytes ...\n", r);

      r = write(tun_fd, tun_buf, r);
      if (r < 0)
      {
        // TODO: ignore some errno
        perror("write tun_fd error");
        break;
      }
    }
  }

  close(tun_fd);
  close(sock);
  SSL_free(ssl);
  SSL_CTX_free(ctx);

  cleanup_route_table();

  return 0;
}
