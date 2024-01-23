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

#include "ssl.h"
#define AS_CLIENT YES
#include "vpn.h"

int create_socket_server(int port)
{
  int s;
  struct sockaddr_in addr;

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0)
  {
    perror("Unable to create socket");
    exit(EXIT_FAILURE);
  }

  if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
    perror("Unable to bind");
    exit(EXIT_FAILURE);
  }

  if (listen(s, 1) < 0)
  {
    perror("Unable to listen");
    exit(EXIT_FAILURE);
  }

  return s;
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

  ctx = create_context();

  configure_context(ctx);

  sock = create_socket_server(PORT);

  /*
   * tun_buf - memory buffer read from/write to tun dev - is always plain
   * tcp_buf - memory buffer read from/write to tcp fd - is always encrypted
   */
  char tun_buf[MTU], tcp_buf[MTU];
  bzero(tun_buf, MTU);
  bzero(tcp_buf, MTU);

  struct sockaddr_in addr;
  unsigned int len = sizeof(addr);
  SSL *ssl;

  int client = accept(sock, (struct sockaddr *)&addr, &len);
  if (client < 0)
  {
    perror("Unable to accept");
    exit(EXIT_FAILURE);
  }

  ssl = SSL_new(ctx);

  SSL_set_fd(ssl, client);

  if (SSL_accept(ssl) <= 0)
  {
    ERR_print_errors_fp(stderr);
  }

  while (1)
  {

    fd_set readset;
    FD_ZERO(&readset);
    FD_SET(tun_fd, &readset);
    FD_SET(client, &readset);
    int max_fd = max(tun_fd, client) + 1;

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
        // TODO: ignore some errno
        perror("read from tun_fd error");
        break;
      }

      printf("Writing to TCP %d bytes ...\n", r);

      r = SSL_write(ssl, tcp_buf, r);
      if (r < 0)
      {
        // TODO: ignore some errno
        perror("send tcp_fd error");
        break;
      }
    }

    if (FD_ISSET(client, &readset))
    {
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

  SSL_shutdown(ssl);
  SSL_free(ssl);
  close(client);

  close(tun_fd);
  close(sock);

  SSL_CTX_free(ctx);

  cleanup_route_table();

  return 0;
}
