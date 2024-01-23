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

#include "client.h"
#include "vpn.h"

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

  int tcp_fd;
  struct sockaddr_storage client_addr;
  socklen_t client_addrlen = sizeof(client_addr);

  if ((tcp_fd = tcp_bind((struct sockaddr *)&client_addr, &client_addrlen)) < 0)
  {
    return 1;
  }

  /*
   * tun_buf - memory buffer read from/write to tun dev - is always plain
   * tcp_buf - memory buffer read from/write to udp fd - is always encrypted
   */
  char tun_buf[MTU], tcp_buf[MTU];
  bzero(tun_buf, MTU);
  bzero(tcp_buf, MTU);

  while (1)
  {
    fd_set readset;
    FD_ZERO(&readset);
    FD_SET(tun_fd, &readset);
    FD_SET(tcp_fd, &readset);
    int max_fd = max(tun_fd, tcp_fd) + 1;

    if (-1 == select(max_fd, &readset, NULL, NULL, NULL))
    {
      perror("select error");
      break;
    }

    int r;
    if (listen(tcp_fd, 2))
    {
      perror("Listen failed\n")
    }

    if (FD_ISSET(tun_fd, &readset))
    {
      r = read(tun_fd, tun_buf, MTU);
      if (r < 0)
      {
        // TODO: ignore some errno
        perror("read from tun_fd error");
        break;
      }

      encrypt(tun_buf, tcp_buf, r);
      printf("Writing to TCP %d bytes ...\n", r);

      r = sendto(tcp_fd, tcp_buf, r, 0, (const struct sockaddr *)&client_addr, client_addrlen);
      if (r < 0)
      {
        // TODO: ignore some errno
        perror("sendto tcp_fd error");
        break;
      }
    }

    if (FD_ISSET(tcp_fd, &readset))
    {
      // r = recvfrom(tcp_fd, tcp_buf, MTU, 0, (struct sockaddr *)&client_addr, &client_addrlen);
      r = accept(tcp_fd, tcp_buf, MTU, 0, (struct sockaddr *)&client_addr, &client_addrlen);
      if (r < 0)
      {
        // TODO: ignore some errno
        perror("recvfrom tcp_fd error");
        break;
      }

      decrypt(tcp_buf, tun_buf, r);
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
  close(tcp_fd);

  cleanup_route_table();

  return 0;
}
