#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

int main(){
    int tun_fd;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    // Use TUN device (IFF_TUN) and provide no headers (IFF_NO_PI)
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    tun_fd = open("/dev/net/tun", O_RDWR);
    ioctl(tun_fd, TUNSETIFF, &ifr);

    printf("TUN file descriptor: %d\n", tun_fd);


    execve("/bin/bash", NULL, NULL);
    return 0;
}