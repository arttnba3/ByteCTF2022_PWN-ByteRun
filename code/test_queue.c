#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>

struct bytedev_data {
    unsigned short len, offset;
    char data[0];
};

#define BYTEDEV_BUF_SIZE (4096 - sizeof(struct bytedev_data))

void errExit(char * msg)
{
    printf("\033[31m\033[1m[x] Error : \033[0m%s\n", msg);
    exit(EXIT_FAILURE);
}

char buf1[0x5000];
char buf2[0x5000];

int main(int argc, char **argv, char **envp)
{
    int dev_fd, res, msqid;
    int sk_sockets[2];
    struct bytedev_data *fake_data;
    cpu_set_t   cpu_set;

    if ((dev_fd = open("/dev/bytedev", O_RDWR)) < 0) {
        errExit("failed to open bytedev!");
    }

    /* to run the exp on the specific core only */
    CPU_ZERO(&cpu_set);
    CPU_SET(0, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    memset(buf1, 0, 0x5000);
    memset(buf2, 0, 0x5000);

    for (int i = 0; i < 100; i++) {
        memset(buf1, 1 + i, 0x4000);
        printf("write %d bytes\n", write(dev_fd, buf1, 0x4000));
        printf("read %d bytes\n", read(dev_fd, buf2, 0x4000));
        if (strcmp(buf1, buf2)) {
            printf("[x] diff at %d\n", strcmp(buf1, buf2));
            errExit("failed to pass copy check!");
        }
    }
}