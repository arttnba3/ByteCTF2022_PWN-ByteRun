#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

void errExit(char * msg)
{
    printf("\033[31m\033[1m[x] Error : \033[0m%s\n", msg);
    exit(EXIT_FAILURE);
}

char buf1[0x5000];
char buf2[0x5000];

int main(int argc, char **argv, char **envp)
{
    int dev_fd = open("/dev/bytedev", O_RDWR);
    int res;

    if (dev_fd < 0) {
        errExit("failed to open bytedev!");
    }

    memset(buf1, 'A', 0x1000);
    memset(buf1 + 0x1000, 'B', 0x1000);
    memset(buf1 + 0x2000, 'C', 0x1000);
    memset(buf1 + 0x3000, 'D', 0x1000);
    memset(buf1 + 0x4000, 0, 0x1000);
    memset(buf2, 0, 0x5000);

    puts("[*] start writing...");
    printf("write %d bytes\n", write(dev_fd, buf1, 0x4000));
    puts("[+] write done!");
    puts("[*] start reading...");
    printf("read %d bytes\n", read(dev_fd, buf2, 0x4000));

    res = strcmp(buf1, buf2);
    printf("diff for buf1 and buf2 is at %d\n", res);
    if (res) {
        printf("char for buf1 is %d, for buf2 is %d\n", buf1[res], buf2[res]);
    }

    return 0;
}