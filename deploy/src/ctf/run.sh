#!/bin/sh
/home/ctf/qemu-system-x86_64 \
    -kernel /home/ctf/bzImage \
    -append "root=/dev/ram console=ttyS0 oops=panic panic=1 loglevel=3 quiet kaslr" \
    -cpu kvm64,+smep,+smap \
    -smp cores=2,threads=2 \
    -initrd /home/ctf/rootfs.cpio \
    -m 128M \
    -nographic \
    -device byte_dev-pci \
    -no-reboot \
    -monitor /dev/null
