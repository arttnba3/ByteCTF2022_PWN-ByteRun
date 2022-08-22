#!/bin/sh
./qemu-system-x86_64 \
    -kernel ./bzImage \
    -append "root=/dev/ram console=ttyS0 oops=panic panic=1 loglevel=3 quiet kaslr" \
    -cpu kvm64,+smep,+smap \
    -smp cores=2,threads=2 \
    -initrd ./rootfs.cpio \
    -m 128M \
    -nographic \
    -device byte_dev-pci \
    -s \
    -no-reboot \
    -monitor /dev/null
