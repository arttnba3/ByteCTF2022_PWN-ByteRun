#!/bin/sh
cd ./kernel/linux-5.19/
make -j$(nproc)
cp ./arch/x86/boot/bzImage ../../environ/