#!/bin/sh
gcc code/exp/exp.c -o filesystem/exp -static -masm=intel
cd ./filesystem
find . | cpio -o --format=newc > ../environ/rootfs.cpio
