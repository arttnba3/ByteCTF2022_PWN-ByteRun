#!/bin/sh
cd ./filesystem
cp ../code/kmodule/bytedev.ko ./
rm -r ./tmp/
rm ./exp
find . | cpio -o --format=newc > ../environ/rootfs.cpio
