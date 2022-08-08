cd ./filesystem
cp ../code/kmodule/bytedev.ko ./
rm -r ./tmp/
find . | cpio -o --format=newc > ../environ/rootfs.cpio
