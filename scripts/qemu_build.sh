#!/bin/sh
CODE_PATH="./code/qdev"
QEMU_PATH="./qemu/qemu-7.0.0"

if test -e $QEMU_PATH
then
    echo "qemu code exists."
else
    echo "no qemu!" && exit
fi

if test -e $CODE_PATH
then
    echo "bytedev code exists."
else
    echo "no bytedev!" && exit
fi

cp $CODE_PATH/bytedev.c $QEMU_PATH/hw/misc/
cp $CODE_PATH/Kconfig $QEMU_PATH/hw/misc/
cp $CODE_PATH/meson.build $QEMU_PATH/hw/misc/

cd qemu/
# rm -rf ./build/
# mkdir build
cd build
../qemu-7.0.0/configure \
    --enable-kvm \
    --target-list=x86_64-softmmu \
    --disable-debug
if make
then
    cp ./qemu-system-x86_64 ../../environ/
    cp -r ./pc-bios/ ../../environ/
    echo "done!"
else
    echo "failed to make!"
fi
