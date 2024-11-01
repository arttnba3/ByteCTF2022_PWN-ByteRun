#!/bin/sh
cd code/kmodule
make
cd ../../
./scripts/fs_repack.sh
cd code/kmodule
make clean