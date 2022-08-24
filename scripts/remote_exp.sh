#!/bin/sh

cd code/exp
musl-gcc exp.c -o exp -static -masm=intel
python3 exp.py