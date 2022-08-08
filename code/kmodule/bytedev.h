/* 
 * ByteCTF2022 kernel module
 * 
 * Copyright (c) 2022 Bytedance Inc.
 * Author: arttnba3 <arttnba@gmail.com>
 * 
 * This module is developed for ByteCTF2022 - Pwn - ByteChain.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>

#define DEVICE_NAME "bytedev"
#define DEVICE_PATH "/dev/bytedev"
#define CLASS_NAME "bytedev_module"

static int major_num;
static struct class * module_class = NULL;
static struct device * module_device = NULL;
static struct file * __file = NULL;
struct inode * __inode = NULL;

static struct file_operations a3_module_fo = 
{
    .owner = THIS_MODULE
};
