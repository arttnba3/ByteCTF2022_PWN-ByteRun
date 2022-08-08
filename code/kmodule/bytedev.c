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
#include "bytedev.h"

static int __init kernel_module_init(void)
{
    printk(KERN_INFO "[bytedev:] Module loaded. Start to register device...\n");
    major_num = register_chrdev(0, DEVICE_NAME, &a3_module_fo);
    if (major_num < 0)
    {
        printk(KERN_INFO "[bytedev:] Failed to register a major number.\n");
        return major_num;
    }    
    printk(KERN_INFO "[bytedev:] Register complete, major number: %d\n", major_num);

    module_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(module_class))
    {
        unregister_chrdev(major_num, DEVICE_NAME);
        printk(KERN_INFO "[bytedev:] Failed to register class device!\n");
        return PTR_ERR(module_class);
    }
    printk(KERN_INFO "[bytedev:] Class device register complete.\n");

    module_device = device_create(module_class, NULL, MKDEV(major_num, 0), NULL, DEVICE_NAME);
    if (IS_ERR(module_device))
    {
        class_destroy(module_class);
        unregister_chrdev(major_num, DEVICE_NAME);
        printk(KERN_INFO "[bytedev:] Failed to create the device!\n");
        return PTR_ERR(module_device);
    }
    printk(KERN_INFO "[bytedev:] Module register complete.\n");

    __file = filp_open(DEVICE_PATH, O_RDONLY, 0);
    if (IS_ERR(__file))
    {
        device_destroy(module_class, MKDEV(major_num, 0));
        class_destroy(module_class);
        unregister_chrdev(major_num, DEVICE_NAME);
        printk(KERN_INFO "[bytedev:] Unable to change module privilege!\n");
        return PTR_ERR(__file);
    }
    __inode = file_inode(__file);
    __inode->i_mode |= 0666;
    filp_close(__file, NULL);
    printk(KERN_INFO "[bytedev:] Module privilege change complete.\n");

    return 0;
}

static void __exit kernel_module_exit(void)
{
    printk(KERN_INFO "[bytedev:] Start to clean up the module.\n");
    device_destroy(module_class, MKDEV(major_num, 0));
    class_destroy(module_class);
    unregister_chrdev(major_num, DEVICE_NAME);
    printk(KERN_INFO "[bytedev:] Module clean up. See you next time.\n");
}

module_init(kernel_module_init);
module_exit(kernel_module_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("arttnba3");
