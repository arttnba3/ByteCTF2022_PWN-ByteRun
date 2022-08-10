/* 
 * ByteCTF2022 kernel module
 * 
 * Copyright (c) 2022 ByteDance Inc.
 * Author: arttnba3 <arttnba@gmail.com>
 * 
 * This module is developed for ByteCTF2022 - Pwn - ByteChain.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/virtio.h>
#include <linux/cred.h>
#include <asm-generic/iomap.h>
#include <linux/cdev.h>
#include "bytedev.h"
#include <linux/io.h>

static int bytedev_open(struct inode *i, struct file *f)
{
    int minor = MINOR(i->i_rdev);
    f->private_data = bytedev_arr[minor];

    printk(KERN_INFO "[bytedev:] bytedev open!\n");

    return 0;
}

static ssize_t bytedev_read(struct file *f, 
                            char __user *buf, 
                            size_t size, 
                            loff_t *loff)
{
    return size;
}
static ssize_t bytedev_write(struct file *f, 
                            const char __user *buf, 
                            size_t size, 
                            loff_t *loff)
{
    return size;
}

static int bytedev_release(struct inode *i, struct file *f)
{
    printk(KERN_INFO "[bytedev:] bytedev close!\n");
    return 0;
}

static long bytedev_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct bytedev *bytedev = f->private_data;
    int err = 0;

    spin_lock(&bytedev_lock_ioctl);

    switch (cmd) {
        case BYTEDEV_MODE_CHANGE:
            if (!uid_eq(current_uid(), GLOBAL_ROOT_UID)) {
                printk(KERN_ERR
                    "[bytedev:] Permission denied, root privilege needed."
                );
                err = -EACCES;
            } else {
                //iowrite32();
                printk(KERN_INFO
                    "[bytedev:] device mode changed."
                );
            }
            break;
        default:
            printk(KERN_ERR "[bytedev:] INVALID COMMAND!");
    }

    spin_unlock(&bytedev_lock_ioctl);

    return err;
}

static void bytedev_set_unused_minor_num(int minor)
{
    spin_lock(&bytedev_lock_minor_num);

    /* You're trying to free an unused minor number, what? */
    if (!bytedev_minor_num[minor]) {
        printk(KERN_ERR "[bytedev:] Unable to free an unused minor num!");
        BUG();
    } else {
        bytedev_minor_num[minor] = 0;
    }

    spin_unlock(&bytedev_lock_minor_num);
}

static int bytedev_get_unused_minor_num(void)
{
    int ret = -1;

    spin_lock(&bytedev_lock_minor_num);

    for (int i = 0; i < BYTEDEV_MAX_DEVICE_NUM; i++) {
        if (!bytedev_minor_num[i]) {
            bytedev_minor_num[i] = 1;
            ret = i;
            break;
        }
    }

    spin_unlock(&bytedev_lock_minor_num);

    return ret;
}

static int bytedev_pci_probe(struct pci_dev *pdev,
                            const struct pci_device_id *id)
{
    struct bytedev *bytedev;
    struct device   *dev_node;
    char dname[BYTEDEV_DEVNAME_LENGTH];
    int minor_num;
    int err;

    printk(KERN_INFO "[bytedev:] ByteDance pci device detected!");

    /* alloc space for bytedev struct*/
    if (!(bytedev = kzalloc(sizeof(struct bytedev), GFP_KERNEL))) {
        err = -ENOMEM;
        goto err_no_mem;
    }

    pci_set_drvdata(pdev, bytedev);

    /* enable the device */
    if ((err = pci_enable_device(pdev))) {
        printk(KERN_ERR "[bytedev:] Cannot enable PCI device, abort.");
        goto err_out_free_dev;
	}

    /* check for MMIO flags on BAR 0 */
    if (!(pci_resource_flags(pdev, 0) & IORESOURCE_MEM)) {
        printk(KERN_ERR 
            "[bytedev:] Cannot find PCI device base address for MMIO, abort.");
        err = -ENODEV;
        goto err_out_disable_pdev;
    }

    /* check for PMIO flags on BAR 1 */
    if (!(pci_resource_flags(pdev, 1) & IORESOURCE_IO)) {
        printk(KERN_ERR 
            "[bytedev:] Cannot find PCI device base address for PMIO, abort.");
        err = -ENODEV;
        goto err_out_disable_pdev;
    }

    /* request for PCI bar spaces */
    if ((err = pci_request_regions(pdev, DRV_NAME))) {
        printk(KERN_ERR "Cannot obtain PCI resources, abort.");
        goto err_out_disable_pdev;
    }

    /* iomap for mmio space */
    bytedev->mmio_addr = pci_ioremap_bar(pdev, 0);
    if (!bytedev->mmio_addr) {
        printk(KERN_ERR "Cannot ioremap for MMIO space, abort.");
        err = -ENOMEM;
        goto err_out_free_region;
    }

    /* get I/O ports base */
    bytedev->io_base = pci_resource_start(pdev, 1);

    /* register device node */
    minor_num = bytedev_get_unused_minor_num();

    if (minor_num < 0) {
        printk(KERN_ERR "[bytedev:] bytedev amount limits!");
        goto err_out_iounmap_mmio;
    }
    else if (minor_num == 0) {
        snprintf(dname, sizeof(dname), "%s", DEVICE_NAME);
    } else{
        snprintf(dname, sizeof(dname), "%s%d", DEVICE_NAME, minor_num);
    }

    dev_node = device_create(bytedev_class, NULL, 
                            MKDEV(bytedev_major_num, minor_num), 
                            NULL, dname);
    if (IS_ERR(dev_node)) {
        printk(KERN_ERR "[bytedev:] Failed to create the device!");
        err = PTR_ERR(dev_node);
        goto err_out_unuse_minor;
    }

    /* info records */
    bytedev->pdev = pdev;
    bytedev->dev_node = dev_node;
    bytedev->minor_num = minor_num;
    bytedev_arr[minor_num] = bytedev;

    printk(KERN_INFO "[bytedev:] bytedev%d register complete.", minor_num);

    return 0;

err_out_unuse_minor:
    bytedev_set_unused_minor_num(minor_num);
err_out_iounmap_mmio:
    pci_iounmap(pdev, bytedev->mmio_addr);
err_out_free_region:
    pci_release_regions(pdev);
err_out_disable_pdev:
    pci_disable_device(pdev);
err_out_free_dev:
    kfree(bytedev);
err_no_mem:
    return err;
}

static void bytedev_resource_release(struct bytedev *bytedev)
{
    printk(KERN_ERR "[bytedev:] release for %x bytedev\n", bytedev->minor_num);

    pci_iounmap(bytedev->pdev, bytedev->mmio_addr);
    pci_release_regions(bytedev->pdev);
    pci_disable_device(bytedev->pdev);
    device_destroy(bytedev_class, 
                    MKDEV(bytedev_major_num, bytedev->minor_num));
    bytedev_set_unused_minor_num(bytedev->minor_num);
    kfree(bytedev);
}

static void bytedev_pci_remove(struct pci_dev *pdev)
{
    struct bytedev *bytedev = pci_get_drvdata(pdev);

    if (bytedev) {
        bytedev_resource_release(bytedev);
    }
}

static int __init bytedev_init(void)
{
    dev_t   device_number;
    int     retval;

    /* init basic args for driver */
    spin_lock_init(&bytedev_lock_minor_num);
    spin_lock_init(&bytedev_lock_ioctl);
    memset(bytedev_minor_num, 0, sizeof(bytedev_minor_num));
    memset(bytedev_arr, 0, sizeof(bytedev_arr));

    /* register chrdev */
    printk(KERN_INFO "[bytedev:] Module loaded. Start to register device...\n");

    retval = alloc_chrdev_region(&device_number, 0, 
                                BYTEDEV_MAX_DEVICE_NUM, DEVICE_NAME);
    if (retval < 0) {
        printk(KERN_ERR "[bytedev:] Failed to register a major number.\n");
        goto err_out;
    }
    bytedev_major_num = MAJOR(device_number);

    printk(KERN_INFO "[bytedev:] Register complete, major number: %d\n", 
            bytedev_major_num);

    /* register cdev */
    cdev_init(&bytedev_cdev, &bytedev_fops);
    retval = cdev_add(&bytedev_cdev, MKDEV(bytedev_major_num, 0), 
            BYTEDEV_MAX_DEVICE_NUM);
    if (retval < 0) {
        printk(KERN_ERR "[bytedev:] Failed to add device!\n");
        goto err_out_unregister_chrdev;
    }

    /* register class */
    bytedev_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(bytedev_class)) {
        printk(KERN_ERR "[bytedev:] Failed to create class device!\n");
        retval = PTR_ERR(bytedev_class);
        goto err_out_unregister_chrdev;
    }
    printk(KERN_INFO "[bytedev:] Class device register complete.\n");

    /* register pci driver */
    return pci_register_driver(&bytedev_driver);

err_out_unregister_chrdev:
    unregister_chrdev_region(device_number, BYTEDEV_MAX_DEVICE_NUM);
err_out:
    return retval;
}

static void __exit bytedev_exit(void)
{
    printk(KERN_INFO "[bytedev:] Start to clean up the module.\n");
    
    for (int i = 0; i < BYTEDEV_MAX_DEVICE_NUM; i++) {
        if (bytedev_minor_num[i]) {
            device_destroy(bytedev_class, MKDEV(bytedev_major_num, i));
        }
    }
    class_destroy(bytedev_class);
    unregister_chrdev_region(MKDEV(bytedev_major_num, 0), 
                            BYTEDEV_MAX_DEVICE_NUM);
    pci_unregister_driver(&bytedev_driver);
    printk(KERN_INFO "[bytedev:] Module clean up. See you next time.\n");
}
