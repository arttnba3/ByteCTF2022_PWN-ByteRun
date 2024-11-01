/* 
 * ByteCTF2022 kernel module
 * 
 * Copyright (c) 2022 ByteDance Corp.
 * Author: arttnba3 <arttnba@gmail.com>
 * 
 * This module is developed for ByteCTF2022 - Pwn - ByteRun.
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
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/dma-mapping.h>

#include "bytedev.h"

static inline uint32_t 
bytedev_get_mode(struct bytedev *dev)
{
    return inl(dev->io_base + BYTEDEV_REG_MODE);
}

static inline void 
bytedev_set_mode(struct bytedev *dev, int mode)
{
    outl(mode, dev->io_base + BYTEDEV_REG_MODE);
}

static inline uint32_t 
bytedev_get_blk_status(struct bytedev *dev)
{
    return inl(dev->io_base + BYTEDEV_REG_BLK_STATUS);
}

static inline uint32_t 
bytedev_get_blk_idx(struct bytedev *dev)
{
    return inl(dev->io_base + BYTEDEV_REG_BLK_IDX);
}

static inline void 
bytedev_set_blk_idx(struct bytedev *dev, int idx)
{
    outl(idx, dev->io_base + BYTEDEV_REG_BLK_IDX);
}

static inline int bytedev_queue_empty(struct bytedev *dev)
{
    return dev->head_idx == dev->tail_idx;
}

static inline int bytedev_queue_full(struct bytedev *dev)
{
    if (((dev->tail_idx + 1) % BYTEDEV_MAX_BUFS) == dev->head_idx) {
        if (dev->data_queue[dev->tail_idx] && 
            dev->data_queue[dev->tail_idx]->len >= BYTEDEV_BUF_SIZE) {
            return 1;
        }
    }

    return 0;
}

static inline int bytedev_queue_last_empty(struct bytedev *dev)
{
    int idx = (dev->tail_idx - 1 + BYTEDEV_MAX_BUFS) % BYTEDEV_MAX_BUFS;

    if (!dev->data_queue[idx]) {
        return 0;
    }

    /* there's where we made our expand bug: integer overflow */
    return (BYTEDEV_BUF_SIZE - dev->data_queue[idx]->len) > 0;

    /* the correct version */
    //return dev->data_queue[idx]->len < BYTEDEV_BUF_SIZE;
}

static int bytedev_open(struct inode *i, struct file *f)
{
    int minor = MINOR(i->i_rdev);
    f->private_data = bytedev_arr[minor];

    printk(KERN_INFO "[bytedev:] bytedev open!\n");

    return 0;
}

static ssize_t bytedev_stream_read(struct file *f, 
                            char __user *buf, 
                            size_t size, 
                            loff_t *loff)
{
    struct bytedev *dev = f->private_data;
    ssize_t ret;
    ssize_t rlen = 0;

    if (bytedev_queue_empty(dev)) {
        ret = -EFAULT;
        goto out;
    }

    while (size > 0) {
        struct bytedev_data *d;
        unsigned int left, clen;

        /**
         * If the data queue is already empty,
         * just quit out is OK.
         */
        if (bytedev_queue_empty(dev)) {
            ret = rlen;
            goto out;
        }

        d = dev->data_queue[dev->head_idx];
        left = d->len - d->offset;
        clen = left > size ? size : left;

        ret = copy_to_user(buf + rlen, &d->data[d->offset], clen);
        if (ret) {
            printk(KERN_ERR "[bytedev:] failed while reading the buffer!");
            goto out;
        }

        size -= clen;
        d->offset += clen;
        rlen += clen;

        if (d->offset == d->len) {
            if (d->len == BYTEDEV_BUF_SIZE) {
                kfree(d);
                /* ther's where we made our basic bug: a UAF */
                //dev->data_queue[dev->head_idx] = NULL;
                dev->head_idx++;
                dev->head_idx %= BYTEDEV_MAX_BUFS;
            } else {
                ret = rlen;
                break;
            }
        }
    }

    ret = rlen;

out:

    return ret;
}

static ssize_t bytedev_blk_read(struct file *f, 
                            char __user *buf, 
                            size_t size, 
                            loff_t *loff)
{
    struct bytedev *dev = f->private_data;
    size_t rlen = size > BYTEDEV_SECTOR_SIZE ? BYTEDEV_SECTOR_SIZE : size;

    if (bytedev_get_mode(dev) != BYTEDEV_MODE_BLK) {
        printk(KERN_ERR "[bytedev:] invalid operation in non-blk mode!");
        return -EFAULT;
    }

    if (bytedev_get_blk_status(dev) != BYTEDEV_BLK_STATUS_READY) {
        printk(KERN_ERR "[bytedev:] device not ready!");
        return -EFAULT;
    }

    if (copy_to_user(buf, dev->mmio_addr, rlen)) {
        printk(KERN_ERR "[bytedev:] failed to read from dev!");
        return -EFAULT;
    }

    return rlen;
}

static ssize_t bytedev_read(struct file *f, 
                            char __user *buf, 
                            size_t size, 
                            loff_t *loff)
{
    struct bytedev *dev = f->private_data;
    ssize_t ret;

    spin_lock(&dev->dev_lock);

    switch (bytedev_get_mode(dev)) {
        case BYTEDEV_MODE_STREAM:
            ret = bytedev_stream_read(f, buf, size, loff);
            break;
        case BYTEDEV_MODE_BLK:
            ret = bytedev_blk_read(f, buf, size, loff);
            break;
        default:
            printk(KERN_ERR "[bytedev:] invalid mode of devices!");
            ret = -EFAULT;
    }

    spin_unlock(&dev->dev_lock);

    return ret;
}

static ssize_t bytedev_stream_write(struct file *f, 
                            const char __user *buf, 
                            size_t size, 
                            loff_t *loff)
{
    struct bytedev *dev = f->private_data;
    ssize_t ret;
    ssize_t wlen = 0;

    if (bytedev_queue_full(dev)) {
        ret = -EFAULT;
        goto out;
    }

    while (size > 0) {
        struct bytedev_data *d;
        unsigned int left, clen;
        int d_idx;

        /**
         * If the data queue is already full,
         * just quit out is OK.
         */
        if (bytedev_queue_full(dev)) {
            ret = wlen;
            goto out;
        }

        /**
         * Fill the unused part of last buffer.
         * We mainly fill the data that is less than BYTEDEV_BUF_SIZE there.
         */
        if (bytedev_queue_last_empty(dev)) {
            int d_idx = 
                    (dev->tail_idx - 1 + BYTEDEV_MAX_BUFS) % BYTEDEV_MAX_BUFS;
            struct bytedev_data *d = dev->data_queue[d_idx];
            unsigned int left = BYTEDEV_BUF_SIZE - d->len;
            unsigned int clen = left > size ? size : left;

            ret = copy_from_user(&d->data[d->len], buf + wlen, clen);
            if (ret) {
                printk(KERN_ERR "[bytedev:] failed while writing the buffer!");
                goto out;
            }

            size -= clen;
            d->len += clen;
            wlen += clen;

            continue;
        }

        /**
         * When we arrive at there, it means that there's no space left
         * on the tail buffer, so we alloc a new buffer there.
         */
        d_idx = dev->tail_idx;
        dev->data_queue[d_idx] = 
                    kmalloc(BYTEDEV_BUF_SIZE + sizeof(struct bytedev_data), 
                            GFP_KERNEL_ACCOUNT);
        dev->tail_idx++;
        dev->tail_idx %= BYTEDEV_MAX_BUFS;

        d = dev->data_queue[d_idx];
        d->len = 0;
        d->offset = 0;

        /* Copy the data there */
        left = BYTEDEV_BUF_SIZE;
        clen = left > size ? size : left;

        ret = copy_from_user(&d->data[d->len], buf + wlen, clen);
        if (ret) {
            printk(KERN_ERR "[bytedev:] failed while writing the buffer!");
            goto out;
        }

        size -= clen;
        d->len += clen;
        wlen += clen;
    }

    ret = wlen;

out:

    return ret;
}

static ssize_t bytedev_blk_write(struct file *f, 
                            const char __user *buf, 
                            size_t size, 
                            loff_t *loff)
{
    struct bytedev *dev = f->private_data;
    size_t wlen = size > BYTEDEV_SECTOR_SIZE ? BYTEDEV_SECTOR_SIZE : size;

    if (bytedev_get_mode(dev) != BYTEDEV_MODE_BLK) {
        printk(KERN_ERR "[bytedev:] invalid operation in non-blk mode!");
        return -EFAULT;
    }

    if (bytedev_get_blk_status(dev) != BYTEDEV_BLK_STATUS_READY) {
        printk(KERN_ERR "[bytedev:] device not ready!");
        return -EFAULT;
    }

    if (copy_from_user(dev->mmio_addr, buf, wlen)) {
        printk(KERN_ERR "[bytedev:] failed to write on dev!");
        return -EFAULT;
    }

    return wlen;
}

static ssize_t bytedev_write(struct file *f, 
                            const char __user *buf, 
                            size_t size, 
                            loff_t *loff)
{
    struct bytedev *dev = f->private_data;
    ssize_t ret;

    spin_lock(&dev->dev_lock);

    switch (bytedev_get_mode(dev)) {
        case BYTEDEV_MODE_STREAM:
            ret = bytedev_stream_write(f, buf, size, loff);
            break;
        case BYTEDEV_MODE_BLK:
            ret = bytedev_blk_write(f, buf, size, loff);
            break;
        default:
            printk(KERN_ERR "[bytedev:] invalid mode of devices!");
            ret = -EFAULT;
    }

    spin_unlock(&dev->dev_lock);

    return ret;
}

static int bytedev_release(struct inode *i, struct file *f)
{
    printk(KERN_INFO "[bytedev:] bytedev close!\n");
    return 0;
}

static long bytedev_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct bytedev *dev = f->private_data;
    int err = 0;

    spin_lock(&dev->dev_lock);

    switch (cmd) {
        case BYTEDEV_MODE_CHANGE:
            if (!uid_eq(current_uid(), GLOBAL_ROOT_UID)
                || !uid_eq(current_euid(), GLOBAL_ROOT_UID)) {
                printk(KERN_ERR
                    "[bytedev:] Permission denied, root privilege needed."
                );
                err = -EACCES;
            } else {
                bytedev_set_mode(dev, arg);
                printk(KERN_INFO "[bytedev:] device mode changed." );
            }
            break;
        case BYTEDEV_BLK_IDX_CHANGE:
            if(bytedev_get_mode(dev) != BYTEDEV_MODE_BLK) {
                printk(KERN_ERR "[bytedev:] device not in blk-mode!");
                err = -EFAULT;
            } else {
                bytedev_set_blk_idx(dev, arg);
            }
            break;
        default:
            printk(KERN_ERR "[bytedev:] INVALID COMMAND!");
            err = -EFAULT;
    }

    spin_unlock(&dev->dev_lock);

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
    struct bytedev *bdev;
    struct device   *dev_node;
    char dname[BYTEDEV_DEVNAME_LENGTH];
    int minor_num;
    int err;

    printk(KERN_INFO "[bytedev:] ByteDance pci device detected!");

    /* alloc space for bytedev struct*/
    if (!(bdev = kzalloc(sizeof(struct bytedev), GFP_KERNEL))) {
        err = -ENOMEM;
        goto err_no_mem;
    }

    pci_set_drvdata(pdev, bdev);

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
    bdev->mmio_addr = pci_ioremap_bar(pdev, 0);
    if (!bdev->mmio_addr) {
        printk(KERN_ERR "Cannot ioremap for MMIO space, abort.");
        err = -ENOMEM;
        goto err_out_free_region;
    }

    /* get I/O ports base */
    bdev->io_base = pci_resource_start(pdev, 1);

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

    /* other data init */
    spin_lock_init(&bdev->dev_lock);
    memset(bdev->data_queue, 0, sizeof(void*) * BYTEDEV_MAX_BUFS);
    bdev->head_idx = 0;
    bdev->tail_idx = 0;

    /* info records */
    bdev->pdev = pdev;
    bdev->dev_node = dev_node;
    bdev->minor_num = minor_num;
    bytedev_arr[minor_num] = bdev;

    printk(KERN_INFO "[bytedev:] bytedev%d register complete.", minor_num);

    return 0;

err_out_unuse_minor:
    bytedev_set_unused_minor_num(minor_num);
err_out_iounmap_mmio:
    pci_iounmap(pdev, bdev->mmio_addr);
err_out_free_region:
    pci_release_regions(pdev);
err_out_disable_pdev:
    pci_disable_device(pdev);
err_out_free_dev:
    kfree(bdev);
err_no_mem:
    return err;
}

static void bytedev_resource_release(struct bytedev *bytedev)
{
    printk(KERN_ERR "[bytedev:] release for %x bytedev\n", bytedev->minor_num);

    pci_iounmap(bytedev->pdev, bytedev->mmio_addr);
    pci_release_regions(bytedev->pdev);
    pci_disable_device(bytedev->pdev);
    /**
     * TODO: fix the NULL-dereference bug there
     */
    /*device_destroy(bytedev_class, 
                    MKDEV(bytedev_major_num, bytedev->minor_num));*/
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
    class_destroy(bytedev_class);
    unregister_chrdev_region(MKDEV(bytedev_major_num, 0), 
                            BYTEDEV_MAX_DEVICE_NUM);
    pci_unregister_driver(&bytedev_driver);
    printk(KERN_INFO "[bytedev:] Module clean up. See you next time.\n");
}
