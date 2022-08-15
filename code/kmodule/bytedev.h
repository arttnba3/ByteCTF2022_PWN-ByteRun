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
#include <linux/types.h>
#include <linux/cdev.h>

#define DEVICE_NAME "bytedev"
#define CLASS_NAME "bytedev_module"

#define DRV_NAME "ByteDance-CTFDevice"

#define BYTEDEV_MMIO_SIZE 0x1000
#define BYTEDEV_PMIO_SIZE 0x10

#define PCI_VENDOR_ID_BYTEDEV 0x4441
#define PCI_DEVICE_ID_BYTEDEV 0x7A9F

#define BYTEDEV_DEVNAME_LENGTH 64
#define BYTEDEV_MAX_DEVICE_NUM 256

#define BYTEDEV_MODE_CHANGE 0x114514
#define BYTEDEV_STATUS_CHANGE 0x1919810

enum BYTEDEV_REG {
    BYTEDEV_REG_MODE = 0,
    BYTEDEV_REG_STATUS,
    BYTEDEV_REG_TX,
    BYTEDEV_REG_RX,
};

struct bytedev_pmio {
    u32     mode;
    u32     status;
    u32     tx_addr;
    u32     rx_addr;
};

struct bytedev_msg {
    struct bytedev_msg  *next;
    size_t size;
    char data[0];
};

struct bytedev {
    struct device   *dev_node;
    struct pci_dev  *pdev;
    int minor_num;
    u64 __iomem  *mmio_addr;
    u64 io_base;
    void *tx_ring_desc;
    void *rx_ring_desc;
    void *data_buf;
};

static struct bytedev *bytedev_arr[BYTEDEV_MAX_DEVICE_NUM];

static struct cdev  bytedev_cdev;
static struct class *bytedev_class;
static int  bytedev_major_num;
static int  bytedev_minor_num[BYTEDEV_MAX_DEVICE_NUM];
static spinlock_t bytedev_lock_minor_num, bytedev_lock_ioctl;

static int bytedev_open(struct inode *i, struct file *f);
static ssize_t bytedev_read(struct file *f, 
                            char __user *buf, 
                            size_t size, 
                            loff_t *loff);
static ssize_t bytedev_write(struct file *f, 
                            const char __user *buf, 
                            size_t size, 
                            loff_t *loff);
static int bytedev_release(struct inode *i, struct file *f);
static long bytedev_ioctl(struct file *f, unsigned int cmd, unsigned long arg);

static struct file_operations bytedev_fops =  {
    .owner          = THIS_MODULE,
    .open           = bytedev_open,
    .release        = bytedev_release,
    .read           = bytedev_read,
    .write          = bytedev_write,
    .unlocked_ioctl = bytedev_ioctl,
};

static int bytedev_pci_probe(struct pci_dev *pdev,
                            const struct pci_device_id *id);

static void bytedev_pci_remove(struct pci_dev *pdev);

static const struct pci_device_id bytedev_ids[] = {
    { PCI_DEVICE(PCI_VENDOR_ID_BYTEDEV, PCI_DEVICE_ID_BYTEDEV) },
    { 0, },
};

static void bytedev_resource_release(struct bytedev *bytedev);
static void bytedev_set_unused_minor_num(int minor);
static int bytedev_get_unused_minor_num(void);

MODULE_DEVICE_TABLE(pci, bytedev_ids);

static struct pci_driver bytedev_driver = {
    .name       = "bytedev",
    .id_table   = bytedev_ids,
    .probe      = bytedev_pci_probe,
    .remove     = bytedev_pci_remove,
};

static int __init bytedev_init(void);
static void __exit bytedev_exit(void);

module_init(bytedev_init);
module_exit(bytedev_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("arttnba3");
