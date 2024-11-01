/* 
 * ByteCTF2022 PCI device
 * 
 * Copyright (c) 2022 Bytedance Inc.
 * Author: arttnba3 <arttnba@gmail.com>
 * 
 * This device is developed for ByteCTF2022 - Pwn - ByteChain.
 */

#include "qemu/osdep.h"
#include "hw/pci/pci.h"
#include "hw/qdev-properties.h"
#include "qemu/event_notifier.h"
#include "qemu/module.h"
#include "sysemu/kvm.h"
#include "qom/object.h"
#include "qemu/log.h"

enum BYTEDEV_REG {
    BYTEDEV_REG_MODE = 0,
    BYTEDEV_REG_BLK_IDX,
    BYTEDEV_REG_BLK_STATUS,

    BYTEDEV_REG_UNUSE,
    BYTEDEV_REG_TYPES,
};

enum BYTEDEV_MODE {
    BYTEDEV_MODE_STREAM = 0,
    BYTEDEV_MODE_BLK,

    BYTEDEV_MODE_TYPES,
};

enum BYTEDEV_BLK_STATUS {
    BYTEDEV_BLK_STATUS_INIT = 0,
    BYTEDEV_BLK_STATUS_BUSY,
    BYTEDEV_BLK_STATUS_READY,

    BYTEDEV_BLK_STATUS_TYPES,
};

#define BYTEDEV_SECTOR_SIZE 512
#define BYTEDEV_SECTOR_NUM 256

#define BYTEDEV_MMIO_SIZE (BYTEDEV_SECTOR_SIZE)
#define BYTEDEV_PMIO_SIZE (BYTEDEV_REG_TYPES)

#define PCI_VENDOR_ID_BYTEDEV 0x4441
#define PCI_DEVICE_ID_BYTEDEV 0x7A9F

typedef struct BYTEPCIDevRegs {
    int mode;
    int blk_idx;
    int blk_status;
} BYTEPCIDevRegs;

typedef struct BYTEPCIDevState {
    /*< private >*/
    PCIDevice parent_obj;

    /*< public >*/
    BYTEPCIDevRegs regs;

    MemoryRegion mmio;
    MemoryRegion pmio;

    char *blk_mem[BYTEDEV_SECTOR_NUM];
} BYTEPCIDevState;

typedef struct BYTEPCIDevClass {
    /*< private >*/
    PCIDeviceClass parent;
} BYTEPCIDevClass;

#define TYPE_BYTEDEV_PCI "byte_dev-pci"
#define BYTEDEV_PCI(obj) \
    OBJECT_CHECK(BYTEPCIDevState, (obj), TYPE_BYTEDEV_PCI)
#define BYTEDEV_PCI_GET_CLASS(obj) \
    OBJECT_GET_CLASS(BYTEPCIDevClass, obj, TYPE_BYTEDEV_PCI)
#define BYTEDEV_PCI_CLASS(klass) \
    OBJECT_CLASS_CHECK(BYTEPCIDevClass, klass, TYPE_BYTEDEV_PCI)

static uint64_t
byte_dev_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    BYTEPCIDevState *ds = BYTEDEV_PCI(opaque);

    if (ds->regs.mode != BYTEDEV_MODE_BLK) {
        return -1;
    }

    if (ds->regs.blk_status != BYTEDEV_BLK_STATUS_READY) {
        return -1;
    }

    if ((addr + size) > BYTEDEV_SECTOR_SIZE) {
        return -1;
    }

    return *(uint64_t*)(&ds->blk_mem[ds->regs.blk_idx][addr]);
}

static void
byte_dev_mmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    BYTEPCIDevState *ds = BYTEDEV_PCI(opaque);
    
    if (ds->regs.mode != BYTEDEV_MODE_BLK) {
        return ;
    }

    if (ds->regs.blk_status != BYTEDEV_BLK_STATUS_READY) {
        return ;
    }

    if ((addr + size) > BYTEDEV_SECTOR_SIZE) {
        return ;
    }

    switch (size) {
        case 1:
            *(uint8_t*)(&ds->blk_mem[ds->regs.blk_idx][addr]) = val;
            break;
        case 2:
            *(uint16_t*)(&ds->blk_mem[ds->regs.blk_idx][addr]) = val;
            break;
        case 4:
            *(uint32_t*)(&ds->blk_mem[ds->regs.blk_idx][addr]) = val;
            break;
        case 8:
            *(uint64_t*)(&ds->blk_mem[ds->regs.blk_idx][addr]) = val;
            break;
        default:
            break;
    }
}

static uint64_t
byte_dev_pmio_read(void *opaque, hwaddr addr, unsigned size)
{
    BYTEPCIDevState *ds = BYTEDEV_PCI(opaque);

    if (size != 4) {
        return -1;
    }

    switch (addr) {
        case BYTEDEV_REG_MODE:
            return ds->regs.mode;
        case BYTEDEV_REG_BLK_IDX:
            return ds->regs.blk_idx;
        case BYTEDEV_REG_BLK_STATUS:
            return ds->regs.blk_status;
        default:
            return -1;
    }
}

static void
byte_dev_pmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    BYTEPCIDevState *ds = BYTEDEV_PCI(opaque);
    int op_idx = val;

    if (size != 4) {
        return ;
    }

    smp_mb();

    switch (addr) {
        case BYTEDEV_REG_MODE:
            switch (val) {
                case BYTEDEV_MODE_BLK:
                case BYTEDEV_MODE_STREAM:
                    ds->regs.mode = val;
                    break;
                default:
                    return ;
            }
            break;
        case BYTEDEV_REG_BLK_IDX:
            if (ds->regs.blk_status == BYTEDEV_BLK_STATUS_BUSY) {
                return ;
            }

            if (ds->regs.mode != BYTEDEV_MODE_BLK) {
                return ;
            }
            /** 
             * There's where we made our basic bug: OOB rw forward 
             * Because there's no check for minus idx there.
             * */
            if (op_idx >= BYTEDEV_SECTOR_NUM) {
                return ;
            }

            ds->regs.blk_idx = op_idx;
            ds->regs.blk_status = BYTEDEV_BLK_STATUS_BUSY;
            if (!ds->blk_mem[ds->regs.blk_idx]) {
                ds->blk_mem[ds->regs.blk_idx] = g_malloc(BYTEDEV_SECTOR_SIZE);
            }
            ds->regs.blk_status = BYTEDEV_BLK_STATUS_READY;
            break;
        default:
            break;
    }

}

static const MemoryRegionOps byte_dev_mmio_ops = {
    .read = byte_dev_mmio_read,
    .write = byte_dev_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .max_access_size = 8,
        .min_access_size = 1,
        .unaligned = true,
    },
    .impl = {
        .unaligned = true,
    },
};

static const MemoryRegionOps byte_dev_pmio_ops = {
    .read = byte_dev_pmio_read,
    .write = byte_dev_pmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .max_access_size = 4,
        .min_access_size = 1,
        .unaligned = true,
    },
    .impl = {
        .unaligned = true,
    },
};

static void byte_dev_realize(PCIDevice *pci_dev, Error **errp)
{
    BYTEPCIDevState *ds = BYTEDEV_PCI(pci_dev);

    ds->regs.mode = BYTEDEV_MODE_STREAM;
    ds->regs.blk_idx = 0;
    ds->regs.blk_status = BYTEDEV_BLK_STATUS_INIT;
    memset(ds->blk_mem, 0, sizeof(char*) * BYTEDEV_SECTOR_NUM);

    /* PCI resources register */
    memory_region_init_io(&ds->mmio, OBJECT(ds), &byte_dev_mmio_ops,
                        pci_dev, "byte_dev-mmio", BYTEDEV_MMIO_SIZE);
    pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &ds->mmio);
    memory_region_init_io(&ds->pmio, OBJECT(ds), &byte_dev_pmio_ops,
                        pci_dev, "byte_dev-pmio", BYTEDEV_PMIO_SIZE);
    pci_register_bar(pci_dev, 1, PCI_BASE_ADDRESS_SPACE_IO, &ds->pmio);
}

static void byte_dev_instance_init(Object *obj)
{
    // do something
}

static void byte_dev_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    PCIDeviceClass *pci = PCI_DEVICE_CLASS(oc);

    pci->realize = byte_dev_realize;
    pci->vendor_id = PCI_VENDOR_ID_BYTEDEV;
    pci->device_id = PCI_DEVICE_ID_BYTEDEV;
    pci->revision = 0x81;
    pci->class_id = PCI_CLASS_OTHERS;

    dc->desc = "Bytedance CTF device";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo byte_dev_type_info = {
    .name = TYPE_BYTEDEV_PCI,
    .parent = TYPE_PCI_DEVICE,
    .instance_init = byte_dev_instance_init,
    .instance_size = sizeof(BYTEPCIDevState),
    .class_size = sizeof(BYTEPCIDevClass),
    .class_init = byte_dev_class_init,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    },
};

static void byte_dev_register_types(void) {
    type_register_static(&byte_dev_type_info);
}

type_init(byte_dev_register_types);
