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

enum BYTEDEV_REG {
    BYTEDEV_REG_MODE = 0,
    BYTEDEV_REG_STATUS,
    BYTEDEV_REG_TX,
    BYTEDEV_REG_RX,
    BYTEDEV_REG_TYPES,
};

#define BYTEDEV_MMIO_SIZE 0x1000
#define BYTEDEV_PMIO_SIZE (BYTEDEV_REG_TYPES)

#define PCI_VENDOR_ID_BYTEDEV 0x4441
#define PCI_DEVICE_ID_BYTEDEV 0x7A9F

typedef struct BYTEPCIDevRegs {
    uint32_t mode;
    uint32_t status;
    uint32_t tx_addr;
    uint32_t rx_addr;
} BYTEPCIDevRegs;

typedef struct BYTEPCIDevState {
    /*< private >*/
    PCIDevice parent_obj;

    /*< public >*/
    MemoryRegion mmio;
    MemoryRegion pmio;

    BYTEPCIDevRegs regs;
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

    if (size != 4)
        return -1;

    return -1;
}

static uint64_t
byte_dev_pmio_read(void *opaque, hwaddr addr, unsigned size)
{
    BYTEPCIDevState *ds = BYTEDEV_PCI(opaque);

    if (size != 4)
        return -1;

    return -1;
}

static void
byte_dev_mmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    BYTEPCIDevState *ds = BYTEDEV_PCI(opaque);

}

static void
byte_dev_pmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    BYTEPCIDevState *ds = BYTEDEV_PCI(opaque);

    if (size != 4) {
        return ;
    }

    switch (addr) {
        case BYTEDEV_REG_MODE:
            ds->regs.mode = val;
            break;
        case BYTEDEV_REG_STATUS:
            ds->regs.status = val;
            break;
        case BYTEDEV_REG_TX:
            ds->regs.tx_addr = val;
            break;
        case BYTEDEV_REG_RX:
            ds->regs.rx_addr = val;
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
