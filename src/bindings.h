#include "usbip_common.h"
#include "usbip_network.h"

#undef __USBIP_COMMON_H
#define __packed __attribute__((packed));
#include "k_usbip_common.h"

#include <linux/usb/ch9.h>
#include <linux/hid.h>
#include <errno.h>
