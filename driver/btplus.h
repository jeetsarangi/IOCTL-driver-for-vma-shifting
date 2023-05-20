#ifndef CHARDEV_H
#define CHARDEV_H

#include <linux/ioctl.h>

#define MAJOR_NUM 100
#define DEVNAME "cs614"


#define IOCTL_MVE_VMA_TO _IOR(MAJOR_NUM, 0, char*)
#define IOCTL_MVE_VMA _IOWR(MAJOR_NUM, 1, char*)



#endif
