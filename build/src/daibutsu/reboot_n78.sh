#!/bin/bash

# mount fs as r/w
mount_hfs /dev/disk0s1s1 /mnt1
mount_hfs /dev/disk0s1s2 /mnt2

# remove iboot haxx related nvram values
nvram -d boot-partition
nvram -d boot-ramdisk

# dyld haxx
/usr/bin/haxx_overwrite -n78
