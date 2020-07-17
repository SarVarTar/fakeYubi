#!/bin/bash

set -eux
# dummy_hcd and raw_gadget depend on udc_core
if ! lsmod | grep "udc_core" > /dev/null 2>&1;
then 
  sudo modprobe udc_core
fi
# make and load dummy_hcd for this kernel
cd ./dummy_hcd
if ! lsmod | grep "dummy_hcd" > /dev/null 2>&1;
then
  sudo make
  sudo insmod ./dummy_hcd.ko
fi
cd ../raw_gadget
# make and load raw_gadget for this kernel
if ! lsmod | grep "raw_gadget" > /dev/null 2>&1;
then
  sudo cp raw_gadget.h /usr/include/linux/usb
  sudo make
  sudo insmod ./raw_gadget.ko
fi
sudo ./fakeYubi