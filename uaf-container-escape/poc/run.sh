#!/bin/sh

pkill -9 qemu-system-x86_64

qemu-system-x86_64 \
    -m 700M \
    -smp cores=4 \
    -cpu qemu64,+smep,+smap,+rdrand \
    -kernel bzImage \
    -append "console=ttyS0 root=/dev/sda quiet loglevel=3 oops=panic panic=-1 net.ifnames=0 pti=on" \
    -hda rootfs.qcow2 \
    -snapshot \
    -monitor /dev/null \
    -nographic
