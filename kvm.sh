#!/bin/bash

./x86_64-softmmu/qemu-system-x86_64 --enable-kvm -bios pc-bios/bios.bin -hda hd10m.img -vnc 0:0
