#!/bin/bash

./x86_64-softmmu/qemu-system-x86_64 --enable-kvm -m 128M -smp 1 -L pc-bios -hda hd10m.img -vnc 0:0
