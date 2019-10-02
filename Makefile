# Makefile for QEMU.

include config-host.mak
include $(SRC_PATH)/rules.mak

.PHONY: all clean distclean recurse-all 

VPATH=$(SRC_PATH):$(SRC_PATH)/hw


CFLAGS += $(OS_CFLAGS) $(ARCH_CFLAGS)
LDFLAGS += $(OS_LDFLAGS) $(ARCH_LDFLAGS)

CPPFLAGS += -I. -I$(SRC_PATH) -MMD -MP -MT $@
CPPFLAGS += -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
LIBS=
ifdef CONFIG_STATIC
LDFLAGS += -static
endif

LIBS+=$(AIOLIBS)

all: $(TOOLS) $(DOCS) recurse-all

SUBDIR_RULES=$(patsubst %,subdir-%, $(TARGET_DIRS))

subdir-%:
	$(call quiet-command,$(MAKE) -C $* V="$(V)" TARGET_DIR="$*/" all,)

$(filter %-softmmu,$(SUBDIR_RULES)): libqemu_common.a

recurse-all: $(SUBDIR_RULES)

#######################################################################
# BLOCK_OBJS is code used by both qemu system emulation and qemu-img

BLOCK_OBJS=cutils.o qemu-malloc.o
BLOCK_OBJS+=block-cow.o block-qcow.o aes.o block-cloop.o
BLOCK_OBJS+=block-bochs.o
BLOCK_OBJS+=block-qcow2.o block-parallels.o block-nbd.o
BLOCK_OBJS+=nbd.o block.o aio.o

ifdef CONFIG_AIO
BLOCK_OBJS += posix-aio-compat.o
endif
BLOCK_OBJS += block-raw-posix.o

######################################################################
# libqemu_common.a: Target independent part of system emulation. The
# long term path is to suppress *all* target specific code in case of
# system emulation, i.e. a single QEMU executable should support all
# CPUs and machines.

OBJS=$(BLOCK_OBJS)
OBJS+=readline.o console.o

OBJS+=irq.o
OBJS+=i2c.o smbus.o smbus_eeprom.o max7310.o max111x.o wm8750.o
OBJS+=ssd0303.o ssd0323.o ads7846.o stellaris_input.o twl92230.o
OBJS+=tmp105.o lm832x.o
OBJS+=scsi-disk.o cdrom.o
OBJS+=scsi-generic.o
OBJS+=usb.o usb-hub.o usb-$(HOST_USB).o usb-hid.o usb-msd.o usb-wacom.o
OBJS+=usb-serial.o usb-net.o
OBJS+=sd.o ssi-sd.o
OBJS+=bt.o bt-host.o bt-vhci.o bt-l2cap.o bt-sdp.o bt-hci.o bt-hid.o usb-bt.o
OBJS+=buffered_file.o migration.o migration-tcp.o net.o qemu-sockets.o
OBJS+=qemu-char.o aio.o net-checksum.o savevm.o cache-utils.o

ifdef CONFIG_BRLAPI
OBJS+= baum.o
LIBS+=-lbrlapi
endif

OBJS+=migration-exec.o

AUDIO_OBJS = audio.o noaudio.o wavaudio.o mixeng.o
ifdef CONFIG_SDL
AUDIO_OBJS += sdlaudio.o
endif
ifdef CONFIG_OSS
AUDIO_OBJS += ossaudio.o
endif
ifdef CONFIG_COREAUDIO
AUDIO_OBJS += coreaudio.o
AUDIO_PT = yes
endif
ifdef CONFIG_ALSA
AUDIO_OBJS += alsaaudio.o
endif
ifdef CONFIG_DSOUND
AUDIO_OBJS += dsoundaudio.o
endif
ifdef CONFIG_FMOD
AUDIO_OBJS += fmodaudio.o
audio/audio.o audio/fmodaudio.o: CPPFLAGS := -I$(CONFIG_FMOD_INC) $(CPPFLAGS)
endif
ifdef CONFIG_ESD
AUDIO_PT = yes
AUDIO_PT_INT = yes
AUDIO_OBJS += esdaudio.o
endif
ifdef CONFIG_PA
AUDIO_PT = yes
AUDIO_PT_INT = yes
AUDIO_OBJS += paaudio.o
endif
ifdef AUDIO_PT
LDFLAGS += -pthread
endif
ifdef AUDIO_PT_INT
AUDIO_OBJS += audio_pt_int.o
endif
AUDIO_OBJS+= wavcapture.o
OBJS+=$(addprefix audio/, $(AUDIO_OBJS))

ifdef CONFIG_SDL
OBJS+=sdl.o x_keymap.o
endif
ifdef CONFIG_CURSES
OBJS+=curses.o
endif
OBJS+=vnc.o d3des.o

ifdef CONFIG_COCOA
OBJS+=cocoa.o
endif

ifdef CONFIG_SLIRP
CPPFLAGS+=-I$(SRC_PATH)/slirp
SLIRP_OBJS=cksum.o if.o ip_icmp.o ip_input.o ip_output.o \
slirp.o mbuf.o misc.o sbuf.o socket.o tcp_input.o tcp_output.o \
tcp_subr.o tcp_timer.o udp.o bootp.o debug.o tftp.o
OBJS+=$(addprefix slirp/, $(SLIRP_OBJS))
endif

LIBS+=$(VDE_LIBS)

cocoa.o: cocoa.m

sdl.o: sdl.c keymaps.c sdl_keysym.h

sdl.o audio/sdlaudio.o: CFLAGS += $(SDL_CFLAGS)

vnc.o: vnc.c keymaps.c sdl_keysym.h vnchextile.h d3des.c d3des.h

vnc.o: CFLAGS += $(CONFIG_VNC_TLS_CFLAGS)

curses.o: curses.c keymaps.c curses_keys.h

libqemu_common.a: $(OBJS)

#######################################################################
# USER_OBJS is code used by qemu userspace emulation
USER_OBJS=cutils.o  cache-utils.o

libqemu_user.a: $(USER_OBJS)

######################################################################

qemu-img$(EXESUF): qemu-img.o qemu-tool.o osdep.o $(BLOCK_OBJS)

qemu-nbd$(EXESUF):  qemu-nbd.o qemu-tool.o osdep.o $(BLOCK_OBJS)

qemu-img$(EXESUF) qemu-nbd$(EXESUF): LIBS += -lz

clean:
# avoid old build problems by removing potentially incorrect old files
	rm -f config.mak config.h op-i386.h opc-i386.h gen-op-i386.h
	rm -f *.o *.d *.a $(TOOLS) TAGS cscope.* *.pod *~ */*~
	rm -f slirp/*.o slirp/*.d audio/*.o audio/*.d
	for d in $(TARGET_DIRS); do \
	make -C $$d clean || exit 1 ; \
        done

distclean: clean
	rm -f config-host.mak config-host.h $(DOCS)
	rm -f qemu-{doc,tech}.{info,aux,cp,dvi,fn,info,ky,log,pg,toc,tp,vr}
	for d in $(TARGET_DIRS); do \
	rm -rf $$d || exit 1 ; \
        done

KEYMAPS=modifiers en-us mk common 

VERSION ?= $(shell cat VERSION)
FILE = qemu-$(VERSION)

# Include automatically generated dependency files
-include $(wildcard *.d audio/*.d slirp/*.d)
