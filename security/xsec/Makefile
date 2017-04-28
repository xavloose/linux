# grsecurity - access control and security hardening for Linux
# All code in this directory and various hooks located throughout the Linux kernel are
# Copyright (C) 2001-2014 Bradley Spengler, Open Source Security, Inc.
# http://www.grsecurity.net spender@grsecurity.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

KBUILD_CFLAGS = -Werror

obj-y = xsec_chdir.o xsec_chroot.o xsec_exec.o xsec_fifo.o xsec_fork.o \
	xsec_mount.o xsec_sig.o xsec_sysctl.o \
	xsec_time.o xsec_tpe.o xsec_link.o xsec_pax.o xsec_ptrace.o \
	xsec_usb.o xsec_ipc.o xsec_proc.o xsec_tty.o

obj-$(CONFIG_XKERNSEC) = xsec_init.o xsum.o xacl.o xacl_segv.o \
	xacl_cap.o xacl_alloc.o xacl_shm.o xsec_mem.o xacl_fs.o \
	xacl_learn.o xsec_log.o xacl_policy.o
ifdef CONFIG_COMPAT
obj-$(CONFIG_XKERNSEC) = xacl_compat.o
endif

obj-$(CONFIG_XKERNSEC_RESLOG) = xacl_res.o

ifdef CONFIG_NET
obj-y = xsec_sock.o
obj-$(CONFIG_XKERNSEC) = xacl_ip.o
endif

ifndef CONFIG_XKERNSEC
obj-y = xsec_disabled.o
endif

ifdef CONFIG_XKERNSEC_HIDESYM
extra-y := xsec_hidesym.o
$(obj)/xsec_hidesym.o:
	@-chmod -f 500 /boot
	@-chmod -f 500 /lib/modules
	@-chmod -f 500 /lib64/modules
	@-chmod -f 500 /lib32/modules
	@-chmod -f 700 .
	@-chmod -f 700 $(objtree)
	@echo '  xsec: protected kernel image paths'
endif
