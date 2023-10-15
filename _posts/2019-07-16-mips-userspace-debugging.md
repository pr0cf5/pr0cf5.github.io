---
layout: post
title:  "Setting up gdb for MIPS pwnables"
date:   2019-07-16
categories: ctf
---
This week, I decided to solve a challenge on [pwnable.kr](pwnable.kr) called **mipstake**. It is a simple mips userspace pwnable, but since I did not have any MIPS device I went through some painful processes during the debugging environment setup. In this post, I will be introducing the usage of `qemu-system-mips` to emulate MIPS userspace binaries and debug them using GDBserver.

## STEP.1 Install qemu-system-mips
This part is easy. Just execute `apt-get install qemu qemu-system`

## STEP.2 Download the Debian image for MIPS and install the OS
This process can be done with the following script.
```bash
#!/bin/sh
wget http://ftp.debian.org/debian/dists/stable/main/installer-mips/current/images/malta/netboot/initrd.gz
wget http://ftp.debian.org/debian/dists/stable/main/installer-mips/current/images/malta/netboot/vmlinux-4.19.0-5-4kc-malta
qemu-img create -f qcow2 hda.img 20G
qemu-system-mips -M malta \ -m 256 -hda hda.img \ -kernel vmlinux-4.19.0-5-4kc-malta \ -initrd initrd.gz \ -append "console=ttyS0 nokaslr" \ -nographic
```

The last line will pop up a curses based install, where you can just set options as you wish.

## STEP.3 Extract initrd
This can be done with the following script.
```bash
#!/bin/sh
sudo modprobe nbd max_part=63
sudo qemu-nbd -c /dev/nbd0 hda.img
sudo mount /dev/nbd0p1 /mnt
cp -r /mnt/boot/initrd.img-4.19.0-5-4kc-malta .  # copy only initrd.img file
cp -r /mnt/boot .  
sudo umount /mnt
sudo qemu-nbd -d /dev/nbd0
```

## STEP.4 Boot the VM
```bash
#!/bin/sh
qemu-system-mips -M malta \
  -m 256 -hda hda.img \
  -kernel vmlinux-4.19.0-5-4kc-malta \
  -initrd initrd.img-4.19.0-5-4kc-malta \
  -append "root=/dev/sda1 console=ttyS0 nokaslr" \
  -nographic \
  -redir tcp:2222::22 \
  -redir tcp:5555::1234 \
  -redir tcp:5556::9033
```

There are a total of 3 TCP redirections. The first one, *2222::22* is used for ssh and sftp. You can ssh the VM via: `ssh <user>@localhost -p 2222`

The redirection *5555:1234* is for GDBserver, as GDBserver's default port is 1234.

The last redirection *5556:9033* is required to send packets to the userspace binary we will be exploiting. 

## STEP.5 Install gdbserver on the vm

Easy: `apt-get install gdbserver gdb`

## STEP.6 Install GDB-multiarch on the host

Easy again: `apt-get install gdb-multiarch`

## STEP.7 Execute the user program under gdbserver

`gdbserver localhost:1234 <userprog_name>`

## Step.8 Connect to the gdbserver and get debugging

First, execute `gdb-multiarch`. Then execute the following commands. Afterwards, you can add breakpoints, view memory, set follow-fork-mode or whatever. It is convenient to save the necessary commands as a script and use the `source` command in GDB to execute them all at once.

```
set architecture mips
target remote localhost:5555
```

The thing with GDBserver is that all GDB plugins in the host (outside the vm) are applied, so it is possible to use plugins like **pwndbg** and **peda** if you use gdbserver instead of just gdb'ing the binary.