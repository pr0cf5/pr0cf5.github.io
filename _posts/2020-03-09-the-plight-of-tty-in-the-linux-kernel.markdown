---
layout: post
title:  "The Plight of TTY in the Linux Kernel"
date:   2020-03-09 00:00:00 -0700
categories: ctf
---
# Introduction
I solved a bunch of pwnable tasks from zer0pts CTF 2020. Despite the fact that one person wrote most of the challenges in diverse categories (I think that's really admirable) the quality of tasks was impressive. I hope the organizers get a chance to do it next year too.

One of the tasks was a linux kernel pwnable challenge called 'meow'. I liked this challenge because it helped me discover some good and useful techniques for exploiting linux kernel vulnerabilities under SMEP+SMAP+KPTI. As the title suggests, I made heavy use of the `tty_struct`. By overwriting a `tty_struct`, I could **turn a function pointer overwrite into a stable arbitrary read write primitive.** I am going to discuss how I did it.

But before we get to any exploitation details, I'd like to discuss some tips for solving linux kernel CTF tasks. Unlike when doing kernel research, CTF tasks have some complications, and I'd like to share how I dealt with those issues.

If you want to skip all of this and go to the exploit details, you can use this [teleporter](#exploitation-strategy). If you want to see my exploit code, [take a look](https://github.com/pr0cf5/CTF-writeups/blob/master/2020/zer0pts-ctf/meow/exploit.c).

# CTF Tips for Linux Kernel Tasks
If you download dist files for a linux kernel task, you will usually find 3 things: bzImage, rootfs.cpio, start.sh. The bzImage is a compressed kernel image. rootfs.cpio is the filesystem that the vm will be using. It is similar to virtual HDDs except for the fact that they are not persistent, meaning that changes will not be refelcted to them. The start.sh script usually runs QEMU with the correct arguments.

In order to add a binary and run it in a local VM, you need to decompress the roofs.cpio, compile your binary (statically, as usually rootfs'es don't have libraries), add your binary to the rootfs, and compress it back. If you want to know how to do this, check out my [tutorial](https://github.com/pr0cf5/kernel-exploit-practice/tree/master/building-kernel-module) I wrote last year. Also you can use the scripts `compress.sh` and `decompress.sh` for future challenges.

You can't add a binary to the challenge server this way however. You need to 'cut' the binary into pieces and paste them using shell commands. Since this is non important, I suggest that you modify this [script](https://github.com/pr0cf5/CTF-writeups/blob/master/2020/zer0pts-ctf/meow/solve.py) to make that happen. If you want to do it more quickly, you can use `gzip` to send less bytes.

Also you need to make the binary as small as possible for remote situations. This is difficult because the binary needs to be compiled statically, and the libc static archive is huge, resulting in more than 600000 bytes. Therefore we need to use special build solutions to make builds small. For example, we can use uclibc, a micro-libc for embedded systems. Using it is easy. First, download the uclibc binary from [here](https://www.uclibc.org/downloads/binaries/). When you open it up, it will look sort of like a root filesystem. Copy the source code you wish to compile into the folder, and chroot into it. Then, compile it using `gcc -o exploit -static exploit.c`. Some challenges need to exploit kernel race conditions and might need libpthread, which also works by adding `-pthread`. Due to chroot, `gcc` will be uclibc's implementation of gcc and will link it with uclibc's static archive instead of GNU libc's archive, making it about 10x smaller.

Debugging the kernel is easy. Just add the `-s` argument to QEMU and connect to gdbserver binding at localhost:1234. However, there are no kernel symbols, so setting breakpoints can be frustrating. You will need to boot the VM as root, read /proc/kallsyms and figure out function addresses manually. It might be a good idea to run the VM without KASLR so that breakpoints can be statically embedded in GDBscripts.

Another pain is analyzing structures. It is nearly impossible to manually calculate offsetof(some structure, some member) just by looking at header files, and you'll know why if you try it. Therefore, I suggest you to build a kernel module that does something like the following, and disassemble it to find offsets. For example, compiling the following source emits the assembly code below.

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm_types.h>
#include <linux/slab_def.h>
#include <linux/tty.h>
#include <linux/pipe_fs_i.h>
#include <asm/syscalls.h>

static int __init lkm_example_init(void) {
    printk(KERN_INFO "offset: %lx\n", offsetof(struct task_struct, tasks));
    printk(KERN_INFO "offset: %lx\n", offsetof(struct task_struct, cred));
    printk(KERN_INFO "offset: %lx\n", offsetof(struct task_struct, pid));
    printk(KERN_INFO "offset: %lx\n", offsetof(struct cred, uid));
    printk(KERN_INFO "offset: %lx\n", offsetof(struct cred, gid));
    return 0;
}
static void __exit lkm_example_exit(void) {
    printk(KERN_INFO "Goodbye, World!\n");
}

module_init(lkm_example_init);
module_exit(lkm_example_exit);
```

```asm
0000000000000000 <init_module>:
   0:   be 88 03 00 00          mov    $0x388,%esi
   5:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
   c:   e8 00 00 00 00          callq  11 <init_module+0x11>
  11:   be 28 06 00 00          mov    $0x628,%esi
  16:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
  1d:   e8 00 00 00 00          callq  22 <init_module+0x22>
  22:   be 88 04 00 00          mov    $0x488,%esi
  27:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
  2e:   e8 00 00 00 00          callq  33 <init_module+0x33>
  33:   be 04 00 00 00          mov    $0x4,%esi
  38:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
  3f:   e8 00 00 00 00          callq  44 <init_module+0x44>
  44:   be 08 00 00 00          mov    $0x8,%esi
  49:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
  50:   e8 00 00 00 00          callq  55 <init_module+0x55>
  55:   31 c0                   xor    %eax,%eax
  57:   c3                      retq
```

You can check that the member `pid` is 0x488 bytes away from the start of the `task_struct` structure.

Since linux kernel structures vary dramatically even by slight change of version, it is important to download the exact kernel source. Linux kernel source can be obtained from kernel.org, and you can check the version by running `uname -a` within the vm. In this challenge the kernel version was 4.14.98, so I downloaded the kernel source from `curl -OL https://www.kernel.org/pub/linux/kernel/v4.x/linux-4.19.98.tar.xz` and built my module. If you want to know how to build a kernel module you can check out files from [this](https://github.com/pr0cf5/kernel-exploit-practice/tree/master/building-kernel-module) tutorial. The tutorial uses buildroot but it can be easily applied to pure kernel source codes too.

# Starting Point
The vulnerability is a very obvious heap read/write overflow in a chunk allocated by `kmalloc`. With the read overflow we can disclose a heap pointer. With the write overflow we can manipulate the freelist of kmalloc-0x400 chunks. (kmalloc-0x400 chunks hold objects from size 0x201 to 0x400) 

In kernel heap overflows, the `tty_struct` is often used. This is most likely because it has a good size of 0x2C0 (it might vary among kernel versions) and has a function table, which is easy to trigger. The basic idea behind this is that if you open `/dev/ptmx`, there will be a corresponding device in `/dev/pts/*` where * is an unknown specific number which can be figured out using some system calls. The opening of `/dev/ptmx` calls `alloc_tty_struct`, and the `tty_struct` allocated here is used by the device in `/dev/pts/*`. Therefore if we can forge a `tty_struct` we can get RIP control.

There are many good tutorials on this, both for real world writeups and CTF writeups. [link1](https://github.com/saelo/cve-2014-0038) [link2](https://anhtai.me/linux-kernel-exploit-cheetsheet/) [link3](https://github.com/perfectblue/ctf-writeups/tree/26e73c4818aaef31f5b0e94e81f36f2161713a14/0ctf-finals-2019/Fast%26Furious)

By using a technique called physmap spray, we can make the physical address of an mmap'ed userspace page and the `tty_struct` equal. Therefore reading/writing from the userspace mmap page will also read/write from the `tty_struct` in the kernel heap. This allows us to change `tty_struct` as many times as we want, which is a strong but also realistic primitive.

If you want to know more about this, try to understand [this](https://github.com/De1ta-team/De1CTF2019/tree/master/writeup/pwn/Race) writeup. There are many similarities. Also [this](https://resources.infosecinstitute.com/exploiting-linux-kernel-heap-corruptions-slub-allocator/#gref) might help too.

# Exploitation Strategy
If we didn't have SMAP and KPTI, we can get ring0 code execution very easily. Without SMEP we can jump directly to userspace, and with SMEP we can do kernel ROP. SMAP and KPTI makes things very difficult. To bypass them, we need a good read/write primitive.

I thought for a long time to think how to get a read/write primitive by controlling the `tty_struct`, and came to a rather simple solution. The solution is based on the fact that `ioctl` handlers have 3 arguments, and the last 2 arguments are completely user controllable. (The second one is 32bit though) To be exact, the prototype of `ioctl` is below.
```c
unsigned int ioctl(struct tty_struct *tty, unsigned int cmd, unsigned long arg)
```

So if we overwrite the `ioctl` handler with a gadget like the following, we can get a 4byte arbitrary write primitive.

```
0xffffffff810a0333: mov dword ptr [rdx], esi; ret; 
```

There are 2 reasons for not using `mov qword ptr [rdx], rsi; ret`. First its opcode is longer and therefore it has a low chance of existing in the kernel. Second the second argument, which corresponds to RSI is of type `unsigned int`, so we can only control the lower 4 bytes of it. The last argument is fully controllable though.

Since we can get the return value of `ioctl`, we can use the following gadget as a 4 byte read primitive as well.

```
0xffffffff81051543: mov rax, qword ptr [rdx + 0x28]; ret;
```

Because the return type is `unsigned long` for `ioctl` we can only get the lower 4 bytes of RAX.

You might think that it would be better to use functions such as `write` because its second argument is fully controllable and its return value is 64bit, but functions whose argument types are pointers cannot be used in this manner, because the syscall wrapper functions check if the pointers are userspace pointers, so control will be stopped before jumping to the gadget.

By using the 4 byte R/W primitives we can bypass SMAP+KPTI very easily. I chose the method of traversing `task_struct`s until we got the current task, and overwrote fields of the `cred` structure.

```c
unsigned long cur = init_task, cred;
    unsigned int pid;
    unsigned int this_pid = getpid();
    while(1) {
        pid = read32(cur + PID_OFFSET);
        if (pid == this_pid) {
            cred = read64(cur + CRED_OFFSET);
            LOG("Found current process(pid=%d)'s cred struct %p\n", pid, (void *)cred);
            LOG("original uid=%d, gid=%d. now escalating to root\n", read32(cred + 4), read32(cred + 8));
            write64(0x0, cred + 4);
            write64(0x0, cred + 12);
            write64(0x0, cred + 20);
            write64(0x0, cred + 28);
            LOG("now i am uid=%d\n", getuid());
            break;
        }
        cur = read64(cur + TASKS_OFFSET) - TASKS_OFFSET;
    }
```

# Overall
Using those gadgets is a very CTFish approach, but I think it can be used for real world exploits too. I didn't see a writeup discussing this technique, so I wanted people to know, since it is powerful yet simple to understand. Thanks for reading this.