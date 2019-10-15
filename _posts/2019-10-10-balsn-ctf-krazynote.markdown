---
layout: post
title: Balsn CTF 2019 - KrazyNote
date: 2019-10-10
categories: ctf
---
I solved a challenge called KrazyNote on Balsn CTF 2019. As expected, Balsn CTF was extremely hard, and the pwnable challenge with the most solves was KrazyNote. It had about 10 solves, which is quite a lot but I learned a lot of important stuff through this challenge so I decided to publish a write-up for it.

It was my first time doing a non-userspace pwn challenge in a CTF, so I did a lot of stupid and useless things and wasted a lot of time. I spent about 30 hours, including sleep and break for this challenge.

My goal is to try to describe the solving process as detailed as possible, so that people who don't have experience in kernel exploitation can understand it as well. I will also add links to resources I've used to solve it.

## Some Background Information

### task_struct and cred_struct

The essence of kernel pwning is not so different from userspace pwning. With flaws in the program, we get arbitrary memory read/write or control flow hijack and do what we want. However, the final goal of kernel exploitation is different from that of userspace exploitation.

In userspace, our final goal is to execute `system("/bin/sh")` usually. In kernel space, exploitation goal is to get uid0. There are many ways to do this, but two methods are common:

```
1. overwrite the data structure that stores uid, gid, euid, ... to 0
2. execute commit_cred(prepare_kernel_creds(0))
```

In the linux kernel, every user process (and thread) is actually a kernel thread. When a process executes a system call or an interrupt instruction, it switches to kernel mode and executes kernel code, and afterwards returns back to user mode. Each kernel thread's information, such as credentials (uid), execution state, ptrace information, ...etc is saved at a structure at the bottom of each threads' stack. It is called the `task_struct` structure. Inside the `task_struct` there is a pointer to a `cred_struct`, which stores the user credentials. The `cred_struct` is allocated via kmalloc, so it is a heap pointer.

```c
struct cred {
	atomic_t	usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
	atomic_t	subscribers;	/* number of processes subscribed */
	void		*put_addr;
	unsigned	magic;
#define CRED_MAGIC	0x43736564
#define CRED_MAGIC_DEAD	0x44656144
#endif
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
	kernel_cap_t	cap_ambient;	/* Ambient capability set */
#ifdef CONFIG_KEYS
	unsigned char	jit_keyring;	/* default keyring to attach requested
					 * keys to */
	struct key	*session_keyring; /* keyring inherited over fork */
	struct key	*process_keyring; /* keyring private to this process */
	struct key	*thread_keyring; /* keyring private to this thread */
	struct key	*request_key_auth; /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
	void		*security;	/* subjective LSM security */
#endif
	struct user_struct *user;	/* real user ID subscription */
	struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
	struct group_info *group_info;	/* supplementary groups for euid/fsgid */
	/* RCU deletion */
	union {
		int non_rcu;			/* Can we skip RCU deletion? */
		struct rcu_head	rcu;		/* RCU deletion hook */
	};
} __randomize_layout;
```

So if we have arbitrary memory read/write and we can locate a cred structure for a particular process, we can make its uid become 0. 

Another way is to execute the code `commit_cred(prepare_kernel_creds(0))`. Basically this will automatically locate the task_struct of the current thread and change its cred_struct to a new one with uid 0.

### kernel memory protections

On modern operating system, kernelspace and userspace is strictly separated. Obviously, userspace programs should not have access to kernel memory. The opposite is a bit ambiguous. There are definitely instances where kernel code must access data in userland, such as in a system call, where the system call must read or write to userland addresses.

If we have the primitive of overwriting a function pointer in kernel space, how would you exploit it? In userspace exploits when we had RIP control we called these exploit techniques return-to-something, such as in return-to-shellcode, return-to-libc, or return-oriented-programming. In kernelspace, we can think of something like return-to-userspace. Basically it means by controlling RIP in kernelspace we can force it to jump to code in userspace, which is user-controllable. We can place a shellcode that does `commit_cred(prepare_kernel_creds(0))` in address 0xdead000 and change a function pointer 0xdead000 and trigger it. 

A good mitigation against this kind of exploit is SMEP. (supervisor mode execution prevention) As you can infer from its acronym, it prevents the execution of data in usermode from kernelspace. 

To bypass this, hackers thought of kernel ROP, where the function pointer is overwritten to gadget that changes the stack pointer to a userspace address, (stack pivot) To protect against kernel ROP attacks, SMAP (supervisor mode access prevention) was introduced. This prevents dereferencing userspace addresses directly from kernel space.

One question should emerge: in system calls sometimes kernel code must fetch data from userspace. Under SMAP, how should this be done? It is done with a special API called `copy_from_user` and `copy_to_user`. It works very similarly to `memcpy` except it overrides SMEP/SMAP and has many underlying, complex memory mechanisms.

### paging and virtual memory

In modern systems an ingenious abstraction called virtual memory is applied. The core concepts are long enough to explain in a book, I'll only be explaining the basics.

The kernel stores memory in mainly two regions: RAM and the swap partition. Memory that will be used right now will be stored in the RAM, and memory that will not be used right now will be 'swapped out' to the swap parition. The swapping in and swapping out is managed by the kernel.

If the memory is stored in RAM, the kernel must find a way to locate it within RAM. The offset of data within RAM is called a physical address. 

However, for many reasons programs do not use physical addresses. They use virtual addresses, and each virtual address corresponds to a physical address. The data structure that tells the relationship between a virtual address and a physical address is called a page table. Basically a page table is a lookup table for virtual addresses.

A page is a unit of virtual memory, which is normally 0x1000 bytes. A frame is a unit of physical memory, which is also 0x1000 bytes. In a page table each virtual page is mapped to a physical frame. Since x64 has `2**64` different addresses, there can be a total of `2**52` pages. That means a page table must have `2**52` entires, which is too huge. 

To prevent the page table from being too huge, people thought of something called multi-level paging. The basic idea is similar to a tree-based-search. Each page table entry points to a lower-level page table instead of pointing to the page table itself. You can check [this](https://0xax.gitbooks.io/linux-insides/content/Theory/linux-theory-1.html) out to fully understand multilevel paging.

An important concept here is that each page table entry also contains the page permissions such as READ/WRITE/EXECUTE. Therefore altering page table entires will cause the page table permissions to change.

## Analysis
We are given four files, `initramfs.cpio.gz`, 'bzImage', 'run.sh' and 'note.ko'. Let's first look at `run.sh`, it is the bash script that turns on the qemu vm.

```bash
#!/bin/bash
qemu-system-x86_64 \
    -m 128M \
    -nographic \
    -kernel ./bzImage \
    -append 'console=ttyS0 loglevel=3 oops=panic panic=1 kaslr' \
    -monitor /dev/null \
    -initrd ./initramfs.cpio.gz  \
    -smp cores=4,threads=4 \
    -cpu kvm64,smep,smap \
```

Basically the script executes `qemu-system-x86_64` with a lot of arguments. The first one is the `-m` option, which specifies the memory size. In this case, it is 128MB. The `-kernel` option specifies the kernel image file, which in this case is the bzImage file provided. Now we know the bzImage file is the kernel image. Doing `file ./bzImage` shows us `bzImage: Linux kernel x86 boot executable bzImage, version 5.1.9 (billy@Billy) #1 SMP Fri Jun 14 17:32:01 CST 2019, RO-rootFS, swap_dev 0x5, Normal VGA`, which proves we are right. The `-initrd` option specifies the initial filesystem, which is `initramfs.cpio.gz`. Basically, it is a compressed root filesystem, whose format is CPIO. Like any compression formats such as ZIP or RAR we can decompress CPIO files using archive utility in ubuntu desktop. You can also use the following script as well.

```bash
#!/bin/sh
mkdir -p initramfs
cd initramfs
gzip -cd ../initramfs.cpio.gz | cpio -imd --quiet
```

Basically this script puts all the contents of initramfs.cpio.gz to the initramfs directory. 

In the filesystem, there aren't that many important files, but there are a few notable points.

```
1. basic utilities such as gzip, sha256sum, strings, ... are provided in the /bin directory
2. glibc and pthread libraries as well as gcc is not provided.
3. In the /home/note directory there is the file note.ko, which is identical to the one provided to us.
4. There is the file /etc/init.d/rcS which looks like it is custom-written.
5. There are two users, root and note. root has uid 0 and note has uid 1000. note does not have read access to the /flag file.
```

The content of the /etc/init.d/rcS file is the follwing:
```bash
#!/bin/sh

mount -t proc none /proc
mount -t devtmpfs none /dev
mkdir /dev/pts
mount /dev/pts

echo 1 > /proc/sys/kernel/dmesg_restrict
echo 1 > /proc/sys/kernel/kptr_restrict
cd /home/note
insmod note.ko
chmod 644 /dev/note
setsid cttyhack setuidgid 1000 sh
poweroff -f
```

It mounts procfs, devfs, disables dmesg and kptr and `insmod`'s note.ko. Insmod means install-module, which is installing a LKM (Linux-Kernel-Mdoule). A Linux-Kernel-Module is a piece of code that can be added to kernelspace, and there are many purposes for this. It can be used to implemenet a character device driver(ptmx, urandom, null), a virtual filesystem, or a network driver. In this case, note.ko is a kernel module used to implement a character device driver. (which cannot be directly realized just by looking at the rcS file but most CTF challenges test us to pwn character device drivers because they are simple to implement and understand) LKMs are also widely used for implementing rootkits and kernel backdoors, so it is an important concept in linux information security. 

Afterwards it spawns a shell with uidgid 1000, so we can't read the flag with this shell. We need to gain root by pwning the LKM, and probably we need to change our creds to uid0 or get ring0 ACE (Arbitrary-Code-Execution) and do `commit_cred(prepare_kernel_creds(0))`. (note.ko) 

Just like we do in any other pwn challenge, we analyze the provided file for vulnerabilites. First we look at the `module_init` function in note.ko. As implied in its name, this function should be called when the module is initialized. The logic is very simple.

```c
void init_module()
{
  bufPtr = bufStart;
  return misc_register(&dev);
}
```

It initializes a global `char *` pointer to the address of a `char[]` buffer, and calls `misc_register` with a global structure, `dev`. `misc_register` is an external call, it is probably within the code of the linux kernel. We check its API documentation to figure out what it does, as well as what `dev` is. With a brief google search, we get [this](https://www.kernel.org/doc/htmldocs/kernel-api/API-misc-register.html) page, which tells us that `dev` is a `struct miscdevice` structure. In memory, `dev` looks something like this:


```c
struct ??? {
	int a; /* initialized to 0 */
	char *b; /* a pointer to "note".
	void *c; /* a pointer to something that looks like a function table */

};
```

More google search and we get this:

```c
struct miscdevice  {
	int minor;
	const char *name;
	const struct file_operations *fops;
	struct list_head list;
	struct device *parent;
	struct device *this_device;
	const struct attribute_group **groups;
	const char *nodename;
	umode_t mode;
};
```

So a is `minor`, b is `name`, and c is `fops`, which looks like this:

```c
struct file_operations {
	struct module *owner;
	loff_t (*llseek) (struct file *, loff_t, int);
	ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
	ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
	ssize_t (*read_iter) (struct kiocb *, struct iov_iter *);
	ssize_t (*write_iter) (struct kiocb *, struct iov_iter *);
	int (*iopoll)(struct kiocb *kiocb, bool spin);
	int (*iterate) (struct file *, struct dir_context *);
	int (*iterate_shared) (struct file *, struct dir_context *);
	__poll_t (*poll) (struct file *, struct poll_table_struct *);
	long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
	long (*compat_ioctl) (struct file *, unsigned int, unsigned long);
	
	... truncated
};
```
One thing about linux kernel module analysis is that there are so many huge structures which are sometimes nested. Google search is always good for these recursive structures. 
From the `file_operations` structure above, we can check that only `open` and `unlocked_ioctl` is defined for the module, and all else is set to NULL. 

But what's the difference between `unlocked_ioctl` and `compat_ioctl`? You can check [here](https://unix.stackexchange.com/questions/4711/what-is-the-difference-between-ioctl-unlocked-ioctl-and-compat-ioctl) for a better explanantion. Basically, `unlocked_ioctl` does not use a global synchronization lock provided by the linux kernel, and all synchorinzation primitives must be implemented by the module author. This is a very important hint: there may be race conditions in the LKM.


