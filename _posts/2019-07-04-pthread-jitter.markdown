---
layout: post
title:  "Pthread Jitter"
date:   2019-07-04
categories: miscy-shit
---
I just finished my 3rd semester in university, and last semester was very intense because of an Operating Systems course I took. Looking back to it, it was very helpful for me and I had lots of fun doing it, but after looking at my grade I realized it was merely memory beautification. 

One of the difficult parts of doing the assignments was that for some labs (virtual memroy and filesystems) some test cases showed different outputs on every execution. I could only speculate that this was the result of memory corruption via race, but where the race occurs was questionable. Race condition bugs were very hard to debug, since they occur about 1 out of 100 trials and they magically disappear under the presence of GDB.

This kind of problem was also present in userspace programs, not only kernels. (although I think it is rather questionable if my version of PintOS can be considered a kernel, hmmm...) After a bit of googling, I found some reasonable recommendations for debugging race conditions.

```
1. Log intermediary values/variables in critical sections.
2. Use a timeless or time-travel-time debugger.
```

An example of a timeless or reverse debugger is [QIRA](https://qira.me/) which logs every changes that each instruction makes throughout execution. Also I found something called [UDB](https://undo.io/solutions/products/live-recorder/undodb-reverse-debugger/), which is an acronym for Undo-DeBugger, which is similar to QIRA but has replay features. However, I found a drawback for these debugging techniques. You cannot change the control flow like GDB can. In GDB, you can change memory/variables/registers using the `set` command. However time-travel or timeless debugging techniques do not allow this. 

Also, in linux, each user-threads are managed and scheduled by the kernel, which means that you cannot change the properties of the scheduler in userspace. One may want to dramatically decrease the scheduling timeslice in order to maximize the possibility of races. However this is not possible with the POSIX thread API.

Therefore, I decided to implement my own user-threads, which is completely managed in userspace. Now, I know there are plenty of reasons that people don't do that. However, this tool is not meant for performance, it is a debugging tool that makes pthreads more 'user-observable' and 'user-controlled'. There are mainly two features I am planning to introduce.

First, I am going to allow users to alter the thread scheduling mechanism. This means that the user can choose scheduling algorithm, time slice, priority and etc. This can be used in ways to make results more stable and consistent. For example, one can dramatically increase the number of context switches so that races occur more often.

Second, I am going to allow a replay feature without the presence of a ptrace sandbox. This can be done by 'replaying' timer interrupts. To emulate timer interrupts I used a UNIX timer, that sends a SIGALRM every time a time interval passes. Therefore every re-scheduling is done on a SIGALRM handler. If we replay the SIGALRM signal patterns precisely the output will be the same. 

I only implemented up to basic context switching, which is even failing with more than 2 threads. (lol) However the overall goal is not too difficult to implement, so I think it'll be complete in less than a month. The [repo](https://github.com/pr0cf5/pthread_jitter) is public and I am open to all sorts of feedback. (your coding style is shit, your idea is shit, your makefile is shit, etc...) This is my first time building anything from scratch, so there will be many mistakes and misunderstandings. 