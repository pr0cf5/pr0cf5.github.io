---
layout: post
title:  "What I've done over the last 2 years"
date:   2020-08-04 00:00:00 -0700
categories: ctf
---
# Purpose
All other posts in this blog are technical posts related to CTF challenges that I've solved or authored. Unfortunately, this one isn't. It's a wrap-up entry showing all the things I've done over the last 2 years. So if you're not interested in my sentiment, you can skip this.

2 years ago I started learning binary exploitation and participated in CTFs.
Looking back at it, I can confidently say that CTFs were a big turning point in my life. There were negative and positive aspects of engaging in CTF events. I could become very skilled in system programming/low level debugging and etc. Also, I could meet very skilled people and realize that I have a lot to learn. But because I spent all of my weekens playing CTF I lost the opportunity to do some 'social' activities. And my enthusiasm for CTFs were not distrubed by exams, so my GPA was... affected. But overall, I have a very positive memory about CTFs and I think that many other CTFers feel this way too. 

For some personal reasons, I can't do CTFs regularly anymore. So I'll probably lose most of the skill and knowledge that I have right now. Therefore, I wanted to write a 'study guide' so that I can recover quickly when I get back into CTFs again. I hope that this entry helps me in the future, and people who are just entering CTFs these days. 

# CTF virgin
I don't really remember the reason I decided to study computer science in general. I think it's because studying EE/CS makes it easier to make a living. Also I didn't like biology and chemistry so I didn't consider chemical/bio engineering fields. Hmmm... 

Also I don't remember why I started to study binary exploitation in the first place. I think it's because it seemed cool, which is a very dumb and immature reason to start something. But I managed to deceive club members into accepting me by showing them my 'enthusiasm' for programming and hacking. Hmmm...

One of the main educational material that I studied was the material written by senior club members in my CTF team, GoN. By reading them thoroughly, I could learn about stack buffer overflows and 'house of series' stuff. At that time glibc heap exploitation seemed very complex and difficult to me. I solved some very simple past CTF challenges and challenges made by club members. But I couldn't solve anything in large CTFs like PlaidCTF 2018 and 0CTF 2018.  

# Getting better
My first big CTF that I could actually 'effectively participate in' was TokyoWesterns CTF 4th (2018). It was held in the summer of 2018, and after playing this CTF I started to use the nickname procfs. It's because one of the challenges that I solved (actually I think I only solved one challenge) uses the `/proc` filesystem. 

After TWCTF 4th I started to gain confidence and began to solve more challenges. I solved a challenge called `groot` in HITCON CTF 2018, which was about tcache heap exploitation. I kept playing more and more challenges and became better. 

Also at that time there were some trends in CTF pwnables. At that time there were many 3-layer style challenges, where one must pwn a userspace program, kernel and a tiny hypervisor sequentially. Also people made heap exploit challenges involving tcache. All of these themes are now cliches in pwnables.

# Surprises
The winter of 2018 came, and I participated in 35c3 ctf. 35c3 CTF was SUPER hard and there were many browser exploit challenges. It was the first CTF that involved realworld components. 

During this CTF I solved a challenge called `collection` and it was marked as 'easy'. But it wasn't easy for me at that time. `collection` was a pwnable task that involved pwning a custom Cpython extension. It took me a lot of time to find the bug, because analyzing python runtime structures were hard for me. It was the first CTF where I was forced to read some oss code. I learned so much from this 'easy' challenge that I even wrote a long [writeup](https://github.com/pr0cf5/CTF-writeups/tree/master/2018/35c3-collection) for it.

# CTF Hell
After 35c3 ctf putting realworld components in pwnables became a new trend. Also, there were new themes that were trendy for a long time.

* Linux kernel heap exploitation
* Windows exploitation
* Browser JIT exploitation
* Browser sandbox escape
* PHP exploitation (???)

And the long history of linux glibc heap exploitation kinda died. (which is not that sad though)

# Making CTF challenges
During the 1 year of intensive CTF participation, I participated in many great CTFs but also shitty ones. The reason for a CTF being shitty is (usually) because the challenge authors are not CTF players. Everytime I got 'fooled' into playing shitty CTFs I felt the urge to organize or author challenges on my own. I thought that I could make better challenges than them.

Luckily, I got an opportuniy to make challenges for codegate 2020 preliminary, which I think is pretty cool. I tried to make challenges that adhere to some criteria.

#### 0% hardcore binary analysis
It is true that binary analysis is the most important skill in hacking. But I think that understanding the fundamentals of a program is more important than de-obfuscating it. So I prefer to disclose the source code of the target program or make it trivial to analyze it by providing debug symbols. 

#### model of existing concepts
Since I'm not a professional security researcher, I can't make challenges out of my works, since there is nothing that I worked on. But, since I'm a CS student I can embed CS knowledge into my challenges. So when I write a program that is meant to be analyzed/exploited I try to model an important CS concept, so that people can learn about this concept while analyzing the binary. For example, if I write an OS with demand paging, people can (are forced to) learn about it while analyzing it on IDA.

A challenge that I made with this concept is `babyllvm` from codegate 2020. I tried to make a very simple optimizing compiler. I think it served its purpose as I intended, looking from the writeups submitted by people who solved the challenge. 

After making these challenges, I realized that it's very hard to make a CTF challenge if you don't have good ideas. From this point, I became thankful to every CTF organizer for their hard works...