---
layout: archive
title: "CV"
permalink: /cv/
author_profile: true
redirect_from:
  - /resume
---

{% include base_path %}

Education
======
* B.S. in EE/CS, KAIST 2018 Mar - 2024 Feb (GPA Total: **3.96/4.3**, GPA Major: **4.08/4.3**)

Work experience
======
* Spring 2024 - Current: Junior Security Auditor
  * [Otter Security LLC](https://osec.io/)
  * Duties included: EVM Smart Contract Audits
  * Supervisor: [Robert Chen](https://www.linkedin.com/in/robert-chen-573147161?challengeId=AQEr6izQe4S2fQAAAYsymMkfsrzEQruqOkpx9lw--BkYKrr7i1f-txyZ41EZVxZLD_ohQNzjydQo2Gj3RCvR8lukF-HoZk5OFQ&submissionId=0720b6be-cb3c-8e17-738b-f12897ee7266&challengeSource=AgF6eF_ySZSYcwAAAYsymQSpGG636kcVBMtM0Wf4-ZjUEqYnYx4j0cpJYEGi69g&challegeType=AgEUEgQFXPfJ6AAAAYsymQSs0OUlq9wpQxV0_KD2d3Bbtno26z4hKOM&memberId=AgHF-v3yRo1q9wAAAYsymQSupvD6D-wl2ouFvxb_421nosA&recognizeDevice=AgGbogs0fCdOnQAAAYsymQSxdNSx9gEoAYqCt4lZvHdsfExXPHi-)

* Fall 2023 - Fall 2024 : Undergraduate Research Assistant
  * [KAIST Hacking Lab](https://kaist-hacking.github.io/)
  * Duties included: Browser Research, Decompiler Research
  * Supervisor: [Professor Insu Yun](https://insuyun.github.io/)
  
Publications
======
  <ul>{% for post in site.publications %}
    {% include archive-single-cv.html %}
  {% endfor %}</ul>

Projects
======
* **A Beginner-Friendly Tutorial on Kernel Exploitation**
  * [link](https://github.com/pr0cf5/kernel-exploit-practice) (343 stars / 45 forks)
  * Wargame style tutorial for teaching kernel exploit techniques.
  * Discusses popular techniques to bypass Linux Kernel exploit defenses such as SMEP/SMAP/kPTI.
* **dTLB Timer: Measuring L1 dTLB Latency Under the Absence of Fine Grained Timing Primitives**
  * [link](https://github.com/pr0cf5/dtlb-timer)
  * Term project for KAIST 2022 Spring EE595: Hardware Security
  * Proposed a method to reverse engineer the pLRU replacement policy of Intel Skylake's L1 dTLB
  * Contains a working PoC in JavaScript/WebAssembly that uses DOM's `performance.now()` API for time measurement
* **CosmWasm Simulator**
  * [link](https://github.com/dream-academy/cosmwasm-simulate)
  * Smart contract debugging framework for the CosmWasm ecosystem.
  * Developed during the [security audit](https://terraswap.io/wp-content/uploads/2023/01/terraswap_report.pdf) of TerraSwap, a decentralized exchange deployed on Luna2.0
* **Smart Contract Audits**
  * [link](https://github.com/pr0cf5/My-Audits-List)
  * Audited 12+ DeFi protocls of various types while working in [OtterSec](https://osec.io/).
  * Uncovered 4 high severity vulnerabilities.

Awards and Honors
======
* **Bug Bounties**
  * Remote code Execution in HanCell(domestic alternative to Microsoft Excel), CVE assignment in progress 
* **CTF(Capture-The-Flag) Competitions**
  * HXP CTF 2021, 2nd place (with team Super Guesser)
  * DEFCON CTF 27 Finals, 12th place (with team KaisHackGoN)
  * Codegate CTF 2019 University Division, 3rd place (with team GoN)
* **Academic Awards**
  * KAIST [Dean's List](https://engineering.kaist.ac.kr/student/dean): 2018 Spring, 2022 Spring, 2022 Fall
* **Scholarships**
  * National Science \& Technology Scholarship (2019 Fall - Present)

Service and leadership
======
* Aug 2020 - Feb 2022: Mandatory Military Service (Korea Army, English Interpreter)
