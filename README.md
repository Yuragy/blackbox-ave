## Overview
> **Ave** is a post-5.18 Linux kernel module for x86-64 and ARM64 that stealth-hides processes, files, directories, sockets and network traffic at the kernel level.  
> It dynamically hooks system calls (via ftrace & direct syscall-table edits), encrypts in-kernel communications with AES, bypasses SELinux/AppArmor hardening, thwarts debuggers, and can persist across reboots.  
> Built to adapt to kernel updates, Ave provides a one-stop toolkit for invisible operation—complete with optional Netcat/OpenSSL/Socat back-doors and utilities for automatic privilege escalation.

*Key capabilities*
- **Kernel-level cloaking** — removes traces from `lsmod`, `/proc`, `/sys`, `ps`, `top`, etc.  
- **File & directory hiding** — `filldir`/`filldir64` hooks suppress listings.  
- **Dynamic syscall substitution** — live patching of `read`, `kill`, `clone`. 
- **Encrypted networking** — Netfilter-based AES tunnel with signature obfuscation.  
- **Anti-debug & hardening bypass** — blocks `ptrace/strace`, skirts `RELRO/PIE/NX`.  
- **Persistence** — ELF patching & init-system hooks for auto-start.  

---

## Disclaimer
> ⚠️ **Educational & Research Purposes Only**  
> This code is provided *as is* with the explicit intention that it be studied in controlled, legal environments—such as security research labs, malware-analysis sandboxes, or coursework on kernel internals.  
>
> *You are solely responsible for any use or misuse.*  
> Deploying Ave on systems without the explicit permission of their owners **may violate local, national, and international laws**. The authors and maintainers accept **no liability** for damages, data loss, or legal consequences arising from the use of this software.  
>
> Always obtain informed, written consent before testing on any device you do not own, and comply with all relevant regulations and organizational policies.
```
