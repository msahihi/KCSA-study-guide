# AppArmor and Seccomp

## Introduction

AppArmor and Seccomp are Linux security modules that provide fine-grained access control for containers. They implement "defense-in-depth" by restricting what containers can do, even if they're compromised.

**Key Concept**: "Trust, but verify" - even if you trust your container image, AppArmor and Seccomp ensure it can only perform allowed operations.

### Quick Comparison

| Feature | AppArmor | Seccomp |
| --------- | ---------- | --------- |
| **Controls** | File access, network, capabilities | System calls |
| **Granularity** | File paths, protocols | Individual syscalls |
| **Default** | Profile-based | Default deny dangerous calls |
| **Kubernetes** | Annotations | SecurityContext |
| **Format** | Custom syntax | JSON |
| **Performance** | Low overhead | Very low overhead |

## AppArmor (Application Armor)

### What is AppArmor?

AppArmor is a Mandatory Access Control (MAC) system that restricts programs based on predefined profiles. It answers the question: "What can this program access?"

**How It Works**:

```
┌─────────────────┐
│   Application   │
│   (container)   │
└────────┬────────┘
         │ Attempts to: open file, bind port, execute program
         ▼
┌─────────────────┐
│ AppArmor Module │ ← Checks against profile
└────────┬────────┘
         │ Allow or Deny
         ▼
┌─────────────────┐
│  Linux Kernel   │
└─────────────────┘
```

### AppArmor Modes

1. **Enforce Mode**: Enforces profile rules, denies violations
1. **Complain Mode**: Logs violations but allows them (audit only)
1. **Unconfined**: No profile restrictions

### Check AppArmor Status

```bash

# Check if AppArmor is enabled

sudo aa-status

# Example output:
# apparmor module is loaded.
# 42 profiles are loaded.
# 38 profiles are in enforce mode.
#    /snap/snapd/21465/usr/lib/snapd/snap-confine
#    /usr/bin/man
#    /usr/sbin/cups-browsed
#    docker-default
# 4 profiles are in complain mode.
# 0 processes have profiles defined.
# 0 processes are in enforce mode.
# 0 processes are in complain mode.
# 0 processes are unconfined but have a profile defined.

# Check a specific profile

sudo apparmor_status | grep docker

# List all profiles

sudo aa-status --json | jq '.profiles'
```

```

### AppArmor Profile Structure

**Basic Profile Syntax**:

```

# include <tunables/global>

profile <profile-name> flags=(attach_disconnected,mediate_deleted) {

  #include <abstractions/base>

# Capabilities

  capability setgid,
  capability setuid,

# Network access

  network inet tcp,
  network inet udp,

# File access rules

  /path/to/file r,    # read
  /path/to/file w,    # write
  /path/to/file x,    # execute
  /path/to/file rw,   # read and write
  /path/to/dir/** r,  # recursive read

# Denials

  deny /etc/shadow r,
  deny /root/** rwx,
}

```
```

**Permission Modes**:

- `r` - read
- `w` - write
- `x` - execute
- `m` - memory map with exec
- `l` - link
- `k` - lock
- `ix` - inherit execute
- `px` - discrete profile execute
- `ux` - unconfined execute

### Default Docker Profile

Kubernetes uses the `docker-default` AppArmor profile:

```bash

# View docker-default profile

sudo cat /etc/apparmor.d/docker

# Or from kernel

sudo cat /sys/kernel/security/apparmor/profiles | grep docker
```

```

**Key Restrictions in docker-default**:

```

profile docker-default flags=(attach_disconnected,mediate_deleted) {

# Deny dangerous capabilities

  deny @{PROC}/* w,
  deny @{PROC}/sys/kernel/** w,
  deny @{PROC}/sysrq-trigger rwklx,
  deny @{PROC}/kcore rwklx,

# Deny mounting

  deny mount,

# Deny access to host devices

  deny /sys/[^f]*/** wklx,
  deny /sys/f[^s]*/**wklx,
  deny /sys/fs/[^c]*/** wklx,

# Allow network

  network,

# Allow signal operations

  signal (send,receive) peer=docker-default,
}

```
```

### Creating Custom AppArmor Profiles

#### Example 1: Restrict Nginx Container

**Objective**: Allow nginx to read config and serve files, but deny shell access.

**Profile** (`/etc/apparmor.d/k8s-nginx`):

```

#include <tunables/global>

profile k8s-nginx flags=(attach_disconnected,mediate_deleted) {

  #include <abstractions/base>
  #include <abstractions/openssl>

  # Network access for HTTP/HTTPS

  network inet tcp,
  network inet udp,
  network inet6 tcp,
  network inet6 udp,

  # Nginx binary

  /usr/sbin/nginx mr,
  /usr/bin/nginx mr,

  # Nginx configuration

  /etc/nginx/** r,
  /etc/ssl/openssl.cnf r,

  # Runtime files

  /run/nginx.pid w,
  /var/run/nginx.pid w,

  # Logs

  /var/log/nginx/** w,

  # Content to serve

  /usr/share/nginx/html/** r,
  /var/www/html/** r,

  # Temporary files

  /var/cache/nginx/** rw,
  /var/tmp/ r,
  /var/tmp/** rw,

  # System libraries

  /lib/x86_64-linux-gnu/** mr,
  /usr/lib/x86_64-linux-gnu/** mr,

  # Deny dangerous paths

  deny /bin/** wl,
  deny /sbin/** wl,
  deny /usr/bin/** wl,
  deny /usr/sbin/** wl,
  deny /boot/** rwlx,
  deny /root/** rwlx,
  deny /etc/shadow r,
  deny /etc/gshadow r,

  # Deny executing shells

  deny /bin/sh mrwlkx,
  deny /bin/bash mrwlkx,
  deny /bin/dash mrwlkx,
  deny /bin/zsh mrwlkx,

  # Capabilities (minimal)

  capability setuid,
  capability setgid,
  capability chown,
  capability dac_override,
  capability net_bind_service,

  # Deny mount operations

  deny mount,
  deny umount,
}
```

```

**Load the Profile**:

```bash

# Copy profile to AppArmor directory

sudo cp k8s-nginx /etc/apparmor.d/

# Parse and load profile

sudo apparmor_parser -r /etc/apparmor.d/k8s-nginx

# Verify it's loaded

sudo aa-status | grep k8s-nginx

# Output: k8s-nginx (enforce)

```

```

**Use in Kubernetes**:

```yaml

apiVersion: v1
kind: Pod
metadata:
  name: nginx-hardened
  annotations:

    # Specify AppArmor profile for container

    container.apparmor.security.beta.kubernetes.io/nginx: localhost/k8s-nginx
spec:
  containers:
  - name: nginx
    image: nginx:1.27
    ports:
    - containerPort: 80
```

```

**Test the Profile**:

```bash

# Create pod

kubectl apply -f nginx-hardened.yaml

# Verify AppArmor is applied

kubectl exec nginx-hardened -- cat /proc/1/attr/current

# Output: k8s-nginx (enforce)

# Try to execute shell (should fail)

kubectl exec nginx-hardened -- /bin/bash

# Output: OCI runtime exec failed: exec failed: unable to start container process:
# exec: "/bin/bash": permission denied: unknown

# Nginx should still work

kubectl port-forward nginx-hardened 8080:80
curl localhost:8080

# Output: Welcome to nginx!

```

```

#### Example 2: Deny Network Access

**Profile** (`/etc/apparmor.d/k8s-no-network`):

```

# include <tunables/global>

profile k8s-no-network flags=(attach_disconnected,mediate_deleted) {

  #include <abstractions/base>

# File access (allow)

  /usr/**r,
  /lib/** r,
  /etc/** r,

# Deny all network access

  deny network inet,
  deny network inet6,
  deny network unix,

# Deny raw socket

  deny capability net_raw,
}

```
```

**Load and Apply**:

```bash

sudo apparmor_parser -r /etc/apparmor.d/k8s-no-network
```

```

```yaml

apiVersion: v1
kind: Pod
metadata:
  name: no-network
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: localhost/k8s-no-network
spec:
  containers:
  - name: app
    image: busybox
    command: ["sleep", "3600"]
```

```

**Test**:

```bash

# Network should fail

kubectl exec no-network -- ping 8.8.8.8

# Output: PING 8.8.8.8 (8.8.8.8): 56 data bytes
# ping: permission denied (are you root?)

```

```

#### Example 3: Read-Only File System

**Profile** (`/etc/apparmor.d/k8s-readonly`):

```

# include <tunables/global>

profile k8s-readonly flags=(attach_disconnected,mediate_deleted) {

  #include <abstractions/base>

# Read-only access to everything

  /** r,

# Deny all write operations

  deny /** w,

# Allow write only to specific directories

  /tmp/**rw,
  /var/tmp/** rw,

# Allow network

  network,
}

```
```

### Debugging AppArmor Issues

#### Common Errors

**Error 1**: `Pod failed to start - apparmor profile not found`

```bash

# Check profile is loaded on all nodes

ssh node-1 'sudo aa-status | grep k8s-nginx'

# Load profile on node

ssh node-1 'sudo apparmor_parser -r /etc/apparmor.d/k8s-nginx'
```

```

**Error 2**: `Permission denied` in container logs

```bash

# Check AppArmor denials

sudo dmesg | grep apparmor | grep DENIED

# Or use audit log

sudo ausearch -m AVC -ts recent

# Example output:
# type=AVC msg=audit(1234567890.123:456): apparmor="DENIED"
# operation="open" profile="k8s-nginx" name="/bin/bash"
# pid=1234 comm="bash" requested_mask="r" denied_mask="r"

```

```

**Solution**: Update profile to allow the operation or fix the application.

#### Audit/Complain Mode

Test profiles in complain mode before enforcing:

```bash

# Set profile to complain mode

sudo aa-complain /etc/apparmor.d/k8s-nginx

# Generate audit log entries (instead of denying)

kubectl exec nginx-hardened -- /bin/bash

# Works, but logs the violation

# Check logs

sudo dmesg | grep apparmor | grep ALLOWED

# Switch back to enforce mode

sudo aa-enforce /etc/apparmor.d/k8s-nginx
```

```

### Generating Profiles Automatically

Use `aa-genprof` to create profiles based on observed behavior:

```bash

# Install apparmor-utils

sudo apt install apparmor-utils -y

# Generate profile (run in one terminal)

sudo aa-genprof /usr/sbin/nginx

# In another terminal, use the application
# aa-genprof will observe system calls and suggest rules

# Follow prompts to allow/deny operations

# Save the generated profile

```

```

## Seccomp (Secure Computing Mode)

### What is Seccomp?

Seccomp filters system calls (syscalls) made by a process. It answers: "What system calls can this program make?"

**System Call Examples**:

- `open()` - open files
- `read()` - read from file descriptor
- `write()` - write to file descriptor
- `socket()` - create network socket
- `execve()` - execute program
- `mount()` - mount filesystem
- `ptrace()` - debug processes
- `reboot()` - reboot system

**How It Works**:

```

┌─────────────────┐
│   Application   │
└────────┬────────┘
         │ Makes syscall: open("/etc/passwd", O_RDONLY)
         ▼
┌─────────────────┐
│ Seccomp Filter  │ ← Checks against profile
└────────┬────────┘
         │ Allow or Deny (EPERM)
         ▼
┌─────────────────┐
│  Linux Kernel   │
└─────────────────┘

```
```

### Seccomp Modes

1. **Mode 0 (Disabled)**: No filtering
1. **Mode 1 (Strict)**: Only `read()`, `write()`, `exit()`, `sigreturn()` allowed
1. **Mode 2 (Filter)**: Custom filter via BPF (Berkeley Packet Filter)

Kubernetes uses Mode 2 (Filter) with JSON profiles.

### Check Seccomp Status

```bash

# Check if seccomp is enabled in kernel

grep CONFIG_SECCOMP /boot/config-$(uname -r)

# Output: CONFIG_SECCOMP=y

# Check container's seccomp status

kubectl exec <pod> -- grep Seccomp /proc/1/status

# Output:
# Seccomp:        2
# Seccomp_filters:        1

```

```

**Seccomp Status Values**:

- `0` - Disabled
- `1` - Strict mode
- `2` - Filter mode

### Default Seccomp Profile

Kubernetes applies a default seccomp profile that blocks dangerous syscalls:

**Blocked Syscalls** (examples):

- `acct` - process accounting
- `add_key` / `request_key` - kernel keyring
- `bpf` - eBPF programs
- `clock_adjtime` / `clock_settime` - modify system clock
- `create_module` / `delete_module` - kernel modules
- `ioperm` / `iopl` - I/O port access
- `kexec_load` - load new kernel
- `mount` / `umount` - filesystem mounting
- `ptrace` - process debugging
- `reboot` - reboot system
- `setns` - change namespace
- `swapon` / `swapoff` - swap management
- `unshare` - create namespace

### Seccomp Profile Format

**JSON Structure**:

```json

{
  "defaultAction": "SCMP_ACT_ERRNO",
  "defaultErrnoRet": 1,
  "architectures": [
    "SCMP_ARCH_X86_64",
    "SCMP_ARCH_X86",
    "SCMP_ARCH_X32"
  ],
  "syscalls": [
    {
      "names": [
        "syscall1",
        "syscall2"
      ],
      "action": "SCMP_ACT_ALLOW",
      "args": []
    }
  ]
}
```

```

**Actions**:

- `SCMP_ACT_ALLOW` - Allow the syscall
- `SCMP_ACT_ERRNO` - Deny with error
- `SCMP_ACT_KILL` - Kill the process
- `SCMP_ACT_TRAP` - Send SIGSYS signal
- `SCMP_ACT_TRACE` - Trace with ptrace
- `SCMP_ACT_LOG` - Allow but log

### Creating Custom Seccomp Profiles

#### Example 1: Minimal Profile (Allow Only Basic Syscalls)

**Profile** (`/var/lib/kubelet/seccomp/profiles/minimal.json`):

```json

{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": [
    "SCMP_ARCH_X86_64"
  ],
  "syscalls": [
    {
      "names": [
        "read",
        "write",
        "open",
        "close",
        "stat",
        "fstat",
        "lstat",
        "poll",
        "lseek",
        "mmap",
        "mprotect",
        "munmap",
        "brk",
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigreturn",
        "ioctl",
        "pread64",
        "pwrite64",
        "readv",
        "writev",
        "access",
        "pipe",
        "select",
        "sched_yield",
        "mremap",
        "msync",
        "mincore",
        "madvise",
        "shmget",
        "shmat",
        "shmctl",
        "dup",
        "dup2",
        "pause",
        "nanosleep",
        "getitimer",
        "alarm",
        "setitimer",
        "getpid",
        "sendfile",
        "socket",
        "connect",
        "accept",
        "sendto",
        "recvfrom",
        "sendmsg",
        "recvmsg",
        "shutdown",
        "bind",
        "listen",
        "getsockname",
        "getpeername",
        "socketpair",
        "setsockopt",
        "getsockopt",
        "clone",
        "fork",
        "vfork",
        "execve",
        "exit",
        "wait4",
        "kill",
        "uname",
        "semget",
        "semop",
        "semctl",
        "shmdt",
        "msgget",
        "msgsnd",
        "msgrcv",
        "msgctl",
        "fcntl",
        "flock",
        "fsync",
        "fdatasync",
        "truncate",
        "ftruncate",
        "getdents",
        "getcwd",
        "chdir",
        "fchdir",
        "rename",
        "mkdir",
        "rmdir",
        "creat",
        "link",
        "unlink",
        "symlink",
        "readlink",
        "chmod",
        "fchmod",
        "chown",
        "fchown",
        "lchown",
        "umask",
        "gettimeofday",
        "getrlimit",
        "getrusage",
        "sysinfo",
        "times",
        "ptrace",
        "getuid",
        "syslog",
        "getgid",
        "setuid",
        "setgid",
        "geteuid",
        "getegid",
        "setpgid",
        "getppid",
        "getpgrp",
        "setsid",
        "setreuid",
        "setregid",
        "getgroups",
        "setgroups",
        "setresuid",
        "getresuid",
        "setresgid",
        "getresgid",
        "getpgid",
        "setfsuid",
        "setfsgid",
        "getsid",
        "capget",
        "capset",
        "rt_sigpending",
        "rt_sigtimedwait",
        "rt_sigqueueinfo",
        "rt_sigsuspend",
        "sigaltstack",
        "utime",
        "mknod",
        "uselib",
        "personality",
        "ustat",
        "statfs",
        "fstatfs",
        "sysfs",
        "getpriority",
        "setpriority",
        "sched_setparam",
        "sched_getparam",
        "sched_setscheduler",
        "sched_getscheduler",
        "sched_get_priority_max",
        "sched_get_priority_min",
        "sched_rr_get_interval",
        "mlock",
        "munlock",
        "mlockall",
        "munlockall",
        "vhangup",
        "modify_ldt",
        "pivot_root",
        "_sysctl",
        "prctl",
        "arch_prctl",
        "adjtimex",
        "setrlimit",
        "chroot",
        "sync",
        "acct",
        "settimeofday",
        "mount",
        "umount2",
        "swapon",
        "swapoff",
        "reboot",
        "sethostname",
        "setdomainname",
        "iopl",
        "ioperm",
        "create_module",
        "init_module",
        "delete_module",
        "get_kernel_syms",
        "query_module",
        "quotactl",
        "nfsservctl",
        "getpmsg",
        "putpmsg",
        "afs_syscall",
        "tuxcall",
        "security",
        "gettid",
        "readahead",
        "setxattr",
        "lsetxattr",
        "fsetxattr",
        "getxattr",
        "lgetxattr",
        "fgetxattr",
        "listxattr",
        "llistxattr",
        "flistxattr",
        "removexattr",
        "lremovexattr",
        "fremovexattr",
        "tkill",
        "time",
        "futex",
        "sched_setaffinity",
        "sched_getaffinity",
        "set_thread_area",
        "io_setup",
        "io_destroy",
        "io_getevents",
        "io_submit",
        "io_cancel",
        "get_thread_area",
        "lookup_dcookie",
        "epoll_create",
        "epoll_ctl_old",
        "epoll_wait_old",
        "remap_file_pages",
        "getdents64",
        "set_tid_address",
        "restart_syscall",
        "semtimedop",
        "fadvise64",
        "timer_create",
        "timer_settime",
        "timer_gettime",
        "timer_getoverrun",
        "timer_delete",
        "clock_settime",
        "clock_gettime",
        "clock_getres",
        "clock_nanosleep",
        "exit_group",
        "epoll_wait",
        "epoll_ctl",
        "tgkill",
        "utimes",
        "vserver",
        "mbind",
        "set_mempolicy",
        "get_mempolicy",
        "mq_open",
        "mq_unlink",
        "mq_timedsend",
        "mq_timedreceive",
        "mq_notify",
        "mq_getsetattr",
        "kexec_load",
        "waitid",
        "add_key",
        "request_key",
        "keyctl",
        "ioprio_set",
        "ioprio_get",
        "inotify_init",
        "inotify_add_watch",
        "inotify_rm_watch",
        "migrate_pages",
        "openat",
        "mkdirat",
        "mknodat",
        "fchownat",
        "futimesat",
        "newfstatat",
        "unlinkat",
        "renameat",
        "linkat",
        "symlinkat",
        "readlinkat",
        "fchmodat",
        "faccessat",
        "pselect6",
        "ppoll",
        "unshare",
        "set_robust_list",
        "get_robust_list",
        "splice",
        "tee",
        "sync_file_range",
        "vmsplice",
        "move_pages",
        "utimensat",
        "epoll_pwait",
        "signalfd",
        "timerfd_create",
        "eventfd",
        "fallocate",
        "timerfd_settime",
        "timerfd_gettime",
        "accept4",
        "signalfd4",
        "eventfd2",
        "epoll_create1",
        "dup3",
        "pipe2",
        "inotify_init1",
        "preadv",
        "pwritev",
        "rt_tgsigqueueinfo",
        "perf_event_open",
        "recvmmsg",
        "fanotify_init",
        "fanotify_mark",
        "prlimit64",
        "name_to_handle_at",
        "open_by_handle_at",
        "clock_adjtime",
        "syncfs",
        "sendmmsg",
        "setns",
        "getcpu",
        "process_vm_readv",
        "process_vm_writev",
        "kcmp",
        "finit_module",
        "sched_setattr",
        "sched_getattr",
        "renameat2",
        "seccomp",
        "getrandom",
        "memfd_create",
        "kexec_file_load",
        "bpf",
        "execveat",
        "userfaultfd",
        "membarrier",
        "mlock2",
        "copy_file_range",
        "preadv2",
        "pwritev2",
        "pkey_mprotect",
        "pkey_alloc",
        "pkey_free",
        "statx"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

```

This profile is still quite permissive. For tighter security:

#### Example 2: Deny Dangerous Syscalls

**Profile** (`/var/lib/kubelet/seccomp/profiles/deny-dangerous.json`):

```json

{
  "defaultAction": "SCMP_ACT_ALLOW",
  "architectures": [
    "SCMP_ARCH_X86_64",
    "SCMP_ARCH_X86",
    "SCMP_ARCH_X32"
  ],
  "syscalls": [
    {
      "names": [
        "mount",
        "umount",
        "umount2",
        "unshare",
        "setns",
        "ptrace",
        "reboot",
        "swapon",
        "swapoff",
        "kexec_load",
        "kexec_file_load",
        "init_module",
        "finit_module",
        "delete_module",
        "create_module",
        "get_kernel_syms",
        "query_module",
        "ioperm",
        "iopl",
        "modify_ldt",
        "pivot_root",
        "bpf",
        "perf_event_open",
        "fanotify_init",
        "clock_adjtime",
        "clock_settime",
        "settimeofday",
        "adjtimex",
        "acct",
        "add_key",
        "request_key",
        "keyctl",
        "lookup_dcookie",
        "process_vm_readv",
        "process_vm_writev",
        "uselib",
        "userfaultfd",
        "_sysctl"
      ],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1
    }
  ]
}
```

```

**Apply to Pod**:

```yaml

apiVersion: v1
kind: Pod
metadata:
  name: seccomp-demo
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/deny-dangerous.json
  containers:
  - name: app
    image: nginx:1.27
```

```

**Test**:

```bash

# Should fail to mount

kubectl exec seccomp-demo -- mount -t tmpfs tmpfs /mnt

# Output: mount: /mnt: permission denied.

# Should fail to load kernel module

kubectl exec seccomp-demo -- modprobe ip_tables

# Output: modprobe: ERROR: could not insert 'ip_tables': Operation not permitted

```

```

#### Example 3: Audit Mode (Log syscalls)

**Profile** (`/var/lib/kubelet/seccomp/profiles/audit.json`):

```json

{
  "defaultAction": "SCMP_ACT_LOG",
  "architectures": [
    "SCMP_ARCH_X86_64"
  ]
}
```

```

This allows everything but logs all syscalls - useful for generating a whitelist:

```bash

# Check audit log

sudo ausearch -m SECCOMP -ts recent

# Example output:
# type=SECCOMP msg=audit(1234567890.123:456): auid=1000 uid=0 gid=0
# ses=1 subj=unconfined pid=12345 comm="nginx" exe="/usr/sbin/nginx"
# sig=0 arch=c000003e syscall=59 compat=0 ip=0x7f1234567890 code=0x7ffc0000

```

```

### Using Seccomp in Kubernetes

**Three ways to specify seccomp profiles**:

1. **RuntimeDefault** (Recommended):

```yaml

apiVersion: v1
kind: Pod
metadata:
  name: seccomp-runtime-default
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: nginx:1.27
```

```

1. **Localhost** (Custom profile):

```yaml

apiVersion: v1
kind: Pod
metadata:
  name: seccomp-custom
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/my-profile.json
  containers:
  - name: app
    image: nginx:1.27
```

```

1. **Unconfined** (Disable - not recommended):

```yaml

apiVersion: v1
kind: Pod
metadata:
  name: seccomp-unconfined
spec:
  securityContext:
    seccompProfile:
      type: Unconfined
  containers:
  - name: app
    image: nginx:1.27
```

```

**Per-Container Seccomp**:

```yaml

apiVersion: v1
kind: Pod
metadata:
  name: multi-container
spec:
  containers:
  - name: app
    image: nginx:1.27
    securityContext:
      seccompProfile:
        type: RuntimeDefault
  - name: debug
    image: busybox
    command: ["sleep", "3600"]
    securityContext:
      seccompProfile:
        type: Localhost
        localhostProfile: profiles/debug.json
```

```

### Profile Deployment

Seccomp profiles must be on each node:

```bash

# Create profile directory

sudo mkdir -p /var/lib/kubelet/seccomp/profiles

# Copy profile

sudo cp my-profile.json /var/lib/kubelet/seccomp/profiles/

# Set permissions

sudo chmod 644 /var/lib/kubelet/seccomp/profiles/my-profile.json

# Repeat on ALL nodes

```

```

**Automate with DaemonSet**:

```yaml

apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: seccomp-installer
  namespace: kube-system
spec:
  selector:
    matchLabels:
      name: seccomp-installer
  template:
    metadata:
      labels:
        name: seccomp-installer
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: installer
        image: busybox
        command:
        - sh
        - -c
        - |
          mkdir -p /host/var/lib/kubelet/seccomp/profiles
          cat > /host/var/lib/kubelet/seccomp/profiles/my-profile.json <<'EOF'
          {
            "defaultAction": "SCMP_ACT_ERRNO",
            "architectures": ["SCMP_ARCH_X86_64"],
            "syscalls": [
              {"names": ["read", "write", "open", "close"], "action": "SCMP_ACT_ALLOW"}
            ]
          }
          EOF
          sleep infinity
        volumeMounts:
        - name: host-fs
          mountPath: /host
      volumes:
      - name: host-fs
        hostPath:
          path: /
```

```

## Combining AppArmor and Seccomp

Use both for defense-in-depth:

```yaml

apiVersion: v1
kind: Pod
metadata:
  name: hardened-pod
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: localhost/k8s-nginx
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
    runAsNonRoot: true
    runAsUser: 1000
  containers:
  - name: app
    image: nginx:1.27
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
        add: ["NET_BIND_SERVICE"]
      readOnlyRootFilesystem: true
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: cache
      mountPath: /var/cache/nginx
    - name: run
      mountPath: /var/run
  volumes:
  - name: tmp
    emptyDir: {}
  - name: cache
    emptyDir: {}
  - name: run
    emptyDir: {}
```

```

**Security Layers**:

1. **AppArmor**: Restricts file access, network, execution
1. **Seccomp**: Blocks dangerous syscalls
1. **Capabilities**: Drops unnecessary privileges
1. **Read-only root**: Prevents filesystem tampering
1. **Non-root user**: Limits privilege escalation

## Troubleshooting

### Issue 1: Pod Fails with Seccomp Error

**Error**: `Failed to create pod sandbox: rpc error: code = Unknown desc = failed to create containerd task: failed to create shim: OCI runtime create failed: cannot load seccomp profile: open /var/lib/kubelet/seccomp/profiles/my-profile.json: no such file or directory`

**Solution**:

```bash

# Verify profile exists on node

kubectl debug node/worker-1 -it --image=busybox
ls /host/var/lib/kubelet/seccomp/profiles/

# Copy profile to all nodes

for node in $(kubectl get nodes -o name); do
  kubectl debug $node -it --image=busybox -- sh -c "cat > /host/var/lib/kubelet/seccomp/profiles/my-profile.json <<'EOF'
  <profile-content>
  EOF"
done
```

```

### Issue 2: Application Breaks After Applying Profile

**Debug**:

```bash

# Check seccomp denials

sudo ausearch -m SECCOMP -ts recent | grep comm="<app-name>"

# Or use audit log (if enabled)

kubectl logs -n kube-system <audit-pod>

# Switch to audit mode
# Change profile action to SCMP_ACT_LOG temporarily

```

```

**Identify missing syscalls from audit log**, then update profile.

### Issue 3: AppArmor Profile Not Loading

**Error**: `apparmor profile not found`

**Solution**:

```bash

# Check profile syntax

sudo apparmor_parser -Q /etc/apparmor.d/k8s-nginx

# Reload profile

sudo apparmor_parser -r /etc/apparmor.d/k8s-nginx

# Verify loaded

sudo aa-status | grep k8s-nginx
```

```

## Best Practices

### AppArmor Best Practices

1. **Start with complain mode** - Observe violations before enforcing
1. **Use abstractions** - Include standard abstractions like `#include <abstractions/base>`
1. **Deny by default** - Start restrictive, add permissions as needed
1. **Test thoroughly** - Run application through all code paths
1. **Version profiles** - Track changes to profiles
1. **Automate deployment** - Use ConfigMaps or DaemonSets
1. **Monitor violations** - Set up alerting on denials

### Seccomp Best Practices

1. **Use RuntimeDefault** - Start with the default profile
1. **Generate from audit logs** - Let applications run, then whitelist syscalls
1. **Deny dangerous syscalls** - Always block mount, ptrace, reboot, etc.
1. **Test in staging** - Seccomp errors can be cryptic
1. **Document profiles** - Explain why each syscall is allowed
1. **Centralize profiles** - Store in Git, distribute via CI/CD
1. **Regular updates** - Review and update as applications change

### General Best Practices

1. **Defense-in-depth** - Use both AppArmor and Seccomp
1. **Principle of least privilege** - Only allow what's necessary
1. **Audit everything** - Log denials for security monitoring
1. **Automate testing** - CI/CD should test with security profiles
1. **Document exceptions** - If you must allow something risky, document why
1. **Regular reviews** - Audit profiles quarterly
1. **Incident response** - Have runbooks for profile-related outages

## Next Steps

- Review [Kernel Security](kernel-security.md) concepts
- Complete [Lab 2: AppArmor Profiles](../../labs/03-system-hardening/lab-02-apparmor-profiles.md)
- Complete [Lab 3: Seccomp Profiles](../../labs/03-system-hardening/lab-03-seccomp-profiles.md)

---

**Key Takeaway**: AppArmor and Seccomp provide fine-grained control over container behavior. Use AppArmor for file/network restrictions and Seccomp for syscall filtering. Always test profiles thoroughly before enforcing in production.
