# Lab 3: Seccomp Profiles

## Objectives

By the end of this lab, you will be able to:

- Understand seccomp (secure computing mode) and its purpose
- Check if seccomp is enabled on your cluster
- Apply RuntimeDefault seccomp profile to pods
- Create custom seccomp profiles in JSON format
- Block dangerous system calls
- Test and verify syscall filtering
- Debug seccomp profile issues
- Generate seccomp profiles from audit logs

## Prerequisites

- Completed Lab 1 and Lab 2
- Running Kubernetes cluster (Kind or Minikube)
- kubectl configured and working
- Basic understanding of Linux system calls

## Estimated Time

90 minutes

## Lab Environment Setup

```bash
# Create cluster

cat <<EOF | kind create cluster --name seccomp-lab --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  image: kindest/node:v1.30.0
- role: worker
  image: kindest/node:v1.30.0
  extraMounts:
  - hostPath: /tmp/seccomp-profiles
    containerPath: /var/lib/kubelet/seccomp/profiles
EOF

# Verify cluster

kubectl get nodes
```

## Part 1: Seccomp Basics

### Step 1.1: Check Seccomp Support

```bash
# Access worker node

docker exec -it seccomp-lab-worker bash

# Check if seccomp is enabled in kernel

grep CONFIG_SECCOMP /boot/config-$(uname -r) 2>/dev/null || echo "Config file not available (expected in containers)"

# Alternative: Check if seccomp is available

grep Seccomp /proc/self/status

# Expected output:
# Seccomp:        0  (0=disabled, 1=strict, 2=filter)
# Seccomp_filters:        0

# Exit node

exit
```

### Step 1.2: Deploy Pod Without Seccomp

```bash
# Create pod without seccomp

cat <<EOF > /tmp/pod-no-seccomp.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-no-seccomp
spec:
  securityContext:
    seccompProfile:
      type: Unconfined
  containers:
  - name: test
    image: busybox
    command: ["sleep", "3600"]
EOF

# Deploy

kubectl apply -f /tmp/pod-no-seccomp.yaml

# Wait for ready

kubectl wait --for=condition=Ready pod/pod-no-seccomp --timeout=60s
```

### Step 1.3: Check Container's Seccomp Status

```bash
# Get container ID

CONTAINER_ID=$(kubectl get pod pod-no-seccomp -o jsonpath='{.status.containerStatuses[0].containerID}' | cut -d/ -f3)
echo "Container ID: $CONTAINER_ID"

# Access worker node

docker exec -it seccomp-lab-worker bash

# Get container PID

PID=$(crictl inspect $CONTAINER_ID | jq -r '.info.pid')
echo "Container PID: $PID"

# Check seccomp status

grep Seccomp /proc/$PID/status

# Expected output:
# Seccomp:        2  (2 = filter mode)
# Seccomp_filters:        0 or 1

# Even "Unconfined" pods may have basic filtering in some runtimes

# Exit node

exit
```

## Part 2: RuntimeDefault Seccomp Profile

### Step 2.1: Deploy Pod with RuntimeDefault

```bash
# Create pod with RuntimeDefault seccomp

cat <<EOF > /tmp/pod-runtime-default.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-runtime-default
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: test
    image: busybox
    command: ["sleep", "3600"]
EOF

# Deploy

kubectl apply -f /tmp/pod-runtime-default.yaml

# Wait for ready

kubectl wait --for=condition=Ready pod/pod-runtime-default --timeout=60s
```

### Step 2.2: Test Dangerous Syscalls

```bash
# Test 1: Try to use ptrace (should be blocked)

kubectl exec pod-runtime-default -- sh -c "echo 'Not testing ptrace directly, as it requires tools'"

# Test 2: Try to mount filesystem (should fail)

kubectl exec pod-runtime-default -- mount -t tmpfs tmpfs /mnt 2>&1

# Expected output:
# mount: permission denied (are you root?)

# Test 3: Try to load kernel module (should fail)

kubectl exec pod-runtime-default -- sh -c "ls /proc/modules" 2>&1

# May work (reading is allowed), but loading modules is blocked

# Test 4: Try to reboot (should fail)

kubectl exec pod-runtime-default -- reboot 2>&1

# Expected output:
# reboot: must be superuser

# Test 5: Normal operations (should work)

kubectl exec pod-runtime-default -- ls /etc
kubectl exec pod-runtime-default -- cat /etc/hostname
```

### Step 2.3: Compare with Unconfined Pod

```bash
# Both pods likely behave similarly for basic operations
# RuntimeDefault blocks dangerous syscalls that need special privileges

# Create a comparison

echo "=== Testing pod-no-seccomp ==="
kubectl exec pod-no-seccomp -- mount 2>&1 | head -2

echo "=== Testing pod-runtime-default ==="
kubectl exec pod-runtime-default -- mount 2>&1 | head -2

# In both cases, mount fails (lack of privileges, not seccomp alone)
# Seccomp is one layer of defense-in-depth

```

## Part 3: Create Custom Seccomp Profile

### Step 3.1: Create Profile Directory

```bash
# Create directory on host (maps into Kind nodes)

sudo mkdir -p /tmp/seccomp-profiles
sudo chmod 755 /tmp/seccomp-profiles
```

### Step 3.2: Create Minimal Seccomp Profile

This profile allows only essential syscalls:

```bash
# Create very restrictive profile

cat <<'EOF' | sudo tee /tmp/seccomp-profiles/minimal.json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": [
    "SCMP_ARCH_X86_64",
    "SCMP_ARCH_X86",
    "SCMP_ARCH_X32"
  ],
  "syscalls": [
    {
      "names": [
        "accept",
        "accept4",
        "access",
        "arch_prctl",
        "bind",
        "brk",
        "capget",
        "capset",
        "chdir",
        "chmod",
        "chown",
        "clock_getres",
        "clock_gettime",
        "clone",
        "close",
        "connect",
        "dup",
        "dup2",
        "dup3",
        "epoll_create",
        "epoll_create1",
        "epoll_ctl",
        "epoll_pwait",
        "epoll_wait",
        "eventfd",
        "eventfd2",
        "execve",
        "exit",
        "exit_group",
        "faccessat",
        "fchdir",
        "fchmod",
        "fchmodat",
        "fchown",
        "fchownat",
        "fcntl",
        "fdatasync",
        "flock",
        "fork",
        "fstat",
        "fstatfs",
        "fsync",
        "ftruncate",
        "futex",
        "getcwd",
        "getdents",
        "getdents64",
        "getegid",
        "geteuid",
        "getgid",
        "getgroups",
        "getpeername",
        "getpgid",
        "getpgrp",
        "getpid",
        "getppid",
        "getpriority",
        "getrandom",
        "getresgid",
        "getresuid",
        "getrlimit",
        "getrusage",
        "getsid",
        "getsockname",
        "getsockopt",
        "gettid",
        "gettimeofday",
        "getuid",
        "inotify_add_watch",
        "inotify_init",
        "inotify_init1",
        "inotify_rm_watch",
        "ioctl",
        "kill",
        "lchown",
        "listen",
        "lseek",
        "lstat",
        "madvise",
        "memfd_create",
        "mkdir",
        "mkdirat",
        "mmap",
        "mprotect",
        "mremap",
        "munmap",
        "nanosleep",
        "newfstatat",
        "open",
        "openat",
        "pipe",
        "pipe2",
        "poll",
        "ppoll",
        "prctl",
        "pread64",
        "preadv",
        "prlimit64",
        "pselect6",
        "pwrite64",
        "pwritev",
        "read",
        "readlink",
        "readlinkat",
        "readv",
        "recvfrom",
        "recvmmsg",
        "recvmsg",
        "rename",
        "renameat",
        "renameat2",
        "rmdir",
        "rt_sigaction",
        "rt_sigpending",
        "rt_sigprocmask",
        "rt_sigqueueinfo",
        "rt_sigreturn",
        "rt_sigsuspend",
        "rt_sigtimedwait",
        "rt_tgsigqueueinfo",
        "sched_getaffinity",
        "sched_getparam",
        "sched_getscheduler",
        "sched_setaffinity",
        "sched_setparam",
        "sched_setscheduler",
        "sched_yield",
        "select",
        "sendfile",
        "sendmmsg",
        "sendmsg",
        "sendto",
        "set_robust_list",
        "set_tid_address",
        "setgid",
        "setgroups",
        "setitimer",
        "setpgid",
        "setpriority",
        "setregid",
        "setresgid",
        "setresuid",
        "setreuid",
        "setsid",
        "setsockopt",
        "setuid",
        "shutdown",
        "sigaltstack",
        "socket",
        "socketpair",
        "stat",
        "statfs",
        "symlink",
        "symlinkat",
        "sync",
        "syncfs",
        "tgkill",
        "time",
        "timer_create",
        "timer_delete",
        "timer_getoverrun",
        "timer_gettime",
        "timer_settime",
        "timerfd_create",
        "timerfd_gettime",
        "timerfd_settime",
        "times",
        "tkill",
        "truncate",
        "umask",
        "uname",
        "unlink",
        "unlinkat",
        "utimensat",
        "vfork",
        "wait4",
        "waitid",
        "write",
        "writev"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
EOF

# View the profile

cat /tmp/seccomp-profiles/minimal.json | jq .
```

### Step 3.3: Create Deny-Dangerous Profile

This profile allows most syscalls but explicitly denies dangerous ones:

```bash
# Create deny-dangerous profile

cat <<'EOF' | sudo tee /tmp/seccomp-profiles/deny-dangerous.json
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
        "acct",
        "add_key",
        "bpf",
        "clock_adjtime",
        "clock_settime",
        "create_module",
        "delete_module",
        "finit_module",
        "get_kernel_syms",
        "get_mempolicy",
        "init_module",
        "ioperm",
        "iopl",
        "kcmp",
        "kexec_file_load",
        "kexec_load",
        "keyctl",
        "lookup_dcookie",
        "mbind",
        "modify_ldt",
        "mount",
        "move_pages",
        "name_to_handle_at",
        "open_by_handle_at",
        "perf_event_open",
        "personality",
        "pivot_root",
        "process_vm_readv",
        "process_vm_writev",
        "ptrace",
        "query_module",
        "quotactl",
        "reboot",
        "request_key",
        "set_mempolicy",
        "setns",
        "settimeofday",
        "swapon",
        "swapoff",
        "sysfs",
        "syslog",
        "_sysctl",
        "umount",
        "umount2",
        "unshare",
        "uselib",
        "userfaultfd",
        "ustat",
        "vm86",
        "vm86old"
      ],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1
    }
  ]
}
EOF

# View the profile

cat /tmp/seccomp-profiles/deny-dangerous.json | jq .
```

### Step 3.4: Create Audit Profile

This profile logs all syscalls but doesn't block them (useful for discovering what an app needs):

```bash
# Create audit profile

cat <<'EOF' | sudo tee /tmp/seccomp-profiles/audit.json
{
  "defaultAction": "SCMP_ACT_LOG",
  "architectures": [
    "SCMP_ARCH_X86_64",
    "SCMP_ARCH_X86",
    "SCMP_ARCH_X32"
  ]
}
EOF

# View the profile

cat /tmp/seccomp-profiles/audit.json | jq .
```

### Step 3.5: Verify Profiles Are Accessible in Nodes

```bash
# Access worker node

docker exec -it seccomp-lab-worker bash

# Check profiles are mounted

ls -la /var/lib/kubelet/seccomp/profiles/

# Expected output:
# minimal.json
# deny-dangerous.json
# audit.json

# Exit node

exit
```

## Part 4: Apply Custom Seccomp Profiles

### Step 4.1: Deploy Pod with Deny-Dangerous Profile

```bash
# Create pod with deny-dangerous profile

cat <<EOF > /tmp/pod-deny-dangerous.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-deny-dangerous
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/deny-dangerous.json
  containers:
  - name: test
    image: busybox
    command: ["sleep", "3600"]
EOF

# Deploy

kubectl apply -f /tmp/pod-deny-dangerous.yaml

# Wait for ready

kubectl wait --for=condition=Ready pod/pod-deny-dangerous --timeout=60s
```

### Step 4.2: Test Blocked Syscalls

```bash
# Test 1: Try to mount (should fail)

kubectl exec pod-deny-dangerous -- mount -t tmpfs tmpfs /mnt 2>&1

# Expected output:
# mount: mounting tmpfs on /mnt failed: Operation not permitted

# Test 2: Try to reboot (should fail)

kubectl exec pod-deny-dangerous -- reboot 2>&1

# Expected output:
# reboot: must be superuser (or similar)

# Test 3: Normal operations (should work)

kubectl exec pod-deny-dangerous -- ls /
kubectl exec pod-deny-dangerous -- echo "Hello from seccomp!"
kubectl exec pod-deny-dangerous -- ps aux

# Test 4: Try to use ptrace (should fail)
# ptrace requires special tools, but we can verify it's blocked

kubectl exec pod-deny-dangerous -- sh -c "echo 'ptrace is blocked by profile'"
```

### Step 4.3: Deploy Pod with Minimal Profile

```bash
# Create pod with minimal profile

cat <<EOF > /tmp/pod-minimal.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-minimal
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/minimal.json
  containers:
  - name: test
    image: busybox
    command: ["sleep", "3600"]
EOF

# Deploy

kubectl apply -f /tmp/pod-minimal.yaml

# Wait for ready

kubectl wait --for=condition=Ready pod/pod-minimal --timeout=60s
```

### Step 4.4: Test Minimal Profile

```bash
# Test 1: Basic operations (should work)

kubectl exec pod-minimal -- echo "Hello"
kubectl exec pod-minimal -- ls /

# Test 2: Operations that might be blocked

kubectl exec pod-minimal -- mount 2>&1

# Expected: Operation not permitted (blocked by seccomp)

# Test 3: Create file (should work)

kubectl exec pod-minimal -- touch /tmp/test.txt
kubectl exec pod-minimal -- ls -la /tmp/test.txt

# The minimal profile allows common syscalls, so most operations work

```

## Part 5: Nginx with Seccomp

### Step 5.1: Create Nginx-Specific Profile

```bash
# Create nginx-optimized profile

cat <<'EOF' | sudo tee /tmp/seccomp-profiles/nginx.json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": [
    "SCMP_ARCH_X86_64"
  ],
  "syscalls": [
    {
      "names": [
        "accept",
        "accept4",
        "access",
        "arch_prctl",
        "bind",
        "brk",
        "chown",
        "clone",
        "close",
        "dup2",
        "epoll_create",
        "epoll_ctl",
        "epoll_wait",
        "eventfd2",
        "execve",
        "exit",
        "exit_group",
        "fchown",
        "fcntl",
        "fstat",
        "ftruncate",
        "futex",
        "getcwd",
        "getdents",
        "getdents64",
        "getegid",
        "geteuid",
        "getgid",
        "getpid",
        "getppid",
        "getrlimit",
        "getsockname",
        "getsockopt",
        "gettid",
        "gettimeofday",
        "getuid",
        "ioctl",
        "listen",
        "lseek",
        "lstat",
        "mmap",
        "mprotect",
        "munmap",
        "newfstatat",
        "open",
        "openat",
        "pipe",
        "poll",
        "pread64",
        "prlimit64",
        "pwrite64",
        "read",
        "readlink",
        "recvfrom",
        "recvmsg",
        "rename",
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigreturn",
        "sendfile",
        "sendmsg",
        "set_robust_list",
        "set_tid_address",
        "setgid",
        "setgroups",
        "setsockopt",
        "setuid",
        "shutdown",
        "sigaltstack",
        "socket",
        "stat",
        "uname",
        "wait4",
        "write",
        "writev"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
EOF

# Verify profile

cat /tmp/seccomp-profiles/nginx.json | jq .
```

### Step 5.2: Deploy Nginx with Custom Profile

```bash
# Create nginx pod with seccomp

cat <<EOF > /tmp/nginx-seccomp.yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-seccomp
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/nginx.json
  containers:
  - name: nginx
    image: nginx:1.27
    ports:
    - containerPort: 80
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
        add: ["NET_BIND_SERVICE"]
EOF

# Deploy

kubectl apply -f /tmp/nginx-seccomp.yaml

# Wait for ready

kubectl wait --for=condition=Ready pod/nginx-seccomp --timeout=60s
```

### Step 5.3: Test Nginx Functionality

```bash
# Test nginx is working

kubectl port-forward nginx-seccomp 8080:80 &
PF_PID=$!
sleep 2

# Test HTTP request

curl http://localhost:8080

# Expected: Welcome to nginx!

# Stop port-forward

kill $PF_PID

# Check nginx logs

kubectl logs nginx-seccomp

# Should show nginx started successfully

```

### Step 5.4: Verify Dangerous Syscalls Are Blocked

```bash
# Try to exec into container (may fail depending on profile strictness)

kubectl exec nginx-seccomp -- ls /etc/nginx

# Should work

# Try dangerous operation

kubectl exec nginx-seccomp -- mount 2>&1

# Expected: mount: can't find /etc/fstab: No such file or directory
# Or: Operation not permitted

```

## Part 6: Debugging Seccomp Issues

### Step 6.1: Create Profile That's Too Restrictive

```bash
# Create overly restrictive profile

cat <<'EOF' | sudo tee /tmp/seccomp-profiles/too-restrictive.json
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
        "exit",
        "exit_group"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
EOF

# Verify profile

cat /tmp/seccomp-profiles/too-restrictive.json | jq .
```

### Step 6.2: Deploy Pod with Restrictive Profile

```bash
# Create pod

cat <<EOF > /tmp/pod-too-restrictive.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-too-restrictive
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/too-restrictive.json
  containers:
  - name: test
    image: busybox
    command: ["sleep", "3600"]
EOF

# Deploy

kubectl apply -f /tmp/pod-too-restrictive.yaml

# Check status

kubectl get pod pod-too-restrictive

# Pod will likely fail or crash loop

# Check logs

kubectl logs pod-too-restrictive 2>&1

# May show errors or be empty (container can't even start properly)

# Check events

kubectl describe pod pod-too-restrictive | grep -A 10 Events
```

### Step 6.3: Debug with Audit Profile

```bash
# Delete broken pod

kubectl delete pod pod-too-restrictive

# Deploy with audit profile instead

cat <<EOF > /tmp/pod-audit.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-audit
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/audit.json
  containers:
  - name: test
    image: busybox
    command: ["sleep", "3600"]
EOF

# Deploy

kubectl apply -f /tmp/pod-audit.yaml
kubectl wait --for=condition=Ready pod/pod-audit --timeout=60s
```

### Step 6.4: Check Audit Logs

```bash
# Run some operations

kubectl exec pod-audit -- ls /
kubectl exec pod-audit -- cat /etc/hostname
kubectl exec pod-audit -- ps aux

# Access worker node to check audit logs

docker exec -it seccomp-lab-worker bash

# Get container PID

CONTAINER_ID=$(crictl ps --name test --pod $(crictl pods --name pod-audit -q) -q)
PID=$(crictl inspect $CONTAINER_ID | jq -r '.info.pid')

# Check seccomp status (should show audit mode)

grep Seccomp /proc/$PID/status

# View kernel audit logs (if auditd is running)

ausearch -m SECCOMP -ts recent 2>/dev/null || echo "auditd not running or no seccomp events"

# Alternative: Check kernel messages

dmesg | grep audit | grep seccomp | tail -20

# Exit node

exit
```

## Part 7: Best Practices

### Step 7.1: Create Production-Grade Profile

Combining lessons learned:

```bash
# Create production profile

cat <<'EOF' | sudo tee /tmp/seccomp-profiles/production.json
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
        "accept",
        "accept4",
        "access",
        "arch_prctl",
        "bind",
        "brk",
        "capget",
        "capset",
        "chdir",
        "chmod",
        "chown",
        "clock_getres",
        "clock_gettime",
        "clock_nanosleep",
        "clone",
        "close",
        "connect",
        "copy_file_range",
        "creat",
        "dup",
        "dup2",
        "dup3",
        "epoll_create",
        "epoll_create1",
        "epoll_ctl",
        "epoll_pwait",
        "epoll_wait",
        "eventfd",
        "eventfd2",
        "execve",
        "exit",
        "exit_group",
        "faccessat",
        "fadvise64",
        "fallocate",
        "fanotify_mark",
        "fchdir",
        "fchmod",
        "fchmodat",
        "fchown",
        "fchownat",
        "fcntl",
        "fdatasync",
        "fgetxattr",
        "flistxattr",
        "flock",
        "fork",
        "fremovexattr",
        "fsetxattr",
        "fstat",
        "fstatfs",
        "fsync",
        "ftruncate",
        "futex",
        "getcpu",
        "getcwd",
        "getdents",
        "getdents64",
        "getegid",
        "geteuid",
        "getgid",
        "getgroups",
        "getitimer",
        "getpeername",
        "getpgid",
        "getpgrp",
        "getpid",
        "getppid",
        "getpriority",
        "getrandom",
        "getresgid",
        "getresuid",
        "getrlimit",
        "getrusage",
        "getsid",
        "getsockname",
        "getsockopt",
        "gettid",
        "gettimeofday",
        "getuid",
        "getxattr",
        "inotify_add_watch",
        "inotify_init",
        "inotify_init1",
        "inotify_rm_watch",
        "io_cancel",
        "io_destroy",
        "io_getevents",
        "io_setup",
        "io_submit",
        "ioctl",
        "ioprio_get",
        "ioprio_set",
        "kill",
        "lchown",
        "lgetxattr",
        "link",
        "linkat",
        "listen",
        "listxattr",
        "llistxattr",
        "lremovexattr",
        "lseek",
        "lsetxattr",
        "lstat",
        "madvise",
        "memfd_create",
        "mincore",
        "mkdir",
        "mkdirat",
        "mknod",
        "mknodat",
        "mlock",
        "mlock2",
        "mlockall",
        "mmap",
        "mprotect",
        "mq_getsetattr",
        "mq_notify",
        "mq_open",
        "mq_timedreceive",
        "mq_timedsend",
        "mq_unlink",
        "mremap",
        "msgctl",
        "msgget",
        "msgrcv",
        "msgsnd",
        "msync",
        "munlock",
        "munlockall",
        "munmap",
        "nanosleep",
        "newfstatat",
        "open",
        "openat",
        "pause",
        "pipe",
        "pipe2",
        "poll",
        "ppoll",
        "prctl",
        "pread64",
        "preadv",
        "preadv2",
        "prlimit64",
        "pselect6",
        "pwrite64",
        "pwritev",
        "pwritev2",
        "read",
        "readahead",
        "readlink",
        "readlinkat",
        "readv",
        "recv",
        "recvfrom",
        "recvmmsg",
        "recvmsg",
        "remap_file_pages",
        "removexattr",
        "rename",
        "renameat",
        "renameat2",
        "restart_syscall",
        "rmdir",
        "rt_sigaction",
        "rt_sigpending",
        "rt_sigprocmask",
        "rt_sigqueueinfo",
        "rt_sigreturn",
        "rt_sigsuspend",
        "rt_sigtimedwait",
        "rt_tgsigqueueinfo",
        "sched_get_priority_max",
        "sched_get_priority_min",
        "sched_getaffinity",
        "sched_getattr",
        "sched_getparam",
        "sched_getscheduler",
        "sched_rr_get_interval",
        "sched_setaffinity",
        "sched_setattr",
        "sched_setparam",
        "sched_setscheduler",
        "sched_yield",
        "seccomp",
        "select",
        "semctl",
        "semget",
        "semop",
        "semtimedop",
        "send",
        "sendfile",
        "sendmmsg",
        "sendmsg",
        "sendto",
        "set_robust_list",
        "set_tid_address",
        "setfsgid",
        "setfsuid",
        "setgid",
        "setgroups",
        "setitimer",
        "setpgid",
        "setpriority",
        "setregid",
        "setresgid",
        "setresuid",
        "setreuid",
        "setrlimit",
        "setsid",
        "setsockopt",
        "setuid",
        "setxattr",
        "shmat",
        "shmctl",
        "shmdt",
        "shmget",
        "shutdown",
        "sigaltstack",
        "signalfd",
        "signalfd4",
        "socket",
        "socketpair",
        "splice",
        "stat",
        "statfs",
        "statx",
        "symlink",
        "symlinkat",
        "sync",
        "sync_file_range",
        "syncfs",
        "sysinfo",
        "tee",
        "tgkill",
        "time",
        "timer_create",
        "timer_delete",
        "timer_getoverrun",
        "timer_gettime",
        "timer_settime",
        "timerfd_create",
        "timerfd_gettime",
        "timerfd_settime",
        "times",
        "tkill",
        "truncate",
        "umask",
        "uname",
        "unlink",
        "unlinkat",
        "utime",
        "utimensat",
        "utimes",
        "vfork",
        "vmsplice",
        "wait4",
        "waitid",
        "write",
        "writev"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
EOF

cat /tmp/seccomp-profiles/production.json | jq . | head -30
```

### Step 7.2: Test Production Profile

```bash
# Deploy pod with production profile

cat <<EOF > /tmp/pod-production.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-production
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/production.json
    runAsNonRoot: true
    runAsUser: 1000
  containers:
  - name: app
    image: busybox
    command: ["sleep", "3600"]
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      readOnlyRootFilesystem: true
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: tmp
    emptyDir: {}
EOF

# Deploy

kubectl apply -f /tmp/pod-production.yaml
kubectl wait --for=condition=Ready pod/pod-production --timeout=60s

# Test functionality

kubectl exec pod-production -- ls /
kubectl exec pod-production -- touch /tmp/test
kubectl exec pod-production -- cat /etc/hostname

# Test blocked operations

kubectl exec pod-production -- mount 2>&1 | grep -i "not permitted"
```

## Part 8: Cleanup

```bash
# Delete all test pods

kubectl delete pod --all

# Delete cluster

kind delete cluster --name seccomp-lab

# Clean up profile directory

sudo rm -rf /tmp/seccomp-profiles
```

## Troubleshooting

### Issue 1: "Profile not found" Error

**Error**: `Error: failed to create containerd task: cannot load seccomp profile`

**Solution**:

```bash
# Ensure profile exists on all nodes

docker exec -it seccomp-lab-worker ls -la /var/lib/kubelet/seccomp/profiles/

# Check profile is valid JSON

cat /tmp/seccomp-profiles/your-profile.json | jq .

# Recreate cluster if mount path is wrong

```

### Issue 2: Pod CrashLoopBackOff

**Symptom**: Pod fails to start with seccomp profile

**Debug**:

```bash
# Check pod events

kubectl describe pod <pod-name>

# Check logs

kubectl logs <pod-name>

# Try with audit profile first to see what syscalls are needed

```

### Issue 3: Application Doesn't Work

**Symptom**: App fails with cryptic errors

**Solution**:

```bash
# Use audit profile to discover needed syscalls
# Deploy with audit.json
# Run app through all code paths
# Check audit logs for syscalls used
# Add those syscalls to your profile

```

## Key Takeaways

1. **Seccomp filters syscalls** - Blocks dangerous kernel operations
1. **JSON format** - Profiles are JSON, easier to generate programmatically
1. **Two approaches**: Allowlist (minimal) or Denylist (deny-dangerous)
1. **Test thoroughly** - Missing syscalls cause cryptic failures
1. **Use audit mode** - Discover syscalls before enforcing
1. **RuntimeDefault is good** - Blocks most dangerous syscalls
1. **Combine with other controls** - Seccomp + AppArmor + capabilities = defense-in-depth

## Next Steps

- Proceed to [Lab 4: Runtime Security](lab-04-runtime-security.md)
- Review [AppArmor and Seccomp concepts](../../domains/03-system-hardening/apparmor-seccomp.md)
- Explore [Seccomp documentation](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)

## Additional Challenges

1. **Generate profile from running app**: Use audit mode to discover all syscalls an app uses, then create minimal profile
1. **Create per-app profiles**: Build custom profiles for Redis, PostgreSQL, etc.
1. **Automate profile deployment**: Use InitContainer or DaemonSet to deploy profiles
1. **Integrate with CI/CD**: Test apps with seccomp profiles in your pipeline

---

**Congratulations!** You've mastered seccomp profile creation and syscall filtering in Kubernetes. You can now restrict container behavior at the kernel level.
