# Kernel Security

## Introduction

The Linux kernel is the core of container security. Since all containers share the host kernel, understanding kernel security mechanisms is essential for securing Kubernetes workloads. This guide covers namespaces, cgroups, capabilities, and other kernel-level security features.

**Key Concept**: Containers are NOT virtual machines. They are processes running on the host, isolated by kernel features. If the kernel is compromised, all containers are compromised.

## Linux Kernel Architecture

```
┌─────────────────────────────────────────────────┐
│              User Space                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│  │Container │  │Container │  │Container │     │
│  │    1     │  │    2     │  │    3     │     │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘     │
│       │             │             │            │
│       └─────────────┴─────────────┘            │
│                     │                          │
├─────────────────────┼──────────────────────────┤
│              Kernel Space                      │
│       ┌─────────────▼────────────┐             │
│       │    System Call Interface │             │
│       └─────────────┬────────────┘             │
│  ┌────────┬─────────┴────────┬────────────┐   │
│  │        │                  │            │   │
│  ▼        ▼                  ▼            ▼   │
│ Namespaces Cgroups     Capabilities  Seccomp  │
│          │                  │            │     │
│          └──────────────────┴────────────┘     │
│                     │                          │
│              ┌──────▼──────┐                   │
│              │ Linux Kernel│                   │
│              └──────┬──────┘                   │
├─────────────────────┼──────────────────────────┤
│                     ▼                          │
│              Hardware Layer                    │
└─────────────────────────────────────────────────┘
```

## Namespaces

Namespaces provide isolation by giving each container its own view of system resources.

### Types of Namespaces

| Namespace | Isolates | Created With | Checks |
| ----------- | ---------- | -------------- | -------- |
| **PID** | Process IDs | `unshare -p` | `ps aux` |
| **Network** | Network interfaces, IPs | `unshare -n` | `ip addr` |
| **Mount** | Filesystem mount points | `unshare -m` | `mount` |
| **UTS** | Hostname, domain name | `unshare -u` | `hostname` |
| **IPC** | Inter-process communication | `unshare -i` | `ipcs` |
| **User** | User and group IDs | `unshare -U` | `id` |
| **Cgroup** | Cgroup hierarchy view | `unshare -C` | `cat /proc/self/cgroup` |

### PID Namespace

Isolates process IDs - container sees only its processes.

**Without PID namespace**:

```bash
# On host

ps aux | wc -l

# Output: 347 processes

# Inside container (without isolation)

docker run --pid=host busybox ps aux | wc -l

# Output: 347 processes (sees all host processes!)

```

**With PID namespace** (default):

```bash
# Inside container

docker run busybox ps aux

# Output:
# PID   USER     TIME  COMMAND
#   1   root     0:00  ps aux

# Container only sees its own processes

```

**Check Container PID Namespace**:

```bash
# Get container PID on host

crictl inspect <container-id> | jq '.info.pid'

# Output: 12345

# Check namespace

sudo ls -la /proc/12345/ns/pid

# Output: lrwxrwxrwx 1 root root 0 Feb 27 10:00 /proc/12345/ns/pid -> 'pid:[4026532516]'

# Compare with host PID namespace

ls -la /proc/self/ns/pid

# Output: lrwxrwxrwx 1 user user 0 Feb 27 10:00 /proc/self/ns/pid -> 'pid:[4026531836]'

# Different numbers = isolated namespaces

```

**Kubernetes Shared PID Namespace**:

Containers in a pod can share PID namespace:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: shared-pid
spec:
  shareProcessNamespace: true
  containers:
  - name: app
    image: nginx:1.27
  - name: sidecar
    image: busybox
    command: ["sleep", "3600"]
```

```
# Sidecar can see nginx process

kubectl exec shared-pid -c sidecar -- ps aux

# Output:
# PID   USER     TIME  COMMAND
#   1   65535    0:00  /pause
#  10   root     0:00  nginx: master process
#  20   101      0:00  nginx: worker process
#  30   root     0:00  sleep 3600
#  40   root     0:00  ps aux

```

**Security Implications**:

- Processes in same PID namespace can signal each other
- Can read `/proc/<pid>` of other processes
- Useful for debugging, but reduces isolation

### Network Namespace

Isolates network stack (interfaces, routing, firewall rules).

**Check Network Namespace**:

```bash
# Host network interfaces

ip addr

# Output: eth0, lo, docker0, veth...

# Container network (isolated)

kubectl run test --image=busybox --restart=Never -- ip addr
kubectl logs test

# Output: eth0@if123, lo (different from host)

```

**Shared Network Namespace** (hostNetwork):

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: host-network
spec:
  hostNetwork: true  # Use host's network namespace
  containers:
  - name: app
    image: nginx:1.27
```

```
# Pod sees host's network interfaces

kubectl exec host-network -- ip addr

# Same output as host's `ip addr`

```

**Security Implications**:

- `hostNetwork: true` bypasses Network Policies
- Container can bind to any host port
- Can sniff all host network traffic
- Only use for CNI plugins or trusted infrastructure

### Mount Namespace

Isolates filesystem mount points.

**Check Mount Namespace**:

```bash
# Host mounts

mount | wc -l

# Output: 57

# Container mounts

kubectl run test --image=busybox --restart=Never -- mount
kubectl logs test | wc -l

# Output: 12 (only container's mounts visible)

```

**Volume Mounts**:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: mount-demo
spec:
  containers:
  - name: app
    image: nginx:1.27
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    hostPath:
      path: /mnt/data
```

**Security Implications**:

- Mounting host paths can leak sensitive data
- Use read-only mounts when possible: `readOnly: true`
- Avoid mounting Docker socket or Kubernetes credentials

**Dangerous Mounts**:

```yaml
# BAD: Mounting Docker socket

volumeMounts:
- name: docker-sock
  mountPath: /var/run/docker.sock
volumes:
- name: docker-sock
  hostPath:
    path: /var/run/docker.sock

# BAD: Mounting root filesystem

volumeMounts:
- name: root
  mountPath: /host
volumes:
- name: root
  hostPath:
    path: /
```

With these mounts, container can escape to host!

### UTS Namespace

Isolates hostname and domain name.

```bash
# Host hostname

hostname

# Output: worker-1

# Container hostname (default: pod name)

kubectl run test --image=busybox --restart=Never --command -- hostname
kubectl logs test

# Output: test

```

**Shared UTS Namespace** (hostNetwork implies hostUTS):

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: host-uts
spec:
  hostNetwork: true
  containers:
  - name: app
    image: busybox
    command: ["hostname"]
```

**Security Implications**:

- Low security impact
- Mainly affects logging and identification

### IPC Namespace

Isolates inter-process communication (shared memory, message queues, semaphores).

```bash
# Host IPC resources

ipcs

# Output:
# Shared Memory Segments: 5
# Message Queues: 0
# Semaphore Arrays: 0

# Container IPC (isolated)

kubectl run test --image=busybox --restart=Never -- ipcs
kubectl logs test

# Output: empty (no IPC resources visible)

```

**Shared IPC** (hostIPC):

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: host-ipc
spec:
  hostIPC: true
  containers:
  - name: app
    image: busybox
    command: ["ipcs"]
```

**Security Implications**:

- Shared memory can leak sensitive data
- Message queues can be abused for communication
- Avoid `hostIPC: true` unless required

### User Namespace

Maps user IDs inside container to different IDs on host.

**Without User Namespace**:

```bash
# Root in container = root on host

kubectl run test --image=busybox --restart=Never -- id
kubectl logs test

# Output: uid=0(root) gid=0(root)

# Find container process on host

ps aux | grep "sleep 3600"

# Output: root  12345  ... sleep 3600
# Still root on host!

```

**With User Namespace** (requires runtime support):

```bash
# Root in container != root on host
# uid=0 in container might be uid=100000 on host

# Rootless container runtimes use user namespaces:

podman run --rm busybox id

# uid=0(root) gid=0(root) groups=0(root)

# But on host:

ps aux | grep sleep

# Output: user  12345  ... sleep 3600
# Running as regular user!

```

**Security Implications**:

- Strongest namespace isolation
- Container escape only gives unprivileged user access
- Not fully supported in Kubernetes (as of v1.30)
- Available with rootless container runtimes

### Cgroup Namespace

Isolates cgroup view - container sees itself as root of cgroup hierarchy.

```bash
# Without cgroup namespace

cat /proc/self/cgroup

# Output: 0::/kubepods/pod<uuid>/<container-id>

# With cgroup namespace (default in modern runtimes)

kubectl run test --image=busybox --restart=Never -- cat /proc/self/cgroup
kubectl logs test

# Output: 0::/
# Container thinks it's at cgroup root

```

**Security Implications**:

- Prevents container from seeing host cgroup hierarchy
- Limits information leakage
- Prevents cgroup manipulation attempts

## Control Groups (cgroups)

Cgroups limit and account for resource usage.

### Cgroup Controllers

| Controller | Limits | Kubernetes Resource |
| ------------ | -------- | --------------------- |
| **cpu** | CPU time | `resources.limits.cpu` |
| **memory** | RAM usage | `resources.limits.memory` |
| **pids** | Number of processes | Pod limit |
| **cpuset** | CPU affinity | Topology Manager |
| **blkio** | Block I/O | Storage classes |
| **devices** | Device access | Device plugins |
| **hugetlb** | Huge pages | `hugepages-*` |

### Memory Cgroup

**Set Memory Limits**:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: memory-limit
spec:
  containers:
  - name: app
    image: nginx:1.27
    resources:
      requests:
        memory: "64Mi"
      limits:
        memory: "128Mi"
```

**Check Memory Cgroup**:

```bash
# Find cgroup path

kubectl get pod memory-limit -o jsonpath='{.metadata.uid}'

# Output: abc123-def456-...

# On worker node

sudo cat /sys/fs/cgroup/kubepods.slice/kubepods-pod<uid>.slice/memory.max

# Output: 134217728 (128Mi in bytes)

# Check current usage

sudo cat /sys/fs/cgroup/kubepods.slice/kubepods-pod<uid>.slice/memory.current

# Output: 12345678 (current usage in bytes)

```

**OOM Kill**:

When container exceeds memory limit, kernel kills it:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: oom-demo
spec:
  containers:
  - name: app
    image: polinux/stress
    resources:
      limits:
        memory: "50Mi"
    command: ["stress"]
    args: ["--vm", "1", "--vm-bytes", "100M"]
```

```
# Pod will be OOMKilled

kubectl get pod oom-demo

# Output:
# NAME       READY   STATUS      RESTARTS   AGE
# oom-demo   0/1     OOMKilled   1          10s

# Check events

kubectl describe pod oom-demo

# Output: Container killed due to OOM (Out of Memory)

```

### CPU Cgroup

**Set CPU Limits**:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: cpu-limit
spec:
  containers:
  - name: app
    image: nginx:1.27
    resources:
      requests:
        cpu: "250m"  # 0.25 CPU cores
      limits:
        cpu: "500m"  # 0.5 CPU cores
```

**Check CPU Cgroup**:

```bash
# CPU quota (max CPU time per period)

sudo cat /sys/fs/cgroup/kubepods.slice/kubepods-pod<uid>.slice/cpu.max

# Output: 50000 100000
# Meaning: 50ms of CPU time per 100ms period = 50% of one core

# CPU shares (relative weight for requests)

sudo cat /sys/fs/cgroup/kubepods.slice/kubepods-pod<uid>.slice/cpu.weight

# Output: 10 (proportional to cpu request)

```

**CPU Throttling**:

Container using more CPU than limit is throttled:

```bash
# Check throttling stats

sudo cat /sys/fs/cgroup/kubepods.slice/kubepods-pod<uid>.slice/cpu.stat

# Output:
# nr_periods 1000
# nr_throttled 800
# throttled_time 400000000
# 80% of periods were throttled

```

### PID Cgroup

Limits number of processes/threads:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pid-limit
spec:
  containers:
  - name: app
    image: nginx:1.27
```

```
# Check PID limit

sudo cat /sys/fs/cgroup/kubepods.slice/kubepods-pod<uid>.slice/pids.max

# Output: max (unlimited by default)

# Kubelet can set global limits
# Via --pod-max-pids flag

```

**Fork Bomb Protection**:

```yaml
# Set PID limit in security context (future Kubernetes feature)

securityContext:
  procMount: Default
  pidLimit: 100
```

## Capabilities

Linux capabilities divide root privileges into distinct units.

### Capability List

**Common Capabilities**:

| Capability | Allows | Risk |
| ------------ | -------- | ------ |
| `CAP_CHOWN` | Change file ownership | Medium |
| `CAP_DAC_OVERRIDE` | Bypass file permission checks | High |
| `CAP_FOWNER` | Bypass permission checks on file operations | High |
| `CAP_FSETID` | Set file SUID/SGID bits | High |
| `CAP_KILL` | Send signals to any process | Medium |
| `CAP_SETGID` | Manipulate GIDs | High |
| `CAP_SETUID` | Manipulate UIDs | High |
| `CAP_NET_BIND_SERVICE` | Bind to ports < 1024 | Low |
| `CAP_NET_RAW` | Use RAW/PACKET sockets | Medium |
| `CAP_SYS_CHROOT` | Use chroot() | Medium |
| `CAP_SYS_ADMIN` | Perform system admin operations | **Critical** |
| `CAP_SYS_MODULE` | Load/unload kernel modules | **Critical** |
| `CAP_SYS_PTRACE` | Trace any process | High |
| `CAP_SYS_TIME` | Set system clock | High |
| `CAP_SYS_BOOT` | Reboot system | **Critical** |

**Default Container Capabilities** (Docker/containerd):

```
CAP_CHOWN
CAP_DAC_OVERRIDE
CAP_FSETID
CAP_FOWNER
CAP_MKNOD
CAP_NET_RAW
CAP_SETGID
CAP_SETUID
CAP_SETFCAP
CAP_SETPCAP
CAP_NET_BIND_SERVICE
CAP_SYS_CHROOT
CAP_KILL
CAP_AUDIT_WRITE

```

### Viewing Capabilities

**Check Process Capabilities**:

```bash
# Host process

cat /proc/self/status | grep Cap

# Output:
# CapInh:    0000000000000000
# CapPrm:    000001ffffffffff
# CapEff:    000001ffffffffff
# CapBnd:    000001ffffffffff
# CapAmb:    0000000000000000

# Decode capabilities

capsh --decode=000001ffffffffff

# Output: 0x000001ffffffffff=cap_chown,cap_dac_override,...

```

**Container Capabilities**:

```bash
# Inside container

kubectl exec <pod> -- cat /proc/1/status | grep Cap

# Or from host

kubectl exec <pod> -- sh -c 'grep Cap /proc/1/status | cut -f2'
```

### Dropping Capabilities

**Drop ALL capabilities** (recommended):

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: no-caps
spec:
  containers:
  - name: app
    image: nginx:1.27
    securityContext:
      capabilities:
        drop: ["ALL"]
        add: ["NET_BIND_SERVICE"]  # Only what's needed
```

**Verify**:

```bash
kubectl exec no-caps -- cat /proc/1/status | grep CapEff

# Output: CapEff:    0000000000000400
# Only NET_BIND_SERVICE (0x400)

capsh --decode=0000000000000400

# Output: cap_net_bind_service

```

**Test Capability Restrictions**:

```bash
# Without CAP_NET_RAW, can't ping

kubectl exec no-caps -- ping 8.8.8.8

# Output: ping: permission denied (are you root?)

# Without CAP_CHOWN, can't change file ownership

kubectl exec no-caps -- chown 1000:1000 /tmp/test

# Output: chown: /tmp/test: Operation not permitted

```

### Privileged Containers

**Privileged containers** get ALL capabilities:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: privileged
spec:
  containers:
  - name: app
    image: nginx:1.27
    securityContext:
      privileged: true  # Dangerous!
```

**Capabilities of privileged container**:

```bash
kubectl exec privileged -- cat /proc/1/status | grep CapEff

# Output: CapEff:    000001ffffffffff
# All capabilities (38 in total)

# Privileged container can:
# - Load kernel modules
# - Access all devices
# - Mount filesystems
# - Reboot the host
# - Escape to host easily

```

**NEVER use privileged containers** unless absolutely necessary (e.g., CNI plugins, device drivers).

## Kernel Security Parameters

### sysctl Parameters

**View All Kernel Parameters**:

```bash
sudo sysctl -a | wc -l

# Output: ~1000 parameters

# Security-related parameters

sudo sysctl -a | grep -E "kernel\.|net\."
```

### Important Security Parameters

**Address Space Layout Randomization (ASLR)**:

```bash
# Check ASLR status

sudo sysctl kernel.randomize_va_space

# Output: kernel.randomize_va_space = 2

# Values:
# 0 = Disabled
# 1 = Randomize stack/heap
# 2 = Full randomization (recommended)

```

**Restrict dmesg**:

```bash
# Prevent non-root users from reading kernel logs

sudo sysctl kernel.dmesg_restrict=1
```

**Restrict ptrace**:

```bash
# Prevent processes from tracing other processes

sudo sysctl kernel.yama.ptrace_scope=1

# Values:
# 0 = All processes can be traced
# 1 = Only child processes can be traced
# 2 = Admin-only tracing
# 3 = No tracing allowed

```

**Prevent core dumps**:

```bash
# Disable core dumps for SUID programs

sudo sysctl fs.suid_dumpable=0
```

### Kubernetes-Required Parameters

These must be enabled for Kubernetes:

```bash
# Enable IP forwarding

sudo sysctl -w net.ipv4.ip_forward=1

# Enable bridge netfilter

sudo sysctl -w net.bridge.bridge-nf-call-iptables=1
sudo sysctl -w net.bridge.bridge-nf-call-ip6tables=1

# Make permanent

cat <<EOF | sudo tee /etc/sysctl.d/99-kubernetes.conf
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF

sudo sysctl -p /etc/sysctl.d/99-kubernetes.conf
```

### Unsafe sysctl Parameters

Some sysctls affect the entire host and are not namespace-aware:

**Unsafe sysctls** (denied by default in Kubernetes):

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: unsafe-sysctl
spec:
  securityContext:
    sysctls:
    - name: kernel.shm_rmid_forced
      value: "1"
  containers:
  - name: app
    image: nginx:1.27
```

```
# Pod creation fails

kubectl apply -f unsafe-sysctl.yaml

# Output: Error: Forbidden: sysctl "kernel.shm_rmid_forced" is not allowed

```

**Allow unsafe sysctls** (kubelet flag):

```bash
# In kubelet configuration

--allowed-unsafe-sysctls=kernel.shm_rmid_forced,net.core.somaxconn
```

**Safe sysctls** (namespace-aware, allowed by default):

- `kernel.shm_rmid_forced`
- `net.ipv4.ip_local_port_range`
- `net.ipv4.tcp_syncookies`
- `net.ipv4.ping_group_range`

## SELinux

SELinux is an alternative to AppArmor (Red Hat/CentOS/Fedora).

### SELinux vs AppArmor

| Feature | SELinux | AppArmor |
| --------- | --------- | ---------- |
| **Distribution** | RHEL, CentOS, Fedora | Ubuntu, Debian, SUSE |
| **Model** | Type enforcement, labels | Path-based |
| **Complexity** | High | Medium |
| **Granularity** | Very fine | Fine |
| **Kubernetes** | seLinuxOptions | Annotations |

### SELinux Modes

```bash
# Check SELinux status

getenforce

# Output: Enforcing | Permissive | Disabled

# Set mode temporarily

sudo setenforce 0  # Permissive
sudo setenforce 1  # Enforcing
```

### SELinux in Kubernetes

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: selinux-demo
spec:
  securityContext:
    seLinuxOptions:
      level: "s0:c123,c456"  # MCS label
      role: "spc_r"
      type: "spc_t"
      user: "system_u"
  containers:
  - name: app
    image: nginx:1.27
```

**Check SELinux Context**:

```bash
# Inside container

kubectl exec selinux-demo -- ps auxZ

# Output: system_u:spc_r:spc_t:s0:c123,c456 root 1 0.0 0.1 ...

```

**Note**: For KCSA exam, focus on AppArmor as it's more common in exam scenarios.

## Kernel Module Security

### View Loaded Modules

```bash
# List all modules

lsmod

# Check specific module

lsmod | grep ip_tables
```

### Block Module Loading

**Prevent loading modules** in container:

```bash
# Drop CAP_SYS_MODULE capability

kubectl run test --image=busybox --restart=Never \
  --overrides='{"spec":{"containers":[{"name":"test","securityContext":{"capabilities":{"drop":["CAP_SYS_MODULE"]}}}]}}'

# Try to load module (will fail)

kubectl exec test -- modprobe ip_tables

# Output: modprobe: can't change directory to '/lib/modules': No such file or directory

```

**Block kernel module loading host-wide**:

```bash
# Disable module loading

sudo sysctl kernel.modules_disabled=1

# This is irreversible until reboot!

```

## Best Practices

### Security Hardening Checklist

#### Namespace Security

- [ ] Never use `hostPID: true` unless required
- [ ] Avoid `hostNetwork: true` (bypasses NetworkPolicies)
- [ ] Don't use `hostIPC: true` (shared memory leaks)
- [ ] Consider rootless containers for high-security workloads

#### Cgroup Security

- [ ] Always set resource limits (CPU, memory)
- [ ] Set pod PID limits to prevent fork bombs
- [ ] Monitor for OOMKills (sign of under-provisioning)
- [ ] Use QoS classes appropriately

#### Capability Security

- [ ] Drop ALL capabilities by default
- [ ] Add only specific capabilities needed
- [ ] Never use `privileged: true`
- [ ] Regularly audit capability usage

#### Kernel Security

- [ ] Keep kernel updated with security patches
- [ ] Enable ASLR, restrict ptrace, dmesg
- [ ] Set Kubernetes-required sysctls only
- [ ] Avoid unsafe sysctls
- [ ] Use AppArmor or SELinux

### Defense-in-Depth Example

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hardened-app
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: localhost/k8s-nginx
spec:
  securityContext:

    # Seccomp filter

    seccompProfile:
      type: RuntimeDefault

    # Run as non-root

    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000

    # Drop all capabilities

    sysctls:
    - name: net.ipv4.ip_local_port_range
      value: "32768 60999"
  containers:
  - name: app
    image: nginx:1.27
    securityContext:

      # Deny privilege escalation

      allowPrivilegeEscalation: false

      # Drop all capabilities

      capabilities:
        drop: ["ALL"]
        add: ["NET_BIND_SERVICE"]

      # Read-only root filesystem

      readOnlyRootFilesystem: true

    # Resource limits

    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
      limits:
        memory: "128Mi"
        cpu: "500m"

    # Writable tmpfs for runtime files

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

## Troubleshooting

### Issue 1: Container Can't Bind to Port

**Error**: `bind: permission denied`

**Cause**: Dropped `CAP_NET_BIND_SERVICE` capability

**Solution**:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]
```

Or use port >= 1024.

### Issue 2: OOMKilled Pods

**Symptom**: Pod constantly restarts with `OOMKilled` status

**Debug**:

```bash
# Check memory limit

kubectl get pod <pod> -o jsonpath='{.spec.containers[0].resources.limits.memory}'

# Check actual usage

kubectl top pod <pod>

# View OOM events

kubectl describe pod <pod> | grep -A 10 Events
```

**Solution**: Increase memory limit or optimize application.

### Issue 3: Permission Denied in Container

**Error**: Various "permission denied" errors

**Check**:

```bash
# Check capabilities

kubectl exec <pod> -- cat /proc/1/status | grep Cap

# Check AppArmor/Seccomp

kubectl exec <pod> -- cat /proc/1/attr/current
kubectl exec <pod> -- grep Seccomp /proc/1/status

# Check user

kubectl exec <pod> -- id
```

**Solution**: Add required capability, adjust AppArmor profile, or run as root (carefully).

## Next Steps

- Complete [Lab 1: Host Hardening](../../labs/03-system-hardening/lab-01-host-hardening.md)
- Complete [Lab 4: Runtime Security](../../labs/03-system-hardening/lab-04-runtime-security.md)
- Move to [Domain 4: Minimize Microservice Vulnerabilities](../04-minimize-vulnerabilities/README.md)

---

**Key Takeaway**: The Linux kernel provides powerful isolation and resource control mechanisms. Understanding namespaces, cgroups, and capabilities is essential for securing containers. Always apply least privilege principles and defense-in-depth strategies.
