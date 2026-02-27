# Runtime Security Tools

## Overview

Runtime security focuses on detecting and preventing threats during the execution phase of containers and applications. Unlike static security measures (admission control, image scanning), runtime security monitors actual behavior and detects anomalies, policy violations, and malicious activities in real-time.

## Table of Contents

1. [Understanding Runtime Security](#understanding-runtime-security)
1. [Falco - Cloud Native Runtime Security](#falco---cloud-native-runtime-security)
1. [Seccomp - Secure Computing Mode](#seccomp---secure-computing-mode)
1. [AppArmor - Application Security Profiles](#apparmor---application-security-profiles)
1. [SELinux - Security-Enhanced Linux](#selinux---security-enhanced-linux)
1. [Best Practices](#best-practices)
1. [Troubleshooting](#troubleshooting)

## Understanding Runtime Security

### Why Runtime Security?

Traditional security controls (firewalls, admission controllers) are preventive. Runtime security is **detective and responsive**:

- Detects zero-day exploits and unknown threats
- Identifies compromised containers
- Monitors for policy violations
- Detects data exfiltration attempts
- Identifies cryptominers and malware
- Tracks suspicious system calls
- Monitors file access patterns

### Runtime Security Layers

```
┌─────────────────────────────────────────────────────────┐
│                    Application Layer                     │
│  ┌──────────────────────────────────────────────────┐   │
│  │ Falco Rules - Application Behavior Monitoring    │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│                   Container Layer                        │
│  ┌──────────────────────────────────────────────────┐   │
│  │ Seccomp - Syscall Filtering                      │   │
│  │ AppArmor/SELinux - Mandatory Access Control      │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│                    Kernel Layer                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │ eBPF - Kernel Event Monitoring                   │   │
│  │ Syscall Auditing                                 │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### Common Runtime Threats

1. **Container Escape**: Attempts to break out of container isolation
1. **Privilege Escalation**: Gaining higher privileges than intended
1. **Malicious Processes**: Cryptominers, backdoors, shells
1. **Data Exfiltration**: Unauthorized data transfer
1. **Suspicious Network Activity**: Connections to known malicious IPs
1. **File Tampering**: Modification of critical system files
1. **Credential Theft**: Accessing secrets, tokens, passwords

## Falco - Cloud Native Runtime Security

Falco is the de facto standard for Kubernetes runtime security, using eBPF to monitor kernel events.

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Kubernetes Cluster                   │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   Pod        │  │   Pod        │  │   Pod        │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
│         ↓                  ↓                  ↓          │
│  ┌──────────────────────────────────────────────────┐  │
│  │           Kernel (eBPF Hooks)                    │  │
│  └──────────────────────────────────────────────────┘  │
│         ↓                  ↓                  ↓          │
│  ┌──────────────────────────────────────────────────┐  │
│  │        Falco Drivers (Kernel Module or eBPF)     │  │
│  └──────────────────────────────────────────────────┘  │
│         ↓                                                │
│  ┌──────────────────────────────────────────────────┐  │
│  │              Falco Daemon                        │  │
│  │  - Rules Engine                                  │  │
│  │  - Event Processing                              │  │
│  │  - Alert Generation                              │  │
│  └──────────────────────────────────────────────────┘  │
│         ↓                                                │
│  ┌──────────────────────────────────────────────────┐  │
│  │         Outputs (Logs, Slack, PagerDuty, etc.)   │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### Installation

#### Method 1: Helm (Recommended)

```bash
# Add Falco Helm repository

helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# Install Falco with eBPF driver

helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --set driver.kind=ebpf \
  --set tty=true

# Verify installation

kubectl get pods -n falco
kubectl logs -n falco -l app.kubernetes.io/name=falco -f
```

#### Method 2: Kubernetes Manifests

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: falco

---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: falco
  namespace: falco

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: falco
rules:
- apiGroups: [""]
  resources: ["pods", "nodes", "events"]
  verbs: ["get", "list", "watch"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: falco
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: falco
subjects:
- kind: ServiceAccount
  name: falco
  namespace: falco

---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: falco
  namespace: falco
spec:
  selector:
    matchLabels:
      app: falco
  template:
    metadata:
      labels:
        app: falco
    spec:
      serviceAccountName: falco
      hostNetwork: true
      hostPID: true
      containers:
      - name: falco
        image: falcosecurity/falco-no-driver:0.36.2
        securityContext:
          privileged: true
        args:
          - /usr/bin/falco
          - --cri
          - /run/containerd/containerd.sock
          - -K
          - /var/run/secrets/kubernetes.io/serviceaccount/token
          - -k
          - https://kubernetes.default
          - -pk
        volumeMounts:
        - name: dev
          mountPath: /host/dev
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: boot
          mountPath: /host/boot
          readOnly: true
        - name: lib-modules
          mountPath: /host/lib/modules
          readOnly: true
        - name: usr
          mountPath: /host/usr
          readOnly: true
        - name: etc
          mountPath: /host/etc
          readOnly: true
      volumes:
      - name: dev
        hostPath:
          path: /dev
      - name: proc
        hostPath:
          path: /proc
      - name: boot
        hostPath:
          path: /boot
      - name: lib-modules
        hostPath:
          path: /lib/modules
      - name: usr
        hostPath:
          path: /usr
      - name: etc
        hostPath:
          path: /etc
```

### Falco Rules

Falco uses a rule-based system to detect suspicious behavior.

#### Rule Structure

```yaml
- rule: Shell in Container
  desc: Detect shell execution in a container
  condition: >
    spawned_process and
    container and
    shell_procs and
    proc.pname exists and
    not proc.pname in (shell_procs)
  output: >
    Shell spawned in container
    (user=%user.name
     user_loginuid=%user.loginuid
     container_id=%container.id
     container_name=%container.name
     image=%container.image.repository
     shell=%proc.name
     parent=%proc.pname
     cmdline=%proc.cmdline
     terminal=%proc.tty)
  priority: WARNING
  tags: [container, shell, mitre_execution]
```

#### Default Rules (Examples)

**1. Shell in Container:**

```yaml
- rule: Terminal shell in container
  desc: A shell was used as the entrypoint/exec point into a container
  condition: >
    spawned_process and container
    and shell_procs and proc.tty != 0
    and container_entrypoint
    and not user_expected_terminal_shell_in_container_conditions
  output: >
    A shell was spawned in a container with an attached terminal
    (user=%user.name user_loginuid=%user.loginuid %container.info
     shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline
     terminal=%proc.tty container_id=%container.id image=%container.image.repository)
  priority: NOTICE
  tags: [container, shell, mitre_execution]
```

**2. Sensitive File Access:**

```yaml
- rule: Read sensitive file untrusted
  desc: Detect attempts to read sensitive files
  condition: >
    open_read and
    sensitive_files and
    not trusted_containers and
    not proc.name in (user_mgmt_binaries)
  output: >
    Sensitive file opened for reading by non-trusted program
    (user=%user.name user_loginuid=%user.loginuid
     file=%fd.name parent=%proc.pname
     container_id=%container.id image=%container.image.repository)
  priority: WARNING
  tags: [filesystem, mitre_credential_access]
```

**3. Privilege Escalation:**

```yaml
- rule: Change thread namespace
  desc: Detect attempts to change namespaces (potential container escape)
  condition: >
    syscall.type = setns and
    not proc.name in (docker_binaries, k8s_binaries, lxc_binaries)
    and not container.privileged=true
  output: >
    Namespace change (setns) by non-privileged container
    (user=%user.name user_loginuid=%user.loginuid
     command=%proc.cmdline container_id=%container.id
     image=%container.image.repository)
  priority: WARNING
  tags: [container, mitre_privilege_escalation]
```

#### Custom Rules

**Example: Detect Cryptocurrency Mining:**

```yaml
- list: crypto_miners
  items: [xmrig, ethminer, ccminer, cpuminer]

- rule: Cryptocurrency Mining Activity
  desc: Detect cryptocurrency mining processes
  condition: >
    spawned_process and
    (proc.name in (crypto_miners) or
     proc.cmdline contains "stratum+tcp" or
     proc.cmdline contains "pool.hashvault" or
     proc.cmdline contains "mining")
  output: >
    Cryptocurrency mining activity detected
    (user=%user.name command=%proc.cmdline
     container_id=%container.id image=%container.image.repository)
  priority: CRITICAL
  tags: [malware, cryptocurrency]
```

**Example: Detect Port Scanning:**

```yaml
- rule: Outbound Port Scanning
  desc: Detect potential port scanning activity
  condition: >
    outbound and
    fd.sport_range in (1024, 65535) and
    fd.dport_range in (1, 1024) and
    fd.type = ipv4 and
    not proc.name in (allowed_network_tools)
  output: >
    Potential port scanning detected
    (user=%user.name command=%proc.cmdline
     connection=%fd.name container=%container.info)
  priority: WARNING
  tags: [network, mitre_discovery]
```

### Configuring Falco

#### Falco Configuration File

```yaml
# /etc/falco/falco.yaml

rules_file:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/falco_rules.local.yaml
  - /etc/falco/k8s_audit_rules.yaml

json_output: true
json_include_output_property: true

log_stderr: true
log_syslog: false
log_level: info

priority: debug

# Output channels

file_output:
  enabled: true
  keep_alive: false
  filename: /var/log/falco/events.log

stdout_output:
  enabled: true

syslog_output:
  enabled: false

program_output:
  enabled: false
  keep_alive: false
  program: "jq '{text: .output}' | curl -d @- -X POST https://hooks.slack.com/services/XXX"

http_output:
  enabled: false
  url: http://some.webhook.com/endpoint

grpc:
  enabled: false
  bind_address: "0.0.0.0:5060"
  threadiness: 8

grpc_output:
  enabled: false
```

#### ConfigMap for Custom Rules

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-rules
  namespace: falco
data:
  custom-rules.yaml: |
    - rule: Unauthorized Process in Container
      desc: Detect unexpected processes
      condition: >
        spawned_process and
        container and
        container.image.repository = "nginx" and
        not proc.name in (nginx, sh, bash)
      output: >
        Unauthorized process in nginx container
        (user=%user.name process=%proc.name
         cmdline=%proc.cmdline container=%container.name)
      priority: WARNING
      tags: [container, process]
```

### Viewing Falco Alerts

```bash
# View real-time alerts

kubectl logs -n falco -l app.kubernetes.io/name=falco -f

# View specific container alerts

kubectl logs -n falco -l app.kubernetes.io/name=falco | grep -i "container_name=<name>"

# Filter by priority

kubectl logs -n falco -l app.kubernetes.io/name=falco | grep "priority=CRITICAL"

# Export alerts to file

kubectl logs -n falco -l app.kubernetes.io/name=falco > falco-alerts.log
```

### Testing Falco

#### Test 1: Shell in Container

```bash
# Create test pod

kubectl run test-shell --image=nginx:1.27

# Trigger alert: exec into container

kubectl exec -it test-shell -- /bin/bash

# Expected Falco alert:
# A shell was spawned in a container with an attached terminal

```

#### Test 2: Sensitive File Access

```bash
# Trigger alert: read /etc/shadow

kubectl exec test-shell -- cat /etc/shadow

# Expected Falco alert:
# Sensitive file opened for reading by non-trusted program

```

#### Test 3: Network Activity

```bash
# Trigger alert: unexpected network connection

kubectl exec test-shell -- nc -v google.com 80

# Expected Falco alert:
# Outbound connection from container

```

### Integrating Falco with Alert Systems

#### Falcosidekick (Alert Router)

```bash
# Install Falcosidekick

helm install falcosidekick falcosecurity/falcosidekick \
  --namespace falco \
  --set config.slack.webhookurl="https://hooks.slack.com/services/XXX" \
  --set config.slack.minimumpriority="warning"

# Update Falco to use Falcosidekick

helm upgrade falco falcosecurity/falco \
  --namespace falco \
  --reuse-values \
  --set falcosidekick.enabled=true \
  --set falcosidekick.fullfqdn=falcosidekick:2801
```

## Seccomp - Secure Computing Mode

Seccomp restricts system calls that a container can make to the kernel.

### How Seccomp Works

```
Container Process → Seccomp Filter → Kernel
                         ↓
                   Allow/Deny syscall

```

### Default Seccomp Profile

Docker/containerd use a default seccomp profile that blocks ~44 dangerous syscalls.

**Blocked syscalls include:**

- `mount`, `umount` - Filesystem mounting
- `reboot` - System reboot
- `swapon`, `swapoff` - Swap management
- `setns` - Namespace manipulation
- `ptrace` - Process debugging

### Kubernetes Seccomp Profiles

#### Using RuntimeDefault Profile

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: seccomp-default
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: nginx:1.27
```

#### Using Localhost Profile

**Step 1: Create Custom Profile**

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": [
        "accept4", "access", "arch_prctl", "bind", "brk",
        "capget", "capset", "chdir", "chmod", "chown",
        "clone", "close", "connect", "dup", "dup2",
        "epoll_create", "epoll_ctl", "epoll_wait", "execve",
        "exit", "exit_group", "fchmod", "fchown", "fcntl",
        "fstat", "futex", "getcwd", "getdents64", "getegid",
        "geteuid", "getgid", "getpeername", "getpid", "getppid",
        "getrandom", "getsockname", "getsockopt", "getuid",
        "ioctl", "listen", "lseek", "mmap", "mprotect",
        "munmap", "nanosleep", "openat", "pipe", "poll",
        "read", "readlink", "recvfrom", "recvmsg", "rt_sigaction",
        "rt_sigprocmask", "rt_sigreturn", "sendmsg", "sendto",
        "set_robust_list", "setgid", "setgroups", "setsockopt",
        "setuid", "socket", "stat", "uname", "wait4", "write"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

**Step 2: Place Profile on Nodes**

```bash
# On each node

sudo mkdir -p /var/lib/kubelet/seccomp/profiles
sudo cp custom-profile.json /var/lib/kubelet/seccomp/profiles/custom.json
```

**Step 3: Use Profile in Pod**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: seccomp-custom
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/custom.json
  containers:
  - name: app
    image: nginx:1.27
```

#### Unconfined Profile (Not Recommended)

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: seccomp-unconfined
spec:
  securityContext:
    seccompProfile:
      type: Unconfined  # Disables seccomp
  containers:
  - name: app
    image: nginx:1.27
```

### Testing Seccomp

```bash
# Create pod without seccomp

kubectl run test-no-seccomp --image=alpine --command -- sleep 3600

# Create pod with RuntimeDefault

kubectl run test-seccomp --image=alpine \
  --overrides='{"spec":{"securityContext":{"seccompProfile":{"type":"RuntimeDefault"}}}}' \
  --command -- sleep 3600

# Test blocked syscall (should fail with seccomp)

kubectl exec test-seccomp -- mount /dev/sda1 /mnt

# Error: mount: permission denied (even as root due to seccomp)

# Compare with no seccomp (may succeed if running privileged)

kubectl exec test-no-seccomp -- mount /dev/sda1 /mnt
```

## AppArmor - Application Security Profiles

AppArmor is a Linux Security Module (LSM) that restricts program capabilities using per-program profiles.

### Checking AppArmor Status

```bash
# Check if AppArmor is enabled (on node)

sudo systemctl status apparmor

# View loaded profiles

sudo aa-status

# Check AppArmor kernel module

cat /sys/module/apparmor/parameters/enabled

# Output: Y

```

### AppArmor Profile Structure

```bash
# /etc/apparmor.d/docker-nginx

#include <tunables/global>

profile docker-nginx flags=(attach_disconnected,mediate_deleted) {

  #include <abstractions/base>

  # Allow network access

  network inet tcp,
  network inet udp,

  # Allow read access to /usr/share/nginx

  /usr/share/nginx/** r,

  # Allow write access to /var/log/nginx

  /var/log/nginx/** w,

  # Allow execute

  /usr/sbin/nginx ix,

  # Deny write to sensitive files

  deny /etc/shadow w,
  deny /etc/passwd w,

  # Allow /tmp

  /tmp/** rw,

  # Capability restrictions

  capability net_bind_service,
  capability setuid,
  capability setgid,
}
```

### Using AppArmor in Kubernetes

#### Step 1: Load Profile on Nodes

```bash
# On each node

sudo cat > /etc/apparmor.d/k8s-restricted <<EOF

#include <tunables/global>

profile k8s-restricted flags=(attach_disconnected,mediate_deleted) {

  #include <abstractions/base>

  # Deny access to sensitive files

  deny /etc/shadow r,
  deny /etc/passwd w,
  deny /root/.ssh/** rw,

  # Allow most other operations

  file,
  network,
  capability,
}
EOF

# Load the profile

sudo apparmor_parser -r /etc/apparmor.d/k8s-restricted

# Verify

sudo aa-status | grep k8s-restricted
```

#### Step 2: Apply to Pod

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: apparmor-pod
  annotations:
    container.apparmor.security.beta.kubernetes.io/nginx: localhost/k8s-restricted
spec:
  containers:
  - name: nginx
    image: nginx:1.27
```

#### Alternative: Runtime/Default Profile

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: apparmor-default
  annotations:
    container.apparmor.security.beta.kubernetes.io/nginx: runtime/default
spec:
  containers:
  - name: nginx
    image: nginx:1.27
```

### Testing AppArmor

```bash
# Create pod with AppArmor

kubectl apply -f apparmor-pod.yaml

# Try to access denied file

kubectl exec apparmor-pod -- cat /etc/shadow

# Expected: Permission denied

# Check AppArmor denials in logs (on node)

sudo journalctl -xe | grep audit | grep apparmor
```

## SELinux - Security-Enhanced Linux

SELinux provides mandatory access control (MAC) enforcement.

### SELinux Modes

- **Enforcing**: Denies access and logs violations
- **Permissive**: Allows access but logs violations
- **Disabled**: SELinux is turned off

### Checking SELinux Status

```bash
# Check SELinux status (on node)

getenforce

# Output: Enforcing, Permissive, or Disabled

sestatus

# View denials

sudo ausearch -m avc -ts recent
```

### Using SELinux in Kubernetes

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: selinux-pod
spec:
  securityContext:
    seLinuxOptions:
      level: "s0:c123,c456"
      type: "spc_t"
  containers:
  - name: nginx
    image: nginx:1.27
```

**Common SELinux Types:**

- `container_t`: Default for containers
- `svirt_sandbox_file_t`: For container files
- `spc_t`: Super privileged container (more access)

## Best Practices

### 1. Enable Multiple Security Layers

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: multi-layer-security
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: runtime/default
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
        drop:
        - ALL
      readOnlyRootFilesystem: true
```

### 2. Deploy Falco as DaemonSet

Ensure Falco runs on every node for complete coverage.

### 3. Tune Falco Rules

Start with default rules, then customize for your environment:

```yaml
- list: allowed_images
  items: ["nginx", "redis", "postgres"]

- rule: Unexpected Container Image
  desc: Detect containers from non-approved images
  condition: >
    container and
    not container.image.repository in (allowed_images)
  output: Container from unapproved image (image=%container.image.repository)
  priority: WARNING
```

### 4. Use RuntimeDefault Seccomp

Always set `seccompProfile.type: RuntimeDefault` unless you have specific requirements.

### 5. Test Security Profiles

Test profiles in non-production before enforcing:

```bash
# Test in dry-run mode

kubectl apply --dry-run=server -f pod-with-security.yaml
```

### 6. Monitor and Alert

Integrate Falco with your incident response workflow:

- Send critical alerts to PagerDuty
- Log all events to SIEM
- Create dashboards for security metrics

### 7. Regular Rule Updates

```bash
# Update Falco rules

helm upgrade falco falcosecurity/falco \
  --namespace falco \
  --reuse-values

# Update custom rules via ConfigMap

kubectl apply -f falco-custom-rules.yaml
```

## Troubleshooting

### Falco Not Detecting Events

```bash
# Check Falco is running

kubectl get pods -n falco

# Check Falco logs for errors

kubectl logs -n falco -l app.kubernetes.io/name=falco

# Verify driver is loaded (on node)

sudo lsmod | grep falco

# Test with simple rule
# Add to custom rules:

- rule: Test Rule
  desc: Fires on any process spawn
  condition: spawned_process
  output: Process spawned (command=%proc.cmdline)
  priority: INFO
```

### Seccomp Profile Not Applied

```bash
# Check pod security context

kubectl get pod <pod-name> -o jsonpath='{.spec.securityContext.seccompProfile}'

# Check node supports seccomp
# On node:

grep CONFIG_SECCOMP /boot/config-$(uname -r)

# Should show: CONFIG_SECCOMP=y

# View seccomp denials (on node)

sudo journalctl -xe | grep seccomp
```

### AppArmor Profile Issues

```bash
# Check profile is loaded (on node)

sudo aa-status | grep <profile-name>

# Reload profile

sudo apparmor_parser -r /etc/apparmor.d/<profile-name>

# View denials

sudo journalctl -xe | grep apparmor

# Check pod annotation

kubectl get pod <pod-name> -o yaml | grep apparmor
```

### SELinux Denials

```bash
# View SELinux denials (on node)

sudo ausearch -m avc -ts recent

# Generate policy from denials

sudo audit2allow -a

# Check pod SELinux context

kubectl exec <pod-name> -- id -Z
```

## Summary

Runtime security provides critical defense-in-depth protection:

1. **Falco**: Monitors runtime behavior and detects threats
1. **Seccomp**: Restricts system calls to prevent kernel exploits
1. **AppArmor/SELinux**: Enforces mandatory access control
1. **Defense in Depth**: Combine multiple security layers
1. **Continuous Monitoring**: Integrate with alerting and incident response

**Key Takeaways:**

- Runtime security detects threats that bypass preventive controls
- Falco is essential for Kubernetes runtime monitoring
- Always use RuntimeDefault seccomp profile
- Combine seccomp, AppArmor/SELinux, and Falco for maximum protection
- Test security profiles before production deployment
- Integrate runtime security with incident response workflows

## Additional Resources

- [Falco Documentation](https://falco.org/docs/)
- [Seccomp in Kubernetes](https://kubernetes.io/docs/tutorials/security/seccomp/)
- [AppArmor in Kubernetes](https://kubernetes.io/docs/tutorials/security/apparmor/)
- [SELinux in Kubernetes](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Falco Rules Repository](https://github.com/falcosecurity/rules)

---

[Back to Domain 4 README](./README.md) | [Previous: Admission Controllers ←](./admission-controllers.md) | [Next: Image Security →](./image-security.md)
