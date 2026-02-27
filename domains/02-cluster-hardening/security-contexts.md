# Security Contexts

## Introduction

**Security Contexts** define privilege and access control settings for pods and containers. They are fundamental to implementing defense-in-depth security strategies by controlling what processes running in containers can do at the Linux OS level.

**What Security Contexts Do**:

- Control user and group IDs for processes
- Manage Linux capabilities
- Set filesystem permissions and access modes
- Configure SELinux, AppArmor, and seccomp profiles
- Prevent privilege escalation
- Define read-only root filesystems

**Real-World Scenario**: By default, many container images run as root (UID 0), which poses security risks. If a container is compromised, an attacker running as root has broad permissions. Security contexts allow you to run containers as non-root users, drop dangerous capabilities, and restrict filesystem access, significantly reducing the attack surface.

## Security Context Levels

Security contexts can be applied at two levels, with container-level settings overriding pod-level settings.

### Pod-Level Security Context

Applied to all containers in the pod:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo
spec:
  securityContext:           # Pod-level
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
  containers:
  - name: sec-ctx-demo
    image: busybox:1.36
    command: ["sh", "-c", "sleep 3600"]
```

### Container-Level Security Context

Applied to specific container (overrides pod-level):

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo-2
spec:
  securityContext:
    runAsUser: 1000         # Pod-level: applies to all containers
  containers:
  - name: sec-ctx-demo
    image: busybox:1.36
    command: ["sh", "-c", "sleep 3600"]
    securityContext:        # Container-level: overrides pod setting
      runAsUser: 2000       # This container runs as user 2000
      allowPrivilegeEscalation: false
```

**Priority**: Container-level settings override pod-level settings.

## Running as Non-Root User

### Why Non-Root Matters

Running containers as root (UID 0) is a security risk:

- Root inside container = potential root on host (if container escapes)
- Broader permissions to modify files
- Can install packages and modify system
- Increases blast radius of compromise

### Set User and Group IDs

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: non-root-demo
spec:
  securityContext:
    runAsUser: 1000          # Run as user ID 1000
    runAsGroup: 3000         # Run with group ID 3000
    runAsNonRoot: true       # Enforce non-root (pod fails if image runs as root)
  containers:
  - name: app
    image: nginx:1.27
```

**Fields Explained**:

- **runAsUser**: Specifies the user ID (UID) for container processes
- **runAsGroup**: Specifies the primary group ID (GID)
- **runAsNonRoot**: If true, kubelet validates container image doesn't run as UID 0

### Verify Running User

```bash
# Create a test pod

kubectl run user-test --image=busybox:1.36 --rm -it -- sh

# Check current user (default, often root)

/ # id
uid=0(root) gid=0(root) groups=10(wheel)

# Exit and create with non-root security context

kubectl run user-test --image=busybox:1.36 --rm -it \
  --overrides='{"spec":{"securityContext":{"runAsUser":1000,"runAsGroup":3000}}}' \
  -- sh

# Check user now

/ $ id
uid=1000 gid=3000 groups=3000
```

### Setting in Dockerfile

Configure non-root in container image:

```dockerfile
FROM nginx:1.27

# Create non-root user

RUN useradd -u 1000 -U -s /bin/bash appuser

# Set ownership

RUN chown -R appuser:appuser /usr/share/nginx/html

# Switch to non-root user

USER appuser

EXPOSE 8080
```

**Best Practice**: Set `USER` in Dockerfile AND enforce with `runAsNonRoot: true` in pod spec.

## Filesystem Security

### Read-Only Root Filesystem

Prevent container from writing to root filesystem:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: readonly-demo
spec:
  containers:
  - name: app
    image: nginx:1.27
    securityContext:
      readOnlyRootFilesystem: true    # Make root filesystem read-only
    volumeMounts:
    - name: tmp
      mountPath: /tmp                  # Writable temp directory
    - name: cache
      mountPath: /var/cache/nginx      # Writable cache directory
    - name: run
      mountPath: /var/run              # Writable run directory
  volumes:
  - name: tmp
    emptyDir: {}
  - name: cache
    emptyDir: {}
  - name: run
    emptyDir: {}
```

**Why This Matters**:

- Prevents malware persistence
- Stops attackers from modifying binaries
- Reduces attack surface
- Enforces immutable infrastructure

**Implementation Pattern**:

1. Set `readOnlyRootFilesystem: true`
1. Mount emptyDir volumes for directories that need writes
1. Common writable paths: `/tmp`, `/var/cache`, `/var/run`, `/var/log`

### fsGroup for Shared Volumes

Set group ownership for mounted volumes:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: fsgroup-demo
spec:
  securityContext:
    fsGroup: 2000              # All volumes owned by group 2000
    fsGroupChangePolicy: "OnRootMismatch"  # Only change if needed (performance)
  containers:
  - name: app
    image: busybox:1.36
    command: ["sh", "-c", "sleep 3600"]
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    persistentVolumeClaim:
      claimName: my-pvc
```

**How fsGroup Works**:

- When pod starts, Kubernetes changes volume ownership to `fsGroup` GID
- Processes in pod run with `fsGroup` as supplementary group
- Enables multiple containers to share volumes

**Verify**:

```bash
kubectl exec fsgroup-demo -- ls -ld /data

# Output: drwxrwsr-x 2 root 2000 4096 Feb 27 10:00 /data
#                           ^^^^
#                          fsGroup GID

```

### Supplementary Groups

Add additional group IDs to container process:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: supplemental-groups-demo
spec:
  securityContext:
    supplementalGroups: [4000, 5000]    # Add groups 4000 and 5000
    fsGroup: 2000
  containers:
  - name: app
    image: busybox:1.36
    command: ["sh", "-c", "sleep 3600"]
```

**Verify**:

```bash
kubectl exec supplemental-groups-demo -- id

# Output: uid=0(root) gid=0(root) groups=0(root),2000,4000,5000

```

## Linux Capabilities

Linux capabilities divide root privileges into distinct units. Instead of giving full root, grant specific capabilities.

### Understanding Capabilities

**Common Capabilities**:

| Capability | Description | Risk Level |
| ------------ | ------------- | ------------ |
| `CAP_NET_ADMIN` | Network administration | Medium |
| `CAP_NET_BIND_SERVICE` | Bind ports < 1024 | Low |
| `CAP_SYS_ADMIN` | System administration | **Critical** |
| `CAP_SYS_TIME` | Change system clock | Medium |
| `CAP_CHOWN` | Change file ownership | Medium |
| `CAP_KILL` | Send signals to processes | Low |
| `CAP_SETUID` | Change UID | High |
| `CAP_SETGID` | Change GID | High |
| `CAP_DAC_OVERRIDE` | Bypass file permissions | High |
| `CAP_AUDIT_WRITE` | Write to audit log | Low |

### Default Container Capabilities

By default, containers get these capabilities:

```
CAP_CHOWN
CAP_DAC_OVERRIDE
CAP_FOWNER
CAP_FSETID
CAP_KILL
CAP_SETGID
CAP_SETUID
CAP_SETPCAP
CAP_NET_BIND_SERVICE
CAP_NET_RAW
CAP_SYS_CHROOT
CAP_MKNOD
CAP_AUDIT_WRITE
CAP_SETFCAP

```

### Dropping All Capabilities

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: cap-drop-all
spec:
  containers:
  - name: app
    image: nginx:1.27
    securityContext:
      capabilities:
        drop:
        - ALL    # Drop all capabilities
```

**Best Practice**: Drop all, then add only what's needed.

### Adding Required Capabilities

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: cap-specific
spec:
  containers:
  - name: app
    image: nginx:1.27
    securityContext:
      capabilities:
        drop:
        - ALL                      # Drop all first
        add:
        - NET_BIND_SERVICE         # Add only needed capability
```

**Use Case**: Nginx needs to bind to port 80 (< 1024), requires `NET_BIND_SERVICE`.

### Dangerous Capabilities to Avoid

Never grant these in production:

```yaml
# DANGEROUS - Don't use!

securityContext:
  capabilities:
    add:
    - SYS_ADMIN        # Nearly root-equivalent
    - SYS_MODULE       # Load kernel modules
    - SYS_RAWIO        # Raw I/O access
    - DAC_READ_SEARCH  # Bypass file read permissions
```

### Checking Container Capabilities

```bash
# Check capabilities in running container

kubectl exec my-pod -- grep Cap /proc/1/status

# Decode capability mask

kubectl exec my-pod -- cat /proc/1/status | grep CapEff

# Use capsh to decode:
# capsh --decode=00000000a80425fb

```

## Privilege Escalation

### Preventing Privilege Escalation

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: no-privilege-escalation
spec:
  containers:
  - name: app
    image: nginx:1.27
    securityContext:
      allowPrivilegeEscalation: false    # Prevent setuid binaries
```

**What This Prevents**:

- Processes cannot gain more privileges than parent
- Setuid/setgid binaries don't work
- Prevents exploitation of vulnerable setuid programs

**Default Behavior**: Depends on other settings

- If `privileged: true` → `allowPrivilegeEscalation: true` (automatic)
- If `CAP_SYS_ADMIN` added → often allows escalation
- If `runAsNonRoot: true` → escalation unlikely but not prevented

**Best Practice**: Always explicitly set `allowPrivilegeEscalation: false`.

### Privileged Containers (Avoid!)

```yaml
# DANGEROUS - Avoid in production!

apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: app
    image: nginx:1.27
    securityContext:
      privileged: true    # All capabilities, no restrictions
```

**Privileged Containers**:

- Get all Linux capabilities
- Can access host devices
- Essentially run as root on host
- Should only be used for specific system workloads (DaemonSets, CNI, etc.)

## SELinux, AppArmor, and Seccomp

### SELinux Options

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: selinux-demo
spec:
  securityContext:
    seLinuxOptions:
      level: "s0:c123,c456"    # SELinux level
      role: "object_r"          # SELinux role
      type: "container_t"       # SELinux type
      user: "system_u"          # SELinux user
  containers:
  - name: app
    image: nginx:1.27
```

**Note**: Requires SELinux-enabled nodes (common in RHEL, Fedora).

### AppArmor Profiles

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: apparmor-demo
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: localhost/k8s-apparmor-example
spec:
  containers:
  - name: app
    image: nginx:1.27
```

**AppArmor Profile Types**:

- `runtime/default`: Default container profile
- `localhost/<profile-name>`: Custom profile on node
- `unconfined`: No AppArmor enforcement

### Seccomp Profiles

Seccomp (Secure Computing Mode) restricts system calls:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: seccomp-demo
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault    # Use container runtime's default profile
  containers:
  - name: app
    image: nginx:1.27
```

**Seccomp Profile Types**:

- `RuntimeDefault`: Default profile (recommended)
- `Localhost`: Custom profile from node
- `Unconfined`: No seccomp restrictions (avoid!)

**Custom Seccomp Profile**:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: seccomp-custom
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/audit.json    # Profile on node
  containers:
  - name: app
    image: nginx:1.27
```

## Complete Security Context Example

Combining all best practices:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: runtime/default
spec:
  securityContext:
    runAsUser: 1000                # Non-root user
    runAsGroup: 3000               # Non-root group
    runAsNonRoot: true             # Enforce non-root
    fsGroup: 2000                  # Shared volume group
    seccompProfile:
      type: RuntimeDefault         # Restrict syscalls
  containers:
  - name: app
    image: nginx:1.27
    securityContext:
      allowPrivilegeEscalation: false    # No privilege escalation
      readOnlyRootFilesystem: true       # Immutable filesystem
      capabilities:
        drop:
        - ALL                            # Drop all capabilities
        add:
        - NET_BIND_SERVICE               # Add only needed
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

## Common Patterns

### Pattern 1: Web Server (Nginx)

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-secure
spec:
  securityContext:
    runAsUser: 101           # nginx user
    runAsGroup: 101
    runAsNonRoot: true
    fsGroup: 101
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: nginx
    image: nginx:1.27
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: [ALL]
        add: [NET_BIND_SERVICE]
    ports:
    - containerPort: 80
    volumeMounts:
    - name: cache
      mountPath: /var/cache/nginx
    - name: run
      mountPath: /var/run
  volumes:
  - name: cache
    emptyDir: {}
  - name: run
    emptyDir: {}
```

### Pattern 2: Database (PostgreSQL)

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: postgres-secure
spec:
  securityContext:
    runAsUser: 999           # postgres user
    runAsGroup: 999
    runAsNonRoot: true
    fsGroup: 999
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: postgres
    image: postgres:16
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: [ALL]
        add: [CHOWN, SETUID, SETGID, DAC_OVERRIDE]
    env:
    - name: POSTGRES_PASSWORD
      value: example
    volumeMounts:
    - name: data
      mountPath: /var/lib/postgresql/data
  volumes:
  - name: data
    persistentVolumeClaim:
      claimName: postgres-pvc
```

### Pattern 3: Batch Job

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: secure-job
spec:
  template:
    spec:
      securityContext:
        runAsUser: 1000
        runAsGroup: 1000
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: worker
        image: busybox:1.36
        command: ["sh", "-c", "echo Job completed"]
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: [ALL]
      restartPolicy: Never
```

### Pattern 4: Init Container with Different Context

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: init-security-demo
spec:
  securityContext:
    runAsNonRoot: true
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  initContainers:
  - name: init-setup
    image: busybox:1.36
    command: ["sh", "-c", "echo Initializing > /data/init.txt"]
    securityContext:
      runAsUser: 1000        # Init runs as user 1000
      allowPrivilegeEscalation: false
      capabilities:
        drop: [ALL]
    volumeMounts:
    - name: data
      mountPath: /data
  containers:
  - name: app
    image: busybox:1.36
    command: ["sh", "-c", "cat /data/init.txt && sleep 3600"]
    securityContext:
      runAsUser: 2000        # App runs as different user
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: [ALL]
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    emptyDir: {}
```

## Troubleshooting Security Contexts

### Common Issues

#### 1. Permission Denied Errors

```
Error: failed to create containerd task: failed to create shim task:
OCI runtime create failed: container_linux.go:380: starting container
process caused: exec: "nginx": permission denied

```

**Causes**:

- Running as non-root but binary not executable by user
- `readOnlyRootFilesystem: true` but app writes to root filesystem
- Missing required capability

**Solutions**:

```bash
# Check file permissions in image

docker run --rm -it nginx:1.27 ls -la /usr/sbin/nginx

# Check what user/group container runs as

kubectl get pod my-pod -o jsonpath='{.spec.securityContext}'

# Add writable volumes if using readOnlyRootFilesystem

```

#### 2. Container Crashes on Startup

```
Error: mkdir: cannot create directory '/tmp/app': Read-only file system

```

**Solution**: Add emptyDir volumes for writable paths:

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
- name: tmp
  mountPath: /tmp
volumes:
- name: tmp
  emptyDir: {}
```

#### 3. Port Binding Fails

```
Error: bind: permission denied (port 80)

```

**Causes**:

- Non-root user trying to bind privileged port (< 1024)
- Missing `NET_BIND_SERVICE` capability

**Solutions**:

```yaml
# Option 1: Add capability

securityContext:
  capabilities:
    add: [NET_BIND_SERVICE]

# Option 2: Use non-privileged port

ports:
- containerPort: 8080    # Port > 1024
```

#### 4. runAsNonRoot Validation Fails

```
Error: container has runAsNonRoot and image will run as root

```

**Solution**: Override user in pod spec:

```yaml
securityContext:
  runAsUser: 1000        # Explicit non-root user
  runAsNonRoot: true
```

Or fix Dockerfile:

```dockerfile
USER 1000
```

### Debugging Commands

```bash
# Check current user in container

kubectl exec my-pod -- id

# Check capabilities

kubectl exec my-pod -- grep Cap /proc/1/status

# Check filesystem permissions

kubectl exec my-pod -- ls -la /

# Check if filesystem is read-only

kubectl exec my-pod -- touch /test-write

# If error "Read-only file system" → readOnlyRootFilesystem is working

# View pod security context

kubectl get pod my-pod -o jsonpath='{.spec.securityContext}' | jq

# View container security context

kubectl get pod my-pod -o jsonpath='{.spec.containers[0].securityContext}' | jq

# Check which user process runs as

kubectl exec my-pod -- ps aux
```

## Security Context Best Practices

### 1. Always Run as Non-Root

```yaml
securityContext:
  runAsUser: 1000
  runAsGroup: 1000
  runAsNonRoot: true    # Enforce
```

### 2. Use Read-Only Root Filesystem

```yaml
securityContext:
  readOnlyRootFilesystem: true

# Add emptyDir for writable paths

```

### 3. Drop All Capabilities

```yaml
securityContext:
  capabilities:
    drop: [ALL]

    # Add only specific ones if needed

```

### 4. Prevent Privilege Escalation

```yaml
securityContext:
  allowPrivilegeEscalation: false
```

### 5. Use Seccomp Profiles

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

### 6. Apply Pod-Level Defaults

```yaml
spec:
  securityContext:       # Pod-level defaults
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    securityContext:     # Container-specific overrides
      capabilities:
        drop: [ALL]
```

### 7. Document Security Requirements

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
  annotations:
    security.kubernetes.io/user: "1000"
    security.kubernetes.io/rationale: "Runs as non-root for security"
    security.kubernetes.io/capabilities: "NET_BIND_SERVICE required for port 80"
spec:

  # ... security context configuration

```

## Security Context Priority

When both pod and container security contexts are set:

```yaml
spec:
  securityContext:                  # Pod-level
    runAsUser: 1000
    fsGroup: 2000
  containers:
  - name: container1
    securityContext:                # Container-level overrides
      runAsUser: 3000               # This takes precedence

    # runAsUser: 3000, fsGroup: 2000 (inherited)

  - name: container2

    # No container-level context
    # runAsUser: 1000, fsGroup: 2000 (inherited from pod)

```

**Precedence Rules**:

1. Container-level settings override pod-level
1. Pod-level applies to all containers unless overridden
1. Some fields only exist at pod-level (fsGroup)
1. Some fields only exist at container-level (capabilities)

## Security Context Fields Reference

### Pod-Level Fields

| Field | Type | Description |
| ------- | ------ | ------------- |
| `runAsUser` | integer | User ID for all containers |
| `runAsGroup` | integer | Primary group ID |
| `runAsNonRoot` | boolean | Enforce non-root requirement |
| `fsGroup` | integer | Group ID for volume ownership |
| `fsGroupChangePolicy` | string | How to apply fsGroup |
| `supplementalGroups` | []integer | Additional group IDs |
| `seccompProfile` | object | Seccomp profile |
| `seLinuxOptions` | object | SELinux context |
| `sysctls` | []object | Sysctl parameters |
| `windowsOptions` | object | Windows-specific options |

### Container-Level Fields

| Field | Type | Description |
| ------- | ------ | ------------- |
| `runAsUser` | integer | User ID (overrides pod) |
| `runAsGroup` | integer | Group ID (overrides pod) |
| `runAsNonRoot` | boolean | Enforce non-root |
| `readOnlyRootFilesystem` | boolean | Make root FS read-only |
| `allowPrivilegeEscalation` | boolean | Allow privilege escalation |
| `privileged` | boolean | Run as privileged |
| `capabilities` | object | Linux capabilities |
| `seccompProfile` | object | Seccomp profile |
| `seLinuxOptions` | object | SELinux context |

## Quick Reference

### Minimal Secure Configuration

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: [ALL]
  seccompProfile:
    type: RuntimeDefault
```

### Common Capability Requirements

| Application | Required Capabilities |
| ------------- | ---------------------- |
| Nginx (port 80) | `NET_BIND_SERVICE` |
| PostgreSQL | `CHOWN`, `SETUID`, `SETGID`, `DAC_OVERRIDE` |
| Redis | `SETGID`, `SETUID` |
| Static files | None (drop all) |

### Debugging Checklist

- [ ] Verify user/group IDs with `kubectl exec ... -- id`
- [ ] Check capabilities with `grep Cap /proc/1/status`
- [ ] Test filesystem writes to confirm read-only
- [ ] Review pod events for security-related errors
- [ ] Check container logs for permission errors
- [ ] Validate with `kubectl describe pod`

## Exam Tips

1. **Know both levels**: Pod-level and container-level security contexts
1. **Container overrides pod**: Container settings take precedence
1. **Common fields**: runAsUser, runAsNonRoot, capabilities, readOnlyRootFilesystem
1. **Drop ALL first**: Best practice for capabilities
1. **Non-root required**: Always set runAsNonRoot: true
1. **No privilege escalation**: Set allowPrivilegeEscalation: false
1. **Read-only FS**: Use readOnlyRootFilesystem with emptyDir volumes
1. **fsGroup for volumes**: Set fsGroup for shared volume access

## Next Steps

- Complete [Lab 04: Security Contexts](../../labs/02-cluster-hardening/lab-04-security-contexts.md)
- Study [Pod Security Admission](pod-security-admission.md) for policy enforcement
- Review [RBAC](rbac.md) for access control
- Learn about [AppArmor and Seccomp](../03-system-hardening/apparmor-seccomp.md)

## Additional Resources

- [Configure Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Seccomp in Kubernetes](https://kubernetes.io/docs/tutorials/security/seccomp/)
