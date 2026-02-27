# Container Runtime Security

## Introduction

The container runtime is the software responsible for running containers on a Kubernetes node. It sits between the kubelet and the containers, translating high-level Kubernetes instructions into low-level container operations. Securing the runtime is critical because it controls container lifecycle, resource allocation, and isolation.

**Key Concept**: The container runtime is the "gatekeeper" between Kubernetes and your workloads. A compromised runtime can bypass all pod-level security controls.

## Understanding Container Runtimes

### Container Runtime Architecture

```
┌─────────────────────────────────────────────┐
│           Kubernetes Control Plane          │
└────────────────┬────────────────────────────┘
                 │
         ┌───────▼────────┐
         │    kubelet     │
         └───────┬────────┘
                 │ CRI (gRPC)
         ┌───────▼────────┐
         │   containerd   │  ← High-level runtime
         └───────┬────────┘
                 │ CRI Plugin
         ┌───────▼────────┐
         │      runc      │  ← Low-level runtime (OCI)
         └───────┬────────┘
                 │
         ┌───────▼────────┐
         │   Linux Kernel │
         │  (namespaces,  │
         │   cgroups)     │
         └────────────────┘
```

### Runtime Layers

1. **High-level Runtime (containerd, CRI-O)**:

   - Image management (pull, push, store)
   - Container lifecycle (create, start, stop)
   - CRI implementation (gRPC API)
   - Snapshot management

1. **Low-level Runtime (runc, crun, kata)**:

   - OCI runtime specification implementation
   - Namespace and cgroup setup
   - Process execution
   - Security context application

1. **Container Runtime Interface (CRI)**:

   - Standard API between kubelet and runtime
   - Defined by Kubernetes
   - Allows swappable runtimes

### Kubernetes Runtime Evolution

| Version | Default Runtime | Status |
| --------- | ---------------- | --------- |
| < 1.20 | dockershim | Deprecated |
| 1.20+ | containerd/CRI-O | Recommended |
| 1.24+ | dockershim removed | containerd default |

**For KCSA Exam**: Focus on containerd v1.7.x, which is the standard runtime for Kubernetes v1.30.

## Containerd Security

### Containerd Architecture

```
containerd
├── content store (images, layers)
├── snapshot service (filesystem snapshots)
├── metadata store (container metadata)
├── runtime service (OCI runtime interaction)
├── CRI plugin (Kubernetes integration)
└── security features
    ├── AppArmor integration
    ├── Seccomp integration
    ├── SELinux support
    └── Namespace isolation
```

### Containerd Configuration

**Location**: `/etc/containerd/config.toml`

**View Current Configuration**:

```bash
# Show current config

sudo containerd config dump

# Generate default config

sudo containerd config default > /tmp/config.toml
```

**Secure Containerd Configuration**:

```toml
version = 2

# Root directory for containerd state

root = "/var/lib/containerd"

# State directory for containerd

state = "/run/containerd"

# gRPC socket path

[grpc]
  address = "/run/containerd/containerd.sock"
  uid = 0
  gid = 0
  max_recv_message_size = 16777216
  max_send_message_size = 16777216

# CRI plugin configuration

[plugins."io.containerd.grpc.v1.cri"]

  # Enable CRI plugin

  disable_tcp_service = true
  stream_server_address = "127.0.0.1"
  stream_server_port = "0"
  enable_selinux = false  # Set true if using SELinux

  # Sandbox image (pause container)

  sandbox_image = "registry.k8s.io/pause:3.9"

  # Maximum concurrent downloads per image

  max_concurrent_downloads = 3

  # Container runtime configuration

  [plugins."io.containerd.grpc.v1.cri".containerd]

    # Default runtime

    default_runtime_name = "runc"

    # Available runtimes

    [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
      runtime_type = "io.containerd.runc.v2"

      [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]

        # Enable systemd cgroup driver (recommended for Kubernetes)

        SystemdCgroup = true

        # Security options

        BinaryName = "/usr/local/sbin/runc"

    # Optional: Kata Containers for stronger isolation

    [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata]
      runtime_type = "io.containerd.kata.v2"

  # Registry configuration

  [plugins."io.containerd.grpc.v1.cri".registry]
    config_path = "/etc/containerd/certs.d"

    # Registry mirrors and authentication

    [plugins."io.containerd.grpc.v1.cri".registry.mirrors]
      [plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]
        endpoint = ["https://registry-1.docker.io"]

    # TLS configuration for registries

    [plugins."io.containerd.grpc.v1.cri".registry.configs]
      [plugins."io.containerd.grpc.v1.cri".registry.configs."my-registry.com"]
        [plugins."io.containerd.grpc.v1.cri".registry.configs."my-registry.com".tls]
          insecure_skip_verify = false
          ca_file = "/etc/containerd/certs/registry-ca.crt"
          cert_file = "/etc/containerd/certs/registry-cert.crt"
          key_file = "/etc/containerd/certs/registry-key.key"

# Metrics and debugging

[metrics]
  address = "127.0.0.1:1338"

[debug]
  address = ""  # Empty = disable debug socket
  level = "info"
```

**Apply Configuration**:

```bash
# Backup existing config

sudo cp /etc/containerd/config.toml /etc/containerd/config.toml.backup

# Edit configuration

sudo nano /etc/containerd/config.toml

# Test configuration

sudo containerd config dump

# Restart containerd

sudo systemctl restart containerd

# Verify status

sudo systemctl status containerd
```

### Critical Security Settings

#### 1. Socket Permissions

The containerd socket provides full control over containers:

```bash
# Check socket permissions

ls -la /run/containerd/containerd.sock

# Output: srw-rw---- 1 root root 0 Feb 27 10:00 /run/containerd/containerd.sock

# Ensure only root can access

sudo chmod 660 /run/containerd/containerd.sock
sudo chown root:root /run/containerd/containerd.sock
```

**Why It Matters**: Anyone with socket access can create privileged containers, mount host filesystem, and escape to the host.

#### 2. Restrict Network Access

Disable remote API access:

```toml
[grpc]

  # Only listen on Unix socket, NOT TCP

  address = "/run/containerd/containerd.sock"

  # DO NOT set tcp_address

```

**Never expose containerd over TCP** without proper authentication!

#### 3. Registry Security

Only pull from trusted registries:

```toml
[plugins."io.containerd.grpc.v1.cri".registry]

  # Require TLS for all registries

  [plugins."io.containerd.grpc.v1.cri".registry.configs."*"]
    [plugins."io.containerd.grpc.v1.cri".registry.configs."*".tls]
      insecure_skip_verify = false
```

**Content Trust**:

```bash
# Enable Docker Content Trust (image signing)

export DOCKER_CONTENT_TRUST=1

# Pull only signed images

crictl pull docker.io/library/nginx:1.27
```

#### 4. Resource Limits

Prevent resource exhaustion:

```toml
[plugins."io.containerd.grpc.v1.cri"]

  # Limit concurrent downloads

  max_concurrent_downloads = 3

  # Limit container log size

  max_container_log_line_size = 16384
```

### Using crictl (CRI CLI)

`crictl` is the CLI for interacting with CRI-compatible runtimes:

**Installation**:

```bash
# Download crictl

VERSION="v1.30.0"
wget https://github.com/kubernetes-sigs/cri-tools/releases/download/$VERSION/crictl-$VERSION-linux-amd64.tar.gz

# Extract and install

sudo tar zxvf crictl-$VERSION-linux-amd64.tar.gz -C /usr/local/bin
rm -f crictl-$VERSION-linux-amd64.tar.gz

# Configure crictl

cat <<EOF | sudo tee /etc/crictl.yaml
runtime-endpoint: unix:///run/containerd/containerd.sock
image-endpoint: unix:///run/containerd/containerd.sock
timeout: 10
debug: false
EOF

# Verify

crictl version
```

**Common Commands**:

```bash
# List running containers

crictl ps

# List all containers (including stopped)

crictl ps -a

# Inspect container

crictl inspect <container-id>

# View container logs

crictl logs <container-id>

# Execute command in container

crictl exec -it <container-id> /bin/sh

# List images

crictl images

# Pull image

crictl pull nginx:1.27

# Remove image

crictl rmi nginx:1.27

# List pods (sandbox containers)

crictl pods

# Inspect pod

crictl inspectp <pod-id>

# Get runtime info

crictl info

# Check runtime version

crictl version
```

**Security Inspection**:

```bash
# Check container security settings

crictl inspect <container-id> | jq '.info.runtimeSpec.linux.seccomp'
crictl inspect <container-id> | jq '.info.config.linux.security_context'

# View container capabilities

crictl inspect <container-id> | jq '.info.runtimeSpec.process.capabilities'

# Check AppArmor profile

crictl inspect <container-id> | jq '.info.runtimeSpec.process.apparmorProfile'
```

## Runtime Security Features

### 1. Namespace Isolation

Containerd uses Linux namespaces to isolate containers:

| Namespace | Isolates | Security Impact |
| ----------- | ---------- | ---------------- |
| **PID** | Process IDs | Prevents seeing host processes |
| **NET** | Network stack | Isolated network interfaces |
| **MNT** | Mount points | Separate filesystem view |
| **UTS** | Hostname | Independent hostname |
| **IPC** | Inter-process communication | Isolated message queues |
| **USER** | User/Group IDs | UID mapping (rootless) |
| **CGROUP** | Control groups | Isolated resource view |

**Check Container Namespaces**:

```bash
# Find container PID

crictl inspect <container-id> | jq '.info.pid'

# List namespaces

sudo ls -la /proc/<pid>/ns

# Output:
# lrwxrwxrwx 1 root root 0 Feb 27 10:00 cgroup -> 'cgroup:[4026532515]'
# lrwxrwxrwx 1 root root 0 Feb 27 10:00 ipc -> 'ipc:[4026532514]'
# lrwxrwxrwx 1 root root 0 Feb 27 10:00 mnt -> 'mnt:[4026532512]'
# lrwxrwxrwx 1 root root 0 Feb 27 10:00 net -> 'net:[4026532517]'
# lrwxrwxrwx 1 root root 0 Feb 27 10:00 pid -> 'pid:[4026532516]'
# lrwxrwxrwx 1 root root 0 Feb 27 10:00 user -> 'user:[4026531837]'
# lrwxrwxrwx 1 root root 0 Feb 27 10:00 uts -> 'uts:[4026532513]'

```

**Namespace Sharing (Pod Concept)**:

In Kubernetes, containers in the same pod share some namespaces:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: shared-namespaces
spec:
  containers:
  - name: app
    image: nginx:1.27
  - name: sidecar
    image: busybox
    command: ["sleep", "3600"]

  # These containers share:
  # - Network namespace (localhost communication)
  # - IPC namespace (shared memory)
  # - UTS namespace (same hostname)
  # But have separate:
  # - PID namespace (by default, can be shared with shareProcessNamespace: true)
  # - Mount namespace (different filesystems)

```

### 2. Control Groups (cgroups)

Cgroups limit container resource usage:

**Check Container Cgroups**:

```bash
# Find container cgroup path

crictl inspect <container-id> | jq '.info.runtimeSpec.linux.cgroupsPath'

# View cgroup limits

cat /sys/fs/cgroup/kubepods/pod<pod-uid>/<container-id>/memory.max
cat /sys/fs/cgroup/kubepods/pod<pod-uid>/<container-id>/cpu.max
```

**Kubernetes Resource Limits**:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: resource-limited
spec:
  containers:
  - name: app
    image: nginx:1.27
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
      limits:
        memory: "128Mi"
        cpu: "500m"
```

**Verify Limits Applied**:

```bash
# Get pod UID

kubectl get pod resource-limited -o jsonpath='{.metadata.uid}'

# Check memory limit

cat /sys/fs/cgroup/kubepods/pod<uid>/*/memory.max

# Output: 134217728 (128Mi in bytes)

# Check CPU limit

cat /sys/fs/cgroup/kubepods/pod<uid>/*/cpu.max

# Output: 50000 100000 (50% of CPU)

```

### 3. Capabilities

Capabilities break root privileges into fine-grained permissions:

**View Container Capabilities**:

```bash
# Get container capabilities

crictl inspect <container-id> | jq '.info.runtimeSpec.process.capabilities'

# Output example:
# {
#   "effective": ["CAP_NET_BIND_SERVICE"],
#   "bounding": ["CAP_NET_BIND_SERVICE"],
#   "inheritable": ["CAP_NET_BIND_SERVICE"],
#   "permitted": ["CAP_NET_BIND_SERVICE"],
#   "ambient": []
# }

```

**Drop All Capabilities**:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: no-capabilities
spec:
  containers:
  - name: app
    image: nginx:1.27
    securityContext:
      capabilities:
        drop: ["ALL"]

      # Only add what's needed
      # add: ["NET_BIND_SERVICE"]

```

**Verify Capabilities Dropped**:

```bash
# Inside container

cat /proc/1/status | grep Cap

# All should be 0000000000000000 if dropped ALL

```

### 4. Read-Only Root Filesystem

Prevent container from modifying its filesystem:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: readonly-root
spec:
  containers:
  - name: app
    image: nginx:1.27
    securityContext:
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

**Verify Read-Only**:

```bash
# Try to create file in container

kubectl exec readonly-root -- touch /test

# Output: touch: cannot touch '/test': Read-only file system

# But writable in mounted volumes

kubectl exec readonly-root -- touch /tmp/test

# Success!

```

## Advanced Runtime Security

### Rootless Containers

Run containers without root privileges:

**Install Rootless Containerd**:

```bash
# Install rootless containerd

curl -fsSL https://get.docker.com/rootless | sh

# Configure

containerd-rootless-setuptool.sh install

# Run as regular user (no sudo)

containerd --version
```

**Benefits**:

- Reduced attack surface
- Container escape only gives user privileges
- Better multi-tenancy isolation

**Limitations**:

- No privileged operations
- Port < 1024 require special setup
- Performance overhead

### Runtime Classes

Use different runtimes for different workloads:

**Define Runtime Class**:

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc

---
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: kata-containers
handler: kata

---
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: runc
handler: runc
```

**Use Runtime Class**:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
spec:
  runtimeClassName: gvisor  # Use gVisor for stronger isolation
  containers:
  - name: app
    image: nginx:1.27
```

**Configure in Containerd**:

```toml
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata]
  runtime_type = "io.containerd.kata.v2"
```

### gVisor (Application Kernel)

Stronger isolation via user-space kernel:

```
┌─────────────┐
│ Application │
└──────┬──────┘
       │ System calls intercepted
┌──────▼──────┐
│   gVisor    │ ← User-space kernel
│   (runsc)   │
└──────┬──────┘
       │ Limited syscalls
┌──────▼──────┐
│ Host Kernel │
└─────────────┘

```

**Install gVisor**:

```bash
# Add gVisor repository

curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list

# Install runsc

sudo apt update && sudo apt install -y runsc

# Configure containerd

sudo nano /etc/containerd/config.toml
```

Add:

```toml
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
```

```
# Restart containerd

sudo systemctl restart containerd
```

**Trade-offs**:

- Pros: Much stronger isolation, reduced kernel attack surface
- Cons: ~20% performance overhead, some syscalls not supported

### Kata Containers (Lightweight VMs)

VM-level isolation with container UX:

```
┌─────────────┐
│ Application │
└──────┬──────┘
       │
┌──────▼──────┐
│ Guest Kernel│ ← Separate kernel per pod
└──────┬──────┘
       │ Virtualization
┌──────▼──────┐
│ Host Kernel │
└─────────────┘

```

**Trade-offs**:

- Pros: Strongest isolation, separate kernel
- Cons: Higher resource overhead, slower startup

## Runtime Security Monitoring

### Audit Runtime Events

Monitor containerd events:

```bash
# Stream containerd events

sudo ctr events

# Example output:
# 2024-02-27 10:00:00.000000000 +0000 UTC /containers/create
# 2024-02-27 10:00:01.000000000 +0000 UTC /tasks/start

```

### Detect Suspicious Activity

**Monitor for Privilege Escalation**:

```bash
# Watch for privileged containers

sudo crictl ps --format json | jq -r '.[] | select(.securityContext.privileged == true) | .id'

# Alert on privileged container creation

while true; do
  PRIV=$(sudo crictl ps --format json | jq -r '[.[] | select(.securityContext.privileged == true)] | length')
  if [ "$PRIV" -gt 0 ]; then
    echo "ALERT: Privileged container detected!"
  fi
  sleep 10
done
```

**Monitor Runtime Socket Access**:

```bash
# Audit socket access

sudo auditctl -w /run/containerd/containerd.sock -p rwxa -k containerd_socket

# View audit events

sudo ausearch -k containerd_socket
```

### Integrate with Falco

Falco can detect runtime threats:

```yaml
# Falco rule: Detect privileged container

- rule: Launch Privileged Container
  desc: Detect the initial process started in a privileged container
  condition: >
    container_started and container
    and container.privileged=true
  output: >
    Privileged container started (user=%user.name command=%proc.cmdline
    %container.info)
  priority: WARNING
  tags: [container, cis, mitre_execution]
```

## Security Best Practices

### 1. Runtime Hardening Checklist

- [ ] Restrict socket permissions (mode 660)
- [ ] Disable remote API (Unix socket only)
- [ ] Use systemd cgroup driver
- [ ] Enable content trust for images
- [ ] Configure registry TLS
- [ ] Set resource limits
- [ ] Enable audit logging
- [ ] Regular runtime updates
- [ ] Use runtime classes for sensitive workloads
- [ ] Monitor runtime events

### 2. Containerd Maintenance

```bash
# Check containerd version

containerd --version

# Update containerd

sudo apt update && sudo apt upgrade containerd.io

# Clean up unused images

sudo crictl rmi --prune

# Clean up stopped containers

sudo crictl rm $(sudo crictl ps -a -q --state=Exited)

# Check runtime health

sudo systemctl status containerd
sudo crictl info
```

### 3. Incident Response

**If runtime is compromised**:

1. **Isolate the node**:

   ```bash
   kubectl drain node-1 --ignore-daemonsets --delete-emptydir-data
   kubectl cordon node-1

   ```

1. **Investigate**:

   ```bash
   # Check running containers

   sudo crictl ps -a

   # Review logs

   sudo journalctl -u containerd -n 1000

   # Check for suspicious processes

   sudo ps auxf

   ```

1. **Preserve evidence**:

   ```bash
   # Save container logs

   sudo crictl logs <container-id> > /tmp/evidence/container.log

   # Export container filesystem

   sudo crictl export <container-id> /tmp/evidence/container.tar

   ```

1. **Remediate**:

   ```bash
   # Stop compromised containers

   sudo crictl stop <container-id>
   sudo crictl rm <container-id>

   # Rebuild node from trusted image

   ```

## Common Issues and Solutions

### Issue 1: Container Won't Start

**Error**: `failed to create containerd task: OCI runtime create failed`

**Debug**:

```bash
# Check container logs

sudo crictl logs <container-id>

# Check containerd logs

sudo journalctl -u containerd -n 100

# Inspect container config

sudo crictl inspect <container-id>

# Check runtime

sudo crictl info | jq '.config.containerd.runtimes'

```

### Issue 2: Permission Denied Accessing Runtime

**Error**: `permission denied while trying to connect to the Docker daemon socket`

**Solution**:

```bash
# Check socket permissions

ls -la /run/containerd/containerd.sock

# Add user to group (if appropriate)

sudo usermod -aG docker $USER
newgrp docker

# Or use sudo

sudo crictl ps

```

### Issue 3: Image Pull Fails

**Error**: `failed to pull image: x509: certificate signed by unknown authority`

**Solution**:

```bash
# Add registry CA certificate

sudo mkdir -p /etc/containerd/certs.d/my-registry.com
sudo cp ca.crt /etc/containerd/certs.d/my-registry.com/

# Or skip verification (NOT recommended for production)
sudo nano /etc/containerd/config.toml
```

```toml
[plugins."io.containerd.grpc.v1.cri".registry.configs."my-registry.com".tls]
  insecure_skip_verify = true
```

## Next Steps

After understanding runtime security:

- Learn about [AppArmor and Seccomp](apparmor-seccomp.md) profiles
- Study [Kernel Security](kernel-security.md) mechanisms
- Complete [Lab 4: Runtime Security](../../labs/03-system-hardening/lab-04-runtime-security.md)

---

**Key Takeaway**: The container runtime bridges Kubernetes and Linux. Secure it properly, restrict access to the runtime socket, and use advanced runtimes like gVisor or Kata for high-security workloads.
