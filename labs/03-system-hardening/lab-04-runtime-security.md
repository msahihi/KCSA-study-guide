# Lab 4: Runtime Security

## Objectives

By the end of this lab, you will be able to:

- Configure containerd securely
- Verify container isolation (namespaces, cgroups)
- Understand and drop Linux capabilities
- Test container resource limits
- Monitor runtime events and security violations
- Recognize and prevent container escape attempts
- Use crictl for runtime inspection
- Implement defense-in-depth at the runtime level

## Prerequisites

- Completed Labs 1-3
- Running Kubernetes cluster
- kubectl and crictl configured
- Understanding of Linux namespaces and cgroups

## Estimated Time

90 minutes

## Lab Environment Setup

```bash
# Create cluster with specific runtime configuration

cat <<EOF | kind create cluster --name runtime-security --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  image: kindest/node:v1.30.0
- role: worker
  image: kindest/node:v1.30.0
EOF

# Verify cluster

kubectl get nodes
```

## Part 1: Containerd Configuration

### Step 1.1: Examine Containerd Configuration

```bash
# Access worker node

docker exec -it runtime-security-worker bash

# View containerd config

containerd config dump | head -50

# Check if containerd is running

systemctl status containerd

# View containerd version

containerd --version

# Expected: containerd containerd.io 1.7.x ...

```

### Step 1.2: Check Runtime Security Settings

```bash
# Check CRI plugin configuration

containerd config dump | grep -A 20 'plugins."io.containerd.grpc.v1.cri"'

# Check default runtime

containerd config dump | grep -A 10 'default_runtime_name'

# Check systemd cgroup driver (recommended for K8s)

containerd config dump | grep -A 5 SystemdCgroup

# Should show: SystemdCgroup = true

```

### Step 1.3: Verify Containerd Socket Security

```bash
# Check socket permissions

ls -la /run/containerd/containerd.sock

# Expected: srw-rw---- 1 root root ... containerd.sock

# Verify only root can access

stat -c "%a %U:%G" /run/containerd/containerd.sock

# Expected: 660 root:root

# Test access as non-root (should fail)

su - nobody -s /bin/bash -c "crictl ps" 2>&1 || echo "Access denied (expected)"
```

## Part 2: Namespace Isolation

### Step 2.1: Deploy Test Pods

Exit the node and create test pods:

```bash
# Exit node

exit

# Create pod with default namespaces

cat <<EOF > /tmp/pod-default-ns.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-default-ns
spec:
  containers:
  - name: app
    image: busybox
    command: ["sleep", "3600"]
EOF

kubectl apply -f /tmp/pod-default-ns.yaml
kubectl wait --for=condition=Ready pod/pod-default-ns --timeout=60s

# Create pod with host namespaces (dangerous!)

cat <<EOF > /tmp/pod-host-ns.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-host-ns
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
  - name: app
    image: busybox
    command: ["sleep", "3600"]
    securityContext:
      privileged: true
EOF

kubectl apply -f /tmp/pod-host-ns.yaml
kubectl wait --for=condition=Ready pod/pod-host-ns --timeout=60s
```

### Step 2.2: Compare Namespace Isolation

```bash
# Test 1: PID namespace isolation

echo "=== Default pod (isolated PID namespace) ==="
kubectl exec pod-default-ns -- ps aux

# Should see only container processes

echo "=== Host namespace pod (sees ALL host processes) ==="
kubectl exec pod-host-ns -- ps aux | head -20

# Should see many more processes (host + all containers)

# Test 2: Network namespace isolation

echo "=== Default pod (isolated network) ==="
kubectl exec pod-default-ns -- ip addr

# Shows eth0@ifXX, lo (isolated)

echo "=== Host network pod (sees host network) ==="
kubectl exec pod-host-ns -- ip addr

# Shows all host interfaces (eth0, docker0, etc.)

# Test 3: IPC namespace isolation

echo "=== Default pod (isolated IPC) ==="
kubectl exec pod-default-ns -- ipcs

# Should be empty or minimal

echo "=== Host IPC pod (sees host IPC) ==="
kubectl exec pod-host-ns -- ipcs

# May show shared memory segments from host

```

### Step 2.3: Verify Namespace Separation on Node

```bash
# Access worker node

docker exec -it runtime-security-worker bash

# Get container IDs

DEFAULT_CONTAINER=$(crictl ps --name app --pod $(crictl pods --name pod-default-ns -q) -q)
HOST_CONTAINER=$(crictl ps --name app --pod $(crictl pods --name pod-host-ns -q) -q)

echo "Default container: $DEFAULT_CONTAINER"
echo "Host namespace container: $HOST_CONTAINER"

# Get PIDs

DEFAULT_PID=$(crictl inspect $DEFAULT_CONTAINER | jq -r '.info.pid')
HOST_PID=$(crictl inspect $HOST_CONTAINER | jq -r '.info.pid')

echo "Default PID: $DEFAULT_PID"
echo "Host PID: $HOST_PID"

# Compare namespaces

echo "=== Default container namespaces ==="
ls -la /proc/$DEFAULT_PID/ns/

echo "=== Host namespace container namespaces ==="
ls -la /proc/$HOST_PID/ns/

echo "=== Host process namespaces (compare with above) ==="
ls -la /proc/self/ns/

# Host namespace container should have same namespace IDs as host
# Default container should have different IDs

# Exit node

exit
```

## Part 3: Control Groups (cgroups)

### Step 3.1: Create Pods with Resource Limits

```bash
# Pod without limits

cat <<EOF > /tmp/pod-no-limits.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-no-limits
spec:
  containers:
  - name: app
    image: busybox
    command: ["sleep", "3600"]
EOF

kubectl apply -f /tmp/pod-no-limits.yaml

# Pod with strict limits

cat <<EOF > /tmp/pod-with-limits.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-with-limits
spec:
  containers:
  - name: app
    image: busybox
    command: ["sleep", "3600"]
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
      limits:
        memory: "128Mi"
        cpu: "500m"
EOF

kubectl apply -f /tmp/pod-with-limits.yaml
kubectl wait --for=condition=Ready pod/pod-with-limits --timeout=60s
```

### Step 3.2: Verify Cgroup Limits

```bash
# Access worker node

docker exec -it runtime-security-worker bash

# Get container ID for limited pod

LIMITED_CONTAINER=$(crictl ps --name app --pod $(crictl pods --name pod-with-limits -q) -q)
LIMITED_PID=$(crictl inspect $LIMITED_CONTAINER | jq -r '.info.pid')

echo "Limited container PID: $LIMITED_PID"

# Find cgroup path

CGROUP_PATH=$(cat /proc/$LIMITED_PID/cgroup | grep "0::" | cut -d: -f3)
echo "Cgroup path: $CGROUP_PATH"

# Check memory limit (cgroups v2)

if [ -f "/sys/fs/cgroup${CGROUP_PATH}/memory.max" ]; then
  echo "Memory limit:"
  cat /sys/fs/cgroup${CGROUP_PATH}/memory.max

  # Should show 134217728 (128Mi in bytes)

  echo "Current memory usage:"
  cat /sys/fs/cgroup${CGROUP_PATH}/memory.current
else
  echo "Cgroups v1 or different path"

  # For cgroups v1: find /sys/fs/cgroup/memory -name "*$LIMITED_CONTAINER*" -type d

fi

# Check CPU limit

if [ -f "/sys/fs/cgroup${CGROUP_PATH}/cpu.max" ]; then
  echo "CPU limit:"
  cat /sys/fs/cgroup${CGROUP_PATH}/cpu.max

  # Should show something like: 50000 100000 (50% of one core)

else
  echo "CPU limits in cgroups v1 use different files"
fi

# Exit node

exit
```

### Step 3.3: Test Memory Limits (OOM Kill)

```bash
# Create pod that exceeds memory limit

cat <<EOF > /tmp/pod-oom.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-oom
spec:
  restartPolicy: Never
  containers:
  - name: app
    image: polinux/stress
    command: ["stress"]
    args: ["--vm", "1", "--vm-bytes", "200M", "--timeout", "30s"]
    resources:
      limits:
        memory: "100Mi"
EOF

kubectl apply -f /tmp/pod-oom.yaml

# Wait a bit and check status

sleep 10
kubectl get pod pod-oom

# Should show OOMKilled status

# Check events

kubectl describe pod pod-oom | grep -A 5 "OOMKilled"

# Shows: Container killed due to OOM

# View logs

kubectl logs pod-oom

# May show partial stress output before OOM

```

## Part 4: Capabilities

### Step 4.1: View Default Container Capabilities

```bash
# Deploy pod with default capabilities

cat <<EOF > /tmp/pod-default-caps.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-default-caps
spec:
  containers:
  - name: app
    image: busybox
    command: ["sleep", "3600"]
EOF

kubectl apply -f /tmp/pod-default-caps.yaml
kubectl wait --for=condition=Ready pod/pod-default-caps --timeout=60s

# Check capabilities

kubectl exec pod-default-caps -- sh -c "cat /proc/1/status | grep Cap"

# Access node to decode capabilities

docker exec -it runtime-security-worker bash

# Get container

CONTAINER=$(crictl ps --name app --pod $(crictl pods --name pod-default-caps -q) -q)
PID=$(crictl inspect $CONTAINER | jq -r '.info.pid')

# View capabilities

cat /proc/$PID/status | grep Cap

# Output shows hex values

# Install libcap2-bin to decode

apt-get update && apt-get install -y libcap2-bin

# Decode effective capabilities

CAPEFF=$(cat /proc/$PID/status | grep CapEff | awk '{print $2}')
echo "Effective capabilities:"
capsh --decode=$CAPEFF

# Expected output includes:
# cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,
# cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,
# cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap

# Exit node

exit
```

### Step 4.2: Drop All Capabilities

```bash
# Create pod with no capabilities

cat <<EOF > /tmp/pod-no-caps.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-no-caps
spec:
  containers:
  - name: app
    image: busybox
    command: ["sleep", "3600"]
    securityContext:
      capabilities:
        drop: ["ALL"]
EOF

kubectl apply -f /tmp/pod-no-caps.yaml
kubectl wait --for=condition=Ready pod/pod-no-caps --timeout=60s

# Verify capabilities

kubectl exec pod-no-caps -- sh -c "cat /proc/1/status | grep CapEff"

# Should show: CapEff: 0000000000000000 (no capabilities)

```

### Step 4.3: Test Capability Restrictions

```bash
# Test 1: Try to change file ownership (needs CAP_CHOWN)

echo "=== Pod with default capabilities ==="
kubectl exec pod-default-caps -- sh -c "touch /tmp/test && chown 1000:1000 /tmp/test && echo 'chown succeeded'"

# Should work

echo "=== Pod without capabilities ==="
kubectl exec pod-no-caps -- sh -c "touch /tmp/test && chown 1000:1000 /tmp/test" 2>&1 || echo "chown failed (expected)"

# Should fail: Operation not permitted

# Test 2: Try to use ping (needs CAP_NET_RAW)

echo "=== Pod with default capabilities ==="
kubectl exec pod-default-caps -- ping -c 1 8.8.8.8

# Should work

echo "=== Pod without capabilities ==="
kubectl exec pod-no-caps -- ping -c 1 8.8.8.8 2>&1 || echo "ping failed (expected)"

# Should fail: permission denied

# Test 3: Try to kill process (needs CAP_KILL)

echo "=== Pod with default capabilities ==="
kubectl exec pod-default-caps -- sh -c "kill -0 1 && echo 'kill check succeeded'"

# Should work

echo "=== Pod without capabilities ==="
kubectl exec pod-no-caps -- sh -c "kill -0 1" 2>&1 || echo "kill failed (expected)"

# Should fail

```

### Step 4.4: Selective Capability Addition

```bash
# Create pod with only NET_BIND_SERVICE capability

cat <<EOF > /tmp/pod-selective-caps.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-selective-caps
spec:
  containers:
  - name: app
    image: busybox
    command: ["sleep", "3600"]
    securityContext:
      capabilities:
        drop: ["ALL"]
        add: ["NET_BIND_SERVICE"]
EOF

kubectl apply -f /tmp/pod-selective-caps.yaml
kubectl wait --for=condition=Ready pod/pod-selective-caps --timeout=60s

# Verify only NET_BIND_SERVICE is present

kubectl exec pod-selective-caps -- sh -c "cat /proc/1/status | grep CapEff"

# Should show a small hex value (only NET_BIND_SERVICE)

# This container could bind to port 80, but can't do much else

```

## Part 5: Privileged Containers

### Step 5.1: Create Privileged Container

```bash
# Create privileged pod

cat <<EOF > /tmp/pod-privileged.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-privileged
spec:
  containers:
  - name: app
    image: busybox
    command: ["sleep", "3600"]
    securityContext:
      privileged: true
EOF

kubectl apply -f /tmp/pod-privileged.yaml
kubectl wait --for=condition=Ready pod/pod-privileged --timeout=60s
```

### Step 5.2: Compare Privileged vs. Unprivileged

```bash
# Check capabilities

echo "=== Unprivileged pod ==="
kubectl exec pod-default-caps -- sh -c "cat /proc/1/status | grep CapEff"

echo "=== Privileged pod ==="
kubectl exec pod-privileged -- sh -c "cat /proc/1/status | grep CapEff"

# Should show many more capabilities

# Access to devices

echo "=== Unprivileged pod devices ==="
kubectl exec pod-default-caps -- ls /dev | wc -l

echo "=== Privileged pod devices ==="
kubectl exec pod-privileged -- ls /dev | wc -l

# Should see ALL host devices

# Can mount filesystems

echo "=== Test mount in privileged pod ==="
kubectl exec pod-privileged -- mount -t tmpfs tmpfs /mnt && echo "Mount succeeded!"
kubectl exec pod-privileged -- umount /mnt
```

### Step 5.3: Demonstrate Container Escape Risk

**WARNING**: This is for educational purposes only. Never do this in production!

```bash
# Privileged containers can access host filesystem

echo "=== Privileged container can access host ==="

# Access worker node

docker exec -it runtime-security-worker bash

# Create a marker file on host

echo "Secret host data" > /tmp/host-secret.txt

# Exit node

exit

# Privileged container can read host files (via /proc/1/root)

kubectl exec pod-privileged -- sh -c "cat /proc/1/root/tmp/host-secret.txt" 2>/dev/null && echo "Container accessed host filesystem!" || echo "Access blocked"

# In Kind, /proc/1/root may not directly access host, but in VMs/bare-metal it would
# Privileged containers can also:
# - Load kernel modules
# - Access all devices
# - Modify host network
# - Escape via various techniques

```

## Part 6: Read-Only Root Filesystem

### Step 6.1: Deploy Pod with Read-Only Root

```bash
# Create pod with read-only root filesystem

cat <<EOF > /tmp/pod-readonly.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-readonly
spec:
  containers:
  - name: app
    image: busybox
    command: ["sleep", "3600"]
    securityContext:
      readOnlyRootFilesystem: true
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: tmp
    emptyDir: {}
EOF

kubectl apply -f /tmp/pod-readonly.yaml
kubectl wait --for=condition=Ready pod/pod-readonly --timeout=60s
```

### Step 6.2: Test Read-Only Enforcement

```bash
# Test 1: Try to write to root filesystem (should fail)

kubectl exec pod-readonly -- touch /test.txt 2>&1 || echo "Write to root blocked (expected)"

# Expected: Read-only file system

# Test 2: Try to write to /tmp (should work - it's a volume)

kubectl exec pod-readonly -- touch /tmp/test.txt && echo "Write to /tmp succeeded"

# Test 3: Try to modify system files (should fail)

kubectl exec pod-readonly -- sh -c "echo 'hacked' > /etc/passwd" 2>&1 || echo "Write blocked (expected)"
```

## Part 7: Monitoring Runtime Events

### Step 7.1: Monitor Containerd Events

```bash
# Access worker node

docker exec -it runtime-security-worker bash

# Stream containerd events in background

ctr events &
CTR_PID=$!

# Let it run for a bit

sleep 5

# Stop the stream

kill $CTR_PID
```

### Step 7.2: Use crictl for Runtime Inspection

```bash
# Still on worker node

# List all pods

crictl pods

# List containers

crictl ps -a

# Get container details

CONTAINER=$(crictl ps --name app -q | head -1)
crictl inspect $CONTAINER | jq . | head -50

# Check container logs

crictl logs $CONTAINER | head -10

# Check container stats (resource usage)

crictl stats $CONTAINER

# Get runtime info

crictl info | jq . | head -30
```

### Step 7.3: Check Container Process Tree

```bash
# View container process tree

CONTAINER=$(crictl ps --name app -q | head -1)
PID=$(crictl inspect $CONTAINER | jq -r '.info.pid')

echo "Container PID: $PID"

# View process tree

ps auxf | grep -A 5 "sleep 3600"

# View what namespaces the process is in

ls -la /proc/$PID/ns/

# View process cgroup membership

cat /proc/$PID/cgroup

# Exit node

exit
```

## Part 8: Defense-in-Depth Example

### Step 8.1: Create Hardened Pod

Combining all security measures:

```bash
cat <<EOF > /tmp/pod-hardened.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-hardened
  annotations:

    # Assume we loaded apparmor profile (from Lab 2)

    container.apparmor.security.beta.kubernetes.io/app: localhost/k8s-nginx-restrictive
spec:

  # Pod-level security context

  securityContext:

    # Seccomp profile

    seccompProfile:
      type: RuntimeDefault

    # Run as non-root

    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000

    # Sysctls

    sysctls:
    - name: net.ipv4.ip_local_port_range
      value: "32768 60999"

  containers:
  - name: app
    image: nginx:1.27

    # Container-level security context

    securityContext:

      # No privilege escalation

      allowPrivilegeEscalation: false

      # Drop all capabilities

      capabilities:
        drop: ["ALL"]
        add: ["NET_BIND_SERVICE"]

      # Read-only root filesystem

      readOnlyRootFilesystem: true

      # No privileged mode

      privileged: false

    # Resource limits

    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
      limits:
        memory: "128Mi"
        cpu: "500m"

    # Volume mounts for writable directories

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
EOF

kubectl apply -f /tmp/pod-hardened.yaml 2>&1

# Note: Pod may fail if AppArmor profile not loaded
# This is expected - in Lab 2 you learned how to load profiles

```

### Step 8.2: Verify Security Settings

```bash
# If pod is running, check security context

kubectl get pod pod-hardened -o jsonpath='{.spec.securityContext}' | jq .

kubectl get pod pod-hardened -o jsonpath='{.spec.containers[0].securityContext}' | jq .

# Verify resource limits

kubectl get pod pod-hardened -o jsonpath='{.spec.containers[0].resources}' | jq .

# If pod failed due to AppArmor, that's okay - the manifest shows best practices

kubectl describe pod pod-hardened | grep -A 10 "Events"
```

## Part 9: Detecting Container Escapes

### Step 9.1: Simulate Suspicious Activity

```bash
# Create a pod that tries suspicious actions

cat <<EOF > /tmp/pod-suspicious.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-suspicious
spec:
  containers:
  - name: app
    image: busybox
    command: ["sh", "-c", "while true; do sleep 60; done"]
EOF

kubectl apply -f /tmp/pod-suspicious.yaml
kubectl wait --for=condition=Ready pod/pod-suspicious --timeout=60s
```

### Step 9.2: Try Common Escape Techniques

```bash
# Technique 1: Access Docker socket (if mounted - it's not)

kubectl exec pod-suspicious -- ls -la /var/run/docker.sock 2>&1 || echo "Docker socket not accessible (good!)"

# Technique 2: Access containerd socket

kubectl exec pod-suspicious -- ls -la /run/containerd/containerd.sock 2>&1 || echo "Containerd socket not accessible (good!)"

# Technique 3: Try to access host filesystem via /proc/1/root

kubectl exec pod-suspicious -- ls /proc/1/root 2>&1 || echo "Host filesystem not accessible (good!)"

# Technique 4: Try to load kernel module

kubectl exec pod-suspicious -- modprobe ip_tables 2>&1 || echo "Cannot load modules (good!)"

# All these should fail in a properly secured container

```

### Step 9.3: Monitor for Suspicious Behavior

```bash
# Access worker node

docker exec -it runtime-security-worker bash

# Get suspicious container

SUSPICIOUS_CONTAINER=$(crictl ps --name app --pod $(crictl pods --name pod-suspicious -q) -q)
SUSPICIOUS_PID=$(crictl inspect $SUSPICIOUS_CONTAINER | jq -r '.info.pid')

# Monitor process for suspicious syscalls
# (Requires strace, may not be available in Kind)
# apt-get update && apt-get install -y strace
# strace -p $SUSPICIOUS_PID -e trace=mount,ptrace,socket 2>&1 | head -20

# Check for unexpected capabilities

cat /proc/$SUSPICIOUS_PID/status | grep Cap

# Check for unexpected namespace access

ls -la /proc/$SUSPICIOUS_PID/ns/

# Exit node

exit
```

## Part 10: Cleanup

```bash
# Delete all test pods

kubectl delete pod --all

# Delete cluster

kind delete cluster --name runtime-security
```

## Troubleshooting

### Issue 1: crictl Not Working

**Error**: `crictl: command not found`

**Solution**:

```bash
# Install crictl (on worker node)

VERSION="v1.30.0"
wget https://github.com/kubernetes-sigs/cri-tools/releases/download/$VERSION/crictl-$VERSION-linux-amd64.tar.gz
tar zxvf crictl-$VERSION-linux-amd64.tar.gz -C /usr/local/bin
rm -f crictl-$VERSION-linux-amd64.tar.gz

# Configure crictl

cat > /etc/crictl.yaml <<EOF
runtime-endpoint: unix:///run/containerd/containerd.sock
image-endpoint: unix:///run/containerd/containerd.sock
timeout: 10
EOF
```

### Issue 2: Can't Find Cgroup Files

**Issue**: Cgroup files not in expected locations

**Solution**:

```bash
# Cgroups v2 uses unified hierarchy
# Files are in /sys/fs/cgroup/<path>/

# Find cgroup path for container

cat /proc/$PID/cgroup

# Look for line starting with "0::"

# Navigate to that path under /sys/fs/cgroup/

```

### Issue 3: Capabilities Not Showing

**Issue**: `capsh` command not found

**Solution**:

```bash
# Install libcap2-bin

apt-get update && apt-get install -y libcap2-bin

# Use capsh to decode

capsh --decode=<hex-value>
```

## Key Takeaways

1. **Container runtime is critical** - It's the bridge between Kubernetes and containers
1. **Namespace isolation** - Default isolation is good, but hostNetwork/hostPID are dangerous
1. **Cgroups enforce limits** - Resource limits prevent DoS attacks
1. **Capabilities are powerful** - Drop all capabilities by default, add only what's needed
1. **Privileged containers are dangerous** - Avoid unless absolutely necessary
1. **Read-only root filesystem** - Prevents tampering and persistence
1. **Defense-in-depth** - Combine all security measures for best protection
1. **Monitor runtime events** - Detect suspicious activity early

## Next Steps

- Review all [Domain 3 concepts](../../domains/03-system-hardening/README.md)
- Complete [Domain 3 practice questions](../../mock-questions/domain-03-questions.md)
- Move to [Domain 4: Minimize Microservice Vulnerabilities](../../domains/04-minimize-vulnerabilities/README.md)
- Explore [Falco](https://falco.org/) for runtime threat detection

## Additional Challenges

1. **Container escape challenge**: Research and document 5 container escape techniques and how to prevent them
1. **Runtime monitoring**: Set up Falco to monitor your cluster for runtime threats
1. **Custom runtime class**: Create a RuntimeClass for high-security workloads with gVisor
1. **Audit all pods**: Scan your cluster and report which pods use dangerous settings (privileged, hostNetwork, etc.)

---

**Congratulations!** You've completed all Domain 3 labs and mastered system hardening for Kubernetes. You now understand how to secure the host OS, container runtime, and kernel-level security mechanisms. These skills form the foundation of a defense-in-depth security strategy.
