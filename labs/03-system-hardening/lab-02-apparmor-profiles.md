# Lab 2: AppArmor Profiles

## Objectives

By the end of this lab, you will be able to:

- Check if AppArmor is enabled on Kubernetes nodes
- Load and manage AppArmor profiles
- Create custom AppArmor profiles for containers
- Apply AppArmor profiles to Kubernetes pods
- Test and verify profile enforcement
- Debug AppArmor denials and violations
- Use complain mode for profile development

## Prerequisites

- Completed Lab 1: Host Hardening
- Running Kubernetes cluster with AppArmor support
- kubectl configured and working
- Basic understanding of file permissions and Linux security

## Estimated Time

90 minutes

## Lab Environment Setup

```bash
# Create cluster with AppArmor support

cat <<EOF | kind create cluster --name apparmor-lab --config=-
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

## Part 1: AppArmor Basics

### Step 1.1: Check AppArmor Status

```bash
# Access worker node

docker exec -it apparmor-lab-worker bash

# Check if AppArmor is enabled

aa-status

# Expected output:
# apparmor module is loaded.
# 42 profiles are loaded.
# 38 profiles are in enforce mode.
# 4 profiles are in complain mode.

```

If `aa-status` command is not found:

```bash
# Install AppArmor utilities

apt-get update && apt-get install -y apparmor-utils

# Check again

aa-status
```

### Step 1.2: Understand AppArmor Modes

```bash
# View profiles in enforce mode

aa-status | grep -A 50 "profiles are in enforce mode"

# View profiles in complain mode

aa-status | grep -A 10 "profiles are in complain mode"

# Check docker-default profile (used by Kubernetes)

aa-status | grep docker-default
```

### Step 1.3: Examine Default Docker Profile

```bash
# View docker-default profile

cat /etc/apparmor.d/docker 2>/dev/null || \
  cat /etc/apparmor.d/containers/docker-default 2>/dev/null || \
  echo "Docker profile not found in standard location"

# If not found, it may be compiled into the kernel
# Check loaded profiles

cat /sys/kernel/security/apparmor/profiles | grep docker
```

## Part 2: Create Basic AppArmor Profile

### Step 2.1: Create Directory for Custom Profiles

```bash
# Create directory for our profiles

mkdir -p /etc/apparmor.d/containers

# Change to this directory

cd /etc/apparmor.d/containers
```

### Step 2.2: Create a Restrictive Profile for Nginx

Create a profile that allows nginx to run but denies shell access:

```bash
cat <<'EOF' > /etc/apparmor.d/containers/k8s-nginx-restrictive

#include <tunables/global>

profile k8s-nginx-restrictive flags=(attach_disconnected,mediate_deleted) {

  #include <abstractions/base>

  # Network access

  network inet tcp,
  network inet udp,
  network inet6 tcp,
  network inet6 udp,

  # Capabilities

  capability chown,
  capability setuid,
  capability setgid,
  capability net_bind_service,

  # Nginx binaries

  /usr/sbin/nginx mr,
  /usr/bin/nginx mr,

  # Configuration files (read-only)

  /etc/nginx/** r,
  /etc/ssl/openssl.cnf r,

  # Runtime files

  /run/nginx.pid w,
  /var/run/nginx.pid w,

  # Logs

  /var/log/nginx/** w,

  # Web content (read-only)

  /usr/share/nginx/html/** r,
  /var/www/html/** r,

  # Cache and temp

  /var/cache/nginx/** rw,
  /var/tmp/** rw,

  # System libraries

  /lib/** mr,
  /usr/lib/** mr,

  # Required system files

  /etc/passwd r,
  /etc/group r,
  /etc/nsswitch.conf r,
  /etc/ld.so.cache r,
  /etc/ld.so.conf r,
  /etc/ld.so.conf.d/** r,

  # Proc and sys

  @{PROC}/@{pid}/net/if_inet6 r,
  @{PROC}/@{pid}/net/ipv6_route r,
  @{PROC}/@{pid}/net/dev r,
  @{PROC}/@{pid}/net/tcp r,
  @{PROC}/@{pid}/net/udp r,
  @{PROC}/sys/net/core/somaxconn r,

  # DENY dangerous operations

  deny /bin/** wl,
  deny /sbin/** wl,
  deny /usr/bin/** wl,
  deny /usr/sbin/** wl,
  deny /boot/** rwlx,
  deny /root/** rwlx,
  deny /etc/shadow r,
  deny /etc/gshadow r,

  # DENY shell execution

  deny /bin/sh mrwlkx,
  deny /bin/bash mrwlkx,
  deny /bin/dash mrwlkx,
  deny /bin/zsh mrwlkx,

  # DENY mount operations

  deny mount,
  deny umount,
}
EOF

# View the profile

cat /etc/apparmor.d/containers/k8s-nginx-restrictive
```

### Step 2.3: Load the Profile

```bash
# Parse and load the profile

apparmor_parser -r /etc/apparmor.d/containers/k8s-nginx-restrictive

# Verify it's loaded

aa-status | grep k8s-nginx-restrictive

# Expected output:
#   k8s-nginx-restrictive

# Check it's in enforce mode

aa-status | grep -A 50 "profiles are in enforce mode" | grep k8s-nginx-restrictive
```

## Part 3: Apply AppArmor Profile to Kubernetes Pod

### Step 3.1: Exit Node and Create Pod Manifest

```bash
# Exit the node

exit

# Create pod with AppArmor annotation

cat <<EOF > /tmp/nginx-apparmor.yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-apparmor
  annotations:

    # Format: container.apparmor.security.beta.kubernetes.io/<container-name>: <profile>

    container.apparmor.security.beta.kubernetes.io/nginx: localhost/k8s-nginx-restrictive
spec:
  containers:
  - name: nginx
    image: nginx:1.27
    ports:
    - containerPort: 80
EOF

# View the manifest

cat /tmp/nginx-apparmor.yaml
```

### Step 3.2: Deploy the Pod

```bash
# Apply the manifest

kubectl apply -f /tmp/nginx-apparmor.yaml

# Check pod status

kubectl get pod nginx-apparmor

# Wait for Running status

kubectl wait --for=condition=Ready pod/nginx-apparmor --timeout=60s
```

### Step 3.3: Verify AppArmor Profile is Applied

```bash
# Get container ID

CONTAINER_ID=$(kubectl get pod nginx-apparmor -o jsonpath='{.status.containerStatuses[0].containerID}' | cut -d/ -f3)
echo "Container ID: $CONTAINER_ID"

# Access worker node

docker exec -it apparmor-lab-worker bash

# Check AppArmor profile of container process

cat /proc/$(crictl inspect $CONTAINER_ID | jq -r '.info.pid')/attr/current

# Expected output: k8s-nginx-restrictive (enforce)

# Or use simpler method

crictl inspect $CONTAINER_ID | jq -r '.info.runtimeSpec.process.apparmorProfile'

# Output: k8s-nginx-restrictive

```

### Step 3.4: Test Profile Enforcement

```bash
# Exit node

exit

# Test 1: Nginx should work normally

kubectl port-forward nginx-apparmor 8080:80 &
PF_PID=$!
sleep 2
curl http://localhost:8080

# Expected: Welcome to nginx!

kill $PF_PID

# Test 2: Try to execute shell (should fail!)

kubectl exec nginx-apparmor -- /bin/bash

# Expected output:
# OCI runtime exec failed: exec failed: unable to start container process:
# exec: "/bin/bash": permission denied: unknown

# Test 3: Try to execute sh (should also fail)

kubectl exec nginx-apparmor -- /bin/sh

# Expected: permission denied

# Test 4: Try to read nginx config (should work - we allowed read)

kubectl exec nginx-apparmor -- cat /etc/nginx/nginx.conf

# Expected: Should display nginx config

# Test 5: Try to modify nginx config (should fail - read-only)

kubectl exec nginx-apparmor -- sh -c "echo 'test' >> /etc/nginx/nginx.conf"

# Expected: permission denied or exec failed

```

### Step 3.5: Check AppArmor Denials

```bash
# Access node to check logs

docker exec -it apparmor-lab-worker bash

# Check kernel logs for AppArmor denials

dmesg | grep apparmor | tail -20

# Expected output includes:
# audit: type=1400 audit(1234567890.123:456): apparmor="DENIED"
# operation="exec" profile="k8s-nginx-restrictive" name="/bin/bash"
# pid=12345 comm="bash" requested_mask="x" denied_mask="x" fsuid=0 ouid=0

# Exit node

exit
```

## Part 4: Create Permissive Profile (Complain Mode)

### Step 4.1: Create Profile in Complain Mode

```bash
# Access worker node

docker exec -it apparmor-lab-worker bash

# Create a permissive profile for development

cat <<'EOF' > /etc/apparmor.d/containers/k8s-nginx-permissive

#include <tunables/global>

profile k8s-nginx-permissive flags=(attach_disconnected,mediate_deleted,complain) {

  #include <abstractions/base>

  # In complain mode, everything is allowed but logged
  # This is useful for discovering what permissions an app needs

  # Minimal rules - most will be learned

  network inet tcp,
  network inet udp,

  /usr/sbin/nginx mr,
  /etc/nginx/** r,
  /var/log/nginx/** w,
}
EOF

# Load profile

apparmor_parser -r /etc/apparmor.d/containers/k8s-nginx-permissive

# Verify it's in complain mode

aa-status | grep -A 10 "profiles are in complain mode" | grep k8s-nginx-permissive

# Exit node

exit
```

### Step 4.2: Deploy Pod with Permissive Profile

```bash
# Create pod with permissive profile

cat <<EOF > /tmp/nginx-permissive.yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-permissive
  annotations:
    container.apparmor.security.beta.kubernetes.io/nginx: localhost/k8s-nginx-permissive
spec:
  containers:
  - name: nginx
    image: nginx:1.27
    ports:
    - containerPort: 80
EOF

# Deploy

kubectl apply -f /tmp/nginx-permissive.yaml

# Wait for ready

kubectl wait --for=condition=Ready pod/nginx-permissive --timeout=60s
```

### Step 4.3: Test Permissive Profile

```bash
# Test 1: Shell access (will work in complain mode)

kubectl exec nginx-permissive -- /bin/bash -c "echo 'Shell access works!'"

# Expected: Shell access works!

# Test 2: Read sensitive file (will work but be logged)

kubectl exec nginx-permissive -- cat /etc/shadow 2>/dev/null || echo "Cannot read shadow (good!)"

# Test 3: Multiple operations to generate log data

kubectl exec nginx-permissive -- /bin/bash -c "ls -la /etc/ && whoami && id"
```

### Step 4.4: Analyze Complain Mode Logs

```bash
# Access node

docker exec -it apparmor-lab-worker bash

# View AppArmor logs (allowed in complain mode)

dmesg | grep apparmor | grep k8s-nginx-permissive | tail -20

# Expected output shows ALLOWED operations:
# audit: type=1400 audit(...): apparmor="ALLOWED"
# profile="k8s-nginx-permissive" name="/bin/bash" pid=... comm="bash"

# These logs tell you what permissions the app actually needs
# You can use this to build a minimal profile

# Exit node

exit
```

## Part 5: Create Production-Ready Profile

### Step 5.1: Create Minimal Nginx Profile Based on Logs

```bash
# Access worker node

docker exec -it apparmor-lab-worker bash

# Create production profile with only necessary permissions

cat <<'EOF' > /etc/apparmor.d/containers/k8s-nginx-production

#include <tunables/global>

profile k8s-nginx-production flags=(attach_disconnected,mediate_deleted) {

  #include <abstractions/base>
  #include <abstractions/openssl>
  #include <abstractions/nameservice>

  # Capabilities

  capability chown,
  capability setuid,
  capability setgid,
  capability net_bind_service,
  capability dac_override,

  # Network

  network inet stream,
  network inet6 stream,

  # Nginx execution

  /usr/sbin/nginx mrix,

  # Configuration

  /etc/nginx/** r,
  /etc/ssl/** r,

  # Runtime

  /var/run/nginx.pid w,
  /run/nginx.pid w,

  # Logs

  /var/log/nginx/** w,

  # Content

  /usr/share/nginx/html/** r,

  # Cache and temp

  /var/cache/nginx/** rw,
  /var/tmp/** rw,
  /tmp/** rw,

  # Required for nginx

  /usr/share/nginx/** r,
  /usr/lib/nginx/** mr,

  # DENY everything else

  deny /** wl,
  deny /proc/sys/** rw,
  deny mount,
  deny pivot_root,
}
EOF

# Load profile

apparmor_parser -r /etc/apparmor.d/containers/k8s-nginx-production

# Verify

aa-status | grep k8s-nginx-production

# Exit node

exit
```

### Step 5.2: Deploy with Production Profile

```bash
# Create pod

cat <<EOF > /tmp/nginx-production.yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-production
  annotations:
    container.apparmor.security.beta.kubernetes.io/nginx: localhost/k8s-nginx-production
spec:
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
      readOnlyRootFilesystem: true
    volumeMounts:
    - name: cache
      mountPath: /var/cache/nginx
    - name: run
      mountPath: /var/run
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: cache
    emptyDir: {}
  - name: run
    emptyDir: {}
  - name: tmp
    emptyDir: {}
EOF

# Deploy

kubectl apply -f /tmp/nginx-production.yaml

# Wait for ready

kubectl wait --for=condition=Ready pod/nginx-production --timeout=60s
```

### Step 5.3: Test Production Profile

```bash
# Test 1: Nginx functionality

kubectl port-forward nginx-production 8081:80 &
PF_PID=$!
sleep 2
curl http://localhost:8081

# Expected: Welcome to nginx!

kill $PF_PID

# Test 2: Shell access (should fail)

kubectl exec nginx-production -- /bin/sh

# Expected: permission denied

# Test 3: Read config (should work)

kubectl exec nginx-production -- cat /etc/nginx/nginx.conf | head -5

# Expected: Shows config

# Test 4: Write to allowed directory

kubectl exec nginx-production -- sh -c "echo 'test' > /tmp/test.txt" 2>/dev/null || echo "Write blocked (expected)"
```

## Part 6: Debugging AppArmor Issues

### Step 6.1: Create a Profile That's Too Restrictive

```bash
# Access worker node

docker exec -it apparmor-lab-worker bash

# Create overly restrictive profile

cat <<'EOF' > /etc/apparmor.d/containers/k8s-nginx-broken

#include <tunables/global>

profile k8s-nginx-broken flags=(attach_disconnected,mediate_deleted) {

  # Only allow execution, nothing else

  /usr/sbin/nginx mr,

  # Deny everything else explicitly

  deny /** rwlx,
}
EOF

# Load profile

apparmor_parser -r /etc/apparmor.d/containers/k8s-nginx-broken

# Exit node

exit
```

### Step 6.2: Deploy Pod with Broken Profile

```bash
# Create pod

cat <<EOF > /tmp/nginx-broken.yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-broken
  annotations:
    container.apparmor.security.beta.kubernetes.io/nginx: localhost/k8s-nginx-broken
spec:
  containers:
  - name: nginx
    image: nginx:1.27
EOF

# Deploy

kubectl apply -f /tmp/nginx-broken.yaml

# Check status

kubectl get pod nginx-broken

# Pod might start but nginx will fail

kubectl logs nginx-broken 2>&1 | head -20
```

### Step 6.3: Debug the Issue

```bash
# Access worker node

docker exec -it apparmor-lab-worker bash

# Check AppArmor denials

dmesg | grep apparmor | grep k8s-nginx-broken | tail -30

# Look for patterns like:
# apparmor="DENIED" operation="open" profile="k8s-nginx-broken"
# name="/etc/nginx/nginx.conf" pid=... comm="nginx"

# This tells you nginx tried to open /etc/nginx/nginx.conf but was denied

# To debug systematically, switch to complain mode temporarily

aa-complain /etc/apparmor.d/containers/k8s-nginx-broken

# Verify

aa-status | grep k8s-nginx-broken

# Exit node

exit
```

### Step 6.4: Fix the Profile

```bash
# Delete broken pod

kubectl delete pod nginx-broken

# Access node

docker exec -it apparmor-lab-worker bash

# Update profile with necessary permissions

cat <<'EOF' > /etc/apparmor.d/containers/k8s-nginx-broken

#include <tunables/global>

profile k8s-nginx-broken flags=(attach_disconnected,mediate_deleted) {

  #include <abstractions/base>

  # Nginx execution

  /usr/sbin/nginx mr,

  # Minimum required permissions discovered from logs

  /etc/nginx/** r,
  /var/log/nginx/** w,
  /var/run/nginx.pid w,

  network inet stream,
  capability net_bind_service,
}
EOF

# Reload profile (back to enforce mode)

apparmor_parser -r /etc/apparmor.d/containers/k8s-nginx-broken

# Exit node

exit

# Redeploy pod

kubectl apply -f /tmp/nginx-broken.yaml

# Check status

kubectl wait --for=condition=Ready pod/nginx-broken --timeout=60s
kubectl get pod nginx-broken
```

## Part 7: Managing Profiles with aa-* Tools

### Step 7.1: Use AppArmor Helper Tools

```bash
# Access worker node

docker exec -it apparmor-lab-worker bash

# List all profiles

aa-status --pretty-print

# Set profile to complain mode

aa-complain /etc/apparmor.d/containers/k8s-nginx-production

# Verify

aa-status | grep k8s-nginx-production

# Set back to enforce mode

aa-enforce /etc/apparmor.d/containers/k8s-nginx-production

# Disable a profile

aa-disable /etc/apparmor.d/containers/k8s-nginx-broken

# Re-enable

aa-enforce /etc/apparmor.d/containers/k8s-nginx-broken
```

### Step 7.2: Validate Profile Syntax

```bash
# Check for syntax errors

apparmor_parser -Q /etc/apparmor.d/containers/k8s-nginx-production

# If there are errors, they'll be displayed
# No output means the profile is valid

# Exit node

exit
```

## Part 8: Cleanup and Summary

### Step 8.1: Review Deployed Pods

```bash
# List all pods with AppArmor annotations

kubectl get pods -o json | jq -r '.items[] | select(.metadata.annotations | has("container.apparmor.security.beta.kubernetes.io/nginx")) | .metadata.name'

# Expected output:
# nginx-apparmor
# nginx-permissive
# nginx-production
# nginx-broken

```

### Step 8.2: Clean Up

```bash
# Delete all test pods

kubectl delete pod nginx-apparmor nginx-permissive nginx-production nginx-broken

# Delete cluster

kind delete cluster --name apparmor-lab
```

## Troubleshooting

### Issue 1: "Profile not found" Error

**Error**: `Error: AppArmor profile "localhost/k8s-nginx-restrictive" not found`

**Solution**:

```bash
# Ensure profile is loaded on ALL nodes

docker exec -it apparmor-lab-worker bash
aa-status | grep k8s-nginx-restrictive

# If not loaded:

apparmor_parser -r /etc/apparmor.d/containers/k8s-nginx-restrictive
exit

# Note: In multi-node clusters, profiles must be on all nodes where pods might run

```

### Issue 2: Pod Fails to Start

**Solution**:

```bash
# Check pod events

kubectl describe pod <pod-name> | grep -A 10 Events

# Check container logs

kubectl logs <pod-name>

# Check AppArmor denials on node

docker exec -it apparmor-lab-worker dmesg | grep apparmor | tail -20
```

### Issue 3: Can't Execute Commands in Container

**Expected Behavior**: If AppArmor profile denies shell access, you won't be able to exec into the container.

**Workaround** for debugging:

```bash
# Temporarily switch profile to complain mode

docker exec -it apparmor-lab-worker aa-complain /etc/apparmor.d/containers/<profile-name>

# Delete and recreate pod

kubectl delete pod <pod-name>
kubectl apply -f <manifest>

# Now you can exec for debugging

kubectl exec <pod-name> -- /bin/sh

# Remember to switch back to enforce mode when done!

```

## Key Takeaways

1. **AppArmor provides MAC** (Mandatory Access Control) - even root can't bypass it
1. **Profiles are path-based** - easier to understand than SELinux
1. **Three modes**: enforce (block), complain (log), disabled
1. **Use complain mode for development** - discover required permissions
1. **Test thoroughly** - overly restrictive profiles break applications
1. **Deploy to all nodes** - profiles must exist on nodes where pods run
1. **Combine with other security** - AppArmor + Seccomp + capabilities = defense-in-depth

## Next Steps

- Proceed to [Lab 3: Seccomp Profiles](lab-03-seccomp-profiles.md)
- Review [AppArmor and Seccomp concepts](../../domains/03-system-hardening/apparmor-seccomp.md)
- Experiment with profiles for other applications (Redis, MySQL, etc.)

## Additional Challenges

1. **Create profiles for other apps**: Try creating AppArmor profiles for Redis, PostgreSQL, or your own applications
1. **Automate profile deployment**: Use a DaemonSet to deploy profiles to all nodes
1. **Generate profiles automatically**: Use `aa-genprof` to create profiles based on observed behavior
1. **Profile a multi-container pod**: Create different profiles for each container in a pod

---

**Congratulations!** You've mastered AppArmor profile creation and management in Kubernetes. You can now restrict container behavior at the file and network level.
