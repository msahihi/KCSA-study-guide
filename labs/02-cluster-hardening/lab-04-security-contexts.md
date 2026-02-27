# Lab 04: Security Contexts

## Objective

Master pod and container security contexts to implement defense-in-depth security. Learn to configure non-root users, capabilities, read-only filesystems, and privilege escalation controls.

**What You'll Learn**:

- Run containers as non-root users
- Set read-only root filesystems
- Manage Linux capabilities
- Prevent privilege escalation
- Apply seccomp and AppArmor profiles
- Troubleshoot security context issues

## Prerequisites

- Completed previous RBAC and ServiceAccount labs
- Understanding of Linux users, groups, and capabilities
- Kubernetes cluster running

## Lab Duration

60-75 minutes

## Lab Setup

```bash
# Create lab namespace

kubectl create namespace sec-ctx-lab

# Verify

kubectl get namespace sec-ctx-lab
```

## Exercises

### Exercise 1: Default Security Context (Baseline)

```bash
# Create pod without security context

kubectl run default-pod --image=nginx:1.27 -n sec-ctx-lab

# Wait for pod

kubectl wait --for=condition=ready pod/default-pod -n sec-ctx-lab --timeout=60s

# Check what user container runs as

kubectl exec -it default-pod -n sec-ctx-lab -- id

# Expected output (often root):
# uid=0(root) gid=0(root) groups=0(root)

# Check capabilities

kubectl exec -it default-pod -n sec-ctx-lab -- \
  grep Cap /proc/1/status

# Check if filesystem is writable

kubectl exec -it default-pod -n sec-ctx-lab -- \
  touch /test-write

# Expected: File created (filesystem writable)

# Check if can escalate privileges

kubectl exec -it default-pod -n sec-ctx-lab -- \
  cat /proc/1/status | grep NoNewPrivs

# Expected: NoNewPrivs: 0 (privilege escalation allowed)

```

---

### Exercise 2: Run as Non-Root User

```yaml
# Save as non-root-pod.yaml

apiVersion: v1
kind: Pod
metadata:
  name: non-root-pod
  namespace: sec-ctx-lab
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 3000
    runAsNonRoot: true
  containers:
  - name: app
    image: busybox:1.36
    command: ["sleep", "3600"]
```

```
# Apply pod

kubectl apply -f non-root-pod.yaml

# Wait for ready

kubectl wait --for=condition=ready pod/non-root-pod -n sec-ctx-lab --timeout=60s

# Check user

kubectl exec -it non-root-pod -n sec-ctx-lab -- id

# Expected output:
# uid=1000 gid=3000 groups=3000

# Try to write to root-owned location (should fail)

kubectl exec -it non-root-pod -n sec-ctx-lab -- \
  touch /usr/bin/test 2>&1

# Expected: Permission denied

```

---

### Exercise 3: Enforce Non-Root (Validation)

```yaml
# Save as enforce-non-root.yaml

apiVersion: v1
kind: Pod
metadata:
  name: enforce-non-root-fail
  namespace: sec-ctx-lab
spec:
  securityContext:
    runAsNonRoot: true  # Enforces non-root

    # But image runs as root by default

  containers:
  - name: nginx
    image: nginx:1.27
```

```
# Try to apply (should fail if nginx runs as root)

kubectl apply -f enforce-non-root.yaml

# Check pod status

kubectl get pod enforce-non-root-fail -n sec-ctx-lab

# Check events

kubectl describe pod enforce-non-root-fail -n sec-ctx-lab | grep -A5 Events

# Expected error: container has runAsNonRoot and image will run as root

# Fix by specifying non-root user

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: enforce-non-root-success
  namespace: sec-ctx-lab
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 101  # nginx user UID
  containers:
  - name: nginx
    image: nginx:1.27
EOF

# This should succeed

kubectl wait --for=condition=ready pod/enforce-non-root-success -n sec-ctx-lab --timeout=60s
```

---

### Exercise 4: Read-Only Root Filesystem

```yaml
# Save as readonly-fs-pod.yaml

apiVersion: v1
kind: Pod
metadata:
  name: readonly-fs-pod
  namespace: sec-ctx-lab
spec:
  securityContext:
    runAsUser: 101
    runAsNonRoot: true
  containers:
  - name: nginx
    image: nginx:1.27
    securityContext:
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
```

```
# Apply

kubectl apply -f readonly-fs-pod.yaml

# Wait for ready

kubectl wait --for=condition=ready pod/readonly-fs-pod -n sec-ctx-lab --timeout=60s

# Test root filesystem is read-only

kubectl exec -it readonly-fs-pod -n sec-ctx-lab -- \
  touch /test-write 2>&1

# Expected: Read-only file system

# Test writable volumes work

kubectl exec -it readonly-fs-pod -n sec-ctx-lab -- \
  touch /tmp/test-write

# Expected: Success

# Verify nginx works

kubectl exec -it readonly-fs-pod -n sec-ctx-lab -- \
  curl -s http://localhost | head -5

# Should show nginx welcome page

```

---

### Exercise 5: Drop All Capabilities

```yaml
# Save as drop-caps-pod.yaml

apiVersion: v1
kind: Pod
metadata:
  name: drop-caps-pod
  namespace: sec-ctx-lab
spec:
  securityContext:
    runAsUser: 1000
    runAsNonRoot: true
  containers:
  - name: app
    image: busybox:1.36
    command: ["sleep", "3600"]
    securityContext:
      capabilities:
        drop:
        - ALL
```

```
# Apply

kubectl apply -f drop-caps-pod.yaml

# Wait for ready

kubectl wait --for=condition=ready pod/drop-caps-pod -n sec-ctx-lab --timeout=60s

# Check capabilities

kubectl exec -it drop-caps-pod -n sec-ctx-lab -- \
  grep Cap /proc/1/status

# Expected: CapEff: 0000000000000000 (no capabilities)

# Compare with default pod

kubectl exec -it default-pod -n sec-ctx-lab -- \
  grep Cap /proc/1/status

# Expected: Non-zero capabilities

```

---

### Exercise 6: Add Specific Capabilities

```yaml
# Save as net-bind-pod.yaml

apiVersion: v1
kind: Pod
metadata:
  name: net-bind-pod
  namespace: sec-ctx-lab
spec:
  securityContext:
    runAsUser: 1000
    runAsNonRoot: true
  containers:
  - name: nginx
    image: nginx:1.27
    securityContext:
      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE  # Needed for port 80
      allowPrivilegeEscalation: false
```

```
# Apply

kubectl apply -f net-bind-pod.yaml

# Wait for ready

kubectl wait --for=condition=ready pod/net-bind-pod -n sec-ctx-lab --timeout=60s

# Check capabilities

kubectl exec -it net-bind-pod -n sec-ctx-lab -- \
  grep Cap /proc/1/status

# Verify nginx can bind to port 80

kubectl exec -it net-bind-pod -n sec-ctx-lab -- \
  curl -s http://localhost | head -5

# Should work

```

---

### Exercise 7: Prevent Privilege Escalation

```yaml
# Save as no-privilege-escalation.yaml

apiVersion: v1
kind: Pod
metadata:
  name: no-escalation-pod
  namespace: sec-ctx-lab
spec:
  securityContext:
    runAsUser: 1000
    runAsNonRoot: true
  containers:
  - name: app
    image: busybox:1.36
    command: ["sleep", "3600"]
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
```

```
# Apply

kubectl apply -f no-privilege-escalation.yaml

# Wait for ready

kubectl wait --for=condition=ready pod/no-escalation-pod -n sec-ctx-lab --timeout=60s

# Check NoNewPrivs flag

kubectl exec -it no-escalation-pod -n sec-ctx-lab -- \
  cat /proc/1/status | grep NoNewPrivs

# Expected: NoNewPrivs: 1 (escalation prevented)

# Compare with default pod

kubectl exec -it default-pod -n sec-ctx-lab -- \
  cat /proc/1/status | grep NoNewPrivs

# Expected: NoNewPrivs: 0 (escalation allowed)

```

---

### Exercise 8: fsGroup for Volume Permissions

```yaml
# Save as fsgroup-pod.yaml

apiVersion: v1
kind: Pod
metadata:
  name: fsgroup-pod
  namespace: sec-ctx-lab
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
    runAsNonRoot: true
  containers:
  - name: app
    image: busybox:1.36
    command: ["sleep", "3600"]
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    emptyDir: {}
```

```
# Apply

kubectl apply -f fsgroup-pod.yaml

# Wait for ready

kubectl wait --for=condition=ready pod/fsgroup-pod -n sec-ctx-lab --timeout=60s

# Check volume ownership

kubectl exec -it fsgroup-pod -n sec-ctx-lab -- \
  ls -ld /data

# Expected: drwxrwsr-x 2 root 2000 ... /data
#                              ^^^^
#                            fsGroup

# Check process groups

kubectl exec -it fsgroup-pod -n sec-ctx-lab -- id

# Expected: uid=1000 gid=3000 groups=3000,2000
#                                           ^^^^
#                                         fsGroup

# Verify can write to volume

kubectl exec -it fsgroup-pod -n sec-ctx-lab -- \
  touch /data/testfile

# Should succeed

```

---

### Exercise 9: Seccomp Profile

```yaml
# Save as seccomp-pod.yaml

apiVersion: v1
kind: Pod
metadata:
  name: seccomp-pod
  namespace: sec-ctx-lab
spec:
  securityContext:
    runAsUser: 1000
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: busybox:1.36
    command: ["sleep", "3600"]
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
```

```
# Apply

kubectl apply -f seccomp-pod.yaml

# Wait for ready

kubectl wait --for=condition=ready pod/seccomp-pod -n sec-ctx-lab --timeout=60s

# Check seccomp status

kubectl exec -it seccomp-pod -n sec-ctx-lab -- \
  grep Seccomp /proc/1/status

# Expected: Seccomp: 2 (filtering mode)

# Compare with pod without seccomp

kubectl exec -it default-pod -n sec-ctx-lab -- \
  grep Seccomp /proc/1/status

# May show: Seccomp: 0 (disabled) or 2 (if default enabled)

```

---

### Exercise 10: Complete Secure Pod

```yaml
# Save as fully-secure-pod.yaml

apiVersion: v1
kind: Pod
metadata:
  name: fully-secure-pod
  namespace: sec-ctx-lab
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 3000
    runAsNonRoot: true
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: nginx
    image: nginx:1.27
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE
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
```

```
# Apply

kubectl apply -f fully-secure-pod.yaml

# Wait for ready

kubectl wait --for=condition=ready pod/fully-secure-pod -n sec-ctx-lab --timeout=60s

# Verify all security controls

echo "=== User and Group ==="
kubectl exec -it fully-secure-pod -n sec-ctx-lab -- id

echo "=== Capabilities ==="
kubectl exec -it fully-secure-pod -n sec-ctx-lab -- \
  grep Cap /proc/1/status

echo "=== Privilege Escalation ==="
kubectl exec -it fully-secure-pod -n sec-ctx-lab -- \
  grep NoNewPrivs /proc/1/status

echo "=== Seccomp ==="
kubectl exec -it fully-secure-pod -n sec-ctx-lab -- \
  grep Seccomp /proc/1/status

echo "=== Read-Only Filesystem ==="
kubectl exec -it fully-secure-pod -n sec-ctx-lab -- \
  touch /test-readonly 2>&1 || echo "Confirmed: root filesystem is read-only"

echo "=== Application Functions ==="
kubectl exec -it fully-secure-pod -n sec-ctx-lab -- \
  curl -s http://localhost | head -5
```

---

### Exercise 11: Container vs Pod Security Context

```yaml
# Save as override-security-context.yaml

apiVersion: v1
kind: Pod
metadata:
  name: override-context-pod
  namespace: sec-ctx-lab
spec:
  securityContext:
    runAsUser: 1000      # Pod-level
    runAsGroup: 1000
  containers:
  - name: container1
    image: busybox:1.36
    command: ["sleep", "3600"]
    securityContext:
      runAsUser: 2000    # Override pod-level
  - name: container2
    image: busybox:1.36
    command: ["sleep", "3600"]

    # Uses pod-level user 1000

```

```
# Apply

kubectl apply -f override-security-context.yaml

# Wait for ready

kubectl wait --for=condition=ready pod/override-context-pod -n sec-ctx-lab --timeout=60s

# Check container1 user (should be 2000)

kubectl exec -it override-context-pod -n sec-ctx-lab -c container1 -- id

# Expected: uid=2000 gid=1000

# Check container2 user (should be 1000)

kubectl exec -it override-context-pod -n sec-ctx-lab -c container2 -- id

# Expected: uid=1000 gid=1000

```

---

## Verification

```bash
# 1. Check all pods

kubectl get pods -n sec-ctx-lab

# 2. Verify non-root execution

kubectl exec -it non-root-pod -n sec-ctx-lab -- id | grep "uid=1000"

# 3. Verify read-only filesystem

kubectl exec -it readonly-fs-pod -n sec-ctx-lab -- touch /test 2>&1 | grep "Read-only"

# 4. Verify capabilities dropped

kubectl exec -it drop-caps-pod -n sec-ctx-lab -- \
  grep "CapEff:\s*0000000000000000" /proc/1/status

# 5. Verify privilege escalation prevention

kubectl exec -it no-escalation-pod -n sec-ctx-lab -- \
  grep "NoNewPrivs:\s*1" /proc/1/status

# 6. Verify fsGroup

kubectl exec -it fsgroup-pod -n sec-ctx-lab -- ls -ld /data | grep "2000"

# 7. Verify seccomp

kubectl exec -it seccomp-pod -n sec-ctx-lab -- \
  grep "Seccomp:\s*2" /proc/1/status
```

## Troubleshooting Guide

### Issue: Permission Denied Errors

```bash
# Check user/group

kubectl get pod <pod> -n sec-ctx-lab -o jsonpath='{.spec.securityContext}'

# Check container-level overrides

kubectl get pod <pod> -n sec-ctx-lab -o jsonpath='{.spec.containers[0].securityContext}'

# Add required capabilities

securityContext:
  capabilities:
    add: ["CHOWN", "DAC_OVERRIDE"]
```

### Issue: Read-Only Filesystem Crashes

```bash
# Identify writable paths needed

kubectl logs <pod> -n sec-ctx-lab

# Add emptyDir volumes

volumes:
- name: tmp
  emptyDir: {}
volumeMounts:
- name: tmp
  mountPath: /tmp
```

### Issue: Port Binding Fails

```bash
# Add NET_BIND_SERVICE capability

securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]
```

## Cleanup

```bash
# Delete namespace

kubectl delete namespace sec-ctx-lab

# Verify deletion

kubectl get namespace sec-ctx-lab

# Expected: NotFound

```

## Key Takeaways

1. **Non-root required**: Always set runAsUser and runAsNonRoot
1. **Drop all caps**: Start with drop: [ALL], add only needed
1. **Read-only FS**: Use with emptyDir volumes for writable paths
1. **No escalation**: Always set allowPrivilegeEscalation: false
1. **Seccomp**: Use RuntimeDefault profile
1. **fsGroup**: Set for shared volume access
1. **Container overrides pod**: Container-level settings take precedence

## Next Steps

- Complete [Lab 05: Pod Security Admission](lab-05-pod-security-admission.md)
- Review [Pod Security Admission theory](../../domains/02-cluster-hardening/pod-security-admission.md)

---

**Congratulations!** You now understand how to secure pods with security contexts and implement defense-in-depth.
