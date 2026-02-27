# Lab 05: Pod Security Admission

## Objective

Master Pod Security Admission (PSA) configuration and enforcement. Learn to apply Pod Security Standards at the namespace level using enforce, audit, and warn modes, and create compliant pod specifications.

**What You'll Learn**:

- Understand three Pod Security Standards (Privileged, Baseline, Restricted)
- Configure namespace-level Pod Security Admission
- Use enforce, audit, and warn modes
- Fix non-compliant pod specifications
- Implement gradual policy rollout

## Prerequisites

- Completed previous labs (RBAC, ServiceAccounts, Security Contexts)
- Understanding of security contexts
- Kubernetes v1.25+ (PSA enabled by default)

## Lab Duration

60-75 minutes

## Lab Setup

```bash

# Create lab namespaces

kubectl create namespace psa-privileged
kubectl create namespace psa-baseline
kubectl create namespace psa-restricted
kubectl create namespace psa-migration

# Verify creation

kubectl get namespaces | grep psa-
```

```

## Exercises

### Exercise 1: Privileged Profile (No Restrictions)

```bash

# Label namespace for privileged profile

kubectl label namespace psa-privileged \
  pod-security.kubernetes.io/enforce=privileged

# Verify label

kubectl get namespace psa-privileged --show-labels | grep pod-security

# Create privileged pod (should succeed)

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
  namespace: psa-privileged
spec:
  hostNetwork: true           # Allowed in privileged
  hostPID: true               # Allowed in privileged
  containers:
  - name: nginx
    image: nginx:1.27
    securityContext:
      privileged: true        # Allowed in privileged
EOF

# Verify pod created

kubectl get pod privileged-pod -n psa-privileged

# Check pod status

kubectl describe pod privileged-pod -n psa-privileged | grep -A5 Events

# Should show no security violations

```

```

---

### Exercise 2: Baseline Profile (Block Dangerous Configs)

```bash

# Label namespace for baseline profile

kubectl label namespace psa-baseline \
  pod-security.kubernetes.io/enforce=baseline

# Verify label

kubectl get namespace psa-baseline --show-labels | grep pod-security

# Try to create privileged pod (should FAIL)

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: privileged-fail
  namespace: psa-baseline
spec:
  containers:
  - name: nginx
    image: nginx:1.27
    securityContext:
      privileged: true
EOF

# Expected error: violates PodSecurity "baseline:latest": privileged

# Try hostNetwork (should FAIL)

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: hostnetwork-fail
  namespace: psa-baseline
spec:
  hostNetwork: true
  containers:
  - name: nginx
    image: nginx:1.27
EOF

# Expected error: violates PodSecurity "baseline:latest": host namespaces

# Create compliant baseline pod (should SUCCEED)

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: baseline-compliant
  namespace: psa-baseline
spec:
  containers:
  - name: nginx
    image: nginx:1.27
    securityContext:
      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE
EOF

# Verify creation

kubectl get pod baseline-compliant -n psa-baseline
```

```

---

### Exercise 3: Restricted Profile (Maximum Security)

```bash

# Label namespace for restricted profile

kubectl label namespace psa-restricted \
  pod-security.kubernetes.io/enforce=restricted

# Try baseline-compliant pod (should FAIL)

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: baseline-pod-fail
  namespace: psa-restricted
spec:
  containers:
  - name: nginx
    image: nginx:1.27
EOF

# Expected errors:
# - allowPrivilegeEscalation != false
# - unrestricted capabilities
# - runAsNonRoot != true
# - seccompProfile not set

# Create fully compliant restricted pod

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: restricted-compliant
  namespace: psa-restricted
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
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
  volumes:
  - name: cache
    emptyDir: {}
  - name: run
    emptyDir: {}
EOF

# Verify creation

kubectl get pod restricted-compliant -n psa-restricted

# Check pod is running

kubectl wait --for=condition=ready pod/restricted-compliant -n psa-restricted --timeout=60s
```

```

---

### Exercise 4: Multiple Modes (Enforce + Audit + Warn)

```bash

# Apply all three modes to migration namespace

kubectl label namespace psa-migration \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted

# Verify labels

kubectl get namespace psa-migration --show-labels | grep pod-security

# Create baseline-compliant pod (enforced)
# but not restricted-compliant (audited and warned)

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: migration-pod
  namespace: psa-migration
spec:
  containers:
  - name: nginx
    image: nginx:1.27
    securityContext:
      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE
EOF

# Expected:
# - Pod created (meets baseline enforce)
# - Warning shown (doesn't meet restricted)
# - Audit log entry (doesn't meet restricted)

# View warnings in output
# Warning: would violate PodSecurity "restricted:latest": ...

```

```

---

### Exercise 5: Dry-Run Testing

```bash

# Test pod against restricted namespace without creating

cat <<EOF | kubectl apply -f - --dry-run=server
apiVersion: v1
kind: Pod
metadata:
  name: dry-run-test
  namespace: psa-restricted
spec:
  containers:
  - name: nginx
    image: nginx:1.27
EOF

# Expected: Error listing all violations

# Test compliant pod

cat <<EOF | kubectl apply -f - --dry-run=server
apiVersion: v1
kind: Pod
metadata:
  name: dry-run-test
  namespace: psa-restricted
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: nginx
    image: nginx:1.27
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE
EOF

# Expected: pod/dry-run-test created (server dry run)

```

```

---

### Exercise 6: Version Pinning

```bash

# Create namespace with version-pinned PSA

kubectl create namespace psa-versioned

kubectl label namespace psa-versioned \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=v1.30

# Verify labels

kubectl get namespace psa-versioned -o yaml | grep -A3 "pod-security"

# Test with compliant pod

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: versioned-pod
  namespace: psa-versioned
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: busybox
    image: busybox:1.36
    command: ["sleep", "3600"]
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
EOF

# Verify creation

kubectl get pod versioned-pod -n psa-versioned
```

```

---

### Exercise 7: Gradual Migration Strategy

```bash

# Week 1: Audit only (no enforcement)

kubectl create namespace psa-gradual

kubectl label namespace psa-gradual \
  pod-security.kubernetes.io/audit=baseline

# Deploy non-compliant pod (allowed but audited)

kubectl run test-app --image=nginx:1.27 -n psa-gradual

# Check pod created

kubectl get pod test-app -n psa-gradual

# Succeeds but violations logged

# Week 2: Add warnings

kubectl label namespace psa-gradual \
  pod-security.kubernetes.io/warn=baseline \
  --overwrite

# Create another pod (shows warnings)

kubectl run test-app-2 --image=nginx:1.27 -n psa-gradual

# Warnings displayed but pod created

# Week 3: Enforce baseline

kubectl label namespace psa-gradual \
  pod-security.kubernetes.io/enforce=baseline \
  --overwrite

# Delete old pods

kubectl delete pod test-app test-app-2 -n psa-gradual

# Now deploy compliant pod

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: compliant-app
  namespace: psa-gradual
spec:
  containers:
  - name: nginx
    image: nginx:1.27
    securityContext:
      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE
EOF

# Week 4: Move toward restricted

kubectl label namespace psa-gradual \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted \
  --overwrite

# Audit logs now track restricted compliance

```

```

---

### Exercise 8: Fix Non-Compliant Deployments

```bash

# Create deployment that violates restricted

cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: non-compliant-deploy
  namespace: psa-migration
spec:
  replicas: 2
  selector:
    matchLabels:
      app: test
  template:
    metadata:
      labels:
        app: test
    spec:
      containers:
      - name: nginx
        image: nginx:1.27
EOF

# Deployment created (baseline enforced)
# But shows warnings (restricted audit/warn)

# Fix deployment to be restricted-compliant

cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: compliant-deploy
  namespace: psa-migration
spec:
  replicas: 2
  selector:
    matchLabels:
      app: secure-app
  template:
    metadata:
      labels:
        app: secure-app
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
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
      volumes:
      - name: cache
        emptyDir: {}
      - name: run
        emptyDir: {}
EOF

# Verify deployment

kubectl get deployment compliant-deploy -n psa-migration
kubectl get pods -n psa-migration -l app=secure-app

# No warnings should appear

```

```

---

### Exercise 9: Understand Allowed Volume Types

```bash

# Restricted profile limits volume types
# Test allowed volume types

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: allowed-volumes
  namespace: psa-restricted
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
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
    volumeMounts:
    - name: config
      mountPath: /config
    - name: secret
      mountPath: /secret
    - name: empty
      mountPath: /data
  volumes:
  - name: config
    configMap:
      name: test-config
      optional: true
  - name: secret
    secret:
      secretName: test-secret
      optional: true
  - name: empty
    emptyDir: {}
EOF

# Should succeed (all allowed volume types)

# Try hostPath volume (should FAIL)

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: hostpath-fail
  namespace: psa-restricted
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
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
    volumeMounts:
    - name: host
      mountPath: /host-data
  volumes:
  - name: host
    hostPath:
      path: /tmp
      type: Directory
EOF

# Expected error: hostPath volumes are forbidden

```

```

---

### Exercise 10: PSA Comparison Matrix

```bash

# Create test matrix namespace

kubectl create namespace psa-test-matrix

# Test 1: Privileged containers

echo "=== Test: Privileged Containers ==="
for level in privileged baseline restricted; do
  kubectl label namespace psa-test-matrix \
    pod-security.kubernetes.io/enforce=$level \
    --overwrite
  
  kubectl apply -f - <<EOF 2>&1 | grep -E "(created|forbidden)" | head -1
apiVersion: v1
kind: Pod
metadata:
  name: priv-test
  namespace: psa-test-matrix
spec:
  containers:
  - name: test
    image: busybox:1.36
    command: ["sleep", "10"]
    securityContext:
      privileged: true
EOF
  echo "$level: $(kubectl get pod priv-test -n psa-test-matrix 2>&1 | grep -o 'Running\|NotFound\|Error')"
  kubectl delete pod priv-test -n psa-test-matrix --ignore-not-found
done

# Test 2: hostNetwork

echo "=== Test: hostNetwork ==="
for level in privileged baseline restricted; do
  kubectl label namespace psa-test-matrix \
    pod-security.kubernetes.io/enforce=$level \
    --overwrite
  
  result=$(kubectl apply -f - <<EOF 2>&1
apiVersion: v1
kind: Pod
metadata:
  name: hostnet-test
  namespace: psa-test-matrix
spec:
  hostNetwork: true
  containers:
  - name: test
    image: busybox:1.36
    command: ["sleep", "10"]
EOF
)
  echo "$level: $(echo "$result" | grep -o 'created\|forbidden' | head -1)"
  kubectl delete pod hostnet-test -n psa-test-matrix --ignore-not-found
done

# Cleanup test namespace

kubectl delete namespace psa-test-matrix
```

```

---

## Verification

```bash

# 1. Check all namespace labels

kubectl get namespaces -o custom-columns=\
NAME:.metadata.name,\
ENFORCE:.metadata.labels.pod-security\\.kubernetes\\.io/enforce,\
AUDIT:.metadata.labels.pod-security\\.kubernetes\\.io/audit,\
WARN:.metadata.labels.pod-security\\.kubernetes\\.io/warn \
  | grep psa-

# 2. Verify privileged pod exists

kubectl get pod privileged-pod -n psa-privileged

# Should exist

# 3. Verify baseline blocks privileged

kubectl get pod privileged-fail -n psa-baseline 2>&1

# Should not exist (blocked)

# 4. Verify restricted requires full security

kubectl get pod restricted-compliant -n psa-restricted

# Should exist and be running

# 5. Test enforcement

kubectl run violation-test --image=nginx:1.27 -n psa-restricted 2>&1 | grep forbidden

# Should show forbidden errors

# 6. Check compliant deployments

kubectl get deployments -n psa-migration
```

```

## Restricted Profile Checklist

Create this checklist pod template:

```yaml

apiVersion: v1
kind: Pod
metadata:
  name: restricted-template
  namespace: psa-restricted
spec:

  # Pod-level security context

  securityContext:
    runAsNonRoot: true          # ✓ Required
    runAsUser: 1000             # ✓ Required (non-zero)
    seccompProfile:              # ✓ Required
      type: RuntimeDefault
  containers:
  - name: app
    image: your-image:tag

    # Container-level security context

    securityContext:
      allowPrivilegeEscalation: false  # ✓ Required
      readOnlyRootFilesystem: true     # ✓ Recommended
      capabilities:
        drop:
        - ALL                          # ✓ Required
        add:
        - NET_BIND_SERVICE            # ✓ Only allowed cap
    volumeMounts:
    - name: tmp
      mountPath: /tmp

  # Only allowed volume types

  volumes:
  - name: tmp
    emptyDir: {}                      # ✓ Allowed
```

```

## Troubleshooting

### PSA Violations

```bash

# Use dry-run to see all violations

kubectl apply -f pod.yaml --dry-run=server -n psa-restricted 2>&1

# Check namespace labels

kubectl get namespace psa-restricted -o yaml | grep pod-security

# Review pod spec against checklist

kubectl get pod <pod> -n psa-restricted -o yaml
```

```

### Common Fixes

```yaml

# Add these to fix restricted violations:

spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: [ALL]
        add: [NET_BIND_SERVICE]  # Only if needed
```

```

## Cleanup

```bash

# Delete all PSA lab namespaces

kubectl delete namespace psa-privileged psa-baseline psa-restricted psa-migration psa-versioned psa-gradual

# Verify deletion

kubectl get namespaces | grep psa-

# Should return nothing

```

```

## Key Takeaways

1. **Three levels**: Privileged (none), Baseline (blocks dangerous), Restricted (maximum security)
1. **Three modes**: Enforce (block), Audit (log), Warn (display)
1. **Namespace labels**: PSA configured via pod-security.kubernetes.io/* labels
1. **Restricted requires**: runAsNonRoot, drop ALL caps, allowPrivilegeEscalation=false, seccomp
1. **Version pinning**: Use enforce-version for stability
1. **Gradual rollout**: Start with audit, add warn, then enforce
1. **Not retroactive**: Only applies to new/updated pods

## Next Steps

- Review all Domain 2 labs
- Practice creating compliant pod specifications
- Study [KCSA Cheatsheet](../../KCSA_CHEATSHEET.md)
- Move to Domain 3: System Hardening

---

**Congratulations!** You've completed all Domain 2: Cluster Hardening labs! You now understand RBAC, ServiceAccounts, Security Contexts, and Pod Security Admission.
