# Pod Security Standards

## Overview

Pod Security Standards (PSS) define three levels of security policies for pod specifications. These standards are enforced by Pod Security Admission (PSA), a built-in admission controller that replaced the deprecated PodSecurityPolicy in Kubernetes 1.25.

Think of Pod Security Standards as building codes for your applications. Just as building codes ensure structures are safe and meet minimum requirements, PSS ensures that pods follow security best practices and don't use dangerous configurations.

## Why Pod Security Standards Matter

1. **Prevent Privilege Escalation**: Stop containers from gaining unnecessary privileges.
1. **Reduce Attack Surface**: Limit what containers can do if compromised.
1. **Enforce Least Privilege**: Ensure containers only have necessary capabilities.
1. **Compliance**: Meet security requirements and regulatory standards.
1. **Consistency**: Apply uniform security policies across the cluster.

## The Three Security Levels

### 1. Privileged

**Description**: Unrestricted policy, allows all configurations.

**Use Case**:

- System-level workloads
- Infrastructure components
- CNI plugins
- Storage drivers
- Monitoring agents with host access

**Security Posture**: No restrictions whatsoever.

**When to Use**:

- kube-system namespace
- Infrastructure namespaces
- Only for truly privileged workloads

**Example Workloads**:

```yaml

# Calico CNI Pod
# FluentD log collectors
# Node monitoring agents
# Storage provisioners

```

```

### 2. Baseline

**Description**: Minimally restrictive policy preventing known privilege escalations.

**Use Case**:

- Most applications
- Default for production workloads
- Balance between security and usability

**Key Restrictions**:

- No privileged containers
- No host namespaces (hostNetwork, hostPID, hostIPC)
- Limited host path volumes
- Restricted capabilities
- No privilege escalation (allowPrivilegeEscalation: false)

**Allowed**:

- Non-root users (but doesn't enforce it)
- Specific volume types
- Reasonable capabilities

**When to Use**:

- Production application namespaces
- Default for most workloads
- When you need some flexibility but want basic security

### 3. Restricted

**Description**: Heavily restricted policy following current pod hardening best practices.

**Use Case**:

- Security-critical applications
- Multi-tenant environments
- Compliance-required workloads
- Untrusted code

**Key Restrictions** (All Baseline restrictions PLUS):

- Must run as non-root
- Must drop ALL capabilities
- Must not allow privilege escalation
- Restricted volume types (no hostPath)
- seccompProfile required
- Read-only root filesystem (recommended)

**When to Use**:

- Production applications (when possible)
- Multi-tenant scenarios
- Security-sensitive workloads
- Applications from untrusted sources

## Pod Security Admission (PSA)

PSA is the controller that enforces Pod Security Standards. It operates in three modes per namespace:

### 1. Enforce Mode

**Behavior**: Rejects pods that violate the policy.

**Use Case**: Production enforcement.

**Example**:

```bash

kubectl label namespace production \
  pod-security.kubernetes.io/enforce=baseline
```

```

**Result**: Pods violating baseline standard are rejected.

### 2. Audit Mode

**Behavior**: Allows pods but adds audit log entries for violations.

**Use Case**: Monitoring and compliance reporting.

**Example**:

```bash

kubectl label namespace production \
  pod-security.kubernetes.io/audit=restricted
```

```

**Result**: Pods are allowed, but violations are logged in the API server audit log.

### 3. Warn Mode

**Behavior**: Allows pods but returns warnings to the user.

**Use Case**: Gradual migration, user education.

**Example**:

```bash

kubectl label namespace development \
  pod-security.kubernetes.io/warn=restricted
```

```

**Result**: Pods are allowed, but kubectl displays warnings:

```

Warning: would violate PodSecurity "restricted:latest": ...

```
```

### Combining Modes

You can use all three modes simultaneously:

```bash

kubectl label namespace production \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
```

```

**Effect**:

- **Enforce**: Baseline (reject seriously bad configurations)
- **Audit**: Restricted (log all non-restricted configurations)
- **Warn**: Restricted (warn users about non-restricted configurations)

This approach allows gradual tightening while maintaining visibility.

## Applying Pod Security Standards

### At Namespace Level

**Create Namespace with PSS**:

```yaml

apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

```

**Apply to Existing Namespace**:

```bash

kubectl label namespace production \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
```

```

**With Version Pinning**:

```yaml

apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/enforce-version: v1.30
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

```

**Version Options**:

- `latest`: Use latest version (default)
- `v1.30`: Pin to specific Kubernetes version
- Pinning prevents surprises when standards evolve

### Exemptions

Exempt specific users, namespaces, or runtimeClasses:

```yaml

apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: PodSecurity
  configuration:
    apiVersion: pod-security.admission.config.k8s.io/v1
    kind: PodSecurityConfiguration
    defaults:
      enforce: "baseline"
      audit: "restricted"
      warn: "restricted"
    exemptions:
      usernames:
      - system:serviceaccount:kube-system:replicaset-controller
      runtimeClasses: []
      namespaces:
      - kube-system
      - kube-public
      - kube-node-lease
```

```

## Security Context Configuration

Security contexts define privilege and access control settings for pods and containers.

### Pod-Level Security Context

Applies to all containers in the pod:

```yaml

apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo
  namespace: production
spec:
  securityContext:
    runAsUser: 1000        # Run as user ID 1000
    runAsGroup: 3000       # Primary group ID 3000
    fsGroup: 2000          # Volume ownership group
    fsGroupChangePolicy: "OnRootMismatch"  # Optimize volume permission changes
    seccompProfile:
      type: RuntimeDefault  # Use default seccomp profile
  containers:
  - name: app
    image: nginx:1.26
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      capabilities:
        drop:
        - ALL
```

```

### Container-Level Security Context

More specific, overrides pod-level settings:

```yaml

apiVersion: v1
kind: Pod
metadata:
  name: container-security-demo
  namespace: production
spec:
  containers:
  - name: app
    image: nginx:1.26
    securityContext:

      # User and group

      runAsUser: 1000
      runAsNonRoot: true

      # Privilege escalation

      allowPrivilegeEscalation: false

      # Capabilities

      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE  # Allow binding to ports < 1024

      # Filesystem

      readOnlyRootFilesystem: true

      # SELinux (if enabled)

      seLinuxOptions:
        level: "s0:c123,c456"

      # Seccomp

      seccompProfile:
        type: RuntimeDefault

    volumeMounts:
    - name: cache
      mountPath: /tmp/cache
    - name: config
      mountPath: /etc/nginx
      readOnly: true

  volumes:
  - name: cache
    emptyDir: {}
  - name: config
    configMap:
      name: nginx-config
```

```

## Meeting Each Standard

### Privileged Standard

Allows everything - no configuration needed:

```yaml

apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
  namespace: kube-system  # Typically for system workloads
spec:
  hostNetwork: true       # Allowed
  hostPID: true           # Allowed
  containers:
  - name: privileged-container
    image: myapp:1.0
    securityContext:
      privileged: true    # Allowed
      runAsUser: 0        # Allowed (root)
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /             # Allowed
      type: Directory
```

```

### Baseline Standard

Basic security with some flexibility:

```yaml

apiVersion: v1
kind: Pod
metadata:
  name: baseline-pod
  namespace: production
spec:

  # Host namespaces NOT allowed
  # hostNetwork: false  # default
  # hostPID: false      # default
  # hostIPC: false      # default

  containers:
  - name: app
    image: myapp:1.0
    securityContext:

      # Must not be privileged

      privileged: false  # Required

      # Should not allow privilege escalation

      allowPrivilegeEscalation: false  # Required

      # Can run as root (but not recommended)

      runAsUser: 0  # Allowed but not best practice

      # Capabilities can be limited

      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE

    volumeMounts:
    - name: app-storage
      mountPath: /data

  volumes:

  # Most volume types allowed

  - name: app-storage
    persistentVolumeClaim:
      claimName: app-pvc
```

```

**Baseline Key Requirements**:

```yaml

# Required securityContext settings

securityContext:
  privileged: false
  allowPrivilegeEscalation: false

# Forbidden host settings
# hostNetwork: false
# hostPID: false
# hostIPC: false
# hostPath volumes (with restrictions)

```

```

### Restricted Standard

Maximum security, best practices:

```yaml

apiVersion: v1
kind: Pod
metadata:
  name: restricted-pod
  namespace: production
spec:
  securityContext:

    # MUST run as non-root

    runAsNonRoot: true
    runAsUser: 1000      # Non-zero user ID

    # Group settings

    fsGroup: 2000

    # Seccomp profile REQUIRED

    seccompProfile:
      type: RuntimeDefault

  containers:
  - name: app
    image: myapp:1.0
    securityContext:

      # MUST run as non-root

      runAsNonRoot: true

      # MUST NOT allow privilege escalation

      allowPrivilegeEscalation: false

      # MUST drop ALL capabilities

      capabilities:
        drop:
        - ALL

      # STRONGLY RECOMMENDED: Read-only root filesystem

      readOnlyRootFilesystem: true

      # Seccomp REQUIRED

      seccompProfile:
        type: RuntimeDefault

    volumeMounts:

    # Writable temp directory (since root is read-only)

    - name: tmp
      mountPath: /tmp
    - name: cache
      mountPath: /app/cache
    - name: config
      mountPath: /app/config
      readOnly: true

  volumes:

  # Only safe volume types allowed

  - name: tmp
    emptyDir: {}
  - name: cache
    emptyDir: {}
  - name: config
    configMap:
      name: app-config

  # NO hostPath volumes allowed

```

```

**Restricted Key Requirements**:

```yaml

# All Baseline requirements PLUS:

# Pod securityContext (required)

securityContext:
  runAsNonRoot: true
  seccompProfile:
    type: RuntimeDefault

# Container securityContext (required)

securityContext:
  runAsNonRoot: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
    - ALL
  seccompProfile:
    type: RuntimeDefault

  # Recommended

  readOnlyRootFilesystem: true
```

```

## Common Patterns and Examples

### 1. Web Application (Restricted)

```yaml

apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: web-app
  template:
    metadata:
      labels:
        app: web-app
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 2000
        seccompProfile:
          type: RuntimeDefault

      containers:
      - name: nginx
        image: nginx:1.26
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          capabilities:
            drop:
            - ALL
            add:
            - NET_BIND_SERVICE
          readOnlyRootFilesystem: true
          seccompProfile:
            type: RuntimeDefault

        ports:
        - containerPort: 8080

        volumeMounts:
        - name: cache
          mountPath: /var/cache/nginx
        - name: run
          mountPath: /var/run
        - name: config
          mountPath: /etc/nginx
          readOnly: true

        resources:
          limits:
            cpu: 500m
            memory: 256Mi
          requests:
            cpu: 250m
            memory: 128Mi

      volumes:
      - name: cache
        emptyDir: {}
      - name: run
        emptyDir: {}
      - name: config
        configMap:
          name: nginx-config
```

```

### 2. Database (Baseline)

Some databases need more flexibility:

```yaml

apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: database
  namespace: production
spec:
  serviceName: database
  replicas: 1
  selector:
    matchLabels:
      app: database
  template:
    metadata:
      labels:
        app: database
    spec:
      securityContext:
        fsGroup: 999  # postgres group
        fsGroupChangePolicy: "OnRootMismatch"

      containers:
      - name: postgres
        image: postgres:16
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
            add:
            - CHOWN
            - FOWNER
            - SETGID
            - SETUID

        env:
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-password
              key: password
        - name: PGDATA
          value: /var/lib/postgresql/data/pgdata

        ports:
        - containerPort: 5432

        volumeMounts:
        - name: data
          mountPath: /var/lib/postgresql/data

        resources:
          limits:
            cpu: 2
            memory: 4Gi
          requests:
            cpu: 1
            memory: 2Gi

  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi
```

```

### 3. Monitoring Agent (Privileged)

System-level monitoring needs privileges:

```yaml

apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-exporter
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: node-exporter
  template:
    metadata:
      labels:
        app: node-exporter
    spec:
      hostNetwork: true    # Need to see host metrics
      hostPID: true        # Need to see host processes

      containers:
      - name: node-exporter
        image: prom/node-exporter:v1.7.0
        args:
        - --path.procfs=/host/proc
        - --path.sysfs=/host/sys
        - --path.rootfs=/host/root
        securityContext:
          privileged: false
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
            add:
            - SYS_TIME  # For time metrics

        volumeMounts:
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: sys
          mountPath: /host/sys
          readOnly: true
        - name: root
          mountPath: /host/root
          readOnly: true

        ports:
        - containerPort: 9100
          hostPort: 9100

      volumes:
      - name: proc
        hostPath:
          path: /proc
      - name: sys
        hostPath:
          path: /sys
      - name: root
        hostPath:
          path: /
```

```

### 4. Init Container Pattern

Using init containers with restricted standard:

```yaml

apiVersion: v1
kind: Pod
metadata:
  name: app-with-init
  namespace: production
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault

  initContainers:
  - name: init-setup
    image: busybox:1.36
    command: ['sh', '-c', 'cp /config/* /shared/']
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      capabilities:
        drop:
        - ALL
      readOnlyRootFilesystem: true
      seccompProfile:
        type: RuntimeDefault
    volumeMounts:
    - name: config
      mountPath: /config
      readOnly: true
    - name: shared
      mountPath: /shared

  containers:
  - name: app
    image: myapp:1.0
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      capabilities:
        drop:
        - ALL
      readOnlyRootFilesystem: true
      seccompProfile:
        type: RuntimeDefault
    volumeMounts:
    - name: shared
      mountPath: /app/config
      readOnly: true
    - name: tmp
      mountPath: /tmp

  volumes:
  - name: config
    configMap:
      name: app-config
  - name: shared
    emptyDir: {}
  - name: tmp
    emptyDir: {}
```

```

## Migration Strategy

Migrating from permissive to restricted standards:

### Step 1: Assess Current State

```bash

# Check existing namespaces

kubectl get namespaces -L pod-security.kubernetes.io/enforce

# Test against restricted (dry-run)

kubectl label namespace production \
  pod-security.kubernetes.io/warn=restricted \
  --dry-run=server
```

```

### Step 2: Enable Warn Mode

```bash

# Add warnings first

kubectl label namespace production \
  pod-security.kubernetes.io/warn=baseline
```

```

### Step 3: Monitor and Fix

Deploy applications and observe warnings:

```bash

kubectl apply -f app.yaml

# Warning: would violate PodSecurity "baseline:latest": allowPrivilegeEscalation != false

```

```

Fix issues in manifests:

```yaml

securityContext:
  allowPrivilegeEscalation: false
```

```

### Step 4: Enable Audit Mode

```bash

kubectl label namespace production \
  pod-security.kubernetes.io/audit=baseline
```

```

Check audit logs for violations.

### Step 5: Enable Enforce Mode

```bash

kubectl label namespace production \
  pod-security.kubernetes.io/enforce=baseline
```

```

### Step 6: Progress to Restricted

Repeat steps 2-5 with restricted standard:

```bash

kubectl label namespace production \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted

# After fixing all issues:

kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted
```

```

## Troubleshooting

### Common Violations

#### 1. allowPrivilegeEscalation not set

**Error**:

```

Warning: would violate PodSecurity "baseline:latest":
allowPrivilegeEscalation != false

```
```

**Fix**:

```yaml

securityContext:
  allowPrivilegeEscalation: false
```

```

#### 2. Running as root

**Error**:

```

Warning: would violate PodSecurity "restricted:latest":
runAsNonRoot != true

```
```

**Fix**:

```yaml

securityContext:
  runAsNonRoot: true
  runAsUser: 1000
```

```

#### 3. Missing seccomp profile

**Error**:

```

Warning: would violate PodSecurity "restricted:latest":
seccompProfile

```
```

**Fix**:

```yaml

securityContext:
  seccompProfile:
    type: RuntimeDefault
```

```

#### 4. Capabilities not dropped

**Error**:

```

Warning: would violate PodSecurity "restricted:latest":
unrestricted capabilities

```
```

**Fix**:

```yaml

securityContext:
  capabilities:
    drop:
    - ALL
```

```

#### 5. hostPath volume

**Error**:

```

Error: pods "mypod" is forbidden:
hostPath volumes are not allowed to be used

```
```

**Fix**: Use alternative volume types (emptyDir, ConfigMap, Secret, PVC).

### Debugging Tips

**1. Check namespace labels**:

```bash

kubectl get namespace production -o yaml | grep pod-security
```

```

**2. Dry-run pod creation**:

```bash

kubectl apply -f pod.yaml --dry-run=server
```

```

**3. Describe pod for admission errors**:

```bash

kubectl describe pod failing-pod
```

```

**4. Check API server audit logs**:

```bash

kubectl logs -n kube-system kube-apiserver-<node> | grep PodSecurity
```

```

**5. Use --v=8 for detailed output**:

```bash

kubectl apply -f pod.yaml --v=8
```

```

## Linux Capabilities Reference

Common capabilities you might need to add (after dropping ALL):

| Capability | Description | Use Case |
| ------------ | ------------- | ---------- |
| NET_BIND_SERVICE | Bind to ports < 1024 | Web servers on port 80/443 |
| CHOWN | Change file ownership | File permission management |
| SETUID | Set user ID | User switching |
| SETGID | Set group ID | Group switching |
| FOWNER | File operations | File management |
| DAC_OVERRIDE | Bypass file permissions | Specific file operations |
| NET_RAW | Use RAW and PACKET sockets | Network diagnostics |
| SYS_TIME | Set system clock | Time synchronization |

**Best Practice**: Only add capabilities when absolutely necessary, and document why.

## Best Practices

1. **Start Restrictive**: Begin with restricted and relax only when necessary.

1. **Use All Three Modes**: Combine enforce, audit, and warn for visibility.

1. **Pin Versions**: Use version pinning to prevent surprises:

```yaml

pod-security.kubernetes.io/enforce-version: v1.30
```

```

1. **Document Exceptions**: Clearly document why privileged workloads need privileges.

1. **Regular Audits**: Periodically review namespace labels and pod configurations.

1. **Read-Only Root**: Always use `readOnlyRootFilesystem: true` when possible.

1. **Drop All Capabilities**: Start with `drop: [ALL]` and add back only what's needed.

1. **Use Non-Root Images**: Build or use container images that run as non-root.

1. **Test Thoroughly**: Test PSS changes in non-production first.

1. **Automate Validation**: Use admission controllers or CI/CD checks to enforce standards.

## Key Points to Remember

1. Three standards: Privileged (unrestricted), Baseline (minimal restrictions), Restricted (hardened).
1. Three modes: Enforce (reject), Audit (log), Warn (notify user).
1. PSA replaced PodSecurityPolicy in Kubernetes 1.25.
1. Apply PSS at namespace level using labels.
1. Security contexts can be set at pod and container levels.
1. Restricted standard requires: runAsNonRoot, drop ALL capabilities, seccomp profile.
1. Use readOnlyRootFilesystem with emptyDir volumes for writable directories.
1. Combine modes for gradual migration (warn → audit → enforce).
1. Pin PSS versions to prevent unexpected changes.
1. Start restrictive and relax only when necessary with documentation.

## Study Resources

### Official Documentation

- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)

### Tools

- [kubectl-pss](https://github.com/kubernetes-sigs/kubectl-pss) - PSS validation tool
- [kyverno](https://kyverno.io/) - Policy engine for PSS enforcement
- [OPA Gatekeeper](https://open-policy-agent.github.io/gatekeeper/) - Policy controller

### Additional Reading

- [NSA Kubernetes Hardening Guide - Pod Security](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)

## Next Steps

1. Complete the [Pod Security Standards Lab](../../labs/01-cluster-setup/lab-04-pod-security-standards.md)
1. Practice applying PSS to different namespaces
1. Experiment with security contexts
1. Review [Cluster Hardening](../../domains/02-cluster-hardening/README.md) next

## Quick Reference

### Common Commands

```bash

# Apply PSS labels

kubectl label namespace <namespace> \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted

# Check namespace labels

kubectl get namespace <namespace> --show-labels

# Remove PSS labels

kubectl label namespace <namespace> \
  pod-security.kubernetes.io/enforce- \
  pod-security.kubernetes.io/audit- \
  pod-security.kubernetes.io/warn-

# Test pod against PSS

kubectl apply -f pod.yaml --dry-run=server
```

```

### Security Context Template (Restricted)

```yaml

# Pod-level

securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 2000
  seccompProfile:
    type: RuntimeDefault

# Container-level

securityContext:
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  capabilities:
    drop:
    - ALL
  readOnlyRootFilesystem: true
  seccompProfile:
    type: RuntimeDefault
```

```

### Namespace PSS Configuration

```yaml

# Development (permissive)

pod-security.kubernetes.io/enforce: privileged
pod-security.kubernetes.io/audit: baseline
pod-security.kubernetes.io/warn: baseline

# Staging (balanced)

pod-security.kubernetes.io/enforce: baseline
pod-security.kubernetes.io/audit: restricted
pod-security.kubernetes.io/warn: restricted

# Production (strict)

pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/audit: restricted
pod-security.kubernetes.io/warn: restricted

# System (permissive)

pod-security.kubernetes.io/enforce: privileged
```

```

---

[← Previous: Ingress Security](./ingress-service-security.md) | [Back to Domain 1 README](./README.md) | [Next Domain: Cluster Hardening →](../../domains/02-cluster-hardening/README.md)
