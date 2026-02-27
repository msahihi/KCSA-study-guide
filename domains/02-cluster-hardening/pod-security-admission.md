# Pod Security Admission

## Introduction

**Pod Security Admission (PSA)** is a built-in Kubernetes admission controller that enforces Pod Security Standards at the namespace level. It replaced the deprecated PodSecurityPolicy (PSP) in Kubernetes v1.25 and provides a simpler, more maintainable way to enforce security policies.

**What Pod Security Admission Does**:

- Enforces security policies on pod specifications
- Prevents insecure pods from being created
- Provides audit logging for policy violations
- Warns users about non-compliant configurations
- Operates at the namespace level using labels

**Real-World Scenario**: Your organization has multiple teams deploying to Kubernetes. Without PSA, developers might accidentally deploy privileged containers, containers running as root, or pods with dangerous capabilities. PSA automatically enforces security standards, preventing these risky configurations from being deployed and ensuring all workloads meet baseline security requirements.

## Pod Security Standards (PSS)

PSA enforces three predefined security profiles defined by Pod Security Standards.

### Privileged Profile

**No restrictions** - Most permissive, allows all configurations.

**Use Case**: System-level workloads that require host access (CNI plugins, storage drivers, monitoring agents)

**Allowed**:

- Privileged containers
- Host namespaces (hostNetwork, hostPID, hostIPC)
- Host paths
- All capabilities
- Running as root

**Example Namespace Label**:

```yaml
pod-security.kubernetes.io/enforce: privileged
```

### Baseline Profile

**Minimal restrictions** - Prevents the most dangerous configurations while allowing common deployment patterns.

**Use Case**: Standard applications with relaxed security requirements

**Prohibited**:

- Privileged containers (`privileged: true`)
- Host namespaces (hostNetwork, hostPID, hostIPC)
- Host path volumes
- hostPort usage
- Dangerous capabilities: `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, etc.
- Proc mount type (default or unmasked)
- SELinux privilege escalation

**Allowed**:

- Running as root
- Some capabilities (NET_BIND_SERVICE, etc.)
- Volume types (except hostPath)

**Example Namespace Label**:

```yaml
pod-security.kubernetes.io/enforce: baseline
```

### Restricted Profile

**Heavily restricted** - Best practices for security-hardened workloads.

**Use Case**: Production applications with strong security requirements

**Requirements**:

- Must run as non-root (`runAsNonRoot: true`)
- Must drop all capabilities and add only allowed ones
- Seccomp profile required (`RuntimeDefault` or `Localhost`)
- No privilege escalation (`allowPrivilegeEscalation: false`)
- Read-only root filesystem recommended
- No host namespaces
- No hostPath volumes
- Limited volume types

**Allowed Capabilities** (only these can be added):

- `NET_BIND_SERVICE`

**Allowed Volume Types**:

- configMap
- downwardAPI
- emptyDir
- persistentVolumeClaim
- projected
- secret

**Example Namespace Label**:

```yaml
pod-security.kubernetes.io/enforce: restricted
```

## PSA Enforcement Modes

PSA supports three modes that can be applied independently:

### 1. Enforce Mode

**Rejects pods that violate the policy** - Pod creation fails.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
```

**Behavior**: API server rejects non-compliant pods with an error message.

**Example Error**:

```
Error from server (Forbidden): error when creating "pod.yaml": pods "test-pod"
is forbidden: violates PodSecurity "restricted:latest": allowPrivilegeEscalation
!= false (container "test" must set securityContext.allowPrivilegeEscalation=false)

```

### 2. Audit Mode

**Logs violations to audit log** - Pod creation succeeds.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: development
  labels:
    pod-security.kubernetes.io/audit: restricted
```

**Behavior**: Violations recorded in audit log for review, but pods are created.

**Use Case**: Monitor compliance before enforcing, identify non-compliant workloads.

### 3. Warn Mode

**Shows warnings to users** - Pod creation succeeds.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: staging
  labels:
    pod-security.kubernetes.io/warn: baseline
```

**Behavior**: kubectl displays warnings, but pods are created.

**Example Warning**:

```
Warning: would violate PodSecurity "baseline:latest": host namespaces
(hostNetwork=true)
pod/test-pod created

```

**Use Case**: Educate users about security issues without blocking deployments.

## Applying PSA to Namespaces

### Single Mode

```bash
# Enforce restricted profile

kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted

# Audit baseline violations

kubectl label namespace development \
  pod-security.kubernetes.io/audit=baseline

# Warn about privileged usage

kubectl label namespace testing \
  pod-security.kubernetes.io/warn=privileged
```

### Multiple Modes

Apply all three modes simultaneously:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: secure-namespace
  labels:
    pod-security.kubernetes.io/enforce: baseline   # Block violations
    pod-security.kubernetes.io/audit: restricted   # Log restricted violations
    pod-security.kubernetes.io/warn: restricted    # Warn about restricted violations
```

**Common Pattern**: Enforce baseline, audit/warn restricted:

- Current deployments meet baseline (enforced)
- Working toward restricted (audit logs track progress)
- Developers see warnings for restricted violations

### Version Pinning

Pin to specific Kubernetes version of PSS:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: versioned-namespace
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: v1.30
```

**Why Pin Versions**:

- Standards evolve with Kubernetes versions
- Prevent breaking changes during cluster upgrades
- Control when to adopt new restrictions

**Default**: `latest` (current cluster version)

## Creating Compliant Pods

### Privileged-Compliant Pod

Any pod specification works:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
  namespace: privileged-ns
spec:
  containers:
  - name: nginx
    image: nginx:1.27

    # Any configuration allowed

```

### Baseline-Compliant Pod

Avoid dangerous configurations:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: baseline-pod
  namespace: baseline-ns
spec:

  # No hostNetwork, hostPID, hostIPC

  containers:
  - name: nginx
    image: nginx:1.27
    securityContext:

      # privileged: false (default)
      # No dangerous capabilities

      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE

    # No hostPath volumes

```

**Key Points**:

- Can run as root (not prohibited)
- Must not use host namespaces
- Must not be privileged
- Cannot use dangerous capabilities

### Restricted-Compliant Pod

Full security hardening:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: restricted-pod
  namespace: restricted-ns
spec:
  securityContext:
    runAsNonRoot: true           # Required
    runAsUser: 1000
    seccompProfile:              # Required
      type: RuntimeDefault
  containers:
  - name: nginx
    image: nginx:1.27
    securityContext:
      allowPrivilegeEscalation: false    # Required
      readOnlyRootFilesystem: true       # Recommended
      capabilities:
        drop:
        - ALL                            # Required
        add:
        - NET_BIND_SERVICE               # Only allowed capability
    volumeMounts:
    - name: cache
      mountPath: /var/cache/nginx
    - name: run
      mountPath: /var/run
  volumes:
  - name: cache
    emptyDir: {}                         # Allowed volume type
  - name: run
    emptyDir: {}
```

**Required Fields**:

- `runAsNonRoot: true`
- `allowPrivilegeEscalation: false`
- `seccompProfile.type: RuntimeDefault` (or Localhost)
- `capabilities.drop: [ALL]`

## Namespace Configuration Examples

### Development Namespace (Permissive)

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: development
  labels:
    pod-security.kubernetes.io/enforce: privileged   # No enforcement
    pod-security.kubernetes.io/audit: baseline       # Log baseline violations
    pod-security.kubernetes.io/warn: baseline        # Warn about baseline issues
```

**Rationale**: Allow developers flexibility while educating about security.

### Staging Namespace (Moderate)

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: staging
  labels:
    pod-security.kubernetes.io/enforce: baseline     # Prevent dangerous configs
    pod-security.kubernetes.io/audit: restricted     # Log restricted violations
    pod-security.kubernetes.io/warn: restricted      # Warn about restricted issues
```

**Rationale**: Block dangerous configurations, prepare for production standards.

### Production Namespace (Strict)

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted   # Strict enforcement
    pod-security.kubernetes.io/audit: restricted     # Full audit logging
    pod-security.kubernetes.io/warn: restricted      # Warn on any issues
    pod-security.kubernetes.io/enforce-version: v1.30
```

**Rationale**: Maximum security for production workloads.

### System Namespace (Privileged)

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kube-system
  labels:
    pod-security.kubernetes.io/enforce: privileged   # System components need access
    pod-security.kubernetes.io/audit: privileged
    pod-security.kubernetes.io/warn: privileged
```

**Rationale**: System components require host access and privileges.

## Migration from PodSecurityPolicy

PodSecurityPolicy (PSP) was deprecated in Kubernetes v1.21 and removed in v1.25.

### Key Differences

| Feature | PodSecurityPolicy | Pod Security Admission |
| --------- | ------------------- | ------------------------ |
| Complexity | High (RBAC integration) | Low (namespace labels) |
| Configuration | Per-policy resources | Three predefined standards |
| RBAC | Required | Not required |
| Flexibility | Very flexible | Less flexible |
| Maintenance | Complex | Simple |
| Default behavior | Deny all | Allow all |

### Migration Strategy

1. **Assess Current PSPs**: Understand existing policies
1. **Map to PSS Levels**: Determine which PSS level each namespace needs
1. **Enable PSA**: Turn on Pod Security Admission
1. **Start with Audit/Warn**: Don't enforce immediately
1. **Fix Non-Compliant Workloads**: Update pod specs
1. **Enable Enforcement**: Switch to enforce mode
1. **Remove PSPs**: Delete PodSecurityPolicy resources

### Migration Example

**Old PodSecurityPolicy**:

```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  privileged: false
  runAsUser:
    rule: MustRunAsNonRoot
  seLinux:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  volumes:
  - configMap
  - emptyDir
  - secret
```

**New Pod Security Admission** (equivalent):

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
```

**Simplified**: One label vs. entire PSP resource + RBAC bindings.

## Checking Compliance

### Dry-Run Check

Test pod against namespace policies without creating:

```bash
# Test pod creation

kubectl apply -f pod.yaml --dry-run=server -n restricted-ns

# If compliant: pod/test-pod created (server dry run)
# If non-compliant: Error with violation details

```

### Namespace Audit

Check existing pods against a PSS level:

```bash
# Install kubectl-check-psa plugin

kubectl check-psa --namespace production --level restricted

# Or manually check

kubectl label namespace production \
  pod-security.kubernetes.io/audit=restricted --overwrite

# Review audit logs

kubectl logs -n kube-system kube-apiserver-* | grep pod-security
```

### Bulk Assessment

Check all namespaces:

```bash
# List namespace PSA labels

kubectl get namespaces -o json | \
  jq -r '.items[] | "\(.metadata.name): \(.metadata.labels)"'

# Find namespaces without PSA

kubectl get namespaces -o json | \
  jq -r '.items[] | select(.metadata.labels |
    has("pod-security.kubernetes.io/enforce") | not) |
    .metadata.name'
```

## Exemptions

PSA allows exempting specific pods, users, or namespaces from enforcement.

### Cluster-Wide Exemptions

Configure via API server admission plugin:

```yaml
# /etc/kubernetes/admission-control/psa-config.yaml

apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: PodSecurity
  configuration:
    apiVersion: pod-security.admission.config.k8s.io/v1
    kind: PodSecurityConfiguration
    defaults:
      enforce: "baseline"
      enforce-version: "latest"
      audit: "restricted"
      audit-version: "latest"
      warn: "restricted"
      warn-version: "latest"
    exemptions:
      usernames: []
      runtimeClasses: []
      namespaces:
      - kube-system              # Exempt system namespace
      - ingress-nginx            # Exempt ingress controller
```

**kube-apiserver flag**:

```
--admission-control-config-file=/etc/kubernetes/admission-control/psa-config.yaml

```

### Common Exemption Use Cases

- **System namespaces**: kube-system, kube-public, kube-node-lease
- **Infrastructure**: Ingress controllers, CNI plugins, storage drivers
- **Monitoring**: Prometheus, Grafana with privileged access needs
- **Security tools**: Falco, Trivy operators requiring host access

## Troubleshooting PSA

### Common Issues

#### 1. Pod Rejected by PSA

**Error**:

```
Error from server (Forbidden): error when creating "pod.yaml": pods "test"
is forbidden: violates PodSecurity "restricted:latest": allowPrivilegeEscalation
!= false (container "app" must set securityContext.allowPrivilegeEscalation=false),
unrestricted capabilities (container "app" must set securityContext.capabilities.drop=["ALL"])
```

**Solution**: Fix pod specification:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  capabilities:
    drop: [ALL]
```

#### 2. Existing Pods Work, New Ones Fail

**Cause**: PSA added after pods were created (not retroactive)

**Solution**:

1. Check namespace labels: `kubectl get ns production -o yaml`
1. Review existing pods: `kubectl get pods -n production -o yaml`
1. Update pod specs to be compliant
1. Rollout restart: `kubectl rollout restart deployment -n production`

#### 3. Warnings Flooding kubectl Output

**Example**:

```
Warning: would violate PodSecurity "restricted:latest": ...

```

**Solutions**:

```bash
# Option 1: Suppress warnings

kubectl create -f pod.yaml --warnings-as-errors=false

# Option 2: Fix pod spec to be compliant

# Option 3: Lower warn level

kubectl label namespace staging \
  pod-security.kubernetes.io/warn=baseline --overwrite
```

#### 4. Can't Determine Required Security Context

**Problem**: Not sure what's needed for restricted compliance

**Solution**: Use audit mode to discover issues:

```bash
# Apply pod with audit

kubectl label namespace test \
  pod-security.kubernetes.io/audit=restricted

# Create pod

kubectl apply -f pod.yaml -n test

# Check audit events (if audit logging enabled)
# Or use dry-run to see errors

kubectl apply -f pod.yaml -n test --dry-run=server
```

### Debugging Commands

```bash
# Check namespace PSA configuration

kubectl get namespace production -o yaml | grep pod-security

# List all namespace PSA labels

kubectl get namespaces --show-labels | grep pod-security

# Test pod against PSA

kubectl apply -f pod.yaml --dry-run=server -n production

# Add audit label to investigate

kubectl label namespace test \
  pod-security.kubernetes.io/audit=restricted

# View PSA configuration on API server (if accessible)

kubectl -n kube-system get pod kube-apiserver-* -o yaml | \
  grep -A10 admission-control-config-file
```

## Pod Security Standards Comparison

### Policy Comparison Matrix

| Check | Privileged | Baseline | Restricted |
| ------- | ----------- | ---------- | ----------- |
| Privileged containers | ✅ Allowed | ❌ Forbidden | ❌ Forbidden |
| Host namespaces | ✅ Allowed | ❌ Forbidden | ❌ Forbidden |
| hostPath volumes | ✅ Allowed | ❌ Forbidden | ❌ Forbidden |
| Host ports | ✅ Allowed | ❌ Forbidden | ❌ Forbidden |
| Running as root | ✅ Allowed | ✅ Allowed | ❌ Forbidden |
| Privilege escalation | ✅ Allowed | ✅ Allowed | ❌ Forbidden |
| Capabilities (all) | ✅ Allowed | ⚠️ Some forbidden | ❌ Drop ALL required |
| seccomp profile | ⚠️ Optional | ⚠️ Optional | ✅ Required |
| Volume types (all) | ✅ Allowed | ⚠️ Most allowed | ⚠️ Limited set |

### Restricted Profile Requirements Checklist

Pod/Container must have:

- [ ] `spec.securityContext.runAsNonRoot: true`
- [ ] `spec.securityContext.seccompProfile.type: RuntimeDefault` (or Localhost)
- [ ] Container: `securityContext.allowPrivilegeEscalation: false`
- [ ] Container: `securityContext.capabilities.drop: ["ALL"]`
- [ ] Only allowed volumes used
- [ ] If adding capabilities, only `NET_BIND_SERVICE`

## Best Practices

### 1. Start with Baseline in Production

```yaml
# Begin with baseline enforcement

pod-security.kubernetes.io/enforce: baseline

# Track restricted compliance

pod-security.kubernetes.io/audit: restricted
pod-security.kubernetes.io/warn: restricted
```

### 2. Use Audit/Warn Before Enforce

```bash
# Week 1-2: Audit only

kubectl label namespace prod \
  pod-security.kubernetes.io/audit=restricted

# Week 3-4: Add warnings

kubectl label namespace prod \
  pod-security.kubernetes.io/warn=restricted --overwrite

# Week 5+: Enforce after fixing issues

kubectl label namespace prod \
  pod-security.kubernetes.io/enforce=restricted --overwrite
```

### 3. Pin Versions for Stability

```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/enforce-version: v1.30  # Pin version
```

### 4. Apply Appropriate Levels

| Namespace Type | Recommended Level |
| ---------------- | ------------------- |
| kube-system | privileged |
| Ingress controllers | privileged |
| Monitoring (node access) | privileged or baseline |
| Development | baseline |
| Staging | baseline or restricted |
| Production | restricted |
| CI/CD | baseline or restricted |

### 5. Document Privileged Exceptions

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: monitoring
  labels:
    pod-security.kubernetes.io/enforce: privileged
  annotations:
    pod-security.kubernetes.io/rationale: |
      Node exporter requires hostNetwork and hostPID for metrics collection.
      Reviewed and approved by security team on 2026-02-27.
```

### 6. Regular Compliance Audits

```bash
# Monthly audit script

for ns in $(kubectl get namespaces -o name | cut -d/ -f2); do
  echo "=== Namespace: $ns ==="
  kubectl label namespace $ns \
    pod-security.kubernetes.io/audit=restricted --overwrite
done

# Review audit logs for violations

```

### 7. Combine with Other Security Controls

```yaml
# PSA + Network Policies + RBAC

apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted

    # Also apply:
    # - NetworkPolicies for network segmentation
    # - RBAC for access control
    # - ResourceQuotas for resource limits

```

## Quick Reference

### Apply PSA Labels

```bash
# Enforce level

kubectl label namespace <ns> \
  pod-security.kubernetes.io/enforce=<level>

# Audit level

kubectl label namespace <ns> \
  pod-security.kubernetes.io/audit=<level>

# Warn level

kubectl label namespace <ns> \
  pod-security.kubernetes.io/warn=<level>

# Pin version

kubectl label namespace <ns> \
  pod-security.kubernetes.io/enforce-version=v1.30

# Remove label

kubectl label namespace <ns> \
  pod-security.kubernetes.io/enforce-
```

### PSS Levels

- **privileged**: No restrictions
- **baseline**: Minimal restrictions (prevents most dangerous)
- **restricted**: Best practices (heavily restricted)

### Modes

- **enforce**: Reject non-compliant pods
- **audit**: Log violations (allow pods)
- **warn**: Show warnings (allow pods)

## Exam Tips

1. **Three levels**: Privileged, Baseline, Restricted (memorize differences)
1. **Three modes**: Enforce, audit, warn
1. **Namespace labels**: PSA configured via namespace labels
1. **Restricted requirements**: runAsNonRoot, drop ALL capabilities, seccomp, allowPrivilegeEscalation=false
1. **Baseline blocks**: Host namespaces, privileged containers, hostPath, dangerous capabilities
1. **Multiple modes**: Can apply enforce + audit + warn simultaneously
1. **Version pinning**: Use enforce-version label to pin PSS version
1. **Not retroactive**: Only applies to new/updated pods, not existing ones

## Next Steps

- Complete [Lab 05: Pod Security Admission](../../labs/02-cluster-hardening/lab-05-pod-security-admission.md)
- Review [Security Contexts](security-contexts.md) for pod security configuration
- Study [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) details
- Practice converting existing workloads to be compliant

## Additional Resources

- [Pod Security Admission Documentation](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Migrating from PSP to PSA](https://kubernetes.io/docs/tasks/configure-pod-container/migrate-from-psp/)
- [PSA Configuration](https://kubernetes.io/docs/tasks/configure-pod-container/enforce-standards-admission-controller/)
