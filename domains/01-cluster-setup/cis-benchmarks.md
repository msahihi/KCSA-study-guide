# CIS Kubernetes Benchmarks

## Overview

The Center for Internet Security (CIS) Kubernetes Benchmarks are a set of best practices and security recommendations for securing Kubernetes clusters. These benchmarks provide a comprehensive checklist of security configurations that help organizations establish a secure baseline for their Kubernetes deployments.

Think of CIS Benchmarks as a security audit checklist created by industry experts. Following these recommendations helps ensure your cluster meets widely accepted security standards and reduces the risk of common misconfigurations.

## Why CIS Benchmarks Matter

1. **Industry Standard**: CIS Benchmarks are recognized worldwide as authoritative security guidance.
1. **Compliance**: Many regulatory frameworks (PCI-DSS, HIPAA, SOC 2) reference CIS Benchmarks.
1. **Comprehensive**: Covers all cluster components (master nodes, worker nodes, policies).
1. **Actionable**: Provides specific recommendations with remediation steps.
1. **Regularly Updated**: Maintained to reflect current Kubernetes versions and threats.

## Benchmark Structure

### Sections Overview

The CIS Kubernetes Benchmark is divided into five main sections:

#### 1. Master Node Security Configuration (Formerly Section 1)

Controls for securing the Kubernetes control plane components:

- API Server configuration
- Controller Manager configuration
- Scheduler configuration
- etcd configuration

#### 2. etcd Security Configuration (Formerly Section 2)

Specific security controls for the etcd key-value store:

- Network encryption
- Authentication and authorization
- Data encryption at rest

#### 3. Control Plane Configuration (Formerly Section 3)

Security settings for control plane components:

- Authentication and authorization
- Admission controllers
- Pod Security Standards

#### 4. Worker Node Security Configuration (Formerly Section 4)

Controls for securing worker nodes:

- kubelet configuration
- Container runtime security
- Node security policies

#### 5. Policies (Formerly Section 5)

Kubernetes native security policies:

- Pod Security Standards
- Network Policies
- RBAC policies
- Secrets management

### Scoring Levels

Each recommendation has a scoring level:

- **Level 1**: Basic security measures that:

  - Are practical and prudent
  - Provide clear security benefits
  - Don't inhibit the utility of the technology beyond acceptable means

- **Level 2**: Defense-in-depth measures that:

  - Provide additional security
  - May have operational complexity or constraints
  - Should be applied based on specific security requirements

### Recommendation Status

- **Scored**: Violations can be automatically detected and should be remediated
- **Not Scored**: Important but may require manual verification or have environmental dependencies

## Key Recommendations by Component

### API Server Security

The API Server is the gateway to your cluster. CIS recommends:

#### 1. Enable Anonymous Auth (Scored, Level 1)

**Recommendation**: Set `--anonymous-auth=false`

**Why**: Anonymous authentication allows unauthenticated requests to the API server.

**Implementation**:

```yaml

# /etc/kubernetes/manifests/kube-apiserver.yaml

spec:
  containers:
  - command:
    - kube-apiserver
    - --anonymous-auth=false
```

```

**Verification**:

```bash

ps -ef | grep kube-apiserver | grep anonymous-auth
```

```

#### 2. Enable Basic Auth File (Scored, Level 1)

**Recommendation**: Don't use `--basic-auth-file`

**Why**: Basic authentication uses static passwords and is insecure.

**Implementation**: Remove the flag entirely from API server configuration.

#### 3. Enable Token Auth File (Scored, Level 1)

**Recommendation**: Don't use `--token-auth-file`

**Why**: Token authentication uses static tokens that don't expire.

**Implementation**: Use service account tokens or OIDC instead.

#### 4. Enable Authorization Mode (Scored, Level 1)

**Recommendation**: Set `--authorization-mode=Node,RBAC`

**Why**: Ensures all API requests are properly authorized.

**Implementation**:

```yaml

spec:
  containers:
  - command:
    - kube-apiserver
    - --authorization-mode=Node,RBAC
```

```

**Avoid**: Never use `AlwaysAllow` in production.

#### 5. Enable Admission Controllers (Scored, Level 1)

**Recommendation**: Enable essential admission controllers:

```yaml

spec:
  containers:
  - command:
    - kube-apiserver
    - --enable-admission-plugins=NodeRestriction,PodSecurity,ServiceAccount
```

```

**Required Admission Controllers**:

- `NodeRestriction`: Limits node permissions
- `PodSecurity`: Enforces Pod Security Standards
- `ServiceAccount`: Automates service account management

**Avoid**: Never use `AlwaysAdmit` or `AlwaysPullImages` without understanding implications.

#### 6. Disable Insecure Port (Scored, Level 1)

**Recommendation**: Set `--insecure-port=0`

**Why**: The insecure port allows unauthenticated, unencrypted access.

**Implementation**:

```yaml

spec:
  containers:
  - command:
    - kube-apiserver
    - --insecure-port=0
```

```

#### 7. Enable Audit Logging (Scored, Level 1)

**Recommendation**: Configure comprehensive audit logging:

```yaml

spec:
  containers:
  - command:
    - kube-apiserver
    - --audit-log-path=/var/log/kubernetes/audit.log
    - --audit-log-maxage=30
    - --audit-log-maxbackup=10
    - --audit-log-maxsize=100
    - --audit-policy-file=/etc/kubernetes/audit-policy.yaml
```

```

**Sample Audit Policy**:

```yaml

apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata
  resources:
  - group: ""
    resources: ["secrets", "configmaps"]
- level: RequestResponse
  resources:
  - group: ""
    resources: ["pods"]
```

```

#### 8. Enable TLS (Scored, Level 1)

**Recommendation**: Use TLS for all API server communication:

```yaml

spec:
  containers:
  - command:
    - kube-apiserver
    - --tls-cert-file=/etc/kubernetes/pki/apiserver.crt
    - --tls-private-key-file=/etc/kubernetes/pki/apiserver.key
    - --client-ca-file=/etc/kubernetes/pki/ca.crt
```

```

### Controller Manager Security

#### 1. Service Account Private Key (Scored, Level 1)

**Recommendation**: Set `--service-account-private-key-file`

```yaml

spec:
  containers:
  - command:
    - kube-controller-manager
    - --service-account-private-key-file=/etc/kubernetes/pki/sa.key
```

```

#### 2. Root CA Certificate (Scored, Level 1)

**Recommendation**: Set `--root-ca-file`

```yaml

spec:
  containers:
  - command:
    - kube-controller-manager
    - --root-ca-file=/etc/kubernetes/pki/ca.crt
```

```

#### 3. Bind Address (Scored, Level 1)

**Recommendation**: Set `--bind-address=127.0.0.1`

**Why**: Prevents unauthorized access to controller manager metrics.

```yaml

spec:
  containers:
  - command:
    - kube-controller-manager
    - --bind-address=127.0.0.1
```

```

### Scheduler Security

#### 1. Bind Address (Scored, Level 1)

**Recommendation**: Set `--bind-address=127.0.0.1`

```yaml

spec:
  containers:
  - command:
    - kube-scheduler
    - --bind-address=127.0.0.1
```

```

### etcd Security

etcd stores all cluster state and secrets, making it a critical component to secure.

#### 1. Certificate-Based Authentication (Scored, Level 1)

**Recommendation**: Use certificates for client authentication:

```yaml

spec:
  containers:
  - command:
    - etcd
    - --cert-file=/etc/kubernetes/pki/etcd/server.crt
    - --key-file=/etc/kubernetes/pki/etcd/server.key
    - --client-cert-auth=true
    - --trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
```

```

#### 2. Peer Communication Encryption (Scored, Level 1)

**Recommendation**: Encrypt etcd peer-to-peer communication:

```yaml

spec:
  containers:
  - command:
    - etcd
    - --peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt
    - --peer-key-file=/etc/kubernetes/pki/etcd/peer.key
    - --peer-client-cert-auth=true
    - --peer-trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
```

```

#### 3. Encryption at Rest (Scored, Level 2)

**Recommendation**: Encrypt sensitive data stored in etcd:

**Create Encryption Configuration**:

```yaml

# /etc/kubernetes/enc/encryption-config.yaml

apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <base64-encoded-32-byte-key>
      - identity: {}
```

```

**Configure API Server**:

```yaml

spec:
  containers:
  - command:
    - kube-apiserver
    - --encryption-provider-config=/etc/kubernetes/enc/encryption-config.yaml
```

```

**Generate encryption key**:

```bash

head -c 32 /dev/urandom | base64
```

```

### kubelet Security

#### 1. Anonymous Authentication (Scored, Level 1)

**Recommendation**: Set `--anonymous-auth=false`

```yaml

# /var/lib/kubelet/config.yaml

apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous:
    enabled: false
```

```

#### 2. Authorization Mode (Scored, Level 1)

**Recommendation**: Set `--authorization-mode=Webhook`

```yaml

apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authorization:
  mode: Webhook
```

```

#### 3. Client CA File (Scored, Level 1)

**Recommendation**: Configure client certificate authentication:

```yaml

apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt
```

```

#### 4. Read-Only Port (Scored, Level 1)

**Recommendation**: Disable the read-only port:

```yaml

apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
readOnlyPort: 0
```

```

#### 5. TLS Configuration (Scored, Level 1)

**Recommendation**: Enable TLS:

```yaml

apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
tlsCertFile: /var/lib/kubelet/pki/kubelet.crt
tlsPrivateKeyFile: /var/lib/kubelet/pki/kubelet.key
```

```

#### 6. Rotate Certificates (Scored, Level 1)

**Recommendation**: Enable automatic certificate rotation:

```yaml

apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
rotateCertificates: true
serverTLSBootstrap: true
```

```

### Policy Recommendations

#### 1. Pod Security Standards (Scored, Level 1)

**Recommendation**: Apply appropriate Pod Security Standards:

```bash

# For production namespaces

kubectl label namespace production \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
```

```

#### 2. Network Policies (Scored, Level 2)

**Recommendation**: Implement default-deny network policies:

```yaml

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

```

#### 3. RBAC Configuration (Scored, Level 1)

**Recommendation**: Use RBAC and follow least privilege:

```bash

# Verify RBAC is enabled

kubectl api-versions | grep rbac.authorization.k8s.io

# Audit cluster-admin bindings

kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.roleRef.name=="cluster-admin") | .metadata.name'
```

```

## Using kube-bench

kube-bench is an open-source tool that automates CIS Benchmark checks.

### Installation

**Method 1: Run as a Job**:

```yaml

apiVersion: batch/v1
kind: Job
metadata:
  name: kube-bench
  namespace: default
spec:
  template:
    spec:
      hostPID: true
      containers:
      - name: kube-bench
        image: aquasec/kube-bench:latest
        command: ["kube-bench"]
        volumeMounts:
        - name: var-lib-etcd
          mountPath: /var/lib/etcd
          readOnly: true
        - name: var-lib-kubelet
          mountPath: /var/lib/kubelet
          readOnly: true
        - name: etc-systemd
          mountPath: /etc/systemd
          readOnly: true
        - name: etc-kubernetes
          mountPath: /etc/kubernetes
          readOnly: true
      restartPolicy: Never
      volumes:
      - name: var-lib-etcd
        hostPath:
          path: "/var/lib/etcd"
      - name: var-lib-kubelet
        hostPath:
          path: "/var/lib/kubelet"
      - name: etc-systemd
        hostPath:
          path: "/etc/systemd"
      - name: etc-kubernetes
        hostPath:
          path: "/etc/kubernetes"
```

```

**Method 2: Run Directly on Node**:

```bash

# Download

curl -L https://github.com/aquasecurity/kube-bench/releases/download/v0.7.0/kube-bench_0.7.0_linux_amd64.tar.gz -o kube-bench.tar.gz
tar -xvf kube-bench.tar.gz

# Run on master node

sudo ./kube-bench master

# Run on worker node

sudo ./kube-bench node
```

```

**Method 3: Using Docker**:

```bash

docker run --pid=host --rm \
  -v /etc:/etc:ro \
  -v /var:/var:ro \
  aquasec/kube-bench:latest
```

```

### Understanding kube-bench Output

**Sample Output**:

```

[INFO] 1 Master Node Security Configuration
[INFO] 1.1 Master Node Configuration Files
[PASS] 1.1.1 Ensure that the API server pod specification file permissions are set to 644 or more restrictive (Automated)
[FAIL] 1.1.2 Ensure that the API server pod specification file ownership is set to root:root (Automated)
[PASS] 1.1.3 Ensure that the controller manager pod specification file permissions are set to 644 or more restrictive (Automated)

== Summary ==
45 checks PASS
3 checks FAIL
10 checks WARN
2 checks INFO

```
```

**Output Sections**:

- **[PASS]**: Check passed - no action needed
- **[FAIL]**: Check failed - remediation required
- **[WARN]**: Check couldn't be completed or needs manual verification
- **[INFO]**: Informational message

### Interpreting Results

**Priority for Remediation**:

1. **Critical (Fix Immediately)**:

   - Anonymous authentication enabled
   - Authorization mode set to AlwaysAllow
   - Insecure port enabled
   - No admission controllers configured

1. **High (Fix Soon)**:

   - Missing audit logging
   - Weak RBAC configurations
   - Missing network policies
   - No Pod Security Standards

1. **Medium (Plan Remediation)**:

   - Missing encryption at rest
   - Suboptimal kubelet configuration
   - Certificate rotation disabled

1. **Low (Best Practice)**:

   - File permissions issues
   - Missing resource limits
   - Documentation gaps

### Remediation Workflow

1. **Run kube-bench**:

```bash

kubectl apply -f kube-bench-job.yaml
```

```

1. **Collect Results**:

```bash

kubectl logs job/kube-bench > kube-bench-results.txt
```

```

1. **Analyze Failures**:

```bash

grep FAIL kube-bench-results.txt
```

```

1. **Prioritize**:

- Group by section (master, worker, policies)
- Sort by severity and impact
- Consider operational constraints

1. **Apply Remediations**:

- Test in non-production first
- Apply changes incrementally
- Monitor for issues

1. **Verify**:

```bash

kubectl delete job kube-bench
kubectl apply -f kube-bench-job.yaml
kubectl logs job/kube-bench | grep -E "FAIL|WARN"
```

```

## Common Remediation Examples

### Fix: Enable RBAC

**Problem**: Authorization mode not set to RBAC

**Remediation**:

```bash

# Edit API server manifest

sudo vim /etc/kubernetes/manifests/kube-apiserver.yaml

# Add/modify:

- --authorization-mode=Node,RBAC

# API server will restart automatically

```

```

### Fix: Disable Anonymous Auth

**Problem**: Anonymous authentication enabled on API server

**Remediation**:

```bash

# Edit API server manifest

sudo vim /etc/kubernetes/manifests/kube-apiserver.yaml

# Add:

- --anonymous-auth=false
```

```

### Fix: Enable Audit Logging

**Problem**: No audit logging configured

**Remediation**:

1. **Create audit policy**:

```bash

sudo mkdir -p /etc/kubernetes/audit
sudo vim /etc/kubernetes/audit/policy.yaml
```

```

```yaml

apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata
```

```

1. **Configure API server**:

```yaml

# In /etc/kubernetes/manifests/kube-apiserver.yaml

spec:
  containers:
  - command:
    - kube-apiserver
    - --audit-policy-file=/etc/kubernetes/audit/policy.yaml
    - --audit-log-path=/var/log/kubernetes/audit.log
    - --audit-log-maxage=30
    - --audit-log-maxbackup=10
    - --audit-log-maxsize=100
    volumeMounts:
    - name: audit-policy
      mountPath: /etc/kubernetes/audit
      readOnly: true
    - name: audit-log
      mountPath: /var/log/kubernetes
  volumes:
  - name: audit-policy
    hostPath:
      path: /etc/kubernetes/audit
      type: DirectoryOrCreate
  - name: audit-log
    hostPath:
      path: /var/log/kubernetes
      type: DirectoryOrCreate
```

```

### Fix: kubelet Anonymous Auth

**Problem**: kubelet allows anonymous authentication

**Remediation**:

```bash

# Edit kubelet config

sudo vim /var/lib/kubelet/config.yaml

# Add/modify:

authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
authorization:
  mode: Webhook

# Restart kubelet

sudo systemctl restart kubelet
```

```

### Fix: Apply Pod Security Standards

**Problem**: No Pod Security Standards configured

**Remediation**:

```bash

# Label namespace

kubectl label namespace production \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted

# Verify

kubectl get namespace production -o yaml | grep pod-security
```

```

## Best Practices

1. **Regular Audits**: Run kube-bench regularly (weekly or monthly) to catch configuration drift.

1. **Automate Scanning**: Integrate kube-bench into CI/CD pipelines:

```yaml

# In CI/CD pipeline

- name: Security Audit
  run: |
    kubectl apply -f kube-bench-job.yaml
    kubectl wait --for=condition=complete job/kube-bench --timeout=5m
    kubectl logs job/kube-bench > audit-results.txt
    if grep -q "FAIL" audit-results.txt; then exit 1; fi
```

```

1. **Track Remediation**: Use issue tracking to manage failed checks:

```bash

# Export to JSON for processing

./kube-bench --json > results.json
```

```

1. **Document Exceptions**: Some findings may be acceptable in your environment. Document why:

```yaml

# exception-documentation.yaml

check: 1.2.3
status: accepted
reason: "Using cloud provider managed certificates"
approved_by: "Security Team"
date: "2024-01-15"
```

```

1. **Test Changes**: Always test remediations in non-production first:

```bash

# Test in staging

kubectl --context=staging apply -f remediation.yaml

# Monitor for issues

kubectl --context=staging get pods --watch

# Apply to production

kubectl --context=production apply -f remediation.yaml
```

```

1. **Version-Specific Benchmarks**: Use the correct benchmark version for your Kubernetes version:

```bash

kube-bench --version 1.30
```

```

## Common Pitfalls

### 1. Breaking Changes

**Problem**: Applying all recommendations without testing can break applications.

**Solution**:

- Test incrementally
- Have rollback plans
- Monitor applications after changes

### 2. Cloud Provider Differences

**Problem**: Managed Kubernetes services (EKS, AKS, GKE) handle some controls differently.

**Solution**:

- Use cloud provider-specific benchmarks
- Understand shared responsibility model
- Focus on controls you manage

### 3. False Positives

**Problem**: kube-bench may report failures for correctly configured systems.

**Solution**:

- Understand the check's purpose
- Verify manually if needed
- Configure kube-bench exceptions

### 4. Ignoring WARN Results

**Problem**: Focusing only on FAIL and ignoring WARN items.

**Solution**:

- Review all WARN items
- Many require manual verification
- May indicate real issues

## Key Points to Remember

1. CIS Benchmarks are industry-standard security recommendations.
1. kube-bench automates benchmark checking.
1. Not all recommendations apply to every environment.
1. Prioritize remediation based on risk and impact.
1. Test changes in non-production environments first.
1. Regular audits catch configuration drift.
1. Document exceptions and accepted risks.
1. Cloud providers handle some controls differently.
1. Use version-appropriate benchmarks.
1. Combine with other security practices (PSS, RBAC, Network Policies).

## Study Resources

### Official Documentation

- [CIS Kubernetes Benchmarks](https://www.cisecurity.org/benchmark/kubernetes)
- [kube-bench GitHub](https://github.com/aquasecurity/kube-bench)
- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/)

### Tools

- [kube-bench](https://github.com/aquasecurity/kube-bench)
- [kube-hunter](https://github.com/aquasecurity/kube-hunter)
- [kubesec](https://kubesec.io/)

### Additional Reading

- [NSA/CISA Kubernetes Hardening Guide](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/)
- [NIST Application Container Security Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)

## Next Steps

1. Complete the [CIS Benchmarks Lab](../../labs/01-cluster-setup/lab-02-cis-benchmarks.md)
1. Run kube-bench on a practice cluster
1. Practice interpreting and remediating findings
1. Learn about [Ingress and Service Security](./ingress-service-security.md) next

## Quick Reference

### kube-bench Commands

```bash

# Run all checks

kube-bench

# Run only master checks

kube-bench master

# Run only node checks

kube-bench node

# Output to JSON

kube-bench --json

# Specific version

kube-bench --version 1.30

# Run as Kubernetes Job

kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs job/kube-bench

# Run on specific node

kubectl apply -f node-job.yaml
```

```

### Common File Locations

```bash

# API Server

/etc/kubernetes/manifests/kube-apiserver.yaml

# Controller Manager

/etc/kubernetes/manifests/kube-controller-manager.yaml

# Scheduler

/etc/kubernetes/manifests/kube-scheduler.yaml

# etcd

/etc/kubernetes/manifests/etcd.yaml

# kubelet Config

/var/lib/kubelet/config.yaml

# kubelet Service

/etc/systemd/system/kubelet.service.d/10-kubeadm.conf
```

```

---

[← Previous: Network Policies](./network-policies.md) | [Back to Domain 1 README](./README.md) | [Next: Ingress Security →](./ingress-service-security.md)
