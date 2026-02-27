# Lab 02: CIS Kubernetes Benchmarks

## Objectives

By the end of this lab, you will be able to:

- Install and run kube-bench to audit Kubernetes cluster security
- Interpret kube-bench output and identify security issues
- Prioritize remediation based on severity and impact
- Apply common security fixes to cluster components
- Verify security improvements after remediation
- Document exceptions and accepted risks

## Prerequisites

- Kubernetes cluster v1.30+ with admin access
- kubectl configured with cluster-admin permissions
- SSH access to control plane and worker nodes (for some remediations)
- Basic understanding of Kubernetes architecture
- Familiarity with Linux file permissions and systemd

## Estimated Time

90-120 minutes

## Lab Scenario

You've been tasked with auditing a Kubernetes cluster against industry security standards. Your goals are to:

1. Run a comprehensive security audit using kube-bench
1. Identify critical security misconfigurations
1. Remediate high-priority issues
1. Document findings and improvements
1. Verify the cluster meets baseline security standards

## Important Notes

**Warning**: Some remediations in this lab require modifying cluster components and may cause temporary disruptions. This lab is designed for learning environments, not production clusters.

- Always test in non-production first
- Have a backup plan
- Understand each change before applying
- Some changes require node access

## Exercise 1: Install and Run kube-bench

### Step 1: Understand kube-bench

kube-bench is an open-source tool that checks whether Kubernetes is deployed according to CIS Kubernetes Benchmarks.

**Key Features**:

- Automated security checks
- Based on CIS Benchmarks
- Checks control plane, worker nodes, and policies
- Provides remediation guidance
- Supports multiple Kubernetes versions

### Step 2: Run kube-bench as a Job

This is the easiest method for most clusters.

Create a file named `kube-bench-job.yaml`:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: kube-bench-master
  namespace: default
spec:
  template:
    metadata:
      labels:
        app: kube-bench
    spec:
      hostPID: true
      containers:
      - name: kube-bench
        image: aquasec/kube-bench:v0.7.0
        command: ["kube-bench", "run", "--targets", "master", "--version", "1.30"]
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
      nodeSelector:
        node-role.kubernetes.io/control-plane: ""
      tolerations:
      - key: node-role.kubernetes.io/control-plane
        operator: Exists
        effect: NoSchedule
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

Apply the job:

```bash
kubectl apply -f kube-bench-job.yaml
```

Wait for completion:

```bash
kubectl wait --for=condition=complete job/kube-bench-master --timeout=300s
```

Get the pod name:

```bash
KUBE_BENCH_POD=$(kubectl get pods -l app=kube-bench -o jsonpath='{.items[0].metadata.name}')
echo $KUBE_BENCH_POD
```

View the results:

```bash
kubectl logs $KUBE_BENCH_POD
```

Save results to a file:

```bash
kubectl logs $KUBE_BENCH_POD > kube-bench-master-results.txt
```

### Step 3: Run kube-bench for Worker Nodes

Create a file named `kube-bench-node-job.yaml`:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: kube-bench-node
  namespace: default
spec:
  template:
    metadata:
      labels:
        app: kube-bench-node
    spec:
      hostPID: true
      containers:
      - name: kube-bench
        image: aquasec/kube-bench:v0.7.0
        command: ["kube-bench", "run", "--targets", "node", "--version", "1.30"]
        volumeMounts:
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
      nodeSelector:
        node-role.kubernetes.io/worker: ""
      volumes:
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

**Note**: If your worker nodes don't have the `node-role.kubernetes.io/worker` label, either add it or remove the nodeSelector.

Check node labels:

```bash
kubectl get nodes --show-labels
```

Add worker label if needed:

```bash
kubectl label node <worker-node-name> node-role.kubernetes.io/worker=
```

Apply the job:

```bash
kubectl apply -f kube-bench-node-job.yaml
kubectl wait --for=condition=complete job/kube-bench-node --timeout=300s
```

View and save results:

```bash
KUBE_BENCH_NODE_POD=$(kubectl get pods -l app=kube-bench-node -o jsonpath='{.items[0].metadata.name}')
kubectl logs $KUBE_BENCH_NODE_POD > kube-bench-node-results.txt
```

## Exercise 2: Analyze kube-bench Output

### Step 1: Understand the Output Format

View your saved results:

```bash
cat kube-bench-master-results.txt
```

**Output Structure**:

```
[INFO] 1 Control Plane Security Configuration
[INFO] 1.1 Control Plane Node Configuration Files
[PASS] 1.1.1 Ensure that the API server pod specification file permissions are set to 600 or more restrictive
[FAIL] 1.1.2 Ensure that the API server pod specification file ownership is set to root:root
[WARN] 1.1.3 Ensure that the controller manager pod specification file permissions are set to 600 or more restrictive

== Remediations master ==
1.1.2 Run the below command (based on the file location on your system) on the control plane node.
For example, chown root:root /etc/kubernetes/manifests/kube-apiserver.yaml

== Summary master ==
46 checks PASS
10 checks FAIL
15 checks WARN
0 checks INFO

```

**Status Meanings**:

- **[PASS]**: Check passed - configuration is secure
- **[FAIL]**: Check failed - remediation required
- **[WARN]**: Check couldn't be completed automatically or needs manual verification
- **[INFO]**: Informational message, not a test

### Step 2: Extract Failed Checks

View only failures:

```bash
grep FAIL kube-bench-master-results.txt
```

Count failures:

```bash
grep -c FAIL kube-bench-master-results.txt
```

Create a summary:

```bash
cat > analyze-results.sh << 'EOF'

#!/bin/bash

echo "=== kube-bench Results Summary ==="
echo

if [ -f "kube-bench-master-results.txt" ]; then
    echo "Control Plane Results:"
    grep "checks PASS" kube-bench-master-results.txt
    grep "checks FAIL" kube-bench-master-results.txt
    grep "checks WARN" kube-bench-master-results.txt
    echo
fi

if [ -f "kube-bench-node-results.txt" ]; then
    echo "Worker Node Results:"
    grep "checks PASS" kube-bench-node-results.txt
    grep "checks FAIL" kube-bench-node-results.txt
    grep "checks WARN" kube-bench-node-results.txt
    echo
fi

echo "=== Failed Checks ==="
echo
echo "Control Plane Failures:"
grep FAIL kube-bench-master-results.txt | head -10
echo
echo "Worker Node Failures:"
grep FAIL kube-bench-node-results.txt | head -10

EOF

chmod +x analyze-results.sh
./analyze-results.sh
```

### Step 3: Prioritize Issues

**Critical Priority (Fix Immediately)**:

- Anonymous authentication enabled
- Insecure port enabled
- No authorization configured
- No admission controllers
- Weak RBAC configurations

**High Priority (Fix Soon)**:

- Missing audit logging
- No encryption at rest
- Weak kubelet configuration
- Missing Pod Security Standards

**Medium Priority (Plan Remediation)**:

- File permission issues
- Missing TLS configurations
- Certificate rotation disabled

**Low Priority (Best Practice)**:

- Documentation
- Specific version pinning
- Optional hardening features

Let's create a prioritized list:

```bash
cat > prioritize-findings.sh << 'EOF'

#!/bin/bash

echo "=== Prioritized Security Findings ==="
echo

echo "🔴 CRITICAL (Fix Immediately):"
grep -E "1.2.1|1.2.7|1.2.8|1.2.9|1.2.10" kube-bench-master-results.txt | grep FAIL || echo "  None found - Good!"
echo

echo "🟠 HIGH (Fix Soon):"
grep -E "1.2.11|1.2.12|1.2.22|1.2.23|3.2" kube-bench-master-results.txt | grep FAIL || echo "  None found - Good!"
echo

echo "🟡 MEDIUM (Plan Remediation):"
grep -E "1.1|4.1|4.2" kube-bench-master-results.txt | grep FAIL | head -5 || echo "  None found - Good!"
echo

echo "🟢 LOW (Best Practice):"
grep WARN kube-bench-master-results.txt | head -5
echo

EOF

chmod +x prioritize-findings.sh
./prioritize-findings.sh
```

## Exercise 3: Common Remediations

### Remediation 1: API Server Anonymous Authentication

**Check**: 1.2.1 - Ensure that the --anonymous-auth argument is set to false

**Find if it failed**:

```bash
grep "1.2.1" kube-bench-master-results.txt
```

**If FAIL, remediate**:

```bash
# SSH to control plane node (if needed)
# ssh user@control-plane-node

# Edit API server manifest

sudo vim /etc/kubernetes/manifests/kube-apiserver.yaml
```

Find the `command` section and add or modify:

```yaml
spec:
  containers:
  - command:
    - kube-apiserver
    - --anonymous-auth=false

    # ... other flags

```

Save the file. The API server will automatically restart.

**Verify**:

```bash
# Wait for API server to restart (30-60 seconds)

sleep 60

# Check if flag is present

kubectl get pod kube-apiserver-$(hostname) -n kube-system -o yaml | grep anonymous-auth
```

Expected output: `- --anonymous-auth=false`

### Remediation 2: Audit Logging

**Check**: 1.2.22-1.2.25 - Audit logging configuration

**Find if it failed**:

```bash
grep -E "1.2.22|1.2.23|1.2.24|1.2.25" kube-bench-master-results.txt
```

**If FAIL, remediate**:

1. Create audit policy file:

```bash
sudo mkdir -p /etc/kubernetes/audit

sudo cat > /etc/kubernetes/audit/policy.yaml << 'EOF'
apiVersion: audit.k8s.io/v1
kind: Policy
rules:

# Log all requests at Metadata level

- level: Metadata
  omitStages:
  - RequestReceived

# Don't log these read-only URLs

- level: None
  nonResourceURLs:
  - /healthz*
  - /version
  - /swagger*

# Don't log events, too verbose

- level: None
  resources:
  - group: ""
    resources: ["events"]

# Log secrets, configmaps at Metadata level

- level: Metadata
  resources:
  - group: ""
    resources: ["secrets", "configmaps"]

# Log everything else at Request level

- level: Request
  omitStages:
  - RequestReceived
EOF
```

1. Create log directory:

```bash
sudo mkdir -p /var/log/kubernetes
sudo chmod 755 /var/log/kubernetes
```

1. Edit API server manifest:

```bash
sudo vim /etc/kubernetes/manifests/kube-apiserver.yaml
```

Add to `command` section:

```yaml
spec:
  containers:
  - command:
    - kube-apiserver
    - --audit-policy-file=/etc/kubernetes/audit/policy.yaml
    - --audit-log-path=/var/log/kubernetes/audit.log
    - --audit-log-maxage=30
    - --audit-log-maxbackup=10
    - --audit-log-maxsize=100

    # ... other flags

```

Add volume mounts:

```yaml
    volumeMounts:
    - mountPath: /etc/kubernetes/audit
      name: audit-policy
      readOnly: true
    - mountPath: /var/log/kubernetes
      name: audit-log

    # ... other mounts

```

Add volumes:

```yaml
  volumes:
  - hostPath:
      path: /etc/kubernetes/audit
      type: DirectoryOrCreate
    name: audit-policy
  - hostPath:
      path: /var/log/kubernetes
      type: DirectoryOrCreate
    name: audit-log

  # ... other volumes

```

1. Verify:

```bash
# Wait for API server to restart

sleep 60

# Check if audit log is being written

sudo ls -lh /var/log/kubernetes/
sudo tail -f /var/log/kubernetes/audit.log
```

### Remediation 3: kubelet Anonymous Authentication

**Check**: 4.2.1 - Ensure that the --anonymous-auth argument is set to false

**Find if it failed**:

```bash
grep "4.2.1" kube-bench-node-results.txt
```

**If FAIL, remediate**:

```bash
# On each worker node
# Edit kubelet configuration

sudo vim /var/lib/kubelet/config.yaml
```

Add or modify:

```yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
authorization:
  mode: Webhook
```

Restart kubelet:

```bash
sudo systemctl restart kubelet
```

Verify:

```bash
sudo systemctl status kubelet
kubectl get nodes  # Should still show Ready
```

### Remediation 4: kubelet Read-Only Port

**Check**: 4.2.4 - Ensure that the --read-only-port argument is set to 0

**Find if it failed**:

```bash
grep "4.2.4" kube-bench-node-results.txt
```

**If FAIL, remediate**:

```bash
sudo vim /var/lib/kubelet/config.yaml
```

Add or modify:

```yaml
readOnlyPort: 0
```

Restart kubelet:

```bash
sudo systemctl restart kubelet
```

Verify:

```bash
# This should fail (port closed)

curl http://localhost:10255/metrics
```

### Remediation 5: File Permissions

**Check**: 1.1.X - File permission checks

**Find failed file permission checks**:

```bash
grep "1.1" kube-bench-master-results.txt | grep FAIL
```

**Common fixes**:

```bash
# API server manifest

sudo chmod 600 /etc/kubernetes/manifests/kube-apiserver.yaml
sudo chown root:root /etc/kubernetes/manifests/kube-apiserver.yaml

# Controller manager manifest

sudo chmod 600 /etc/kubernetes/manifests/kube-controller-manager.yaml
sudo chown root:root /etc/kubernetes/manifests/kube-controller-manager.yaml

# Scheduler manifest

sudo chmod 600 /etc/kubernetes/manifests/kube-scheduler.yaml
sudo chown root:root /etc/kubernetes/manifests/kube-scheduler.yaml

# etcd manifest

sudo chmod 600 /etc/kubernetes/manifests/etcd.yaml
sudo chown root:root /etc/kubernetes/manifests/etcd.yaml

# PKI directory

sudo chmod -R 600 /etc/kubernetes/pki/*
sudo chmod 700 /etc/kubernetes/pki

# Admin config

sudo chmod 600 /etc/kubernetes/admin.conf
sudo chown root:root /etc/kubernetes/admin.conf

# kubelet config

sudo chmod 600 /var/lib/kubelet/config.yaml
sudo chown root:root /var/lib/kubelet/config.yaml
```

Verify:

```bash
ls -la /etc/kubernetes/manifests/
ls -la /etc/kubernetes/pki/ | head
ls -la /etc/kubernetes/admin.conf
```

## Exercise 4: Policy-Based Remediations

### Remediation 6: Pod Security Standards

**Check**: 5.2.X - Pod Security Standards

**Remediate**:

1. Label production namespaces:

```bash
# Create test namespace

kubectl create namespace prod-apps

# Apply baseline enforcement

kubectl label namespace prod-apps \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted

# Verify

kubectl get namespace prod-apps -o yaml | grep pod-security
```

1. Test the policy:

```bash
# This should fail (privileged)

cat > test-privileged.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
  namespace: prod-apps
spec:
  containers:
  - name: test
    image: nginx
    securityContext:
      privileged: true
EOF

kubectl apply -f test-privileged.yaml
```

Expected: Error about baseline policy violation

1. Create compliant pod:

```bash
cat > test-compliant.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: compliant-pod
  namespace: prod-apps
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: nginx
    image: nginx:1.26
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
EOF

kubectl apply -f test-compliant.yaml
```

Expected: Success (with possible warnings)

### Remediation 7: Network Policies

**Check**: 5.3.2 - Ensure that all Namespaces have Network Policies defined

**Remediate**:

```bash
# Apply default deny to production namespace

cat > default-deny-netpol.yaml << EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: prod-apps
spec:
  podSelector: {}
  policyTypes:
  - Ingress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: prod-apps
spec:
  podSelector: {}
  policyTypes:
  - Egress
EOF

kubectl apply -f default-deny-netpol.yaml
```

Verify:

```bash
kubectl get networkpolicies -n prod-apps
```

## Exercise 5: Verify Improvements

### Step 1: Run kube-bench Again

Delete old jobs:

```bash
kubectl delete job kube-bench-master kube-bench-node
```

Run new scans:

```bash
kubectl apply -f kube-bench-job.yaml
kubectl wait --for=condition=complete job/kube-bench-master --timeout=300s

KUBE_BENCH_POD=$(kubectl get pods -l app=kube-bench -o jsonpath='{.items[0].metadata.name}')
kubectl logs $KUBE_BENCH_POD > kube-bench-master-results-after.txt
```

### Step 2: Compare Results

```bash
cat > compare-results.sh << 'EOF'

#!/bin/bash

echo "=== Before vs After Comparison ==="
echo

if [ ! -f "kube-bench-master-results.txt" ] || [ ! -f "kube-bench-master-results-after.txt" ]; then
    echo "Error: Missing results files"
    exit 1
fi

BEFORE_FAIL=$(grep -c "checks FAIL" kube-bench-master-results.txt)
AFTER_FAIL=$(grep -c "checks FAIL" kube-bench-master-results-after.txt)

BEFORE_PASS=$(grep -c "checks PASS" kube-bench-master-results.txt)
AFTER_PASS=$(grep -c "checks PASS" kube-bench-master-results-after.txt)

echo "Failed Checks:"
echo "  Before: $BEFORE_FAIL"
echo "  After:  $AFTER_FAIL"
echo "  Improvement: $((BEFORE_FAIL - AFTER_FAIL))"
echo

echo "Passed Checks:"
echo "  Before: $BEFORE_PASS"
echo "  After:  $AFTER_PASS"
echo "  Improvement: $((AFTER_PASS - BEFORE_PASS))"
echo

echo "=== Remaining Failures ==="
grep FAIL kube-bench-master-results-after.txt

EOF

chmod +x compare-results.sh
./compare-results.sh
```

### Step 3: Document Exceptions

For remaining failures, document why they're acceptable (if they are):

```bash
cat > exceptions.md << 'EOF'

# Security Audit Exceptions

## Date: YYYY-MM-DD
## Auditor: Your Name

### Accepted Exceptions

#### 1. Check ID: X.X.X

- **Description**: [What the check is]
- **Status**: FAIL
- **Reason for Exception**: [Why this is acceptable]
- **Compensating Controls**: [What else is in place]
- **Approved By**: [Who approved this]
- **Review Date**: [When to review again]

#### 2. Check ID: X.X.X

- **Description**: [What the check is]
- **Status**: FAIL
- **Reason for Exception**: Cloud provider managed
- **Compensating Controls**: N/A - Provider responsibility
- **Approved By**: [Who approved this]
- **Review Date**: [When to review again]

EOF

echo "Edit exceptions.md to document your findings"
```

## Exercise 6: Automate Regular Audits

### Step 1: Create CronJob for Regular Scans

```yaml
cat > kube-bench-cronjob.yaml << 'EOF'
apiVersion: batch/v1
kind: CronJob
metadata:
  name: kube-bench-audit
  namespace: default
spec:
  schedule: "0 2 * * 0"  # Every Sunday at 2 AM
  jobTemplate:
    spec:
      template:
        metadata:
          labels:
            app: kube-bench-audit
        spec:
          hostPID: true
          containers:
          - name: kube-bench
            image: aquasec/kube-bench:v0.7.0
            command: ["kube-bench", "run", "--targets", "master,node", "--version", "1.30"]
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
          nodeSelector:
            node-role.kubernetes.io/control-plane: ""
          tolerations:
          - key: node-role.kubernetes.io/control-plane
            operator: Exists
            effect: NoSchedule
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
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 1
EOF

kubectl apply -f kube-bench-cronjob.yaml
```

Verify CronJob:

```bash
kubectl get cronjob kube-bench-audit
```

### Step 2: Test CronJob

Manually trigger:

```bash
kubectl create job --from=cronjob/kube-bench-audit kube-bench-manual-test
kubectl wait --for=condition=complete job/kube-bench-manual-test --timeout=300s
kubectl logs job/kube-bench-manual-test
```

## Challenge Questions

1. **What's the difference between a FAIL and a WARN in kube-bench output?**
   <details>
   <summary>Click to see answer</summary>
   FAIL indicates a definite security misconfiguration that can be automatically detected. WARN indicates a check that couldn't be completed automatically and requires manual verification, or where the context determines if it's an issue.
   </details>

1. **Why might some security checks fail in managed Kubernetes services (EKS, GKE, AKS)?**
   <details>
   <summary>Click to see answer</summary>
   Cloud providers manage control plane components, and you don't have access to modify them. Some checks will fail because they're evaluated differently by the provider, or the provider handles security differently. Always refer to cloud provider-specific CIS benchmarks.
   </details>

1. **Is it safe to set --anonymous-auth=false on the API server?**
   <details>
   <summary>Click to see answer</summary>
   Yes, in most cases. However, some integrations might rely on anonymous auth for health checks. Test thoroughly before applying to production. Most modern setups use proper authentication.
   </details>

1. **Why is audit logging important even if you have other logging solutions?**
   <details>
   <summary>Click to see answer</summary>
   API server audit logs provide a security-specific view of who did what in the cluster. They're essential for:
   - Security investigations
   - Compliance requirements
   - Detecting unauthorized access
   - Understanding security incidents
   Unlike application logs, audit logs focus on cluster-level actions and authentication/authorization events.
   </details>

1. **How often should you run kube-bench audits?**
   <details>
   <summary>Click to see answer</summary>
   Best practices:
   - Initial audit: Before production use
   - Regular audits: Weekly or monthly (automated)
   - Change audits: After any cluster configuration changes
   - Compliance audits: As required by your compliance framework (quarterly, annually, etc.)
   </details>

## Troubleshooting

### Issue: kube-bench Job Failing

**Symptoms**: Job fails to complete or no output

**Solutions**:

1. Check pod status:

   ```bash
   kubectl get pods -l app=kube-bench
   kubectl describe pod <kube-bench-pod>

   ```

1. Check logs:

   ```bash
   kubectl logs <kube-bench-pod>

   ```

1. Verify volume mounts exist on node:

   ```bash
   ls -la /etc/kubernetes/manifests
   ls -la /var/lib/kubelet

   ```

### Issue: API Server Won't Restart After Changes

**Symptoms**: API server pod in Error or CrashLoopBackOff state

**Solutions**:

1. Check API server logs:

   ```bash
   kubectl logs -n kube-system kube-apiserver-<node-name> --previous

   ```

1. Verify YAML syntax:

   ```bash
   sudo cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep -A 5 "audit"

   ```

1. Check for typos in flags

1. Rollback the change:

   ```bash
   sudo cp /etc/kubernetes/manifests/kube-apiserver.yaml.backup /etc/kubernetes/manifests/kube-apiserver.yaml

   ```

### Issue: Permission Denied When Editing Files

**Symptoms**: Cannot save changes to manifests

**Solutions**:

1. Use sudo:

   ```bash
   sudo vim /etc/kubernetes/manifests/kube-apiserver.yaml

   ```

1. Check if you're on the correct node (control plane)

1. Verify you have SSH access to the node

## Cleanup

```bash
# Delete test resources

kubectl delete namespace prod-apps
kubectl delete job kube-bench-master kube-bench-node kube-bench-manual-test
kubectl delete cronjob kube-bench-audit

# Remove local files

rm -f kube-bench-*.yaml
rm -f kube-bench-*-results*.txt
rm -f analyze-results.sh compare-results.sh prioritize-findings.sh
rm -f test-*.yaml
rm -f default-deny-netpol.yaml
rm -f exceptions.md
```

**Note**: Don't rollback the security improvements you've made! Keep those in place.

## Key Takeaways

1. kube-bench automates CIS Kubernetes Benchmark audits
1. Not all failures require immediate action - prioritize based on risk
1. Always test remediations in non-production first
1. Some checks don't apply to managed Kubernetes services
1. Document exceptions and accepted risks
1. Automate regular audits with CronJobs
1. Audit logs are essential for security investigations
1. File permissions on manifests prevent unauthorized modifications
1. kubelet security is as important as control plane security
1. Security is ongoing - regular audits catch configuration drift

## Next Steps

1. Review [CIS Benchmarks concept documentation](../../../domains/01-cluster-setup/cis-benchmarks.md)
1. Read the full [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
1. Proceed to [Lab 03: Ingress Security](./lab-03-ingress-security.md)

---

[← Previous Lab: Network Policies](./lab-01-network-policies.md) | [Back to Lab Overview](./README.md) | [Next Lab: Ingress Security →](./lab-03-ingress-security.md)
