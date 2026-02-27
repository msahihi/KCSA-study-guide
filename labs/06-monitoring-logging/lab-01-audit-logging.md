# Lab 1: Audit Logging Configuration

## Objectives

By the end of this lab, you will:

- Enable Kubernetes audit logging on the API server
- Create custom audit policies for different security scenarios
- Analyze audit logs to identify security events
- Use jq to efficiently query audit logs
- Understand audit policy precedence and optimization

**Duration**: 60 minutes

**Difficulty**: Intermediate

## Prerequisites

- Running Kubernetes cluster (v1.30.x)
- Access to control plane node (for kubeadm clusters)
- kubectl configured with cluster-admin privileges
- jq installed (`sudo apt-get install jq` or `brew install jq`)
- Basic understanding of YAML and JSON

## Lab Environment

This lab assumes a kubeadm-deployed cluster where you can access the control plane node and modify API server configuration.

## Part 1: Enable Basic Audit Logging (15 minutes)

### Step 1: Create Audit Policy File

SSH to your control plane node and create an audit policy:

```bash
# SSH to control plane node
ssh user@control-plane-node

# Create audit policy directory
sudo mkdir -p /etc/kubernetes/audit

# Create basic audit policy
sudo tee /etc/kubernetes/audit/policy.yaml <<EOF
apiVersion: audit.k8s.io/v1
kind: Policy
# Don't log requests to the following
omitStages:
  - "RequestReceived"
rules:
  # Log everything at Metadata level
  - level: Metadata
EOF
```

### Step 2: Configure API Server

Modify the API server manifest to enable audit logging:

```bash
# Backup original API server manifest
sudo cp /etc/kubernetes/manifests/kube-apiserver.yaml \
     /etc/kubernetes/kube-apiserver.yaml.backup

# Edit API server manifest
sudo vi /etc/kubernetes/manifests/kube-apiserver.yaml
```

Add these flags to the `command` section:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - command:
    - kube-apiserver
    # ... existing flags ...

    # ADD THESE AUDIT FLAGS:
    - --audit-policy-file=/etc/kubernetes/audit/policy.yaml
    - --audit-log-path=/var/log/kubernetes/audit.log
    - --audit-log-maxage=30
    - --audit-log-maxbackup=10
    - --audit-log-maxsize=100

    # ... other flags ...

    volumeMounts:
    # ... existing mounts ...

    # ADD THESE VOLUME MOUNTS:
    - mountPath: /etc/kubernetes/audit
      name: audit-policy
      readOnly: true
    - mountPath: /var/log/kubernetes
      name: audit-logs

  volumes:
  # ... existing volumes ...

  # ADD THESE VOLUMES:
  - name: audit-policy
    hostPath:
      path: /etc/kubernetes/audit
      type: DirectoryOrCreate
  - name: audit-logs
    hostPath:
      path: /var/log/kubernetes
      type: DirectoryOrCreate
```

### Step 3: Wait for API Server Restart

```bash
# Watch API server pod restart
kubectl get pods -n kube-system -w | grep kube-apiserver

# Or watch API server logs
sudo tail -f /var/log/pods/kube-system_kube-apiserver-*/kube-apiserver/*.log
```

**Expected**: API server should restart within 30-60 seconds.

### Step 4: Verify Audit Logging

```bash
# Check if audit log file exists
sudo ls -lh /var/log/kubernetes/audit.log

# View recent audit entries
sudo tail /var/log/kubernetes/audit.log | jq

# Trigger some API activity
kubectl get pods -A
kubectl get nodes

# Check audit log captured these requests
sudo tail -20 /var/log/kubernetes/audit.log | jq -r '.requestURI'
```

**Expected Output**:
```
/api/v1/pods?limit=500
/api/v1/nodes?limit=500
```

**Verification**:
- [ ] Audit log file exists at `/var/log/kubernetes/audit.log`
- [ ] API server is running (check with `kubectl get pods -n kube-system`)
- [ ] Audit entries are being written (check file growth with `ls -lh`)
- [ ] Audit entries are valid JSON (can be parsed with `jq`)

## Part 2: Create Security-Focused Audit Policy (20 minutes)

### Step 5: Write Comprehensive Audit Policy

Create a more sophisticated audit policy:

```bash
sudo tee /etc/kubernetes/audit/policy.yaml <<'EOF'
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages:
  - "RequestReceived"

rules:
  # 1. Don't log read-only requests to non-sensitive resources
  - level: None
    verbs: ["get", "list", "watch"]
    resources:
    - group: ""
      resources: ["endpoints", "services", "configmaps"]

  # 2. Don't log health checks
  - level: None
    users: ["system:kube-proxy"]
    verbs: ["watch"]
    resources:
    - group: ""
      resources: ["endpoints", "services"]

  # 3. Don't log controller manager and scheduler
  - level: None
    users:
    - system:kube-controller-manager
    - system:kube-scheduler
    - system:serviceaccount:kube-system:generic-garbage-collector

  # 4. Log secret access with full request and response
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["secrets"]

  # 5. Log pod exec, attach, portforward at Request level
  - level: Request
    verbs: ["create"]
    resources:
    - group: ""
      resources: ["pods/exec", "pods/attach", "pods/portforward"]

  # 6. Log all RBAC changes with full details
  - level: RequestResponse
    verbs: ["create", "update", "patch", "delete"]
    resources:
    - group: "rbac.authorization.k8s.io"
      resources: ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]

  # 7. Log security-sensitive resource modifications
  - level: Request
    verbs: ["create", "update", "patch", "delete"]
    resources:
    - group: ""
      resources: ["pods", "services", "serviceaccounts"]
    - group: "apps"
      resources: ["deployments", "daemonsets", "statefulsets"]
    - group: "networking.k8s.io"
      resources: ["networkpolicies"]

  # 8. Log authentication and authorization events
  - level: Metadata
    resources:
    - group: "authentication.k8s.io"
      resources: ["tokenreviews"]
    - group: "authorization.k8s.io"
      resources: ["subjectaccessreviews"]

  # 9. Catch-all: log everything else at Metadata level
  - level: Metadata
    omitStages:
    - "RequestReceived"
EOF
```

**Explanation of Policy Rules**:

| Rule | Purpose | Level |
|------|---------|-------|
| #1-3 | Reduce noise from routine operations | None |
| #4 | Track all secret access (critical) | RequestResponse |
| #5 | Track interactive pod access | Request |
| #6 | Track permission changes (compliance) | RequestResponse |
| #7 | Track workload modifications | Request |
| #8 | Track auth events | Metadata |
| #9 | Catch everything else | Metadata |

### Step 6: Apply Updated Policy

The API server will automatically reload the policy within 30 seconds. Verify:

```bash
# Check API server logs for policy reload
sudo tail -50 /var/log/pods/kube-system_kube-apiserver-*/kube-apiserver/*.log | grep audit

# Generate test activity
kubectl get secrets -n kube-system
kubectl get pods
kubectl exec -it <any-pod> -- echo "test"  # If you have a running pod
```

### Step 7: Verify Policy Effectiveness

```bash
# Test 1: Verify secrets are logged at RequestResponse level
kubectl get secrets -n kube-system
sudo tail -50 /var/log/kubernetes/audit.log | jq 'select(.objectRef.resource=="secrets") | {level, verb, name: .objectRef.name}'

# Expected: level = "RequestResponse"

# Test 2: Verify regular pod list is logged at Metadata level
kubectl get pods
sudo tail -50 /var/log/kubernetes/audit.log | jq 'select(.objectRef.resource=="pods" and .verb=="list") | {level, verb}'

# Expected: level = "Metadata"

# Test 3: Check log file size (should be smaller than before)
sudo ls -lh /var/log/kubernetes/audit.log
```

**Verification**:
- [ ] Secret access logged at RequestResponse level
- [ ] Pod exec logged at Request level
- [ ] Regular operations logged at Metadata level
- [ ] Log file is not growing excessively

## Part 3: Analyze Audit Logs (25 minutes)

### Step 8: Generate Diverse Audit Events

Create various security-relevant activities:

```bash
# Create test namespace
kubectl create namespace audit-test

# Create a secret (should log at RequestResponse)
kubectl create secret generic test-secret \
  --from-literal=password=supersecret \
  -n audit-test

# Read the secret
kubectl get secret test-secret -n audit-test -o yaml

# Create a privileged pod (should log at Request)
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
  namespace: audit-test
spec:
  containers:
  - name: nginx
    image: nginx:1.27
    securityContext:
      privileged: true
EOF

# Wait for pod to be ready
kubectl wait --for=condition=Ready pod/privileged-pod -n audit-test --timeout=60s

# Exec into pod (should log at Request)
kubectl exec -it privileged-pod -n audit-test -- whoami

# Create RBAC role (should log at RequestResponse)
kubectl create role pod-reader \
  --verb=get,list \
  --resource=pods \
  -n audit-test

# Generate failed authentication (try invalid token)
curl -k https://$(kubectl cluster-info | grep "Kubernetes control plane" | awk '{print $7}')/api/v1/namespaces \
  -H "Authorization: Bearer invalid-token"
```

### Step 9: Query Audit Logs with jq

**Query 1: Find All Secret Access**

```bash
sudo cat /var/log/kubernetes/audit.log | \
  jq 'select(.objectRef.resource=="secrets") |
      {time: .requestReceivedTimestamp,
       user: .user.username,
       verb: .verb,
       name: .objectRef.name,
       namespace: .objectRef.namespace}'
```

**Expected Output**:
```json
{
  "time": "2024-01-15T10:30:00.123456Z",
  "user": "kubernetes-admin",
  "verb": "create",
  "name": "test-secret",
  "namespace": "audit-test"
}
```

**Query 2: Find Pod Exec Events**

```bash
sudo cat /var/log/kubernetes/audit.log | \
  jq 'select(.objectRef.resource=="pods" and .objectRef.subresource=="exec") |
      {time: .requestReceivedTimestamp,
       user: .user.username,
       pod: .objectRef.name,
       namespace: .objectRef.namespace,
       command: .requestURI}'
```

**Query 3: Find Failed Authentication Attempts**

```bash
sudo cat /var/log/kubernetes/audit.log | \
  jq 'select(.responseStatus.code >= 400 and
             .objectRef.resource=="tokenreviews") |
      {time: .requestReceivedTimestamp,
       user: .user.username,
       code: .responseStatus.code,
       source: .sourceIPs[0]}'
```

**Query 4: Find Privileged Pod Creation**

```bash
sudo cat /var/log/kubernetes/audit.log | \
  jq 'select(.verb=="create" and
             .objectRef.resource=="pods" and
             .requestObject.spec.containers[].securityContext.privileged==true) |
      {time: .requestReceivedTimestamp,
       user: .user.username,
       pod: .objectRef.name,
       namespace: .objectRef.namespace}'
```

**Query 5: Find RBAC Changes**

```bash
sudo cat /var/log/kubernetes/audit.log | \
  jq 'select(.objectRef.apiGroup=="rbac.authorization.k8s.io" and
             (.verb=="create" or .verb=="update" or .verb=="delete")) |
      {time: .requestReceivedTimestamp,
       user: .user.username,
       verb: .verb,
       resource: .objectRef.resource,
       name: .objectRef.name}'
```

**Query 6: Top 10 Most Active Users**

```bash
sudo cat /var/log/kubernetes/audit.log | \
  jq -r '.user.username' | \
  sort | uniq -c | sort -rn | head -10
```

**Query 7: API Request Rate by Hour**

```bash
sudo cat /var/log/kubernetes/audit.log | \
  jq -r '.requestReceivedTimestamp | split("T")[1] | split(":")[0]' | \
  sort | uniq -c
```

**Verification**:
- [ ] Can find secret access events
- [ ] Can identify pod exec operations
- [ ] Can detect failed authentication
- [ ] Can track privileged pod creation
- [ ] Can see RBAC modifications

### Step 10: Create Audit Analysis Script

Create a helper script for common queries:

```bash
cat > ~/audit-analyzer.sh <<'EOF'
#!/bin/bash
# Kubernetes Audit Log Analyzer

AUDIT_LOG="/var/log/kubernetes/audit.log"

case "$1" in
  secrets)
    echo "=== Secret Access Events ==="
    sudo cat $AUDIT_LOG | \
      jq -r 'select(.objectRef.resource=="secrets") |
             "\(.requestReceivedTimestamp) \(.user.username) \(.verb) \(.objectRef.namespace)/\(.objectRef.name)"'
    ;;

  exec)
    echo "=== Pod Exec Events ==="
    sudo cat $AUDIT_LOG | \
      jq -r 'select(.objectRef.subresource=="exec") |
             "\(.requestReceivedTimestamp) \(.user.username) \(.objectRef.namespace)/\(.objectRef.name)"'
    ;;

  failed-auth)
    echo "=== Failed Authentication Attempts ==="
    sudo cat $AUDIT_LOG | \
      jq -r 'select(.responseStatus.code >= 400 and .objectRef.resource=="tokenreviews") |
             "\(.requestReceivedTimestamp) \(.user.username) \(.responseStatus.code) \(.sourceIPs[0])"'
    ;;

  privileged)
    echo "=== Privileged Pod Creation ==="
    sudo cat $AUDIT_LOG | \
      jq -r 'select(.verb=="create" and .objectRef.resource=="pods" and
                    .requestObject.spec.containers[].securityContext.privileged==true) |
             "\(.requestReceivedTimestamp) \(.user.username) \(.objectRef.namespace)/\(.objectRef.name)"'
    ;;

  rbac)
    echo "=== RBAC Changes ==="
    sudo cat $AUDIT_LOG | \
      jq -r 'select(.objectRef.apiGroup=="rbac.authorization.k8s.io") |
             "\(.requestReceivedTimestamp) \(.user.username) \(.verb) \(.objectRef.resource) \(.objectRef.name)"'
    ;;

  stats)
    echo "=== Audit Log Statistics ==="
    echo "Total events: $(sudo cat $AUDIT_LOG | wc -l)"
    echo ""
    echo "Top 10 users:"
    sudo cat $AUDIT_LOG | jq -r '.user.username' | sort | uniq -c | sort -rn | head -10
    echo ""
    echo "Events by verb:"
    sudo cat $AUDIT_LOG | jq -r '.verb' | sort | uniq -c | sort -rn
    ;;

  *)
    echo "Usage: $0 {secrets|exec|failed-auth|privileged|rbac|stats}"
    echo ""
    echo "  secrets      - Show secret access events"
    echo "  exec         - Show pod exec events"
    echo "  failed-auth  - Show failed authentication"
    echo "  privileged   - Show privileged pod creation"
    echo "  rbac         - Show RBAC changes"
    echo "  stats        - Show general statistics"
    exit 1
    ;;
esac
EOF

chmod +x ~/audit-analyzer.sh
```

Test the script:

```bash
# Show statistics
~/audit-analyzer.sh stats

# Show secret access
~/audit-analyzer.sh secrets

# Show exec events
~/audit-analyzer.sh exec
```

**Verification**:
- [ ] Script executes without errors
- [ ] Can quickly query different event types
- [ ] Output is readable and useful

## Part 4: Advanced Scenarios (Optional)

### Scenario 1: Track Specific User Activity

```bash
# Replace with actual username
USER="kubernetes-admin"

sudo cat /var/log/kubernetes/audit.log | \
  jq --arg user "$USER" \
     'select(.user.username==$user) |
      {time: .requestReceivedTimestamp,
       verb: .verb,
       resource: .objectRef.resource,
       name: .objectRef.name}'
```

### Scenario 2: Find Suspicious After-Hours Activity

```bash
# Find activity between 10 PM and 6 AM
sudo cat /var/log/kubernetes/audit.log | \
  jq 'select(.requestReceivedTimestamp |
             strptime("%Y-%m-%dT%H:%M:%S") |
             .hour < 6 or .hour >= 22) |
      {time: .requestReceivedTimestamp,
       user: .user.username,
       verb: .verb,
       resource: .objectRef.resource}'
```

### Scenario 3: Detect Bulk Secret Reading

```bash
# Find users who read more than 5 secrets in last hour
sudo cat /var/log/kubernetes/audit.log | \
  jq -r 'select(.objectRef.resource=="secrets" and .verb=="get") |
         "\(.user.username)"' | \
  sort | uniq -c | awk '$1 > 5'
```

## Troubleshooting

### Issue 1: API Server Won't Start

**Symptoms**: API server crash loops after enabling audit

**Causes**:
- Invalid YAML in audit policy
- Policy file not found
- Log directory doesn't exist

**Solutions**:

```bash
# Check API server logs
sudo tail -100 /var/log/pods/kube-system_kube-apiserver-*/kube-apiserver/*.log

# Validate policy YAML syntax
cat /etc/kubernetes/audit/policy.yaml | python3 -c "import yaml, sys; yaml.safe_load(sys.stdin)"

# Ensure directories exist
sudo mkdir -p /etc/kubernetes/audit
sudo mkdir -p /var/log/kubernetes

# Restore backup if needed
sudo cp /etc/kubernetes/kube-apiserver.yaml.backup \
     /etc/kubernetes/manifests/kube-apiserver.yaml
```

### Issue 2: No Audit Logs Generated

**Symptoms**: Audit log file is empty or not created

**Causes**:
- Volume mount incorrect
- Path typo in configuration
- Insufficient disk space

**Solutions**:

```bash
# Check volume mounts
kubectl get pod kube-apiserver-<node> -n kube-system -o yaml | grep -A 5 "audit"

# Check disk space
df -h /var/log

# Manually create log file
sudo touch /var/log/kubernetes/audit.log
sudo chmod 600 /var/log/kubernetes/audit.log

# Trigger API activity
kubectl get nodes
```

### Issue 3: Logs Growing Too Fast

**Symptoms**: Disk filling up, log file very large

**Solutions**:

```bash
# Check log size
sudo ls -lh /var/log/kubernetes/audit.log*

# Reduce audit level for noisy resources
# Edit policy: change high-volume resources to None or Metadata level

# Increase rotation frequency
# In API server manifest, reduce --audit-log-maxsize to 50 or 100
```

### Issue 4: Can't Query Logs with jq

**Symptoms**: jq errors or no output

**Solutions**:

```bash
# Install jq if not present
sudo apt-get install jq  # Debian/Ubuntu
brew install jq          # macOS

# Check log format
sudo head -1 /var/log/kubernetes/audit.log

# Ensure log is valid JSON
sudo tail -1 /var/log/kubernetes/audit.log | jq .

# Check for truncated lines (audit log entries can be large)
# Use cat instead of tail for complete lines
```

## Verification Checklist

Before proceeding, verify:

- [ ] API server is running with audit logging enabled
- [ ] Audit log file exists and is growing
- [ ] Can parse audit log with jq
- [ ] Different resources log at appropriate levels
- [ ] Can find secret access events
- [ ] Can identify pod exec operations
- [ ] Can detect privileged pod creation
- [ ] Can track RBAC changes
- [ ] Audit analyzer script works

## Cleanup

```bash
# Remove test resources
kubectl delete namespace audit-test

# Optionally disable audit logging (restore backup)
# sudo cp /etc/kubernetes/kube-apiserver.yaml.backup \
#      /etc/kubernetes/manifests/kube-apiserver.yaml

# Keep audit logging enabled for next labs
```

## Challenge Exercises

1. **Custom Policy**: Write an audit policy that:
   - Logs all write operations at Request level
   - Logs secret access at RequestResponse level
   - Doesn't log read operations
   - Doesn't log system component activity

2. **Compliance Report**: Create a script that generates a daily report of:
   - All secret access (who, when, which secrets)
   - All pod exec operations
   - All RBAC changes
   - All privileged pod creations

3. **Real-time Monitoring**: Write a script that:
   - Tails the audit log in real-time
   - Alerts on critical events (secret access, exec, RBAC changes)
   - Sends notifications to Slack or email

4. **Log Analysis**: Analyze audit logs to answer:
   - Which user is most active?
   - Which namespace has the most changes?
   - What percentage of requests are read vs write?
   - Are there any suspicious patterns?

## Key Takeaways

- Audit logging provides complete API activity record
- Audit policies control what and how much is logged
- Rule order matters - first match wins
- Balance security needs with performance
- jq is essential for efficient log analysis
- Different audit levels serve different purposes
- Logs must be analyzed regularly to be useful

## Next Steps

- Proceed to [Lab 2: Falco Deployment](lab-02-falco-deployment.md)
- Review [Audit Logging theory](../../domains/06-monitoring-logging/audit-logging.md)
- Practice writing audit policies for different scenarios
- Explore audit webhook backend for real-time processing

---

**Congratulations!** You've successfully configured Kubernetes audit logging and learned to analyze security events. This foundation is critical for security monitoring and incident investigation.
