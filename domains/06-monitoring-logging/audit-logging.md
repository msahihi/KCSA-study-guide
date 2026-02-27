# Audit Logging

## Introduction

Kubernetes audit logging provides a security-relevant, chronological set of records documenting the sequence of actions in a cluster. Audit logs answer the questions: who did what, when, and from where?

**Why Audit Logging Matters**:

- **Compliance**: Required for SOC 2, PCI-DSS, HIPAA, and other regulations
- **Forensics**: Essential for investigating security incidents
- **Detection**: Identifies unauthorized or suspicious activity
- **Accountability**: Tracks user and service account actions
- **Change Tracking**: Records all configuration changes
- **Debugging**: Helps understand API interactions

## Audit Architecture

### How Audit Logging Works

```
┌─────────────────────────────────────────────────────────┐
│                    API Request Flow                      │
└─────────────────────────────────────────────────────────┘

    kubectl/client
         │
         ▼
    ┌────────────────┐
    │  API Server    │
    │                │
    │  1. Receive    │──┐
    │     Request    │  │
    │                │  │  ┌──────────────────┐
    │  2. Auth &     │  │  │  Audit Policy    │
    │     Authz      │  ├─▶│  (What to log)   │
    │                │  │  └──────────────────┘
    │  3. Admission  │  │
    │     Control    │  │  ┌──────────────────┐
    │                │  │  │  Audit Backends  │
    │  4. Persist    │  └─▶│  (Where to log)  │
    │     to etcd    │     │  - Log file      │
    │                │     │  - Webhook       │
    │  5. Response   │     │  - Dynamic       │
    └────────────────┘     └──────────────────┘
         │
         ▼
    Success/Error
```

### Audit Processing Stages

Each API request goes through multiple stages, and you can choose which stages to log:

| Stage | Description | When It Occurs | Use Case |
|-------|-------------|----------------|----------|
| **RequestReceived** | Raw request received | As soon as headers processed | Detect all attempts (including auth failures) |
| **ResponseStarted** | Response headers sent | After request processing begins | Long-running requests (watch, exec) |
| **ResponseComplete** | Response body sent | After full response delivered | Complete request/response capture |
| **Panic** | Internal server error | When API server panics | Error investigation |

**Important**: A single request can generate multiple audit events (one per stage).

### Audit Levels

Audit levels control how much information is logged:

| Level | Information Logged | Size Impact | Use Cases |
|-------|-------------------|-------------|-----------|
| **None** | Nothing | No impact | Exclude noisy, non-sensitive endpoints |
| **Metadata** | Request metadata (user, timestamp, resource, verb) | Small | General activity tracking |
| **Request** | Metadata + request body | Medium | Track what users create/modify |
| **RequestResponse** | Metadata + request + response | Large | Complete audit trail, secret access |

**Example of each level**:

```yaml
# None - nothing logged
- level: None
  resources:
  - group: ""
    resources: ["endpoints"]
  verbs: ["watch"]

# Metadata - who/what/when only
- level: Metadata
  resources:
  - group: ""
    resources: ["pods"]
  verbs: ["get", "list"]

# Request - includes request body
- level: Request
  resources:
  - group: ""
    resources: ["configmaps"]
  verbs: ["create", "update"]

# RequestResponse - includes everything
- level: RequestResponse
  resources:
  - group: ""
    resources: ["secrets"]
```

## Configuring Audit Logging

### Audit Policy File

The audit policy defines what gets logged. Create a policy file:

```yaml
# /etc/kubernetes/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
# Don't log RequestReceived stage (too noisy)
omitStages:
  - "RequestReceived"

rules:
  # 1. Log secret access with full details
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["secrets"]

  # 2. Log pod exec/attach/portforward
  - level: Metadata
    resources:
    - group: ""
      resources: ["pods/exec", "pods/attach", "pods/portforward"]

  # 3. Log RBAC changes
  - level: RequestResponse
    verbs: ["create", "update", "patch", "delete"]
    resources:
    - group: "rbac.authorization.k8s.io"
      resources: ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]

  # 4. Log security-sensitive resource modifications
  - level: Request
    verbs: ["create", "update", "patch", "delete"]
    resources:
    - group: ""
      resources: ["pods", "services", "serviceaccounts"]
    - group: "apps"
      resources: ["deployments", "daemonsets", "statefulsets"]
    - group: "networking.k8s.io"
      resources: ["networkpolicies"]

  # 5. Log authentication decisions
  - level: Metadata
    resources:
    - group: "authentication.k8s.io"
      resources: ["tokenreviews"]

  # 6. Catch-all for metadata
  - level: Metadata
    omitStages:
    - "RequestReceived"
```

### Policy Rule Precedence

**CRITICAL**: Rules are evaluated from top to bottom, and the **first match wins**.

```yaml
rules:
  # This rule will match secrets in kube-system
  - level: None
    namespaces: ["kube-system"]
    resources:
    - group: ""
      resources: ["secrets"]

  # This rule will NEVER match secrets in kube-system
  # because the rule above matched first
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["secrets"]
```

**Best Practice**: Order rules from most specific to least specific.

### API Server Configuration

Enable audit logging in the API server (kubeadm clusters):

```yaml
# /etc/kubernetes/manifests/kube-apiserver.yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - name: kube-apiserver
    image: registry.k8s.io/kube-apiserver:v1.30.0
    command:
    - kube-apiserver
    # ... other flags ...

    # Audit policy file
    - --audit-policy-file=/etc/kubernetes/audit-policy.yaml

    # Log backend (choose one or more)
    - --audit-log-path=/var/log/kubernetes/audit.log
    - --audit-log-maxage=30
    - --audit-log-maxbackup=10
    - --audit-log-maxsize=100

    # Optional: webhook backend
    # - --audit-webhook-config-file=/etc/kubernetes/audit-webhook.yaml
    # - --audit-webhook-batch-max-wait=5s

    volumeMounts:
    # Mount the policy file
    - mountPath: /etc/kubernetes/audit-policy.yaml
      name: audit-policy
      readOnly: true
    # Mount the log directory
    - mountPath: /var/log/kubernetes
      name: audit-logs

  volumes:
  - name: audit-policy
    hostPath:
      path: /etc/kubernetes/audit-policy.yaml
      type: File
  - name: audit-logs
    hostPath:
      path: /var/log/kubernetes
      type: DirectoryOrCreate
```

### Audit Backends

Kubernetes supports three audit backends:

#### 1. Log Backend (File)

Writes audit events to a log file on the API server host.

**Pros**: Simple, no dependencies
**Cons**: Must manage log rotation, limited to single file

```bash
# API server flags
--audit-log-path=/var/log/kubernetes/audit.log
--audit-log-maxage=30        # Keep logs for 30 days
--audit-log-maxbackup=10     # Keep 10 backup files
--audit-log-maxsize=100      # Rotate after 100 MB
```

#### 2. Webhook Backend

Sends audit events to an external HTTP API.

**Pros**: Real-time processing, centralized collection
**Cons**: Requires external service, can impact API server performance

```yaml
# /etc/kubernetes/audit-webhook.yaml
apiVersion: v1
kind: Config
clusters:
- name: audit-collector
  cluster:
    server: https://audit-collector.example.com/events
    certificate-authority: /etc/kubernetes/pki/ca.crt
contexts:
- context:
    cluster: audit-collector
    user: api-server
  name: default
current-context: default
users:
- name: api-server
  user:
    client-certificate: /etc/kubernetes/pki/apiserver-audit.crt
    client-key: /etc/kubernetes/pki/apiserver-audit.key
```

#### 3. Dynamic Backend

Configured via API objects (advanced, not covered in KCSA).

## Audit Log Format

### Audit Event Structure

```json
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "Metadata",
  "auditID": "...",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/namespaces/default/secrets/my-secret",
  "verb": "get",
  "user": {
    "username": "jane@example.com",
    "uid": "...",
    "groups": ["developers", "system:authenticated"]
  },
  "sourceIPs": ["192.168.1.100"],
  "userAgent": "kubectl/v1.30.0",
  "objectRef": {
    "resource": "secrets",
    "namespace": "default",
    "name": "my-secret",
    "apiVersion": "v1"
  },
  "responseStatus": {
    "metadata": {},
    "code": 200
  },
  "requestReceivedTimestamp": "2024-01-15T10:30:00.000000Z",
  "stageTimestamp": "2024-01-15T10:30:00.123456Z"
}
```

### Key Fields Explained

| Field | Description | Example Use |
|-------|-------------|-------------|
| **user.username** | Who made the request | Track user actions |
| **sourceIPs** | Where request came from | Detect unusual locations |
| **verb** | What action was requested | Filter by create/delete |
| **objectRef** | What resource was affected | Find all secret access |
| **responseStatus.code** | HTTP response code | Find failures (4xx, 5xx) |
| **stage** | Which processing stage | Filter complete requests |
| **requestReceivedTimestamp** | When request arrived | Timeline reconstruction |

### Audit Event Examples

#### Example 1: Secret Access

```json
{
  "kind": "Event",
  "level": "RequestResponse",
  "stage": "ResponseComplete",
  "verb": "get",
  "user": {
    "username": "developer@example.com",
    "groups": ["developers"]
  },
  "objectRef": {
    "resource": "secrets",
    "namespace": "production",
    "name": "database-credentials"
  },
  "responseStatus": {"code": 200},
  "responseObject": {
    "data": {
      "password": "<redacted>"
    }
  }
}
```

#### Example 2: Failed Authentication

```json
{
  "kind": "Event",
  "level": "Metadata",
  "stage": "ResponseComplete",
  "verb": "create",
  "user": {
    "username": "unknown",
    "groups": ["system:unauthenticated"]
  },
  "objectRef": {
    "resource": "tokenreviews",
    "apiGroup": "authentication.k8s.io"
  },
  "responseStatus": {
    "code": 401,
    "message": "Unauthorized"
  }
}
```

#### Example 3: Pod Exec

```json
{
  "kind": "Event",
  "level": "Metadata",
  "stage": "ResponseComplete",
  "verb": "create",
  "user": {
    "username": "admin@example.com"
  },
  "objectRef": {
    "resource": "pods",
    "subresource": "exec",
    "namespace": "default",
    "name": "nginx-pod"
  },
  "requestURI": "/api/v1/namespaces/default/pods/nginx-pod/exec?command=bash"
}
```

## Analyzing Audit Logs

### Using jq for Analysis

#### Find All Secret Access

```bash
cat /var/log/kubernetes/audit.log | \
  jq 'select(.objectRef.resource=="secrets")'
```

#### Find Failed Authentication Attempts

```bash
cat /var/log/kubernetes/audit.log | \
  jq 'select(.responseStatus.code >= 400 and .objectRef.resource=="tokenreviews")'
```

#### Track Actions by User

```bash
cat /var/log/kubernetes/audit.log | \
  jq 'select(.user.username=="suspicious-user@example.com")'
```

#### Find Pod Exec/Attach Events

```bash
cat /var/log/kubernetes/audit.log | \
  jq 'select(.objectRef.subresource=="exec" or .objectRef.subresource=="attach") |
      {user: .user.username, pod: .objectRef.name, namespace: .objectRef.namespace, time: .requestReceivedTimestamp}'
```

#### Find Privileged Pod Creation

```bash
cat /var/log/kubernetes/audit.log | \
  jq 'select(.verb=="create" and .objectRef.resource=="pods") |
      select(.requestObject.spec.containers[].securityContext.privileged==true) |
      {user: .user.username, pod: .objectRef.name, time: .requestReceivedTimestamp}'
```

#### Find RBAC Changes

```bash
cat /var/log/kubernetes/audit.log | \
  jq 'select(.objectRef.apiGroup=="rbac.authorization.k8s.io" and
             (.verb=="create" or .verb=="update" or .verb=="delete"))'
```

#### Top API Endpoints by Request Count

```bash
cat /var/log/kubernetes/audit.log | \
  jq -r '.requestURI' | \
  sort | uniq -c | sort -rn | head -20
```

#### Find Requests from External IPs

```bash
cat /var/log/kubernetes/audit.log | \
  jq 'select(.sourceIPs[0] | startswith("10.") or startswith("192.168.") | not)'
```

### Common Audit Queries

#### Security-Focused Queries

```bash
# Find all actions on security-sensitive resources
cat audit.log | jq 'select(.objectRef.resource=="secrets" or
                            .objectRef.resource=="serviceaccounts" or
                            (.objectRef.apiGroup=="rbac.authorization.k8s.io"))'

# Find privileged pod creation
cat audit.log | jq 'select(.verb=="create" and
                            .objectRef.resource=="pods" and
                            (.requestObject.spec.hostNetwork==true or
                             .requestObject.spec.hostPID==true or
                             .requestObject.spec.containers[].securityContext.privileged==true))'

# Find NetworkPolicy deletions
cat audit.log | jq 'select(.verb=="delete" and
                            .objectRef.resource=="networkpolicies")'

# Find service account token creation
cat audit.log | jq 'select(.verb=="create" and
                            .objectRef.resource=="serviceaccounts/token")'
```

#### Compliance Queries

```bash
# All write operations (create/update/delete)
cat audit.log | jq 'select(.verb=="create" or .verb=="update" or .verb=="delete" or .verb=="patch")'

# Access to production namespace
cat audit.log | jq 'select(.objectRef.namespace=="production")'

# Actions by service accounts (vs users)
cat audit.log | jq 'select(.user.username | startswith("system:serviceaccount:"))'
```

## Common Audit Policies

### Minimal Security Policy

Log only security-critical events:

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: ["RequestReceived"]
rules:
  # Secrets
  - level: Metadata
    resources:
    - group: ""
      resources: ["secrets"]

  # Exec/attach
  - level: Metadata
    resources:
    - group: ""
      resources: ["pods/exec", "pods/attach", "pods/portforward"]

  # Everything else - don't log
  - level: None
```

### Comprehensive Security Policy

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: ["RequestReceived"]
rules:
  # 1. Don't log read-only access to non-sensitive resources
  - level: None
    verbs: ["get", "list", "watch"]
    resources:
    - group: ""
      resources: ["endpoints", "services", "pods/status"]

  # 2. Don't log health checks
  - level: None
    users: ["system:kube-proxy"]
    verbs: ["watch"]
    resources:
    - group: ""
      resources: ["endpoints", "services"]

  # 3. Log secret access with full request/response
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["secrets"]

  # 4. Log RBAC changes with full details
  - level: RequestResponse
    verbs: ["create", "update", "patch", "delete"]
    resources:
    - group: "rbac.authorization.k8s.io"

  # 5. Log exec/attach/portforward
  - level: Request
    verbs: ["create"]
    resources:
    - group: ""
      resources: ["pods/exec", "pods/attach", "pods/portforward"]

  # 6. Log security-sensitive resource writes
  - level: Request
    verbs: ["create", "update", "patch", "delete"]
    resources:
    - group: ""
      resources: ["pods", "services", "serviceaccounts"]
    - group: "apps"
      resources: ["deployments", "daemonsets", "statefulsets"]
    - group: "networking.k8s.io"
      resources: ["networkpolicies"]
    - group: "policy"
      resources: ["podsecuritypolicies", "poddisruptionbudgets"]

  # 7. Log authentication/authorization
  - level: Metadata
    resources:
    - group: "authentication.k8s.io"
      resources: ["tokenreviews"]
    - group: "authorization.k8s.io"
      resources: ["subjectaccessreviews", "selfsubjectaccessreviews"]

  # 8. Default - log metadata for everything else
  - level: Metadata
```

### Compliance-Focused Policy

For regulatory requirements (SOC 2, PCI-DSS):

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: ["RequestReceived"]
rules:
  # Log ALL write operations with full details
  - level: RequestResponse
    verbs: ["create", "update", "patch", "delete"]

  # Log read access to sensitive resources
  - level: Request
    verbs: ["get", "list"]
    resources:
    - group: ""
      resources: ["secrets", "configmaps"]

  # Log everything else at metadata level
  - level: Metadata
```

## Performance Considerations

### Audit Log Impact

Audit logging can impact API server performance:

| Configuration | Impact | Recommendation |
|--------------|--------|----------------|
| **Level: None** | No impact | Use for noisy endpoints |
| **Level: Metadata** | Very low | Default for most resources |
| **Level: Request** | Low-Medium | Use selectively |
| **Level: RequestResponse** | Medium-High | Only for critical resources |
| **Log Backend** | Low | Preferred for production |
| **Webhook Backend** | Medium-High | Ensure webhook is fast |

### Optimization Strategies

1. **Use None for health checks**:
   ```yaml
   - level: None
     users: ["system:kube-proxy", "system:kube-controller-manager"]
     verbs: ["watch"]
   ```

2. **Omit RequestReceived stage**:
   ```yaml
   omitStages: ["RequestReceived"]
   ```

3. **Don't log read-only for most resources**:
   ```yaml
   - level: None
     verbs: ["get", "list", "watch"]
     resources:
     - group: ""
       resources: ["pods", "nodes"]
   ```

4. **Use metadata for high-volume resources**:
   ```yaml
   - level: Metadata
     resources:
     - group: ""
       resources: ["pods"]
   ```

5. **Batch webhook events**:
   ```bash
   --audit-webhook-batch-max-wait=5s
   --audit-webhook-batch-max-size=400
   ```

### Log Volume Estimation

Example cluster (100 nodes, 1000 pods):

| Audit Level | Events/sec | Log Size/day | Notes |
|-------------|------------|--------------|-------|
| None | 0 | 0 | Not recommended |
| Metadata only | 100-500 | 1-5 GB | Typical production |
| Request for writes | 200-800 | 3-10 GB | Security-focused |
| RequestResponse all | 500-2000 | 10-50 GB | Compliance/forensics |

## Security Best Practices

### What to Log

**Always log**:
- Secret access (get, list, create, update, delete)
- RBAC changes (roles, rolebindings)
- Pod exec, attach, portforward
- Service account token creation
- Privileged pod creation
- Network policy changes
- Authentication failures

**Consider logging**:
- All write operations (create, update, delete)
- ConfigMap access (may contain sensitive data)
- Persistent volume operations
- Node operations

**Usually don't log**:
- Health checks (too noisy)
- Read-only access to non-sensitive resources
- System component internal operations

### Log Retention

**Recommendations**:
- **Compliance**: Follow regulatory requirements (often 1+ years)
- **Security**: Keep 90 days minimum for incident investigation
- **Performance**: Rotate logs frequently (daily or weekly)
- **Storage**: Archive old logs to cheaper storage

```bash
# API server log rotation flags
--audit-log-maxage=90        # Keep for 90 days
--audit-log-maxbackup=30     # Keep 30 backup files
--audit-log-maxsize=100      # Rotate at 100 MB
```

### Log Protection

**Critical**: Audit logs contain sensitive information.

```bash
# Secure the log directory
chmod 700 /var/log/kubernetes
chown root:root /var/log/kubernetes

# Secure individual log files
chmod 600 /var/log/kubernetes/audit.log
```

**Best practices**:
1. Encrypt logs at rest
2. Restrict access to logs (RBAC, filesystem permissions)
3. Send logs to centralized, secure storage
4. Enable log integrity checking (hashing)
5. Monitor for log tampering
6. Backup logs regularly

## Troubleshooting

### Common Issues

#### Audit Logs Not Generated

**Symptoms**: No audit.log file created

**Causes**:
1. Policy file not mounted correctly
2. Log path not writable
3. Policy file syntax error

**Solutions**:
```bash
# Check API server is running
kubectl get pods -n kube-system kube-apiserver-*

# Check API server logs
kubectl logs -n kube-system kube-apiserver-controlplane | grep audit

# Verify policy file exists
ls -la /etc/kubernetes/audit-policy.yaml

# Verify log directory
ls -la /var/log/kubernetes/

# Check API server configuration
kubectl get pod kube-apiserver-controlplane -n kube-system -o yaml | grep audit
```

#### API Server Won't Start

**Symptoms**: API server crash loop after enabling audit

**Causes**:
1. Invalid policy YAML syntax
2. Policy file not found
3. Log directory doesn't exist

**Solutions**:
```bash
# Validate policy YAML
kubectl apply --dry-run=client -f /etc/kubernetes/audit-policy.yaml

# Check API server logs on host
sudo journalctl -u kubelet | grep apiserver

# Create log directory if missing
sudo mkdir -p /var/log/kubernetes
sudo chmod 700 /var/log/kubernetes
```

#### High Log Volume

**Symptoms**: Log files growing too large, disk space issues

**Solutions**:
1. Add None rules for noisy endpoints
2. Increase omitStages
3. Use Metadata instead of Request level
4. Increase rotation frequency

```yaml
# Exclude high-volume endpoints
- level: None
  users: ["system:kube-proxy"]
  verbs: ["watch"]
  resources:
  - group: ""
    resources: ["endpoints", "services"]

# Omit more stages
omitStages:
  - "RequestReceived"
  - "ResponseStarted"  # Add this
```

## Exam Tips

For the KCSA exam, know:

1. **The four audit levels**: None, Metadata, Request, RequestResponse
2. **The four stages**: RequestReceived, ResponseStarted, ResponseComplete, Panic
3. **Rule precedence**: First match wins
4. **Common audit scenarios**: Secret access, pod exec, RBAC changes
5. **API server flags**: --audit-policy-file, --audit-log-path
6. **How to read audit events**: Key fields like user, verb, objectRef
7. **Performance impact**: RequestResponse is most expensive

**Practice**:
- Write audit policies for specific scenarios
- Identify what will be logged given a policy
- Read and interpret audit log entries
- Find security events in audit logs

## Summary

**Key Takeaways**:

1. Audit logging tracks all API server requests
2. Audit policies control what and how much is logged
3. Four levels: None, Metadata, Request, RequestResponse
4. First matching rule wins (order matters)
5. Balance security needs with performance impact
6. Always log security-sensitive operations
7. Protect audit logs - they contain sensitive data
8. Use jq for efficient log analysis

**Next Steps**:
- Complete [Lab 1: Audit Logging Configuration](../../labs/06-monitoring-logging/lab-01-audit-logging.md)
- Practice writing audit policies for different scenarios
- Learn to correlate audit logs with other monitoring data
- Continue to [Behavioral Analytics](behavioral-analytics.md)
