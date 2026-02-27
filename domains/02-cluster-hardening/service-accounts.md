# Service Accounts Security

## Introduction

**ServiceAccounts** are Kubernetes-native identities used by pods to authenticate with the Kubernetes API server. Unlike users (which are managed externally), ServiceAccounts are managed by Kubernetes and are essential for pod-to-API server communication and application security.

**What ServiceAccounts Do**:

- Provide identity for pods running in the cluster
- Enable pods to authenticate to the Kubernetes API
- Allow fine-grained RBAC permissions for applications
- Facilitate secure service-to-service communication

**Real-World Scenario**: Your application needs to list pods or read ConfigMaps from the Kubernetes API. Instead of embedding credentials or using admin tokens, you create a ServiceAccount with limited permissions. This follows the principle of least privilege and ensures your application only has the access it needs.

## Understanding ServiceAccounts

### ServiceAccount Basics

Every namespace has a `default` ServiceAccount automatically created:

```bash
# List service accounts in a namespace

kubectl get serviceaccounts -n default

# Output:

NAME      SECRETS   AGE
default   0         10d
```

### Automatic Token Mounting

By default, Kubernetes automatically mounts a ServiceAccount token into every pod:

```bash
# Check mounted token in a pod

kubectl exec -it my-pod -- ls -la /var/run/secrets/kubernetes.io/serviceaccount/

# Output:

total 0
drwxrwxrwt 3 root root  140 Feb 27 10:00 .
drwxr-xr-x 3 root root 4096 Feb 27 10:00 ..
drwxr-xr-x 2 root root  100 Feb 27 10:00 ..2026_02_27_10_00_00.123456789
lrwxrwxrwx 1 root root   31 Feb 27 10:00 ..data -> ..2026_02_27_10_00_00.123456789
lrwxrwxrwx 1 root root   13 Feb 27 10:00 ca.crt -> ..data/ca.crt
lrwxrwxrwx 1 root root   16 Feb 27 10:00 namespace -> ..data/namespace
lrwxrwxrwx 1 root root   12 Feb 27 10:00 token -> ..data/token
```

**Three Files Mounted**:

1. **token**: JWT bearer token for API authentication
1. **ca.crt**: CA certificate to verify API server's TLS certificate
1. **namespace**: The pod's namespace

### ServiceAccount Token Structure

ServiceAccount tokens are JSON Web Tokens (JWT) containing:

```json
{
  "iss": "kubernetes/serviceaccount",
  "kubernetes.io/serviceaccount/namespace": "default",
  "kubernetes.io/serviceaccount/secret.name": "default-token-xxxxx",
  "kubernetes.io/serviceaccount/service-account.name": "default",
  "kubernetes.io/serviceaccount/service-account.uid": "uuid-here",
  "sub": "system:serviceaccount:default:default"
}
```

**Key Claims**:

- `sub`: Subject identity used by RBAC (system:serviceaccount:NAMESPACE:NAME)
- `namespace`: Pod's namespace
- `exp`: Expiration time (for bound tokens)

## Creating ServiceAccounts

### Method 1: kubectl Command

```bash
# Create a ServiceAccount

kubectl create serviceaccount my-app-sa -n production

# Verify creation

kubectl get sa my-app-sa -n production

# Describe to see details

kubectl describe sa my-app-sa -n production
```

### Method 2: YAML Manifest

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app-sa
  namespace: production
  labels:
    app: my-application
  annotations:
    description: "ServiceAccount for my-application pods"
```

Apply with:

```bash
kubectl apply -f serviceaccount.yaml
```

## Using ServiceAccounts in Pods

### Assigning ServiceAccount to Pod

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app-pod
  namespace: production
spec:
  serviceAccountName: my-app-sa  # Use custom ServiceAccount
  containers:
  - name: app
    image: myapp:1.0
```

### ServiceAccount in Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      serviceAccountName: my-app-sa  # All pods use this SA
      containers:
      - name: app
        image: myapp:1.0
```

### Default Behavior

If no ServiceAccount is specified, pods use the `default` ServiceAccount:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:

  # No serviceAccountName specified - uses 'default' SA

  containers:
  - name: nginx
    image: nginx:1.27
```

## ServiceAccount Token Projection (Bound Tokens)

**Kubernetes v1.22+** introduced bound ServiceAccount tokens with improved security.

### Legacy Tokens vs Bound Tokens

| Feature | Legacy Tokens | Bound Tokens |
| --------- | --------------- | -------------- |
| Expiration | Never | Time-limited (default 1 hour) |
| Audience | Any | Specific audience |
| Binding | None | Bound to pod |
| Security | Lower | Higher |

### Projected Volume Token

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
  namespace: production
spec:
  serviceAccountName: my-app-sa
  containers:
  - name: app
    image: myapp:1.0
    volumeMounts:
    - name: token
      mountPath: /var/run/secrets/tokens
      readOnly: true
  volumes:
  - name: token
    projected:
      sources:
      - serviceAccountToken:
          path: token
          expirationSeconds: 3600  # 1 hour
          audience: api
```

**Benefits**:

- Tokens expire automatically (no long-lived credentials)
- Bound to pod lifecycle (revoked when pod deleted)
- Audience-scoped (can't be used elsewhere)
- Rotated automatically before expiration

### Default Projected Token (v1.22+)

Modern Kubernetes automatically uses projected tokens:

```bash
# Check token in a pod (v1.22+)

kubectl exec -it my-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token

# View token expiration

kubectl exec -it my-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token | \
  cut -d. -f2 | base64 -d | jq .exp
```

## Disabling Token Automounting

**Security Best Practice**: Disable automounting for pods that don't need API access.

### Disable at ServiceAccount Level

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: no-api-access
  namespace: production
automountServiceAccountToken: false  # Disable for all pods using this SA
```

### Disable at Pod Level

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app-pod
  namespace: production
spec:
  serviceAccountName: my-app-sa
  automountServiceAccountToken: false  # Override SA setting
  containers:
  - name: app
    image: myapp:1.0
```

### Disable at Deployment Level

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: frontend
  template:
    metadata:
      labels:
        app: frontend
    spec:
      automountServiceAccountToken: false  # Disable for all pods
      containers:
      - name: nginx
        image: nginx:1.27
```

**Decision Matrix**:

| Application Type | Mount Token? |
| ------------------ | -------------- |
| Static web server (nginx) | No |
| Application calling K8s API | Yes |
| Database | No |
| Monitoring agent (Prometheus) | Yes |
| CI/CD runner | Yes |
| Batch job not using API | No |

## Granting Permissions to ServiceAccounts

ServiceAccounts are subjects in RBAC and can be granted permissions via RoleBindings or ClusterRoleBindings.

### Example: ConfigMap Reader ServiceAccount

```yaml
# 1. Create ServiceAccount

apiVersion: v1
kind: ServiceAccount
metadata:
  name: config-reader
  namespace: production
---

# 2. Create Role with permissions

apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: configmap-reader
  namespace: production
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list"]
---

# 3. Bind Role to ServiceAccount

apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-configmaps
  namespace: production
subjects:
- kind: ServiceAccount
  name: config-reader
  namespace: production
roleRef:
  kind: Role
  name: configmap-reader
  apiGroup: rbac.authorization.k8s.io
---

# 4. Use in Pod

apiVersion: v1
kind: Pod
metadata:
  name: app-pod
  namespace: production
spec:
  serviceAccountName: config-reader
  containers:
  - name: app
    image: myapp:1.0
```

### Example: Cross-Namespace Access

```yaml
# ServiceAccount in namespace 'app'

apiVersion: v1
kind: ServiceAccount
metadata:
  name: data-accessor
  namespace: app
---

# Role in namespace 'data'

apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: data
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["database-credentials"]
  verbs: ["get"]
---

# RoleBinding in namespace 'data' referencing SA from 'app'

apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cross-ns-access
  namespace: data
subjects:
- kind: ServiceAccount
  name: data-accessor
  namespace: app  # SA from different namespace
roleRef:
  kind: Role
  name: secret-reader
  apiGroup: rbac.authorization.k8s.io
```

### Testing ServiceAccount Permissions

```bash
# Test as ServiceAccount

kubectl auth can-i get configmaps \
  --as=system:serviceaccount:production:config-reader \
  --namespace=production

# List all permissions

kubectl auth can-i --list \
  --as=system:serviceaccount:production:config-reader \
  --namespace=production
```

## Using ServiceAccount Tokens from Within Pods

### Accessing Kubernetes API

Applications can read the mounted token to authenticate:

```bash
# From within a pod

TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

# Call API

curl --cacert $CACERT \
  -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/$NAMESPACE/pods
```

### Example: Python Client

```python
from kubernetes import client, config

# Load in-cluster config (uses mounted ServiceAccount token)

config.load_incluster_config()

# Create API client

v1 = client.CoreV1Api()

# List pods

pods = v1.list_namespaced_pod(namespace="default")
for pod in pods.items:
    print(pod.metadata.name)
```

### Example: Go Client

```go
package main

import (
    "context"
    "fmt"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/rest"
)

func main() {
    // Create in-cluster config
    config, err := rest.InClusterConfig()
    if err != nil {
        panic(err)
    }

    // Create clientset
    clientset, err := kubernetes.NewForConfig(config)
    if err != nil {
        panic(err)
    }

    // List pods
    pods, err := clientset.CoreV1().Pods("default").List(context.TODO(), metav1.ListOptions{})
    if err != nil {
        panic(err)
    }

    for _, pod := range pods.Items {
        fmt.Println(pod.Name)
    }
}
```

## ServiceAccount Token Security

### Token Lifetime

**Legacy Tokens** (pre-v1.22):

- Never expire
- Stored as Secret
- Security risk if compromised

**Bound Tokens** (v1.22+):

- Expire after configured duration (default 1 hour)
- Auto-rotated by kubelet
- Bound to pod lifecycle
- More secure

### Token Scope

Limit what ServiceAccount can do:

```yaml
# Minimal permissions example

apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: minimal-role
  namespace: production
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["app-config"]  # Only specific ConfigMap
  verbs: ["get"]  # Only read, not modify
```

### Token Rotation

For bound tokens, rotation is automatic. For legacy tokens:

```bash
# Delete old token secret (forces new token generation)

kubectl delete secret <serviceaccount-token-secret>

# ServiceAccount will automatically create new token

```

### Detecting Token Usage

```bash
# Check which pods use a ServiceAccount

kubectl get pods -n production -o json | \
  jq -r '.items[] | select(.spec.serviceAccountName=="my-app-sa") | .metadata.name'

# Audit API calls by ServiceAccount (requires audit logging)

kubectl logs -n kube-system kube-apiserver-<node> | \
  grep "system:serviceaccount:production:my-app-sa"
```

## Common ServiceAccount Patterns

### Pattern 1: Read-Only Monitoring

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: prometheus-sa
  namespace: monitoring
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: prometheus-reader
rules:
- apiGroups: [""]
  resources: ["nodes", "services", "endpoints", "pods"]
  verbs: ["get", "list", "watch"]
- nonResourceURLs: ["/metrics"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: prometheus-binding
subjects:
- kind: ServiceAccount
  name: prometheus-sa
  namespace: monitoring
roleRef:
  kind: ClusterRole
  name: prometheus-reader
  apiGroup: rbac.authorization.k8s.io
```

### Pattern 2: CI/CD Deployer

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cicd-deployer
  namespace: production
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: deploy-role
  namespace: production
rules:
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "create", "update", "patch"]
- apiGroups: [""]
  resources: ["services", "configmaps"]
  verbs: ["get", "list", "create", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cicd-deploy-binding
  namespace: production
subjects:
- kind: ServiceAccount
  name: cicd-deployer
  namespace: production
roleRef:
  kind: Role
  name: deploy-role
  apiGroup: rbac.authorization.k8s.io
```

### Pattern 3: Job with Cleanup Permissions

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cleanup-job-sa
  namespace: production
automountServiceAccountToken: true
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cleanup-role
  namespace: production
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "delete"]
- apiGroups: [""]
  resources: ["pods/log"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cleanup-binding
  namespace: production
subjects:
- kind: ServiceAccount
  name: cleanup-job-sa
  namespace: production
roleRef:
  kind: Role
  name: cleanup-role
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: batch/v1
kind: Job
metadata:
  name: cleanup-old-pods
  namespace: production
spec:
  template:
    spec:
      serviceAccountName: cleanup-job-sa
      restartPolicy: OnFailure
      containers:
      - name: cleanup
        image: bitnami/kubectl:1.30
        command:
        - /bin/bash
        - -c
        - |
          kubectl get pods --field-selector=status.phase=Failed \
            -o name | xargs kubectl delete
```

### Pattern 4: No API Access (Static App)

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: static-app-sa
  namespace: production
automountServiceAccountToken: false  # No token needed
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-static
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      serviceAccountName: static-app-sa
      automountServiceAccountToken: false
      containers:
      - name: nginx
        image: nginx:1.27
```

## Troubleshooting ServiceAccounts

### Common Issues

#### 1. Pod Cannot Access API

**Symptoms**:

```
Error: Forbidden: User "system:serviceaccount:default:default" cannot list pods

```

**Solutions**:

```bash
# Check if token is mounted

kubectl exec -it my-pod -- ls /var/run/secrets/kubernetes.io/serviceaccount/

# Check ServiceAccount exists

kubectl get sa -n <namespace>

# Check RBAC permissions

kubectl auth can-i list pods \
  --as=system:serviceaccount:<namespace>:<sa-name> \
  --namespace=<namespace>

# Create appropriate RoleBinding

kubectl create rolebinding sa-binding \
  --role=pod-reader \
  --serviceaccount=<namespace>:<sa-name> \
  --namespace=<namespace>
```

#### 2. Token Not Mounted

**Symptoms**: `/var/run/secrets/kubernetes.io/serviceaccount/` directory empty or missing

**Causes**:

- `automountServiceAccountToken: false` set
- ServiceAccount doesn't exist
- Security admission controller blocking

**Solutions**:

```bash
# Check pod spec

kubectl get pod my-pod -o yaml | grep -A2 automountServiceAccountToken

# Check ServiceAccount spec

kubectl get sa my-sa -o yaml | grep automountServiceAccountToken

# Verify ServiceAccount exists

kubectl get sa my-sa -n production
```

#### 3. Permission Denied After Granting Access

**Causes**:

- Wrong namespace in RoleBinding
- Typo in ServiceAccount name
- Pod not restarted after RBAC change

**Solutions**:

```bash
# Verify RoleBinding

kubectl describe rolebinding my-binding -n production

# Check subject matches

kubectl get rolebinding my-binding -n production -o yaml

# Restart pod to apply changes

kubectl rollout restart deployment my-app -n production
```

#### 4. Cross-Namespace Access Not Working

**Example**: ServiceAccount in namespace `app` cannot access resources in namespace `data`

**Solution**: Create RoleBinding in target namespace:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cross-ns-access
  namespace: data  # Target namespace
subjects:
- kind: ServiceAccount
  name: my-sa
  namespace: app  # Source namespace
roleRef:
  kind: Role
  name: reader-role
  apiGroup: rbac.authorization.k8s.io
```

### Debugging Commands

```bash
# List ServiceAccounts

kubectl get sa -n <namespace>

# Describe ServiceAccount

kubectl describe sa <sa-name> -n <namespace>

# Get ServiceAccount YAML

kubectl get sa <sa-name> -n <namespace> -o yaml

# Find pods using a ServiceAccount

kubectl get pods -n <namespace> -o json | \
  jq -r '.items[] | select(.spec.serviceAccountName=="<sa-name>") | .metadata.name'

# Test ServiceAccount permissions

kubectl auth can-i --list \
  --as=system:serviceaccount:<namespace>:<sa-name> \
  --namespace=<namespace>

# View token from within pod

kubectl exec -it <pod> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Decode token (JWT)

kubectl exec -it <pod> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token | \
  cut -d. -f2 | base64 -d | jq
```

## Security Best Practices

### 1. Use Custom ServiceAccounts

Don't rely on the `default` ServiceAccount:

```yaml
# BAD - uses default SA

spec:
  containers:
  - name: app
    image: myapp:1.0

# GOOD - uses custom SA with specific permissions

spec:
  serviceAccountName: my-app-sa
  containers:
  - name: app
    image: myapp:1.0
```

### 2. Disable Automounting When Not Needed

```yaml
# Application doesn't call Kubernetes API

apiVersion: apps/v1
kind: Deployment
metadata:
  name: static-web
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
      - name: nginx
        image: nginx:1.27
```

### 3. Apply Least Privilege

```yaml
# BAD - too permissive

rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]

# GOOD - specific permissions

rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["app-config"]
  verbs: ["get"]
```

### 4. Use Bound Tokens (v1.22+)

```yaml
# Prefer projected volumes with expiration

volumes:
- name: token
  projected:
    sources:
    - serviceAccountToken:
        path: token
        expirationSeconds: 3600
```

### 5. Audit ServiceAccount Usage

```bash
# List all ServiceAccounts

kubectl get sa --all-namespaces

# Find unused ServiceAccounts

for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  for sa in $(kubectl get sa -n $ns -o jsonpath='{.items[*].metadata.name}'); do
    if [ "$sa" != "default" ]; then
      count=$(kubectl get pods -n $ns -o json | jq -r ".items[] | select(.spec.serviceAccountName==\"$sa\") | .metadata.name" | wc -l)
      if [ $count -eq 0 ]; then
        echo "Unused: $ns/$sa"
      fi
    fi
  done
done
```

### 6. Document ServiceAccount Purpose

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-deployer
  namespace: production
  annotations:
    purpose: "Deploy and manage application workloads"
    owner: "platform-team@example.com"
    last-reviewed: "2026-02-27"
  labels:
    app: deployer
    team: platform
```

### 7. Regular Permission Reviews

```bash
# List all RoleBindings for ServiceAccounts

kubectl get rolebindings,clusterrolebindings --all-namespaces -o json | \
  jq -r '.items[] | select(.subjects[]?.kind=="ServiceAccount") |
    "\(.kind)/\(.metadata.name) -> \(.subjects[].name)"'

# Review overly permissive ClusterRoleBindings

kubectl get clusterrolebindings -o json | \
  jq -r '.items[] | select(.subjects[]?.kind=="ServiceAccount" and
    .roleRef.name=="cluster-admin") | .metadata.name'
```

### 8. Separate Workload ServiceAccounts

```yaml
# One ServiceAccount per application/workload

---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: frontend-sa
  namespace: production
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: backend-sa
  namespace: production
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: worker-sa
  namespace: production
```

## ServiceAccount Token API

### TokenRequest API

Request short-lived tokens programmatically:

```bash
# Request a token

kubectl create token <serviceaccount-name> \
  --duration=1h \
  --namespace=<namespace>
```

**Features**:

- Time-limited tokens
- Audience-scoped
- Not stored as Secrets
- More secure than long-lived tokens

### Example: External Token Request

```bash
# Create 1-hour token for CI/CD

TOKEN=$(kubectl create token cicd-deployer \
  --duration=3600s \
  --namespace=production)

# Use token

curl -H "Authorization: Bearer $TOKEN" \
  https://kubernetes-api-server/api/v1/namespaces/production/pods
```

## Migration from Legacy Tokens

### Kubernetes v1.24+ Changes

- **LegacyServiceAccountTokenNoAutoGeneration**: No automatic Secret creation
- Must use TokenRequest API or projected volumes
- Existing Secret-based tokens still work but deprecated

### Checking Token Type

```bash
# Check if using projected token

kubectl get pod my-pod -o yaml | grep -A5 "serviceAccountToken"

# Projected volume output:
#   - serviceAccountToken:
#       expirationSeconds: 3600
#       path: token

```

## Quick Reference

### Common Commands

```bash
# Create ServiceAccount

kubectl create serviceaccount <name> -n <namespace>

# List ServiceAccounts

kubectl get serviceaccounts -n <namespace>

# Describe ServiceAccount

kubectl describe sa <name> -n <namespace>

# Delete ServiceAccount

kubectl delete sa <name> -n <namespace>

# Create token (v1.24+)

kubectl create token <sa-name> -n <namespace> --duration=1h

# Test SA permissions

kubectl auth can-i <verb> <resource> \
  --as=system:serviceaccount:<namespace>:<sa-name>
```

### ServiceAccount Subject Format

```
system:serviceaccount:<namespace>:<serviceaccount-name>

```

Examples:

```
system:serviceaccount:default:default
system:serviceaccount:production:my-app-sa
system:serviceaccount:monitoring:prometheus
```

## Exam Tips

1. **Know default behavior**: Pods use `default` SA if none specified
1. **Token location**: `/var/run/secrets/kubernetes.io/serviceaccount/`
1. **Disable automounting**: Use when pod doesn't need API access
1. **RBAC integration**: ServiceAccounts are RBAC subjects
1. **Subject format**: `system:serviceaccount:NAMESPACE:NAME`
1. **Cross-namespace**: ServiceAccounts can access other namespaces with appropriate RoleBinding
1. **Best practice**: One ServiceAccount per application with least privilege

## Next Steps

- Complete [Lab 03: Service Accounts](../../labs/02-cluster-hardening/lab-03-service-accounts.md)
- Study [Security Contexts](security-contexts.md) for pod-level security
- Review [RBAC](rbac.md) for permission management
- Learn about [Pod Security Admission](pod-security-admission.md)

## Additional Resources

- [Kubernetes ServiceAccounts Documentation](https://kubernetes.io/docs/concepts/security/service-accounts/)
- [Configure Service Accounts](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
- [Managing Service Accounts](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
- [Bound Service Account Tokens](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#bound-service-account-token-volume)
