# Lab 03: Service Accounts

## Objective

Master ServiceAccount creation, configuration, and security best practices. Learn how to control token mounting, grant appropriate permissions, and implement least privilege for pod authentication.

**What You'll Learn**:

- Create and configure custom ServiceAccounts
- Control token automounting behavior
- Grant RBAC permissions to ServiceAccounts
- Test ServiceAccount API access from pods
- Implement security best practices

## Prerequisites

- Completed Lab 01 and Lab 02
- Understanding of RBAC
- Kubernetes cluster running

## Lab Duration

45-60 minutes

## Lab Setup

```bash

# Create lab namespace

kubectl create namespace sa-lab

# Verify

kubectl get namespace sa-lab
```

```

## Exercises

### Exercise 1: Explore Default ServiceAccount

```bash

# Check default ServiceAccount

kubectl get serviceaccount default -n sa-lab

kubectl describe serviceaccount default -n sa-lab

# Create a pod without specifying ServiceAccount

kubectl run default-sa-pod --image=nginx:1.27 -n sa-lab

# Check which ServiceAccount it uses

kubectl get pod default-sa-pod -n sa-lab -o jsonpath='{.spec.serviceAccountName}'

# Expected: default

# Check mounted token

kubectl exec -it default-sa-pod -n sa-lab -- \
  ls -la /var/run/secrets/kubernetes.io/serviceaccount/

# Expected output: token, ca.crt, namespace files

# View token content (JWT)

kubectl exec -it default-sa-pod -n sa-lab -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Try to access API with default SA (should fail - no permissions)

kubectl exec -it default-sa-pod -n sa-lab -- \
  sh -c 'apk add -q curl && \
  TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) && \
  curl -s --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
    -H "Authorization: Bearer $TOKEN" \
    https://kubernetes.default.svc/api/v1/namespaces/sa-lab/pods'

# Expected: Forbidden error (default SA has no permissions)

```

```

---

### Exercise 2: Create Custom ServiceAccount

```bash

# Create ServiceAccount

kubectl create serviceaccount my-app-sa -n sa-lab

# Describe it

kubectl describe serviceaccount my-app-sa -n sa-lab

# Create YAML for more complex SA

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: annotated-sa
  namespace: sa-lab
  labels:
    app: my-application
    team: platform
  annotations:
    purpose: "Application ServiceAccount with specific permissions"
    owner: "platform-team@example.com"
EOF

# Verify

kubectl get serviceaccounts -n sa-lab
```

```

---

### Exercise 3: Grant Permissions to ServiceAccount

```bash

# Create Role for pod reading

kubectl create role pod-reader \
  --verb=get,list,watch \
  --resource=pods \
  --namespace=sa-lab

# Bind Role to ServiceAccount

kubectl create rolebinding my-app-binding \
  --role=pod-reader \
  --serviceaccount=sa-lab:my-app-sa \
  --namespace=sa-lab

# Test permissions

kubectl auth can-i list pods \
  --as=system:serviceaccount:sa-lab:my-app-sa \
  --namespace=sa-lab

# Expected: yes

kubectl auth can-i delete pods \
  --as=system:serviceaccount:sa-lab:my-app-sa \
  --namespace=sa-lab

# Expected: no

```

```

---

### Exercise 4: Use ServiceAccount in Pod

```yaml

# Save as pod-with-sa.yaml

apiVersion: v1
kind: Pod
metadata:
  name: app-with-sa
  namespace: sa-lab
spec:
  serviceAccountName: my-app-sa
  containers:
  - name: kubectl
    image: bitnami/kubectl:1.30
    command: ["sleep", "3600"]
```

```

```bash

# Apply pod

kubectl apply -f pod-with-sa.yaml

# Wait for ready

kubectl wait --for=condition=ready pod/app-with-sa -n sa-lab --timeout=60s

# Test API access from pod

kubectl exec -it app-with-sa -n sa-lab -- \
  kubectl get pods -n sa-lab

# Should succeed (list pods)

# Try to delete pod (should fail)

kubectl exec -it app-with-sa -n sa-lab -- \
  kubectl delete pod default-sa-pod -n sa-lab

# Expected error: Forbidden

```

```

---

### Exercise 5: Disable Token Automounting

**Scenario**: Static web server doesn't need API access.

```yaml

# Save as no-token-sa.yaml

apiVersion: v1
kind: ServiceAccount
metadata:
  name: no-token-sa
  namespace: sa-lab
automountServiceAccountToken: false  # Disable globally for this SA
---
apiVersion: v1
kind: Pod
metadata:
  name: no-token-pod
  namespace: sa-lab
spec:
  serviceAccountName: no-token-sa
  containers:
  - name: nginx
    image: nginx:1.27
```

```

```bash

# Apply

kubectl apply -f no-token-sa.yaml

# Wait for pod

kubectl wait --for=condition=ready pod/no-token-pod -n sa-lab --timeout=60s

# Check for token mount

kubectl exec -it no-token-pod -n sa-lab -- \
  ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>&1

# Expected: No such file or directory (token not mounted)

```

```

---

### Exercise 6: Override Automounting at Pod Level

```yaml

# Save as override-automount.yaml

apiVersion: v1
kind: ServiceAccount
metadata:
  name: default-mount-sa
  namespace: sa-lab

# automountServiceAccountToken defaults to true

---
apiVersion: v1
kind: Pod
metadata:
  name: override-mount-pod
  namespace: sa-lab
spec:
  serviceAccountName: default-mount-sa
  automountServiceAccountToken: false  # Override SA setting
  containers:
  - name: nginx
    image: nginx:1.27
```

```

```bash

# Apply

kubectl apply -f override-automount.yaml

# Check token mount

kubectl exec -it override-mount-pod -n sa-lab -- \
  ls /var/run/secrets/kubernetes.io/serviceaccount/ 2>&1

# Expected: No such file or directory

# Now create pod that allows mounting

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: allow-mount-pod
  namespace: sa-lab
spec:
  serviceAccountName: default-mount-sa
  automountServiceAccountToken: true  # Explicitly enable
  containers:
  - name: nginx
    image: nginx:1.27
EOF

# Check this pod has token

kubectl exec -it allow-mount-pod -n sa-lab -- \
  ls /var/run/secrets/kubernetes.io/serviceaccount/

# Expected: ca.crt namespace token

```

```

---

### Exercise 7: ServiceAccount for ConfigMap Access

```bash

# Create test ConfigMaps

kubectl create configmap app-config \
  --from-literal=env=production \
  --from-literal=log-level=info \
  -n sa-lab

kubectl create configmap db-config \
  --from-literal=host=postgres.default.svc \
  --from-literal=port=5432 \
  -n sa-lab

# Create ServiceAccount

kubectl create serviceaccount config-reader-sa -n sa-lab

# Create Role with ConfigMap read permissions

kubectl create role config-reader \
  --verb=get,list \
  --resource=configmaps \
  --namespace=sa-lab

# Bind Role

kubectl create rolebinding config-reader-binding \
  --role=config-reader \
  --serviceaccount=sa-lab:config-reader-sa \
  --namespace=sa-lab

# Create pod with this SA

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: config-reader-pod
  namespace: sa-lab
spec:
  serviceAccountName: config-reader-sa
  containers:
  - name: kubectl
    image: bitnami/kubectl:1.30
    command: ["sleep", "3600"]
EOF

# Wait for pod

kubectl wait --for=condition=ready pod/config-reader-pod -n sa-lab --timeout=60s

# Test ConfigMap access

kubectl exec -it config-reader-pod -n sa-lab -- \
  kubectl get configmaps -n sa-lab

# Should list configmaps

kubectl exec -it config-reader-pod -n sa-lab -- \
  kubectl get configmap app-config -n sa-lab -o yaml

# Should show configmap data

```

```

---

### Exercise 8: Bound ServiceAccount Tokens (Projected Volumes)

```yaml

# Save as projected-token-pod.yaml

apiVersion: v1
kind: Pod
metadata:
  name: projected-token-pod
  namespace: sa-lab
spec:
  serviceAccountName: my-app-sa
  containers:
  - name: app
    image: busybox:1.36
    command: ["sleep", "3600"]
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
          expirationSeconds: 3600  # 1 hour expiration
          audience: api
```

```

```bash

# Apply

kubectl apply -f projected-token-pod.yaml

# Wait for pod

kubectl wait --for=condition=ready pod/projected-token-pod -n sa-lab --timeout=60s

# Check token location

kubectl exec -it projected-token-pod -n sa-lab -- \
  ls -la /var/run/secrets/tokens/

# View token (it will be different from default mount location)

kubectl exec -it projected-token-pod -n sa-lab -- \
  cat /var/run/secrets/tokens/token

# Decode token to see expiration

kubectl exec -it projected-token-pod -n sa-lab -- \
  cat /var/run/secrets/tokens/token | \
  cut -d. -f2 | base64 -d 2>/dev/null || echo "Token content"
```

```

---

### Exercise 9: Cross-Namespace ServiceAccount Access

```bash

# Create another namespace

kubectl create namespace sa-lab-2

# Create resources in sa-lab-2

kubectl run nginx --image=nginx:1.27 -n sa-lab-2

# Create Role in sa-lab-2 for pod reading

kubectl create role cross-ns-pod-reader \
  --verb=get,list \
  --resource=pods \
  --namespace=sa-lab-2

# Bind sa-lab ServiceAccount to sa-lab-2 resources

kubectl create rolebinding cross-ns-binding \
  --role=cross-ns-pod-reader \
  --serviceaccount=sa-lab:my-app-sa \
  --namespace=sa-lab-2

# Test cross-namespace access

kubectl auth can-i list pods \
  --as=system:serviceaccount:sa-lab:my-app-sa \
  --namespace=sa-lab-2

# Expected: yes

# From pod, access other namespace

kubectl exec -it app-with-sa -n sa-lab -- \
  kubectl get pods -n sa-lab-2

# Should list pods in sa-lab-2

```

```

---

### Exercise 10: Least Privilege ServiceAccount

**Scenario**: Application needs specific ConfigMap and one Secret.

```yaml

# Save as least-privilege-sa.yaml

apiVersion: v1
kind: ServiceAccount
metadata:
  name: least-privilege-sa
  namespace: sa-lab
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: least-privilege-role
  namespace: sa-lab
rules:

# Only specific ConfigMap

- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["app-config"]
  verbs: ["get"]

# Only specific Secret

- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["app-secret"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: least-privilege-binding
  namespace: sa-lab
subjects:
- kind: ServiceAccount
  name: least-privilege-sa
  namespace: sa-lab
roleRef:
  kind: Role
  name: least-privilege-role
  apiGroup: rbac.authorization.k8s.io
```

```

```bash

# Create test secret

kubectl create secret generic app-secret \
  --from-literal=api-key=super-secret \
  -n sa-lab

kubectl create secret generic other-secret \
  --from-literal=key=value \
  -n sa-lab

# Apply SA and RBAC

kubectl apply -f least-privilege-sa.yaml

# Test permissions

kubectl auth can-i get configmap/app-config \
  --as=system:serviceaccount:sa-lab:least-privilege-sa \
  --namespace=sa-lab

# Expected: yes

kubectl auth can-i get configmap/db-config \
  --as=system:serviceaccount:sa-lab:least-privilege-sa \
  --namespace=sa-lab

# Expected: no

kubectl auth can-i list configmaps \
  --as=system:serviceaccount:sa-lab:least-privilege-sa \
  --namespace=sa-lab

# Expected: no (resourceNames doesn't work with list)

kubectl auth can-i get secret/app-secret \
  --as=system:serviceaccount:sa-lab:least-privilege-sa \
  --namespace=sa-lab

# Expected: yes

kubectl auth can-i get secret/other-secret \
  --as=system:serviceaccount:sa-lab:least-privilege-sa \
  --namespace=sa-lab

# Expected: no

```

```

---

## Verification

```bash

# 1. List all ServiceAccounts

kubectl get serviceaccounts -n sa-lab

# Should show: default, my-app-sa, annotated-sa, no-token-sa, etc.

# 2. Check token automounting

kubectl get sa no-token-sa -n sa-lab -o jsonpath='{.automountServiceAccountToken}'

# Expected: false

# 3. Verify RBAC bindings

kubectl get rolebindings -n sa-lab

# 4. Test key permissions

kubectl auth can-i list pods \
  --as=system:serviceaccount:sa-lab:my-app-sa \
  --namespace=sa-lab

# Expected: yes

# 5. Verify cross-namespace access

kubectl auth can-i list pods \
  --as=system:serviceaccount:sa-lab:my-app-sa \
  --namespace=sa-lab-2

# Expected: yes

```

```

## Cleanup

```bash

# Delete namespaces (cascades all resources)

kubectl delete namespace sa-lab
kubectl delete namespace sa-lab-2

# Verify deletion

kubectl get namespace sa-lab sa-lab-2

# Expected: NotFound errors

```

```

## Key Takeaways

1. **Default ServiceAccount**: Every namespace has default SA, limited permissions
1. **Token mounting**: Controlled by automountServiceAccountToken
1. **Subject format**: `system:serviceaccount:NAMESPACE:NAME`
1. **Least privilege**: Create specific SAs with minimal permissions
1. **Cross-namespace**: SAs can access other namespaces with appropriate RBAC
1. **Projected tokens**: Better security with expiration and audience binding
1. **Best practice**: Disable automounting when API access not needed

## Next Steps

- Complete [Lab 04: Security Contexts](lab-04-security-contexts.md)
- Review [Security Contexts theory](../../domains/02-cluster-hardening/security-contexts.md)
- Practice ServiceAccount security patterns

---

**Congratulations!** You now understand ServiceAccount security and can implement least privilege access patterns.
