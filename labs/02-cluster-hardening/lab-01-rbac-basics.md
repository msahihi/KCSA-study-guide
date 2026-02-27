# Lab 01: RBAC Basics

## Objective

Learn the fundamentals of Role-Based Access Control (RBAC) in Kubernetes by creating Roles, RoleBindings, and testing permissions using `kubectl auth can-i`. This lab focuses on namespace-scoped RBAC and implements least privilege principles.

**What You'll Learn**:
- Create Roles with specific permissions
- Bind roles to users and ServiceAccounts
- Test permissions using kubectl auth can-i
- Troubleshoot common RBAC issues
- Implement least privilege access patterns

## Prerequisites

- Kubernetes cluster (Kind/Minikube) running
- kubectl v1.30.x configured
- Basic understanding of Kubernetes resources (pods, deployments)
- Completed reading [RBAC theory](../../domains/02-cluster-hardening/rbac.md)

## Lab Duration

45-60 minutes

## Lab Setup

### 1. Create Lab Namespace

```bash
# Create namespace for this lab
kubectl create namespace rbac-lab

# Verify creation
kubectl get namespace rbac-lab

# Set as default for this lab (optional)
kubectl config set-context --current --namespace=rbac-lab
```

### 2. Create Test Resources

```bash
# Create some pods for testing permissions
kubectl run pod1 --image=nginx:1.27 -n rbac-lab
kubectl run pod2 --image=nginx:1.27 -n rbac-lab
kubectl run pod3 --image=busybox:1.36 --command -n rbac-lab -- sleep 3600

# Create a deployment
kubectl create deployment nginx-deploy --image=nginx:1.27 --replicas=2 -n rbac-lab

# Create a service
kubectl expose deployment nginx-deploy --port=80 --target-port=80 -n rbac-lab

# Verify resources
kubectl get pods,deployments,services -n rbac-lab
```

**Expected Output**:
```
NAME                               READY   STATUS    RESTARTS   AGE
pod/pod1                           1/1     Running   0          10s
pod/pod2                           1/1     Running   0          9s
pod/pod3                           1/1     Running   0          8s
pod/nginx-deploy-xxxxxxxxx-xxxxx   1/1     Running   0          5s
pod/nginx-deploy-xxxxxxxxx-xxxxx   1/1     Running   0          5s

NAME                           READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/nginx-deploy   2/2     2            2           5s

NAME                   TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)   AGE
service/nginx-deploy   ClusterIP   10.96.xxx.xxx   <none>        80/TCP    2s
```

## Exercises

### Exercise 1: Create a Pod Reader Role

**Objective**: Create a Role that allows reading pod information.

**Task**: Create a Role named `pod-reader` that grants `get`, `list`, and `watch` permissions for pods.

**Steps**:

```bash
# Method 1: Using kubectl create
kubectl create role pod-reader \
  --verb=get,list,watch \
  --resource=pods \
  --namespace=rbac-lab

# Verify creation
kubectl get role pod-reader -n rbac-lab

# View role details
kubectl describe role pod-reader -n rbac-lab

# View YAML
kubectl get role pod-reader -n rbac-lab -o yaml
```

**Expected Output** (describe):
```
Name:         pod-reader
Labels:       <none>
Annotations:  <none>
PolicyRule:
  Resources  Non-Resource URLs  Resource Names  Verbs
  ---------  -----------------  --------------  -----
  pods       []                 []              [get list watch]
```

**Alternative Method (YAML)**:

```yaml
# Save as pod-reader-role.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: rbac-lab
rules:
- apiGroups: [""]      # "" indicates core API group
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
```

Apply:
```bash
kubectl apply -f pod-reader-role.yaml
```

**Verification**:
```bash
# Check role exists
kubectl get role pod-reader -n rbac-lab

# Should show: NAME         CREATED AT
#              pod-reader   2026-02-27T10:00:00Z
```

---

### Exercise 2: Create a ServiceAccount and Bind Role

**Objective**: Create a ServiceAccount and grant it pod reading permissions.

**Steps**:

```bash
# Create ServiceAccount
kubectl create serviceaccount pod-reader-sa -n rbac-lab

# Verify creation
kubectl get serviceaccount pod-reader-sa -n rbac-lab

# Create RoleBinding
kubectl create rolebinding pod-reader-binding \
  --role=pod-reader \
  --serviceaccount=rbac-lab:pod-reader-sa \
  --namespace=rbac-lab

# Verify RoleBinding
kubectl describe rolebinding pod-reader-binding -n rbac-lab
```

**Expected Output** (describe):
```
Name:         pod-reader-binding
Labels:       <none>
Annotations:  <none>
Role:
  Kind:  Role
  Name:  pod-reader
Subjects:
  Kind            Name            Namespace
  ----            ----            ---------
  ServiceAccount  pod-reader-sa   rbac-lab
```

**Alternative YAML Method**:

```yaml
# serviceaccount.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: pod-reader-sa
  namespace: rbac-lab
---
# rolebinding.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: pod-reader-binding
  namespace: rbac-lab
subjects:
- kind: ServiceAccount
  name: pod-reader-sa
  namespace: rbac-lab
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

---

### Exercise 3: Test ServiceAccount Permissions

**Objective**: Verify the ServiceAccount has correct permissions.

**Steps**:

```bash
# Test if ServiceAccount can list pods
kubectl auth can-i list pods \
  --as=system:serviceaccount:rbac-lab:pod-reader-sa \
  --namespace=rbac-lab

# Expected output: yes

# Test if ServiceAccount can get specific pod
kubectl auth can-i get pods \
  --as=system:serviceaccount:rbac-lab:pod-reader-sa \
  --namespace=rbac-lab

# Expected output: yes

# Test if ServiceAccount can delete pods (should be denied)
kubectl auth can-i delete pods \
  --as=system:serviceaccount:rbac-lab:pod-reader-sa \
  --namespace=rbac-lab

# Expected output: no

# Test if ServiceAccount can list services (should be denied)
kubectl auth can-i list services \
  --as=system:serviceaccount:rbac-lab:pod-reader-sa \
  --namespace=rbac-lab

# Expected output: no

# List all permissions for ServiceAccount
kubectl auth can-i --list \
  --as=system:serviceaccount:rbac-lab:pod-reader-sa \
  --namespace=rbac-lab
```

**Expected Output** (--list):
```
Resources                                   Non-Resource URLs   Resource Names   Verbs
pods                                        []                  []               [get list watch]
selfsubjectaccessreviews.authorization...   []                  []               [create]
selfsubjectrulesreviews.authorization...    []                  []               [create]
```

---

### Exercise 4: Create a Pod Using the ServiceAccount

**Objective**: Deploy a pod that uses the ServiceAccount to list other pods.

**Steps**:

```yaml
# Save as pod-reader-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-reader-pod
  namespace: rbac-lab
spec:
  serviceAccountName: pod-reader-sa
  containers:
  - name: kubectl
    image: bitnami/kubectl:1.30
    command:
    - sleep
    - "3600"
```

Apply:
```bash
kubectl apply -f pod-reader-pod.yaml

# Wait for pod to be ready
kubectl wait --for=condition=ready pod/pod-reader-pod -n rbac-lab --timeout=60s

# Test listing pods from within the pod
kubectl exec -it pod-reader-pod -n rbac-lab -- \
  kubectl get pods -n rbac-lab

# Should successfully list pods

# Try to delete a pod (should fail)
kubectl exec -it pod-reader-pod -n rbac-lab -- \
  kubectl delete pod pod1 -n rbac-lab

# Expected error: Error from server (Forbidden): pods "pod1" is forbidden:
# User "system:serviceaccount:rbac-lab:pod-reader-sa" cannot delete resource "pods"
```

---

### Exercise 5: Create a Deployment Manager Role

**Objective**: Create a Role with permissions to manage deployments.

**Steps**:

```yaml
# Save as deployment-manager-role.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: deployment-manager
  namespace: rbac-lab
rules:
- apiGroups: ["apps"]         # Deployments are in 'apps' API group
  resources: ["deployments"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["apps"]
  resources: ["replicasets"]  # Deployments create ReplicaSets
  verbs: ["get", "list", "watch"]
- apiGroups: [""]             # Need to view pods
  resources: ["pods"]
  verbs: ["get", "list"]
```

Apply:
```bash
kubectl apply -f deployment-manager-role.yaml

# Verify
kubectl describe role deployment-manager -n rbac-lab
```

**Expected Output**:
```
Name:         deployment-manager
Namespace:    rbac-lab
PolicyRule:
  Resources         Non-Resource URLs  Resource Names  Verbs
  ---------         -----------------  --------------  -----
  deployments.apps  []                 []              [get list watch create update patch delete]
  replicasets.apps  []                 []              [get list watch]
  pods              []                 []              [get list]
```

---

### Exercise 6: Create ServiceAccount and Test Deployment Management

**Steps**:

```bash
# Create ServiceAccount
kubectl create serviceaccount deploy-manager-sa -n rbac-lab

# Create RoleBinding
kubectl create rolebinding deploy-manager-binding \
  --role=deployment-manager \
  --serviceaccount=rbac-lab:deploy-manager-sa \
  --namespace=rbac-lab

# Test permissions
kubectl auth can-i create deployments \
  --as=system:serviceaccount:rbac-lab:deploy-manager-sa \
  --namespace=rbac-lab
# Expected: yes

kubectl auth can-i delete deployments \
  --as=system:serviceaccount:rbac-lab:deploy-manager-sa \
  --namespace=rbac-lab
# Expected: yes

kubectl auth can-i delete pods \
  --as=system:serviceaccount:rbac-lab:deploy-manager-sa \
  --namespace=rbac-lab
# Expected: no (only get and list)
```

---

### Exercise 7: Granular Permissions with resourceNames

**Objective**: Create a Role that only allows access to specific resources.

**Steps**:

```yaml
# Save as specific-configmap-role.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: specific-configmap-reader
  namespace: rbac-lab
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["app-config", "database-config"]  # Only these ConfigMaps
  verbs: ["get", "update"]
```

```bash
# Create test ConfigMaps
kubectl create configmap app-config --from-literal=key1=value1 -n rbac-lab
kubectl create configmap database-config --from-literal=key2=value2 -n rbac-lab
kubectl create configmap other-config --from-literal=key3=value3 -n rbac-lab

# Apply role
kubectl apply -f specific-configmap-role.yaml

# Create ServiceAccount and binding
kubectl create serviceaccount configmap-reader-sa -n rbac-lab

kubectl create rolebinding configmap-reader-binding \
  --role=specific-configmap-reader \
  --serviceaccount=rbac-lab:configmap-reader-sa \
  --namespace=rbac-lab

# Test permissions
kubectl auth can-i get configmap/app-config \
  --as=system:serviceaccount:rbac-lab:configmap-reader-sa \
  --namespace=rbac-lab
# Expected: yes

kubectl auth can-i get configmap/other-config \
  --as=system:serviceaccount:rbac-lab:configmap-reader-sa \
  --namespace=rbac-lab
# Expected: no

# Note: Cannot list ConfigMaps (needs separate rule without resourceNames)
kubectl auth can-i list configmaps \
  --as=system:serviceaccount:rbac-lab:configmap-reader-sa \
  --namespace=rbac-lab
# Expected: no
```

---

### Exercise 8: Combining Multiple Rules

**Objective**: Create a comprehensive Role with multiple resource types.

**Steps**:

```yaml
# Save as app-admin-role.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-admin
  namespace: rbac-lab
rules:
# Manage pods
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch", "delete"]
# Manage deployments
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
# View and update ConfigMaps
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "create", "update", "patch"]
# View services (but not modify)
- apiGroups: [""]
  resources: ["services"]
  verbs: ["get", "list"]
```

```bash
# Apply role
kubectl apply -f app-admin-role.yaml

# Create ServiceAccount and binding
kubectl create serviceaccount app-admin-sa -n rbac-lab

kubectl create rolebinding app-admin-binding \
  --role=app-admin \
  --serviceaccount=rbac-lab:app-admin-sa \
  --namespace=rbac-lab

# Test comprehensive permissions
kubectl auth can-i --list \
  --as=system:serviceaccount:rbac-lab:app-admin-sa \
  --namespace=rbac-lab | grep -E "pods|deployments|configmaps|services"

# Test specific actions
kubectl auth can-i delete pods --as=system:serviceaccount:rbac-lab:app-admin-sa -n rbac-lab
# Expected: yes

kubectl auth can-i create deployments --as=system:serviceaccount:rbac-lab:app-admin-sa -n rbac-lab
# Expected: yes

kubectl auth can-i delete services --as=system:serviceaccount:rbac-lab:app-admin-sa -n rbac-lab
# Expected: no (only get and list)
```

---

### Exercise 9: Troubleshooting RBAC Issues

**Objective**: Practice diagnosing and fixing permission problems.

**Scenario 1: Missing API Group**

```yaml
# Save as broken-role-1.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: broken-deploy-reader
  namespace: rbac-lab
rules:
- apiGroups: [""]           # WRONG: Deployments are in 'apps' group
  resources: ["deployments"]
  verbs: ["get", "list"]
```

```bash
# Apply broken role
kubectl apply -f broken-role-1.yaml

# Create ServiceAccount and binding
kubectl create serviceaccount broken-sa-1 -n rbac-lab
kubectl create rolebinding broken-binding-1 \
  --role=broken-deploy-reader \
  --serviceaccount=rbac-lab:broken-sa-1 \
  --namespace=rbac-lab

# Test - will fail
kubectl auth can-i get deployments \
  --as=system:serviceaccount:rbac-lab:broken-sa-1 \
  --namespace=rbac-lab
# Output: no

# FIX: Update apiGroups
kubectl patch role broken-deploy-reader -n rbac-lab --type='json' \
  -p='[{"op": "replace", "path": "/rules/0/apiGroups", "value": ["apps"]}]'

# Test again - now works
kubectl auth can-i get deployments \
  --as=system:serviceaccount:rbac-lab:broken-sa-1 \
  --namespace=rbac-lab
# Output: yes
```

**Scenario 2: Wrong Namespace in RoleBinding**

```bash
# Create role in rbac-lab namespace
kubectl create role test-role \
  --verb=get \
  --resource=pods \
  --namespace=rbac-lab

# Create RoleBinding in WRONG namespace
kubectl create rolebinding test-binding \
  --role=test-role \
  --serviceaccount=rbac-lab:pod-reader-sa \
  --namespace=default       # WRONG namespace!

# Test - will fail because RoleBinding is in wrong namespace
kubectl auth can-i get pods \
  --as=system:serviceaccount:rbac-lab:pod-reader-sa \
  --namespace=rbac-lab
# Output: no (if only this binding exists)

# FIX: Delete wrong binding and create in correct namespace
kubectl delete rolebinding test-binding -n default

kubectl create rolebinding test-binding \
  --role=test-role \
  --serviceaccount=rbac-lab:pod-reader-sa \
  --namespace=rbac-lab      # Correct namespace

# Test again - now works
kubectl auth can-i get pods \
  --as=system:serviceaccount:rbac-lab:pod-reader-sa \
  --namespace=rbac-lab
# Output: yes
```

---

## Verification

Run these commands to verify your lab completion:

```bash
# 1. Check all created roles
kubectl get roles -n rbac-lab

# Expected output should include:
# - pod-reader
# - deployment-manager
# - specific-configmap-reader
# - app-admin

# 2. Check all RoleBindings
kubectl get rolebindings -n rbac-lab

# Should list all created bindings

# 3. Check all ServiceAccounts
kubectl get serviceaccounts -n rbac-lab

# Should show custom ServiceAccounts created

# 4. Verify pod-reader permissions
kubectl auth can-i list pods \
  --as=system:serviceaccount:rbac-lab:pod-reader-sa \
  --namespace=rbac-lab
# Expected: yes

# 5. Verify deployment-manager permissions
kubectl auth can-i create deployments \
  --as=system:serviceaccount:rbac-lab:deploy-manager-sa \
  --namespace=rbac-lab
# Expected: yes

# 6. Verify resourceNames restriction
kubectl auth can-i get configmap/app-config \
  --as=system:serviceaccount:rbac-lab:configmap-reader-sa \
  --namespace=rbac-lab
# Expected: yes

kubectl auth can-i get configmap/other-config \
  --as=system:serviceaccount:rbac-lab:configmap-reader-sa \
  --namespace=rbac-lab
# Expected: no
```

## Solutions

All exercise solutions are provided inline above. Key concepts:

### Solution 1: Pod Reader Role
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: rbac-lab
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
```

### Solution 2: RoleBinding to ServiceAccount
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: pod-reader-binding
  namespace: rbac-lab
subjects:
- kind: ServiceAccount
  name: pod-reader-sa
  namespace: rbac-lab
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

### Testing Pattern
```bash
kubectl auth can-i <verb> <resource> \
  --as=system:serviceaccount:<namespace>:<sa-name> \
  --namespace=<namespace>
```

## Troubleshooting

### Issue: "no" when testing permissions

**Check**:
1. Role exists: `kubectl get role <role> -n <namespace>`
2. RoleBinding exists: `kubectl get rolebinding <binding> -n <namespace>`
3. RoleBinding references correct role: `kubectl describe rolebinding <binding> -n <namespace>`
4. ServiceAccount name spelled correctly in RoleBinding
5. Namespace matches between Role and RoleBinding
6. API group correct for resource (use `kubectl api-resources`)

### Issue: Can't find API group for resource

```bash
# List all resources with their API groups
kubectl api-resources | grep <resource-name>

# Example for deployments:
kubectl api-resources | grep deployments
# Output: deployments    deploy    apps/v1    true    Deployment
#                                   ^^^^^^^^
#                                   API group is 'apps'
```

### Issue: resourceNames not working

**Remember**: `resourceNames` only works with specific verbs (get, update, delete, etc.), not with list or watch.

**Fix**: Add separate rule for list without resourceNames:
```yaml
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["list"]          # List without restriction
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["app-config"]
  verbs: ["get", "update"]  # Specific resource operations
```

## Cleanup

```bash
# Delete all lab resources
kubectl delete namespace rbac-lab

# Verify deletion
kubectl get namespace rbac-lab
# Expected: Error from server (NotFound): namespaces "rbac-lab" not found

# Reset context if you changed it
kubectl config set-context --current --namespace=default
```

## Key Takeaways

1. **Roles are namespace-scoped**: Only apply within their namespace
2. **API groups matter**: Use `kubectl api-resources` to find correct groups
3. **Test everything**: Always use `kubectl auth can-i` to verify
4. **ServiceAccount format**: `system:serviceaccount:NAMESPACE:NAME`
5. **RoleBinding location**: Must be in the same namespace as the Role (for namespace-scoped)
6. **resourceNames limitation**: Doesn't work with list/watch verbs
7. **Least privilege**: Grant only minimum required permissions

## Next Steps

- Complete [Lab 02: RBAC Advanced](lab-02-rbac-advanced.md) for cluster-scoped RBAC
- Review [RBAC theory](../../domains/02-cluster-hardening/rbac.md) for deeper understanding
- Practice creating roles for real-world scenarios
- Experiment with different permission combinations

## Additional Practice

Try creating roles for these scenarios:

1. **Log Reader**: Can read pod logs but not modify pods
2. **Secret Manager**: Can create and update secrets but not read them
3. **Namespace Admin**: Full access to all resources in namespace except RBAC
4. **Read-Only User**: Can view all resources but not modify anything

---

**Congratulations!** You've completed Lab 01: RBAC Basics. You now understand how to create namespace-scoped roles, bind them to ServiceAccounts, and test permissions.
