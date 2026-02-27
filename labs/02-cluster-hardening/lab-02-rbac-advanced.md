# Lab 02: RBAC Advanced

## Objective

Master advanced RBAC concepts including ClusterRoles, ClusterRoleBindings, aggregated roles, and cross-namespace access patterns. This lab builds on Lab 01 and explores cluster-scoped permissions and complex RBAC scenarios.

**What You'll Learn**:

- Create and use ClusterRoles and ClusterRoleBindings
- Implement aggregated ClusterRoles
- Configure cross-namespace access
- Use built-in roles (admin, edit, view, cluster-admin)
- Design RBAC for complex multi-tenant scenarios

## Prerequisites

- Completed [Lab 01: RBAC Basics](lab-01-rbac-basics.md)
- Kubernetes cluster running
- kubectl v1.30.x configured
- Understanding of namespace-scoped RBAC

## Lab Duration

60-75 minutes

## Lab Setup

```bash
# Create multiple namespaces for multi-tenant scenario

kubectl create namespace team-a
kubectl create namespace team-b
kubectl create namespace shared-services

# Create test resources in each namespace

kubectl run nginx --image=nginx:1.27 -n team-a
kubectl run nginx --image=nginx:1.27 -n team-b
kubectl run nginx --image=nginx:1.27 -n shared-services

kubectl create deployment app --image=nginx:1.27 --replicas=2 -n team-a
kubectl create deployment app --image=nginx:1.27 --replicas=2 -n team-b

# Verify setup

kubectl get pods --all-namespaces | grep -E "team-a|team-b|shared"
```

## Exercises

### Exercise 1: Create a ClusterRole for Node Viewing

**Objective**: Create a ClusterRole to view cluster-scoped resources.

```yaml
# Save as node-viewer-clusterrole.yaml

apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: node-viewer
rules:
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["persistentvolumes"]
  verbs: ["get", "list"]
```

```
# Apply ClusterRole

kubectl apply -f node-viewer-clusterrole.yaml

# Create ServiceAccount

kubectl create serviceaccount node-viewer-sa -n default

# Create ClusterRoleBinding

kubectl create clusterrolebinding node-viewer-binding \
  --clusterrole=node-viewer \
  --serviceaccount=default:node-viewer-sa

# Test permissions

kubectl auth can-i list nodes \
  --as=system:serviceaccount:default:node-viewer-sa

# Expected: yes

kubectl auth can-i list persistentvolumes \
  --as=system:serviceaccount:default:node-viewer-sa

# Expected: yes

# Test that it cannot modify

kubectl auth can-i delete nodes \
  --as=system:serviceaccount:default:node-viewer-sa

# Expected: no

```

---

### Exercise 2: Use ClusterRole with RoleBinding (Cross-Namespace Pattern)

**Objective**: Use a single ClusterRole with multiple RoleBindings for namespace-specific access.

```yaml
# Save as pod-manager-clusterrole.yaml

apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pod-manager
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch", "create", "delete"]
```

```
# Apply ClusterRole

kubectl apply -f pod-manager-clusterrole.yaml

# Create ServiceAccount for Team A

kubectl create serviceaccount team-a-pods -n team-a

# Bind ClusterRole to team-a namespace only

kubectl create rolebinding team-a-pod-manager \
  --clusterrole=pod-manager \
  --serviceaccount=team-a:team-a-pods \
  --namespace=team-a

# Create ServiceAccount for Team B

kubectl create serviceaccount team-b-pods -n team-b

# Bind same ClusterRole to team-b namespace

kubectl create rolebinding team-b-pod-manager \
  --clusterrole=pod-manager \
  --serviceaccount=team-b:team-b-pods \
  --namespace=team-b

# Test Team A can manage pods in team-a

kubectl auth can-i delete pods \
  --as=system:serviceaccount:team-a:team-a-pods \
  --namespace=team-a

# Expected: yes

# Test Team A cannot access team-b

kubectl auth can-i delete pods \
  --as=system:serviceaccount:team-a:team-a-pods \
  --namespace=team-b

# Expected: no

# Test Team B can manage pods in team-b

kubectl auth can-i delete pods \
  --as=system:serviceaccount:team-b:team-b-pods \
  --namespace=team-b

# Expected: yes

```

**Key Point**: ClusterRole is reusable, RoleBinding limits scope to namespace.

---

### Exercise 3: Aggregated ClusterRoles

**Objective**: Create modular ClusterRoles that aggregate into a single role.

```yaml
# Save as aggregated-monitoring-role.yaml
# 1. Main aggregated role (rules auto-filled by matching labels)

apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: monitoring-aggregate
aggregationRule:
  clusterRoleSelectors:
  - matchLabels:
      rbac.monitoring/aggregate: "true"
rules: []  # Rules are automatically filled
---

# 2. Pod monitoring component

apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: monitoring-pods
  labels:
    rbac.monitoring/aggregate: "true"
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch"]
---

# 3. Node monitoring component

apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: monitoring-nodes
  labels:
    rbac.monitoring/aggregate: "true"
rules:
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get", "list"]
---

# 4. Metrics component

apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: monitoring-metrics
  labels:
    rbac.monitoring/aggregate: "true"
rules:
- nonResourceURLs: ["/metrics", "/metrics/cadvisor"]
  verbs: ["get"]
```

```
# Apply all components

kubectl apply -f aggregated-monitoring-role.yaml

# Wait a moment for aggregation

sleep 2

# View aggregated role

kubectl describe clusterrole monitoring-aggregate

# Expected output shows all rules from component roles combined

# Create ServiceAccount and bind

kubectl create serviceaccount prometheus -n default
kubectl create clusterrolebinding prometheus-binding \
  --clusterrole=monitoring-aggregate \
  --serviceaccount=default:prometheus

# Test aggregated permissions

kubectl auth can-i get pods --as=system:serviceaccount:default:prometheus

# Expected: yes

kubectl auth can-i get nodes --as=system:serviceaccount:default:prometheus

# Expected: yes

kubectl auth can-i get /metrics --as=system:serviceaccount:default:prometheus

# Expected: yes

```

**Benefits**:

- Modular role composition
- Easy to add new permissions (just add labeled ClusterRole)
- Cleaner organization

---

### Exercise 4: Built-in ClusterRoles

**Objective**: Use Kubernetes built-in ClusterRoles.

```bash
# View built-in ClusterRoles

kubectl get clusterroles | grep -E "^admin|^edit|^view|^cluster-admin"

# Describe admin role

kubectl describe clusterrole admin | head -30

# Grant admin access to team-a namespace

kubectl create serviceaccount admin-sa -n team-a
kubectl create rolebinding admin-binding \
  --clusterrole=admin \
  --serviceaccount=team-a:admin-sa \
  --namespace=team-a

# Test admin permissions in team-a

kubectl auth can-i '*' '*' \
  --as=system:serviceaccount:team-a:admin-sa \
  --namespace=team-a

# Expected: yes (full namespace access)

# Grant edit access to team-b

kubectl create serviceaccount edit-sa -n team-b
kubectl create rolebinding edit-binding \
  --clusterrole=edit \
  --serviceaccount=team-b:edit-sa \
  --namespace=team-b

# Test edit permissions (cannot manage RBAC)

kubectl auth can-i create deployments \
  --as=system:serviceaccount:team-b:edit-sa \
  --namespace=team-b

# Expected: yes

kubectl auth can-i create roles \
  --as=system:serviceaccount:team-b:edit-sa \
  --namespace=team-b

# Expected: no (edit cannot manage RBAC)

# Grant view access to shared-services

kubectl create serviceaccount view-sa -n shared-services
kubectl create rolebinding view-binding \
  --clusterrole=view \
  --serviceaccount=shared-services:view-sa \
  --namespace=shared-services

# Test view permissions (read-only)

kubectl auth can-i get pods \
  --as=system:serviceaccount:shared-services:view-sa \
  --namespace=shared-services

# Expected: yes

kubectl auth can-i delete pods \
  --as=system:serviceaccount:shared-services:view-sa \
  --namespace=shared-services

# Expected: no

```

**Built-in Roles Summary**:

- **cluster-admin**: Full cluster access (dangerous!)
- **admin**: Full namespace access including RBAC
- **edit**: Read/write access, no RBAC management
- **view**: Read-only access

---

### Exercise 5: Cross-Namespace Access

**Objective**: Grant ServiceAccount from one namespace access to another.

```yaml
# Save as cross-namespace-access.yaml
# ServiceAccount in team-a accessing team-b resources

apiVersion: v1
kind: ServiceAccount
metadata:
  name: cross-ns-sa
  namespace: team-a
---

# Role in team-b

apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: team-b
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
---

# RoleBinding in team-b referencing ServiceAccount from team-a

apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cross-ns-binding
  namespace: team-b
subjects:
- kind: ServiceAccount
  name: cross-ns-sa
  namespace: team-a      # Different namespace!
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

```
# Apply configuration

kubectl apply -f cross-namespace-access.yaml

# Test access from team-a SA to team-b resources

kubectl auth can-i list pods \
  --as=system:serviceaccount:team-a:cross-ns-sa \
  --namespace=team-b

# Expected: yes

# Verify no access to team-a itself

kubectl auth can-i list pods \
  --as=system:serviceaccount:team-a:cross-ns-sa \
  --namespace=team-a

# Expected: no (no binding in team-a)

```

---

### Exercise 6: Cluster-Wide Viewer

**Objective**: Create a ServiceAccount with read-only access across entire cluster.

```yaml
# Save as cluster-viewer.yaml

apiVersion: v1
kind: ServiceAccount
metadata:
  name: cluster-viewer
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-viewer
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps", "namespaces", "nodes"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets", "statefulsets", "daemonsets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["batch"]
  resources: ["jobs", "cronjobs"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cluster-viewer-binding
subjects:
- kind: ServiceAccount
  name: cluster-viewer
  namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-viewer
  apiGroup: rbac.authorization.k8s.io
```

```
# Apply configuration

kubectl apply -f cluster-viewer.yaml

# Test cluster-wide read access

kubectl auth can-i list pods --all-namespaces \
  --as=system:serviceaccount:default:cluster-viewer

# Expected: yes

kubectl auth can-i get nodes \
  --as=system:serviceaccount:default:cluster-viewer

# Expected: yes

# Verify no write access

kubectl auth can-i delete pods --all-namespaces \
  --as=system:serviceaccount:default:cluster-viewer

# Expected: no

# Create pod using this ServiceAccount

kubectl run viewer-pod --image=bitnami/kubectl:1.30 \
  --serviceaccount=cluster-viewer \
  --command -- sleep 3600

# From pod, test cluster access

kubectl exec -it viewer-pod -- kubectl get nodes

# Should succeed

kubectl exec -it viewer-pod -- kubectl get pods --all-namespaces

# Should succeed

```

---

### Exercise 7: CI/CD Deployer Role

**Objective**: Create a realistic CI/CD ServiceAccount with deploy permissions.

```yaml
# Save as cicd-deployer.yaml

apiVersion: v1
kind: ServiceAccount
metadata:
  name: cicd-deployer
  namespace: team-a
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cicd-deploy-role
  namespace: team-a
rules:

# Manage deployments

- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]

# Manage services

- apiGroups: [""]
  resources: ["services"]
  verbs: ["get", "list", "create", "update", "patch"]

# Manage ConfigMaps

- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "create", "update", "patch"]

# View pods for status checking

- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch"]

# Check deployment status

- apiGroups: ["apps"]
  resources: ["deployments/status"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cicd-deploy-binding
  namespace: team-a
subjects:
- kind: ServiceAccount
  name: cicd-deployer
  namespace: team-a
roleRef:
  kind: Role
  name: cicd-deploy-role
  apiGroup: rbac.authorization.k8s.io
```

```
# Apply configuration

kubectl apply -f cicd-deployer.yaml

# Test deployment capabilities

kubectl auth can-i create deployments \
  --as=system:serviceaccount:team-a:cicd-deployer \
  --namespace=team-a

# Expected: yes

kubectl auth can-i update services \
  --as=system:serviceaccount:team-a:cicd-deployer \
  --namespace=team-a

# Expected: yes

# Verify cannot delete pods directly

kubectl auth can-i delete pods \
  --as=system:serviceaccount:team-a:cicd-deployer \
  --namespace=team-a

# Expected: no

# Simulate CI/CD deployment

kubectl run cicd-test --image=bitnami/kubectl:1.30 \
  --serviceaccount=cicd-deployer \
  -n team-a \
  --command -- sleep 3600

# From pod, test deployment

kubectl exec -it cicd-test -n team-a -- \
  kubectl create deployment test-app --image=nginx:1.27 -n team-a

# Should succeed

kubectl exec -it cicd-test -n team-a -- \
  kubectl get deployments -n team-a

# Should list deployments including test-app

```

---

### Exercise 8: Namespace Admin with RBAC Restrictions

**Objective**: Create namespace admin that cannot modify certain resources.

```yaml
# Save as restricted-admin.yaml

apiVersion: v1
kind: ServiceAccount
metadata:
  name: restricted-admin
  namespace: team-b
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: restricted-admin-role
  namespace: team-b
rules:

# Full access to most resources

- apiGroups: ["", "apps", "batch"]
  resources: ["*"]
  verbs: ["*"]

# Explicitly deny RBAC management
# (Note: RBAC doesn't have explicit deny, so we omit rbac.authorization.k8s.io)

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: restricted-admin-binding
  namespace: team-b
subjects:
- kind: ServiceAccount
  name: restricted-admin
  namespace: team-b
roleRef:
  kind: Role
  name: restricted-admin-role
  apiGroup: rbac.authorization.k8s.io
```

```
# Apply configuration

kubectl apply -f restricted-admin.yaml

# Test full access to apps

kubectl auth can-i '*' 'deployments' \
  --as=system:serviceaccount:team-b:restricted-admin \
  --namespace=team-b

# Expected: yes

kubectl auth can-i '*' 'pods' \
  --as=system:serviceaccount:team-b:restricted-admin \
  --namespace=team-b

# Expected: yes

# Test cannot manage RBAC

kubectl auth can-i create roles \
  --as=system:serviceaccount:team-b:restricted-admin \
  --namespace=team-b

# Expected: no

kubectl auth can-i create rolebindings \
  --as=system:serviceaccount:team-b:restricted-admin \
  --namespace=team-b

# Expected: no

```

---

## Verification

```bash
# 1. Verify ClusterRoles exist

kubectl get clusterroles | grep -E "node-viewer|pod-manager|monitoring-aggregate|cluster-viewer"

# 2. Verify ClusterRoleBindings

kubectl get clusterrolebindings | grep -E "node-viewer|prometheus|cluster-viewer"

# 3. Test aggregated role

kubectl describe clusterrole monitoring-aggregate | grep -A5 "Rules:"

# 4. Verify cross-namespace access

kubectl auth can-i list pods \
  --as=system:serviceaccount:team-a:cross-ns-sa \
  --namespace=team-b

# Expected: yes

# 5. Verify cluster-wide viewer

kubectl auth can-i get nodes \
  --as=system:serviceaccount:default:cluster-viewer

# Expected: yes

# 6. List all custom ClusterRoles

kubectl get clusterroles --no-headers | grep -v "system:" | head -10
```

## Cleanup

```bash
# Delete test namespaces (cascades all resources)

kubectl delete namespace team-a
kubectl delete namespace team-b
kubectl delete namespace shared-services

# Delete cluster-scoped resources

kubectl delete clusterrole node-viewer pod-manager monitoring-aggregate monitoring-pods monitoring-nodes monitoring-metrics cluster-viewer
kubectl delete clusterrolebinding node-viewer-binding prometheus-binding cluster-viewer-binding

# Delete any remaining test pods

kubectl delete pod viewer-pod --ignore-not-found
kubectl delete pod cicd-test -n team-a --ignore-not-found
```

## Key Takeaways

1. **ClusterRole vs Role**: ClusterRole is cluster-scoped, can be used with both ClusterRoleBinding (cluster-wide) and RoleBinding (namespace-scoped)
1. **Reusability**: ClusterRoles are reusable across namespaces with RoleBindings
1. **Aggregation**: Break down complex roles into modular components with labels
1. **Built-in roles**: Use admin, edit, view when they fit your needs
1. **Cross-namespace**: ServiceAccounts can access other namespaces with appropriate RoleBindings
1. **Least privilege**: Even with ClusterRoles, scope access with RoleBindings when possible

## Additional Practice

Create RBAC for these scenarios:

1. **Multi-cluster monitor**: Read-only access to all resources plus /healthz endpoint
1. **Backup operator**: Read secrets and configmaps cluster-wide
1. **Network admin**: Manage NetworkPolicies and Services cluster-wide
1. **Security auditor**: Read all resources including secrets but cannot modify

## Next Steps

- Complete [Lab 03: Service Accounts](lab-03-service-accounts.md)
- Review [ServiceAccounts theory](../../domains/02-cluster-hardening/service-accounts.md)
- Practice creating complex multi-tenant RBAC scenarios

---

**Congratulations!** You've mastered advanced RBAC concepts including ClusterRoles, aggregation, and cross-namespace access patterns.
