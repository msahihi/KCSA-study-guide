# Role-Based Access Control (RBAC)

## Introduction

**Role-Based Access Control (RBAC)** is Kubernetes' primary authorization mechanism that regulates access to cluster resources based on roles assigned to users, groups, or service accounts. RBAC is fundamental to cluster security and represents approximately **8-10% of the KCSA exam**.

**What RBAC Does**:
- Controls who can access which Kubernetes resources
- Defines what actions users can perform (read, create, delete, etc.)
- Implements the principle of least privilege
- Provides granular, namespace-scoped or cluster-wide permissions

**Real-World Scenario**: Your organization has three teams:
- **DevOps Team**: Needs full access to all cluster resources
- **Development Team**: Needs to deploy apps in their namespace only
- **QA Team**: Needs read-only access to testing namespaces

Without RBAC, everyone would have the same access level, creating security risks. With RBAC, you grant each team exactly the permissions they need, nothing more.

## Authentication vs Authorization

Before diving into RBAC, understand the difference:

### Authentication (Who are you?)
- **Proves identity**: Are you who you claim to be?
- **Mechanisms**: X.509 certificates, bearer tokens, authentication webhooks, OIDC
- **Kubernetes users**: Not stored in Kubernetes (managed externally)
- **ServiceAccounts**: Kubernetes-native accounts for pods

### Authorization (What can you do?)
- **Grants permissions**: What actions are you allowed to perform?
- **Mechanisms**: RBAC, ABAC, Node Authorization, Webhook
- **Default mode**: RBAC (enabled by default in modern Kubernetes)
- **Decision**: Allow or deny API requests

**Flow**: User authenticates → API server authorizes → Action allowed/denied

## RBAC Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────┐
│                    RBAC Components                       │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  PERMISSIONS                     BINDINGS                │
│  ┌────────────┐                 ┌──────────────┐       │
│  │   Role     │────────────────▶│ RoleBinding  │       │
│  │ (namespace)│                 │  (namespace)  │       │
│  └────────────┘                 └──────────────┘       │
│       │                                 │               │
│       │ defines permissions             │ binds to      │
│       │                                 │               │
│  ┌────────────┐                 ┌──────────────┐       │
│  │ ClusterRole│────────────────▶│ClusterRole   │       │
│  │  (cluster) │                 │   Binding    │       │
│  └────────────┘                 │  (cluster)   │       │
│                                  └──────────────┘       │
│                                         │               │
│                                         ▼               │
│                                  ┌──────────────┐       │
│                                  │   Subjects   │       │
│                                  │ ─────────── │       │
│                                  │ • Users      │       │
│                                  │ • Groups     │       │
│                                  │ • SvcAccounts│       │
│                                  └──────────────┘       │
└─────────────────────────────────────────────────────────┘
```

### 1. Role (Namespace-scoped)
**Defines permissions within a specific namespace**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: development
  name: pod-reader
rules:
- apiGroups: [""]  # "" indicates core API group
  resources: ["pods"]
  verbs: ["get", "watch", "list"]
```

**Key Fields**:
- `apiGroups`: API groups that contain the resources (e.g., `""` for core, `apps` for Deployments)
- `resources`: Kubernetes resources (pods, services, deployments, etc.)
- `verbs`: Actions allowed (get, list, create, update, delete, watch, etc.)

### 2. ClusterRole (Cluster-wide)
**Defines permissions across the entire cluster or for cluster-scoped resources**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secret-reader
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "watch", "list"]
```

**Use Cases**:
- Cluster-scoped resources (nodes, persistentvolumes, namespaces)
- Non-resource endpoints (`/healthz`, `/metrics`)
- Reusable roles across multiple namespaces

### 3. RoleBinding (Namespace-scoped)
**Binds a Role or ClusterRole to subjects within a namespace**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: development
subjects:
- kind: User
  name: jane
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

**Important**: A RoleBinding can reference a ClusterRole but only grants permissions within the binding's namespace.

### 4. ClusterRoleBinding (Cluster-wide)
**Binds a ClusterRole to subjects across the entire cluster**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: read-secrets-global
subjects:
- kind: Group
  name: manager
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: secret-reader
  apiGroup: rbac.authorization.k8s.io
```

## Subjects: Who Gets Permissions

### User
**External human users** (not stored in Kubernetes)

```yaml
subjects:
- kind: User
  name: jane@example.com
  apiGroup: rbac.authorization.k8s.io
```

### Group
**Collection of users** (managed by authentication system)

```yaml
subjects:
- kind: Group
  name: system:developers
  apiGroup: rbac.authorization.k8s.io
```

**Common Groups**:
- `system:authenticated`: All authenticated users
- `system:unauthenticated`: Unauthenticated users
- `system:serviceaccounts`: All service accounts
- `system:serviceaccounts:<namespace>`: All service accounts in a namespace

### ServiceAccount
**Kubernetes-managed accounts for pods**

```yaml
subjects:
- kind: ServiceAccount
  name: my-service-account
  namespace: production
```

## API Groups and Resources

### Core API Group (`""`)
Resources without a group prefix:

```yaml
apiGroups: [""]
resources:
  - pods
  - services
  - configmaps
  - secrets
  - persistentvolumeclaims
  - serviceaccounts
```

### Named API Groups

```yaml
# apps API group
apiGroups: ["apps"]
resources:
  - deployments
  - statefulsets
  - daemonsets
  - replicasets

# batch API group
apiGroups: ["batch"]
resources:
  - jobs
  - cronjobs

# rbac.authorization.k8s.io
apiGroups: ["rbac.authorization.k8s.io"]
resources:
  - roles
  - rolebindings
  - clusterroles
  - clusterrolebindings
```

### Finding API Groups

```bash
# List all API resources with their groups
kubectl api-resources

# Get specific resource information
kubectl api-resources | grep deployments
# Output: deployments    deploy   apps/v1    true    Deployment

# Explain resource to see API group
kubectl explain deployment
```

## Verbs: What Actions Are Allowed

### Common Verbs

| Verb | Description | HTTP Method |
|------|-------------|-------------|
| `get` | Read a specific resource | GET |
| `list` | Read all resources of a type | GET |
| `watch` | Watch for resource changes | GET (streaming) |
| `create` | Create new resources | POST |
| `update` | Modify existing resources | PUT |
| `patch` | Partially modify resources | PATCH |
| `delete` | Remove resources | DELETE |
| `deletecollection` | Remove multiple resources | DELETE |

### Special Verbs

```yaml
verbs:
  - use           # For PodSecurityPolicies
  - bind          # For escalation prevention
  - escalate      # For role/clusterrole creation
  - impersonate   # For impersonating users/groups
```

### Wildcard Verb

```yaml
# Grant all actions (avoid in production)
verbs: ["*"]
```

## Resource Names (Granular Permissions)

Restrict permissions to specific resource instances:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: production
  name: configmap-updater
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["app-config", "database-config"]
  verbs: ["get", "update"]
```

**Use Case**: Allow updating specific ConfigMaps but not creating new ones.

## Subresources

Grant access to resource subresources:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-logger
  namespace: development
rules:
- apiGroups: [""]
  resources: ["pods/log"]  # Subresource
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["pods/exec"]  # Another subresource
  verbs: ["create"]
```

**Common Subresources**:
- `pods/log`: Pod logs
- `pods/exec`: Execute commands in pods
- `pods/portforward`: Port forwarding
- `deployments/scale`: Scale deployments
- `services/proxy`: Proxy to services

## Common RBAC Patterns

### Pattern 1: Namespace Admin

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: development
  name: namespace-admin
rules:
- apiGroups: ["", "apps", "batch"]
  resources: ["*"]
  verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: dev-admin-binding
  namespace: development
subjects:
- kind: User
  name: alice
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: namespace-admin
  apiGroup: rbac.authorization.k8s.io
```

### Pattern 2: Read-Only Cluster Viewer

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-viewer
rules:
- apiGroups: [""]
  resources: ["pods", "services", "nodes", "namespaces"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets", "statefulsets"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: viewer-binding
subjects:
- kind: Group
  name: viewers
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: cluster-viewer
  apiGroup: rbac.authorization.k8s.io
```

### Pattern 3: ServiceAccount for Application

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
  namespace: production
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: production
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["app-secret"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-binding
  namespace: production
subjects:
- kind: ServiceAccount
  name: app-sa
  namespace: production
roleRef:
  kind: Role
  name: app-role
  apiGroup: rbac.authorization.k8s.io
```

### Pattern 4: Multi-Namespace Access with ClusterRole

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pod-manager
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "create", "delete"]
---
# Grant access in dev namespace
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: pod-manager-dev
  namespace: development
subjects:
- kind: User
  name: bob
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: pod-manager
  apiGroup: rbac.authorization.k8s.io
---
# Grant access in staging namespace
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: pod-manager-staging
  namespace: staging
subjects:
- kind: User
  name: bob
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: pod-manager
  apiGroup: rbac.authorization.k8s.io
```

## Aggregated ClusterRoles

Combine multiple ClusterRoles into one using label selectors:

```yaml
# Define a base aggregated role
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: monitoring-aggregate
aggregationRule:
  clusterRoleSelectors:
  - matchLabels:
      rbac.example.com/aggregate-to-monitoring: "true"
rules: []  # Rules are automatically filled
---
# Define component roles
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: monitoring-pods
  labels:
    rbac.example.com/aggregate-to-monitoring: "true"
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: monitoring-metrics
  labels:
    rbac.example.com/aggregate-to-monitoring: "true"
rules:
- nonResourceURLs: ["/metrics"]
  verbs: ["get"]
```

**Benefits**:
- Modular role composition
- Easier maintenance
- Used by Kubernetes built-in roles (admin, edit, view)

## Default ClusterRoles

Kubernetes provides several built-in ClusterRoles:

### cluster-admin
**Superuser access to cluster**

```bash
kubectl describe clusterrole cluster-admin
```

**Permissions**: Full access to all resources
**Use case**: Cluster administrators only

### admin
**Namespace administration**

**Permissions**: Full access within a namespace, including RBAC
**Use case**: Namespace owners

### edit
**Read/write access to most resources**

**Permissions**: Create/update resources but not RBAC
**Use case**: Developers who deploy applications

### view
**Read-only access**

**Permissions**: View resources but no secrets
**Use case**: Read-only users, monitoring systems

### Example Usage

```bash
# Grant namespace admin access
kubectl create rolebinding admin-binding \
  --clusterrole=admin \
  --user=alice \
  --namespace=development

# Grant view access
kubectl create rolebinding viewer-binding \
  --clusterrole=view \
  --serviceaccount=monitoring:prometheus \
  --namespace=production
```

## Testing RBAC Permissions

### kubectl auth can-i

Test if a user can perform an action:

```bash
# Test current user permissions
kubectl auth can-i create deployments --namespace=development

# Test as another user
kubectl auth can-i delete pods --as=jane --namespace=production

# Test as a service account
kubectl auth can-i get secrets \
  --as=system:serviceaccount:development:app-sa \
  --namespace=development

# List all permissions for a user
kubectl auth can-i --list --as=jane --namespace=development

# Test non-resource URLs
kubectl auth can-i get /logs --as=bob
```

### Output Examples

```bash
$ kubectl auth can-i create deployments
yes

$ kubectl auth can-i delete nodes
no

$ kubectl auth can-i '*' '*' --as=system:serviceaccount:default:default
no
```

### Impersonation for Testing

```bash
# Run commands as another user
kubectl get pods --as=jane --namespace=development

# Run as a service account
kubectl get secrets --as=system:serviceaccount:prod:app-sa -n prod

# Run as a group member
kubectl get nodes --as=alice --as-group=system:developers
```

## Creating RBAC Resources

### Using kubectl create

```bash
# Create a Role
kubectl create role pod-reader \
  --verb=get,list,watch \
  --resource=pods \
  --namespace=development

# Create a ClusterRole
kubectl create clusterrole secret-reader \
  --verb=get,list \
  --resource=secrets

# Create a RoleBinding
kubectl create rolebinding read-pods \
  --role=pod-reader \
  --user=jane \
  --namespace=development

# Create a ClusterRoleBinding
kubectl create clusterrolebinding cluster-admin-binding \
  --clusterrole=cluster-admin \
  --user=admin@example.com

# Bind to a ServiceAccount
kubectl create rolebinding app-binding \
  --role=app-role \
  --serviceaccount=production:app-sa \
  --namespace=production

# Bind to a group
kubectl create rolebinding dev-edit \
  --clusterrole=edit \
  --group=developers \
  --namespace=development
```

### Using YAML Manifests

For complex roles, YAML is more maintainable:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: deployment-manager
  namespace: production
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
- apiGroups: ["apps"]
  resources: ["deployments/scale"]
  verbs: ["update"]
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list"]
```

Apply with:

```bash
kubectl apply -f role.yaml
```

## Troubleshooting RBAC

### Common Issues

#### 1. Permission Denied

```
Error from server (Forbidden): pods is forbidden:
User "jane" cannot list resource "pods" in API group "" in the namespace "default"
```

**Troubleshooting Steps**:

```bash
# Check if user has permission
kubectl auth can-i list pods --as=jane --namespace=default

# List user's roles
kubectl get rolebindings,clusterrolebindings \
  -o custom-columns='KIND:.kind,NAME:.metadata.name,SUBJECT:.subjects[*].name' | \
  grep jane

# Describe specific binding
kubectl describe rolebinding <binding-name> --namespace=default
```

#### 2. Wrong Namespace

RoleBindings only apply to their namespace:

```bash
# This binding only works in 'development' namespace
kubectl create rolebinding read-pods \
  --role=pod-reader \
  --user=jane \
  --namespace=development

# Jane cannot list pods in other namespaces
kubectl auth can-i list pods --as=jane --namespace=production  # no
```

#### 3. Missing API Group

```yaml
# WRONG - missing API group for deployments
rules:
- apiGroups: [""]  # Core API group
  resources: ["deployments"]  # Deployments are in 'apps' group!
  verbs: ["get"]

# CORRECT
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get"]
```

#### 4. Verb Mismatch

```bash
# Role allows 'get' but not 'list'
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get"]

# This works
kubectl get pod my-pod

# This fails
kubectl get pods  # Requires 'list' verb
```

### Debugging Commands

```bash
# View all Roles in a namespace
kubectl get roles -n development

# View all ClusterRoles
kubectl get clusterroles

# View all RoleBindings in a namespace
kubectl get rolebindings -n development

# View all ClusterRoleBindings
kubectl get clusterrolebindings

# Describe a Role
kubectl describe role pod-reader -n development

# Get Role in YAML format
kubectl get role pod-reader -n development -o yaml

# Find all bindings for a user
kubectl get rolebindings,clusterrolebindings --all-namespaces \
  -o json | jq '.items[] | select(.subjects[]?.name=="jane")'

# Check API server authorization mode
kubectl -n kube-system get pod <apiserver-pod> -o yaml | grep authorization-mode
```

## RBAC Best Practices

### 1. Principle of Least Privilege
Grant only the minimum permissions needed:

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

### 2. Prefer Roles over ClusterRoles
Use namespace-scoped Roles when possible:

```yaml
# BETTER - limited to namespace
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-manager
  namespace: development

# Use ClusterRole only for cluster-scoped resources
```

### 3. Use Groups for User Management
Bind to groups instead of individual users:

```yaml
# BETTER - group-based
subjects:
- kind: Group
  name: developers
  apiGroup: rbac.authorization.k8s.io

# AVOID - individual users (harder to maintain)
subjects:
- kind: User
  name: alice
- kind: User
  name: bob
- kind: User
  name: charlie
```

### 4. Regular RBAC Audits
Periodically review and clean up:

```bash
# List all ClusterRoleBindings
kubectl get clusterrolebindings

# Check for overly permissive bindings
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.roleRef.name=="cluster-admin")'

# Review unused service accounts
kubectl get serviceaccounts --all-namespaces
```

### 5. Document Roles
Add descriptions to your roles:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-deployer
  namespace: production
  annotations:
    description: "Allows deploying and managing application deployments"
    owner: "platform-team@example.com"
    last-reviewed: "2026-02-27"
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["create", "update", "patch", "delete"]
```

### 6. Avoid Wildcards in Production

```yaml
# AVOID in production
verbs: ["*"]
resources: ["*"]
apiGroups: ["*"]

# USE specific permissions
verbs: ["get", "list", "watch"]
resources: ["pods", "services"]
apiGroups: ["", "apps"]
```

### 7. Use Built-in Roles When Possible

```bash
# Use standard roles
kubectl create rolebinding editor \
  --clusterrole=edit \
  --user=developer \
  --namespace=development

# Don't recreate what already exists
```

### 8. Separate Dev and Prod Permissions

```yaml
# Development - more permissive
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: dev-full-access
  namespace: development
subjects:
- kind: Group
  name: developers
roleRef:
  kind: ClusterRole
  name: admin

# Production - read-only for devs
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: prod-view-access
  namespace: production
subjects:
- kind: Group
  name: developers
roleRef:
  kind: ClusterRole
  name: view
```

## Security Considerations

### Privilege Escalation Prevention
Kubernetes prevents privilege escalation by default:

```yaml
# Cannot grant permissions you don't have
# User with 'get pods' cannot create role with 'delete pods'
```

**Requirements to create/update RBAC**:
- Have the exact permissions you're granting, OR
- Have `escalate` verb on roles/clusterroles

### Prevent RBAC Self-Modification

```yaml
# Dangerous - allows modifying own permissions
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "rolebindings"]
  verbs: ["*"]
```

### Sensitive Resources
Be extra careful with these resources:

- `secrets`: Contains sensitive data
- `nodes`: Cluster infrastructure
- `persistentvolumes`: Persistent storage
- `roles/rolebindings`: Permission management
- `pods/exec`: Execute commands in containers
- `pods/portforward`: Network access to pods

### ServiceAccount Token Auto-mounting
Disable when not needed:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-sa
automountServiceAccountToken: false
```

## Real-World Examples

### Example 1: CI/CD Pipeline ServiceAccount

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
  name: cicd-deploy-role
  namespace: production
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "create", "update", "patch"]
- apiGroups: [""]
  resources: ["services", "configmaps"]
  verbs: ["get", "list", "create", "update", "patch"]
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list"]
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
  name: cicd-deploy-role
  apiGroup: rbac.authorization.k8s.io
```

### Example 2: Monitoring ServiceAccount

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: prometheus
  namespace: monitoring
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: prometheus-reader
rules:
- apiGroups: [""]
  resources: ["nodes", "nodes/metrics", "services", "endpoints", "pods"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get"]
- nonResourceURLs: ["/metrics", "/metrics/cadvisor"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: prometheus-binding
subjects:
- kind: ServiceAccount
  name: prometheus
  namespace: monitoring
roleRef:
  kind: ClusterRole
  name: prometheus-reader
  apiGroup: rbac.authorization.k8s.io
```

### Example 3: Developer with Namespace Isolation

```yaml
# Create namespaces
apiVersion: v1
kind: Namespace
metadata:
  name: team-a
---
apiVersion: v1
kind: Namespace
metadata:
  name: team-b
---
# Team A developers
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: team-a-edit
  namespace: team-a
subjects:
- kind: Group
  name: team-a-developers
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: edit
  apiGroup: rbac.authorization.k8s.io
---
# Team B developers
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: team-b-edit
  namespace: team-b
subjects:
- kind: Group
  name: team-b-developers
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: edit
  apiGroup: rbac.authorization.k8s.io
```

## Quick Reference

### Common Commands

```bash
# Create role
kubectl create role NAME --verb=VERB --resource=RESOURCE

# Create rolebinding
kubectl create rolebinding NAME --role=ROLE --user=USER

# Check permissions
kubectl auth can-i VERB RESOURCE --as=USER

# List all permissions
kubectl auth can-i --list --as=USER

# View roles
kubectl get roles -n NAMESPACE
kubectl describe role ROLE -n NAMESPACE

# View bindings
kubectl get rolebindings -n NAMESPACE
kubectl describe rolebinding BINDING -n NAMESPACE

# Impersonate user
kubectl get pods --as=USER --as-group=GROUP
```

### Resource Hierarchy

```
Cluster Level              Namespace Level
├── ClusterRole           ├── Role
├── ClusterRoleBinding    ├── RoleBinding
├── Nodes                 ├── Pods
├── PersistentVolumes     ├── Services
├── Namespaces            ├── ConfigMaps
└── StorageClasses        └── Secrets
```

## Exam Tips

1. **Know the difference**: Role vs ClusterRole, RoleBinding vs ClusterRoleBinding
2. **Understand subjects**: User, Group, ServiceAccount
3. **API groups matter**: Remember `apps` for Deployments, `""` for core resources
4. **Test permissions**: Always use `kubectl auth can-i` to verify
5. **Namespace scope**: RoleBindings only work in their namespace
6. **Built-in roles**: Know cluster-admin, admin, edit, view
7. **resourceNames**: Use for granular, specific resource permissions
8. **Practice creating**: Be able to create roles and bindings from scratch

## Next Steps

- Complete [Lab 01: RBAC Basics](../../labs/02-cluster-hardening/lab-01-rbac-basics.md)
- Complete [Lab 02: RBAC Advanced](../../labs/02-cluster-hardening/lab-02-rbac-advanced.md)
- Study [Service Accounts](service-accounts.md) for pod authentication
- Review [Security Contexts](security-contexts.md) for pod-level security

## Additional Resources

- [Kubernetes RBAC Documentation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Using RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/authorization/)
- [kubectl auth can-i](https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands#auth)
