# Domain 2 Labs: Cluster Hardening

## Overview

This directory contains hands-on labs for **Domain 2: Cluster Hardening (20%)**. These labs provide practical exercises to reinforce concepts related to RBAC, ServiceAccounts, Security Contexts, and Pod Security Admission.

## Prerequisites

Before starting these labs, ensure you have:

- **Kubernetes cluster** running (Kind, Minikube, or similar)
- **kubectl** v1.30.x installed and configured
- Completed reading the corresponding theory in [domains/02-cluster-hardening/](../../domains/02-cluster-hardening/)
- Basic familiarity with YAML and Kubernetes resources

## Lab Structure

Each lab follows this structure:

1. **Objectives**: What you'll learn
2. **Prerequisites**: Required knowledge/setup
3. **Lab Setup**: Initial configuration
4. **Exercises**: Step-by-step tasks with expected outputs
5. **Verification**: How to confirm success
6. **Solutions**: Complete solutions with explanations
7. **Troubleshooting**: Common issues and fixes
8. **Cleanup**: Remove lab resources

## Available Labs

### [Lab 01: RBAC Basics](lab-01-rbac-basics.md)
**Duration**: 45-60 minutes
**Difficulty**: Beginner

**Topics Covered**:
- Creating Roles and RoleBindings
- Understanding RBAC subjects (users, groups, ServiceAccounts)
- Testing permissions with `kubectl auth can-i`
- Implementing least privilege access
- Troubleshooting permission issues

**Key Skills**:
- Create namespace-scoped Roles
- Bind roles to different subject types
- Test and verify RBAC configurations
- Debug permission denied errors

---

### [Lab 02: RBAC Advanced](lab-02-rbac-advanced.md)
**Duration**: 60-75 minutes
**Difficulty**: Intermediate

**Topics Covered**:
- ClusterRoles and ClusterRoleBindings
- Aggregated ClusterRoles
- Cross-namespace access patterns
- Using default roles (admin, edit, view)
- RBAC for ServiceAccount-to-ServiceAccount communication

**Key Skills**:
- Work with cluster-scoped permissions
- Create reusable roles across namespaces
- Implement complex permission scenarios
- Aggregate roles for modular management

---

### [Lab 03: Service Accounts](lab-03-service-accounts.md)
**Duration**: 45-60 minutes
**Difficulty**: Beginner to Intermediate

**Topics Covered**:
- Creating custom ServiceAccounts
- Disabling token automounting
- Configuring pod ServiceAccount usage
- Testing ServiceAccount API access
- Implementing least privilege for applications

**Key Skills**:
- Create and configure ServiceAccounts
- Control token mounting behavior
- Grant appropriate RBAC permissions
- Verify ServiceAccount functionality

---

### [Lab 04: Security Contexts](lab-04-security-contexts.md)
**Duration**: 60-75 minutes
**Difficulty**: Intermediate

**Topics Covered**:
- Running containers as non-root users
- Setting read-only root filesystems
- Managing Linux capabilities
- Preventing privilege escalation
- Using seccomp profiles

**Key Skills**:
- Configure pod and container security contexts
- Implement defense-in-depth security
- Troubleshoot permission and capability issues
- Apply security best practices

---

### [Lab 05: Pod Security Admission](lab-05-pod-security-admission.md)
**Duration**: 60-75 minutes
**Difficulty**: Intermediate

**Topics Covered**:
- Understanding Pod Security Standards (Privileged, Baseline, Restricted)
- Applying namespace-level policies
- Using enforce, audit, and warn modes
- Creating compliant pod specifications
- Migrating workloads to higher security levels

**Key Skills**:
- Configure Pod Security Admission
- Apply appropriate security levels
- Fix non-compliant pod specifications
- Implement gradual policy rollout

---

## Lab Environment Setup

### Option 1: Kind Cluster (Recommended)

Create a multi-node cluster for realistic testing:

```bash
cat <<EOF | kind create cluster --name kcsa-cluster-hardening --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  image: kindest/node:v1.30.0
- role: worker
  image: kindest/node:v1.30.0
- role: worker
  image: kindest/node:v1.30.0
EOF

# Verify cluster
kubectl cluster-info --context kind-kcsa-cluster-hardening
kubectl get nodes
```

### Option 2: Minikube

```bash
# Start Minikube with sufficient resources
minikube start --kubernetes-version=v1.30.0 --cpus=4 --memory=8192 --driver=docker

# Verify cluster
kubectl cluster-info
kubectl get nodes
```

### Verify kubectl Configuration

```bash
# Check kubectl version
kubectl version --client

# Check cluster access
kubectl get namespaces

# Create test namespace
kubectl create namespace lab-test
kubectl get namespace lab-test

# Clean up test namespace
kubectl delete namespace lab-test
```

## Recommended Learning Path

### Week 1: RBAC Foundation
1. Read [RBAC theory](../../domains/02-cluster-hardening/rbac.md)
2. Complete [Lab 01: RBAC Basics](lab-01-rbac-basics.md)
3. Complete [Lab 02: RBAC Advanced](lab-02-rbac-advanced.md)
4. Review and practice RBAC commands

### Week 2: Application Security
1. Read [ServiceAccounts theory](../../domains/02-cluster-hardening/service-accounts.md)
2. Complete [Lab 03: Service Accounts](lab-03-service-accounts.md)
3. Read [Security Contexts theory](../../domains/02-cluster-hardening/security-contexts.md)
4. Complete [Lab 04: Security Contexts](lab-04-security-contexts.md)

### Week 3: Policy Enforcement
1. Read [Pod Security Admission theory](../../domains/02-cluster-hardening/pod-security-admission.md)
2. Complete [Lab 05: Pod Security Admission](lab-05-pod-security-admission.md)
3. Review entire Domain 2 materials
4. Practice combined scenarios

## Lab Tips

### General Tips
- **Read theory first**: Complete corresponding reading before each lab
- **Take your time**: Understand each step before moving forward
- **Experiment**: Try variations of commands to deepen understanding
- **Use dry-run**: Test configurations with `--dry-run=client` or `--dry-run=server`
- **Check outputs**: Always verify commands produce expected results
- **Clean up**: Complete cleanup sections to maintain clean environment

### RBAC Tips
- Always test permissions with `kubectl auth can-i`
- Remember: RoleBindings only work in their namespace
- Use `--as` flag to impersonate users during testing
- Check API groups with `kubectl api-resources`

### ServiceAccount Tips
- Use `kubectl describe sa` to view ServiceAccount details
- Check token mounting with `kubectl exec ... -- ls /var/run/secrets/kubernetes.io/serviceaccount/`
- Remember ServiceAccount subject format: `system:serviceaccount:NAMESPACE:NAME`

### Security Context Tips
- Test user/group with `kubectl exec ... -- id`
- Verify capabilities with `kubectl exec ... -- grep Cap /proc/1/status`
- Add emptyDir volumes for writable paths with read-only root filesystem
- Use `--dry-run=server` to validate security contexts before applying

### Pod Security Admission Tips
- Start with audit/warn modes before enforcing
- Use `--dry-run=server` to test pod compliance
- Check namespace labels with `kubectl get ns -o yaml`
- Pin PSS version for stability in production

## Common Issues and Solutions

### Issue: Permission Denied
**Symptom**: `Error from server (Forbidden): ...`

**Solutions**:
```bash
# Check current user
kubectl auth can-i --list

# Verify RBAC configuration
kubectl get roles,rolebindings -n <namespace>

# Test as specific user
kubectl auth can-i <verb> <resource> --as=<user>
```

### Issue: ServiceAccount Token Not Mounted
**Symptom**: `/var/run/secrets/kubernetes.io/serviceaccount/` empty

**Solutions**:
```bash
# Check if automounting disabled
kubectl get sa <sa-name> -o yaml | grep automount
kubectl get pod <pod> -o yaml | grep automount

# Verify ServiceAccount exists
kubectl get sa -n <namespace>
```

### Issue: Security Context Violations
**Symptom**: Pod fails to start with security-related errors

**Solutions**:
```bash
# Check pod events
kubectl describe pod <pod>

# Verify security context
kubectl get pod <pod> -o yaml | grep -A10 securityContext

# Test with dry-run
kubectl apply -f pod.yaml --dry-run=server
```

### Issue: PSA Blocking Pods
**Symptom**: Pod rejected by Pod Security Admission

**Solutions**:
```bash
# Check namespace PSA labels
kubectl get namespace <ns> --show-labels

# Test pod compliance
kubectl apply -f pod.yaml --dry-run=server -n <ns>

# Review error message for required changes
# Update pod spec accordingly
```

## Verification Commands

Quick commands to verify lab progress:

```bash
# RBAC
kubectl get roles,rolebindings -n <namespace>
kubectl auth can-i <verb> <resource> --as=<user>

# ServiceAccounts
kubectl get serviceaccounts -n <namespace>
kubectl describe sa <sa-name> -n <namespace>

# Security Contexts
kubectl get pod <pod> -o jsonpath='{.spec.securityContext}'
kubectl exec <pod> -- id

# Pod Security Admission
kubectl get namespace <ns> --show-labels | grep pod-security
```

## Additional Practice

After completing all labs, try these challenge exercises:

### Challenge 1: Secure Multi-Tier Application
Create a three-tier application (frontend, backend, database) with:
- Separate ServiceAccounts for each tier
- Appropriate RBAC permissions
- Restrictive security contexts
- Baseline PSA enforcement

### Challenge 2: CI/CD ServiceAccount
Create a ServiceAccount for CI/CD pipeline with:
- Permission to deploy to specific namespace
- Read-only access to cluster information
- Ability to check deployment status
- No ability to delete or modify RBAC

### Challenge 3: Gradual PSA Rollout
Simulate production PSA migration:
1. Start with privileged (audit=baseline)
2. Move to baseline enforcement (audit=restricted)
3. Achieve restricted enforcement
4. Document all required pod spec changes

## Cleanup

After completing all labs:

```bash
# Delete Kind cluster
kind delete cluster --name kcsa-cluster-hardening

# Or stop Minikube
minikube stop
minikube delete

# Verify cleanup
kind get clusters
# or
minikube status
```

## Next Steps

After completing Domain 2 labs:

1. Review [KCSA Cheatsheet](../../KCSA_CHEATSHEET.md) for quick reference
2. Move to [Domain 3: System Hardening](../../domains/03-system-hardening/)
3. Practice mock questions for Domain 2
4. Revisit any challenging concepts

## Resources

### Documentation
- [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Configure Service Accounts](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
- [Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)

### Tools
- [kubectl Cheat Sheet](https://kubernetes.io/docs/reference/kubectl/cheatsheet/)
- [kubectl auth can-i](https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands#auth)

## Feedback and Contributions

Found an issue or have suggestions? Please contribute:
1. Document the issue
2. Suggest improvements
3. Submit pull requests
4. Share your learning experience

---

**Ready to start?** Begin with [Lab 01: RBAC Basics](lab-01-rbac-basics.md)!
