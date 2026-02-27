# Domain 2: Cluster Hardening (20%)

## Overview

Cluster hardening focuses on securing access to the Kubernetes cluster and implementing security controls at the cluster level. This domain represents **20% of the KCSA exam** and covers essential security mechanisms that control who can access your cluster and what they can do.

**Why Cluster Hardening Matters**:

- Prevents unauthorized access to cluster resources
- Implements the principle of least privilege
- Reduces the attack surface of your cluster
- Protects sensitive workloads from compromised containers
- Ensures compliance with security standards

**Real-World Scenario**: Imagine a development team that needs to deploy applications to a production cluster. Without proper cluster hardening, a compromised developer account could delete critical production workloads, access sensitive secrets, or escalate privileges. Cluster hardening mechanisms like RBAC, security contexts, and pod security admission prevent these scenarios by enforcing strict access controls and security policies.

## Topics Covered

### 1. [Role-Based Access Control (RBAC)](rbac.md)

**Exam Weight**: ~8-10%

- Understanding Kubernetes authentication and authorization
- RBAC API objects: Roles, ClusterRoles, RoleBindings, ClusterRoleBindings
- Creating and managing RBAC policies
- Testing and troubleshooting RBAC rules
- Best practices for least privilege access

**Key Concepts**:

- Authentication vs Authorization
- Subjects (Users, Groups, ServiceAccounts)
- Resources and Verbs
- Namespace-scoped vs Cluster-scoped permissions

### 2. [Service Accounts Security](service-accounts.md)

**Exam Weight**: ~3-4%

- Understanding ServiceAccount purpose and usage
- Default ServiceAccount behavior
- Creating custom ServiceAccounts
- Mounting ServiceAccount tokens
- Disabling automounting for security
- Token management and rotation

**Key Concepts**:

- ServiceAccount tokens
- API authentication with ServiceAccounts
- Bound ServiceAccount tokens (v1.22+)
- ServiceAccount best practices

### 3. [Security Contexts](security-contexts.md)

**Exam Weight**: ~4-5%

- Pod-level vs Container-level security contexts
- Running containers as non-root
- Read-only root filesystems
- Privilege escalation controls
- Linux capabilities management
- fsGroup and supplemental groups

**Key Concepts**:

- runAsUser and runAsGroup
- allowPrivilegeEscalation
- capabilities (add/drop)
- seccompProfile and seLinuxOptions

### 4. [Pod Security Admission](pod-security-admission.md)

**Exam Weight**: ~3-4%

- Understanding Pod Security Standards (PSS)
- Three security levels: Privileged, Baseline, Restricted
- Pod Security Admission controller
- Namespace-level enforcement modes
- Migrating from Pod Security Policies (deprecated)

**Key Concepts**:

- Pod Security Standards
- Admission modes: enforce, audit, warn
- Namespace labels for PSA
- Policy violations and exemptions

## Learning Objectives

After completing this domain, you should be able to:

1. **Configure RBAC**:

   - Create Roles and ClusterRoles with appropriate permissions
   - Bind roles to users, groups, and service accounts
   - Test and verify RBAC configurations
   - Troubleshoot permission issues

1. **Secure ServiceAccounts**:

   - Create and configure custom ServiceAccounts
   - Disable automatic token mounting when not needed
   - Understand token lifecycle and security implications
   - Apply least privilege to ServiceAccounts

1. **Implement Security Contexts**:

   - Configure pods to run as non-root users
   - Set read-only root filesystems
   - Manage Linux capabilities appropriately
   - Prevent privilege escalation

1. **Apply Pod Security Standards**:

   - Understand the three security levels
   - Configure namespace-level pod security
   - Enforce security policies across workloads
   - Handle policy violations appropriately

## Domain Structure

```
02-cluster-hardening/
├── README.md                      # This file - domain overview
├── rbac.md                        # Complete RBAC guide
├── service-accounts.md            # ServiceAccount security
├── security-contexts.md           # Security contexts guide
└── pod-security-admission.md      # Pod Security Admission
```

## Hands-On Labs

Practice your skills with these comprehensive labs:

1. **[Lab 01: RBAC Basics](../../labs/02-cluster-hardening/lab-01-rbac-basics.md)**
   - Create Roles and RoleBindings
   - Test permissions with kubectl auth can-i
   - Implement least privilege access
   - Troubleshoot common RBAC issues

1. **[Lab 02: RBAC Advanced](../../labs/02-cluster-hardening/lab-02-rbac-advanced.md)**
   - Work with ClusterRoles and ClusterRoleBindings
   - Aggregate roles for flexibility
   - Create custom roles for specific use cases
   - Implement service-to-service RBAC

1. **[Lab 03: Service Accounts](../../labs/02-cluster-hardening/lab-03-service-accounts.md)**
   - Create custom ServiceAccounts
   - Disable token automounting
   - Configure pod ServiceAccount usage
   - Test ServiceAccount permissions

1. **[Lab 04: Security Contexts](../../labs/02-cluster-hardening/lab-04-security-contexts.md)**
   - Configure non-root containers
   - Set read-only root filesystems
   - Drop capabilities for security
   - Prevent privilege escalation

1. **[Lab 05: Pod Security Admission](../../labs/02-cluster-hardening/lab-05-pod-security-admission.md)**
   - Configure Pod Security Standards
   - Apply namespace-level policies
   - Test enforcement, audit, and warn modes
   - Handle policy violations

## Quick Reference

### Essential Commands

```bash
# RBAC commands

kubectl get roles,rolebindings -n <namespace>
kubectl get clusterroles,clusterrolebindings
kubectl auth can-i <verb> <resource> --as=<user>
kubectl auth can-i --list --as=<user>

# ServiceAccount commands

kubectl get serviceaccounts -n <namespace>
kubectl describe sa <sa-name> -n <namespace>
kubectl create sa <sa-name> -n <namespace>

# Security Context inspection

kubectl get pod <pod-name> -o yaml | grep -A10 securityContext

# Pod Security Admission

kubectl label namespace <ns> pod-security.kubernetes.io/enforce=restricted
kubectl label namespace <ns> pod-security.kubernetes.io/audit=baseline
```

### Key Files and Paths

- **RBAC**: `/etc/kubernetes/manifests/kube-apiserver.yaml` (authorization mode)
- **ServiceAccount tokens**: `/var/run/secrets/kubernetes.io/serviceaccount/`
- **PSA configuration**: Namespace labels

## Common Exam Scenarios

### Scenario 1: Locked Out User

**Problem**: A developer can't list pods in their namespace.
**Solution**: Check RBAC permissions with `kubectl auth can-i`, create appropriate Role and RoleBinding.

### Scenario 2: Overprivileged Pod

**Problem**: A pod runs as root with all capabilities.
**Solution**: Add security context to run as non-root, drop unnecessary capabilities, set read-only filesystem.

### Scenario 3: ServiceAccount Token Exposure

**Problem**: Pods don't need API access but have ServiceAccount tokens mounted.
**Solution**: Disable automounting with `automountServiceAccountToken: false`.

### Scenario 4: Policy Violations

**Problem**: Pods fail to start after implementing Pod Security Standards.
**Solution**: Review PSA warnings, adjust pod specifications to meet security requirements.

## Study Tips

1. **Practice RBAC extensively**: RBAC is complex and appears frequently on the exam. Create various roles and test them thoroughly.

1. **Understand the hierarchy**: Know the difference between namespace-scoped (Role, RoleBinding) and cluster-scoped (ClusterRole, ClusterRoleBinding) resources.

1. **Security by default**: Remember that Kubernetes is permissive by default. You must explicitly configure security controls.

1. **Test your configurations**: Always use `kubectl auth can-i` to verify RBAC rules before considering them complete.

1. **Know the security contexts**: Memorize common security context fields and their purposes. These appear frequently in exam questions.

1. **PSA levels**: Understand the three Pod Security Standards levels and what each allows/restricts.

1. **Real-world thinking**: Consider "why" each security control exists. Understanding the threat model helps remember the configurations.

## Prerequisites

Before studying this domain, you should:

- Understand basic Kubernetes concepts (Pods, Deployments, Namespaces)
- Be familiar with YAML syntax
- Have a working Kubernetes cluster (Kind/Minikube)
- Know how to use kubectl basic commands

## Common Pitfalls

1. **Confusing authentication with authorization**: Authentication proves who you are; authorization determines what you can do.

1. **Using ClusterRoles when Roles suffice**: Always prefer namespace-scoped Roles when possible (least privilege).

1. **Forgetting namespace scope**: RoleBindings only work in their namespace, even when referencing a ClusterRole.

1. **Ignoring security contexts**: Security contexts are critical for production security but often overlooked in development.

1. **Overly permissive wildcards**: Using `resources: ["*"]` and `verbs: ["*"]` violates least privilege principles.

## Security Best Practices

### RBAC Best Practices

- Apply principle of least privilege
- Use namespace-scoped Roles when possible
- Avoid wildcards in production
- Regularly audit RBAC configurations
- Document role purposes and owners

### ServiceAccount Best Practices

- Create custom ServiceAccounts for each application
- Disable token automounting when not needed
- Use short-lived tokens (projected volumes)
- Limit ServiceAccount permissions with RBAC
- Rotate ServiceAccount tokens regularly

### Security Context Best Practices

- Always run containers as non-root
- Drop all capabilities and add only required ones
- Set read-only root filesystems when possible
- Disable privilege escalation
- Use seccomp and AppArmor/SELinux profiles

### Pod Security Admission Best Practices

- Start with audit/warn modes before enforce
- Apply Baseline standard minimum in production
- Use Restricted standard for sensitive workloads
- Document exceptions and exemptions
- Regularly review and tighten policies

## Additional Resources

### Official Documentation

- [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Configure Service Accounts](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
- [Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

### Security Guidelines

- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/security-checklist/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NSA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)

## Next Steps

1. Start with [RBAC basics](rbac.md) - this is the foundation of cluster security
1. Move to [ServiceAccounts](service-accounts.md) to understand pod authentication
1. Study [Security Contexts](security-contexts.md) for pod-level security
1. Complete with [Pod Security Admission](pod-security-admission.md) for policy enforcement
1. Practice with all five hands-on labs in order
1. Review the [KCSA Cheatsheet](../../KCSA_CHEATSHEET.md) for quick reference

## Exam Preparation Checklist

- [ ] Understand RBAC components and how they interact
- [ ] Can create Roles, ClusterRoles, and bindings from memory
- [ ] Know how to test RBAC with `kubectl auth can-i`
- [ ] Understand ServiceAccount token mounting and security
- [ ] Can configure security contexts for pods and containers
- [ ] Know all Pod Security Standards levels and differences
- [ ] Can apply namespace-level Pod Security Admission
- [ ] Completed all five hands-on labs
- [ ] Can troubleshoot common permission and security issues
- [ ] Understand the "why" behind each security control

---

**Ready to begin?** Start with [Role-Based Access Control (RBAC)](rbac.md) to learn how to control access to your cluster.

**Need practice?** Jump to [Lab 01: RBAC Basics](../../labs/02-cluster-hardening/lab-01-rbac-basics.md) for hands-on exercises.
