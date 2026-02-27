# Domain 1: Cluster Setup (10%)

## Overview

Domain 1 of the Kubernetes Certified Security Specialist (KCSA) exam focuses on the foundational security aspects of setting up and configuring a Kubernetes cluster. This domain covers approximately 10% of the exam and emphasizes securing cluster components, network communications, and establishing baseline security policies.

Understanding cluster setup security is critical because it forms the foundation of your Kubernetes security posture. Misconfigurations at this level can lead to widespread security vulnerabilities that affect all workloads running on the cluster.

## Topics Covered

### 1. [Network Policies](./network-policies.md)

Learn how to control network traffic between pods and implement network segmentation using Kubernetes NetworkPolicy resources.

**Key Learning Objectives:**

- Understand how NetworkPolicies work in Kubernetes
- Implement ingress and egress network policies
- Create default deny policies for network segmentation
- Troubleshoot network policy issues

**Related Lab:** [Lab 01 - Network Policies](../../labs/01-cluster-setup/lab-01-network-policies.md)

### 2. [CIS Kubernetes Benchmarks](./cis-benchmarks.md)

Explore the Center for Internet Security (CIS) Kubernetes Benchmarks and learn how to audit your cluster against industry security standards.

**Key Learning Objectives:**

- Understand CIS Benchmark structure and scoring
- Use kube-bench to audit cluster security
- Interpret audit results and prioritize remediation
- Apply CIS recommendations to harden cluster components

**Related Lab:** [Lab 02 - CIS Benchmarks](../../labs/01-cluster-setup/lab-02-cis-benchmarks.md)

### 3. [Ingress and Service Security](./ingress-service-security.md)

Secure external access to cluster services through proper Ingress and Service configuration, including TLS termination and authentication.

**Key Learning Objectives:**

- Configure TLS termination for Ingress resources
- Implement service mesh security features
- Secure LoadBalancer and NodePort services
- Apply authentication and authorization at the Ingress layer

**Related Lab:** [Lab 03 - Ingress Security](../../labs/01-cluster-setup/lab-03-ingress-security.md)

### 4. [Pod Security Standards](./pod-security-standards.md)

Implement Pod Security Standards (PSS) and Pod Security Admission (PSA) to enforce security policies at the pod level.

**Key Learning Objectives:**

- Understand the three Pod Security Standards levels (Privileged, Baseline, Restricted)
- Configure Pod Security Admission at the namespace level
- Migrate from deprecated PodSecurityPolicy to PSS/PSA
- Apply security contexts to pods and containers

**Related Lab:** [Lab 04 - Pod Security Standards](../../labs/01-cluster-setup/lab-04-pod-security-standards.md)

## Exam Tips

1. **Hands-on Practice**: This domain requires practical knowledge. Make sure to complete all labs multiple times until you're comfortable with the commands and concepts.

1. **Time Management**: Cluster setup questions may require multiple steps. Practice efficient workflows to save time during the exam.

1. **Documentation**: Familiarize yourself with the official Kubernetes documentation for NetworkPolicies, Pod Security Standards, and Ingress resources. You'll have access to kubernetes.io during the exam.

1. **Common Scenarios**: Be prepared for scenarios like:

   - Creating default deny network policies
   - Configuring TLS for Ingress
   - Applying Pod Security Standards to namespaces
   - Interpreting CIS benchmark results

1. **YAML Proficiency**: Many tasks require creating or modifying YAML manifests. Practice writing NetworkPolicies, Ingress resources, and SecurityContexts from scratch.

## Study Approach

### Week 1: Network Policies

- Read the [Network Policies](./network-policies.md) guide
- Complete [Lab 01](../../labs/01-cluster-setup/lab-01-network-policies.md)
- Practice creating various NetworkPolicy scenarios
- Review common patterns (default deny, allow specific traffic, etc.)

### Week 2: CIS Benchmarks

- Study the [CIS Benchmarks](./cis-benchmarks.md) guide
- Complete [Lab 02](../../labs/01-cluster-setup/lab-02-cis-benchmarks.md)
- Run kube-bench on a practice cluster
- Understand remediation strategies for common findings

### Week 3: Ingress Security

- Review the [Ingress and Service Security](./ingress-service-security.md) guide
- Complete [Lab 03](../../labs/01-cluster-setup/lab-03-ingress-security.md)
- Practice TLS certificate creation and configuration
- Understand different Ingress controller security features

### Week 4: Pod Security Standards

- Master the [Pod Security Standards](./pod-security-standards.md) guide
- Complete [Lab 04](../../labs/01-cluster-setup/lab-04-pod-security-standards.md)
- Practice applying PSA labels to namespaces
- Understand security context options and their effects

## Prerequisites

Before diving into Domain 1, ensure you have:

1. **Basic Kubernetes Knowledge**
   - Pod, Deployment, Service concepts
   - kubectl command-line proficiency
   - YAML syntax and structure
   - Namespace management

1. **Lab Environment**
   - Access to a Kubernetes cluster (v1.30.x recommended)
   - kubectl installed and configured
   - Ability to create and delete resources
   - Internet access for pulling container images

1. **Networking Fundamentals**
   - Understanding of TCP/IP, ports, and protocols
   - Basic knowledge of DNS
   - Familiarity with TLS/SSL certificates

1. **Linux Command Line**
   - Basic shell commands
   - File manipulation (cat, grep, etc.)
   - Text editing (vim or nano)

## Additional Resources

### Official Documentation

- [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [Ingress Controllers](https://kubernetes.io/docs/concepts/services-networking/ingress-controllers/)

### Tools

- [kube-bench](https://github.com/aquasecurity/kube-bench) - CIS Kubernetes Benchmark auditing tool
- [kubectl](https://kubernetes.io/docs/reference/kubectl/) - Kubernetes command-line tool
- [Calico](https://docs.projectcalico.org/) - Network policy enforcement (one of many CNI options)

### Best Practices Guides

- [NSA/CISA Kubernetes Hardening Guide](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/)
- [CIS Kubernetes Benchmarks](https://www.cisecurity.org/benchmark/kubernetes)

## Quick Reference

### Common kubectl Commands for Domain 1

```bash
# Network Policies

kubectl get networkpolicies -n <namespace>
kubectl describe networkpolicy <name> -n <namespace>
kubectl apply -f network-policy.yaml

# Pod Security

kubectl label namespace <namespace> pod-security.kubernetes.io/enforce=baseline
kubectl label namespace <namespace> pod-security.kubernetes.io/warn=restricted
kubectl label namespace <namespace> pod-security.kubernetes.io/audit=restricted

# Ingress

kubectl get ingress -n <namespace>
kubectl describe ingress <name> -n <namespace>
kubectl create secret tls <secret-name> --cert=path/to/cert --key=path/to/key

# Services

kubectl get services -n <namespace>
kubectl expose deployment <name> --port=80 --type=ClusterIP

# Verification

kubectl auth can-i create networkpolicies --as=system:serviceaccount:default:default
kubectl get pods -n <namespace> -o jsonpath='{.items[*].spec.securityContext}'
```

## Next Steps

1. Start with the [Network Policies](./network-policies.md) guide
1. Set up your lab environment
1. Complete each lab in order
1. Review and practice regularly
1. Take notes on common patterns and gotchas

Remember: Security is not a one-time configuration but an ongoing practice. Understanding these foundational concepts will help you build secure Kubernetes clusters from the ground up.

---

[Back to Main README](../../README.md) | [Next Domain: Cluster Hardening →](../02-cluster-hardening/README.md)
