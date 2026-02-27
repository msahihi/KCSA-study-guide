# Network Policies

## Overview

Kubernetes NetworkPolicy is a resource that allows you to control network traffic between pods and between pods and external endpoints. By default, Kubernetes allows all pods to communicate with each other without restrictions. NetworkPolicies enable you to implement network segmentation, following the principle of least privilege by only allowing necessary network connections.

Think of NetworkPolicies as firewall rules for your Kubernetes cluster. Just as you would configure a firewall to control which systems can communicate on a traditional network, NetworkPolicies control which pods can communicate in your Kubernetes environment.

## Why Network Policies Matter

1. **Defense in Depth**: Even if an attacker compromises a pod, NetworkPolicies limit lateral movement within the cluster.
2. **Compliance**: Many security frameworks require network segmentation between different tiers of applications.
3. **Blast Radius Reduction**: Isolating workloads limits the impact of security incidents.
4. **Multi-tenancy**: NetworkPolicies help enforce isolation between different teams or applications sharing a cluster.

## Prerequisites

Before NetworkPolicies can work in your cluster, you need:

1. **A Network Plugin (CNI) that supports NetworkPolicy**: Not all CNI plugins support NetworkPolicy enforcement. Common options include:
   - Calico
   - Cilium
   - Weave Net
   - Antrea

   **Note**: The popular Flannel CNI does NOT support NetworkPolicy by default.

2. **Kubernetes 1.7+**: NetworkPolicy has been stable since v1.7.

To check if your cluster supports NetworkPolicy:
```bash
kubectl api-resources | grep networkpolicies
```

## How Network Policies Work

### Basic Concepts

1. **Pod Selectors**: NetworkPolicies use label selectors to identify which pods the policy applies to.

2. **Policy Types**: There are two types of traffic you can control:
   - **Ingress**: Incoming traffic to the selected pods
   - **Egress**: Outgoing traffic from the selected pods

3. **Default Behavior**:
   - If no NetworkPolicy selects a pod, all traffic is allowed (default allow-all).
   - Once a NetworkPolicy selects a pod, only explicitly allowed traffic is permitted (implicit deny).

4. **Additive Nature**: Multiple NetworkPolicies can select the same pod, and the union of all rules applies.

### Traffic Flow Control

NetworkPolicies can allow traffic based on three identifiers:
1. **Pod Selectors**: Allow traffic from/to pods with specific labels
2. **Namespace Selectors**: Allow traffic from/to all pods in specific namespaces
3. **IP Blocks (CIDR)**: Allow traffic from/to specific IP ranges

## Network Policy Syntax

### Basic Structure

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: <policy-name>
  namespace: <namespace>
spec:
  podSelector:
    matchLabels:
      <label-key>: <label-value>
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - <source-selector>
    ports:
    - protocol: TCP
      port: 80
  egress:
  - to:
    - <destination-selector>
    ports:
    - protocol: TCP
      port: 443
```

## Common Network Policy Patterns

### 1. Default Deny All Traffic

This is the recommended starting point for any namespace. It denies all ingress and egress traffic, and then you selectively allow what's needed.

**Deny All Ingress:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: production
spec:
  podSelector: {}  # Empty selector = applies to all pods in namespace
  policyTypes:
  - Ingress
```

**Deny All Egress:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Egress
```

**Deny All Ingress and Egress:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

### 2. Allow Specific Ingress Traffic

Allow incoming traffic only from pods with specific labels:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
      tier: api
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
```

**Explanation:**
- This policy applies to pods labeled `app: backend` and `tier: api`
- It allows ingress traffic from pods labeled `app: frontend`
- Only TCP traffic on port 8080 is allowed
- All other ingress traffic is denied

### 3. Allow Traffic from Specific Namespace

Allow traffic from all pods in a specific namespace:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-from-monitoring-namespace
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - protocol: TCP
      port: 9090
```

**Important**: The namespace must have the label `name: monitoring` for this to work. You can add labels to namespaces:
```bash
kubectl label namespace monitoring name=monitoring
```

### 4. Allow Traffic from Multiple Sources

Use multiple `from` entries to allow traffic from different sources:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-multiple-sources
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: database
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: backend
    - podSelector:
        matchLabels:
          app: admin-tool
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - protocol: TCP
      port: 5432
```

### 5. Allow Egress to External Services

Allow pods to reach external services (e.g., external APIs, databases):

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-external-api
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 203.0.113.0/24  # External API IP range
    ports:
    - protocol: TCP
      port: 443
  - to:  # Allow DNS
    - namespaceSelector:
        matchLabels:
          name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
```

**Important**: Always allow DNS when using egress policies, or your pods won't be able to resolve domain names!

### 6. Allow DNS Only

A common pattern to allow only DNS queries:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-only
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: isolated-app
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
```

### 7. Allow Traffic to Specific Port Range

Allow traffic on a range of ports:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-port-range
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
      endPort: 8090  # Ports 8080-8090
```

**Note**: The `endPort` field is available in Kubernetes 1.25+.

## Complex Scenarios

### Three-Tier Application Security

Here's how to secure a typical three-tier application (frontend, backend, database):

**1. Frontend Policy:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      tier: frontend
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - ipBlock:
        cidr: 0.0.0.0/0  # Allow from anywhere (internet)
    ports:
    - protocol: TCP
      port: 80
    - protocol: TCP
      port: 443
  egress:
  - to:
    - podSelector:
        matchLabels:
          tier: backend
    ports:
    - protocol: TCP
      port: 8080
  - to:  # DNS
    - namespaceSelector: {}
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
```

**2. Backend Policy:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      tier: backend
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          tier: frontend
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          tier: database
    ports:
    - protocol: TCP
      port: 5432
  - to:  # DNS
    - namespaceSelector: {}
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
```

**3. Database Policy:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: database-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      tier: database
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          tier: backend
    ports:
    - protocol: TCP
      port: 5432
  egress:
  - to:  # DNS only
    - namespaceSelector: {}
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
```

### Namespace Isolation

Isolate all namespaces from each other, allowing only specific cross-namespace communication:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-other-namespaces
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector: {}  # Allow all pods in same namespace
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring  # Allow monitoring namespace
```

## Testing Network Policies

### Verification Steps

1. **Check if policy exists:**
```bash
kubectl get networkpolicies -n production
kubectl describe networkpolicy <policy-name> -n production
```

2. **Test connectivity before applying policy:**
```bash
kubectl run test-pod --image=busybox -it --rm --restart=Never -- sh
# Inside the pod:
wget -O- http://backend-service:8080
```

3. **Apply the policy:**
```bash
kubectl apply -f network-policy.yaml
```

4. **Test connectivity after applying policy:**
```bash
kubectl run test-pod --image=busybox -it --rm --restart=Never -- sh
# Should timeout if policy is working:
wget -O- --timeout=5 http://backend-service:8080
```

### Troubleshooting Tools

**1. Use a debug container:**
```bash
kubectl run netpol-test \
  --image=nicolaka/netshoot \
  -it --rm -- bash
```

**2. Check pod labels:**
```bash
kubectl get pods --show-labels -n production
```

**3. Describe the NetworkPolicy:**
```bash
kubectl describe networkpolicy <policy-name> -n production
```

**4. Check CNI plugin logs:**
```bash
# For Calico:
kubectl logs -n kube-system -l k8s-app=calico-node

# For Cilium:
kubectl logs -n kube-system -l k8s-app=cilium
```

## Common Pitfalls

### 1. Forgetting DNS

**Problem**: Pods can't resolve domain names after applying egress policies.

**Solution**: Always include DNS in egress rules:
```yaml
egress:
- to:
  - namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: kube-system
    podSelector:
      matchLabels:
        k8s-app: kube-dns
  ports:
  - protocol: UDP
    port: 53
```

### 2. AND vs OR Logic

**AND logic** (both conditions must match):
```yaml
- from:
  - namespaceSelector:
      matchLabels:
        environment: prod
    podSelector:
      matchLabels:
        app: frontend
```

**OR logic** (either condition can match):
```yaml
- from:
  - namespaceSelector:
      matchLabels:
        environment: prod
  - podSelector:
      matchLabels:
        app: frontend
```

### 3. Missing policyTypes

If you don't specify `policyTypes`, the behavior depends on whether you have ingress/egress rules:
```yaml
# This only affects ingress (implicit)
spec:
  podSelector: {}
  ingress: []
```

**Best practice**: Always explicitly specify `policyTypes`:
```yaml
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

### 4. CNI Plugin Not Installed

NetworkPolicies won't work without a compatible CNI plugin. Check your cluster:
```bash
kubectl get pods -n kube-system | grep -E "calico|cilium|weave"
```

### 5. Namespace Labels

When using `namespaceSelector`, ensure namespaces have the required labels:
```bash
kubectl get namespaces --show-labels
kubectl label namespace <namespace> <key>=<value>
```

## Best Practices

1. **Start with Default Deny**: Always begin with a default deny policy in each namespace, then allow specific traffic.

2. **Use Meaningful Labels**: Create a consistent labeling strategy for your pods and namespaces.

3. **Document Your Policies**: Use annotations to explain why a policy exists:
```yaml
metadata:
  annotations:
    description: "Allows frontend pods to communicate with backend API"
```

4. **Test in Non-Production**: Test NetworkPolicies in development environments first.

5. **Monitor and Audit**: Regularly review NetworkPolicies and remove unused ones.

6. **Layer Your Security**: NetworkPolicies are one layer. Use them in conjunction with:
   - Pod Security Standards
   - RBAC
   - Service Mesh policies
   - Firewall rules

7. **Use Network Policy Tools**: Consider tools like:
   - **Cilium Editor**: Visual NetworkPolicy editor
   - **Network Policy Viewer**: Visualize policies
   - **Inspektor Gadget**: Debug network issues

## Key Points to Remember

1. NetworkPolicies require a compatible CNI plugin to function.
2. By default, Kubernetes allows all pod-to-pod communication.
3. Once a NetworkPolicy selects a pod, traffic is denied unless explicitly allowed.
4. Multiple NetworkPolicies are additive (union of all rules).
5. Always include DNS in egress rules.
6. NetworkPolicies are namespaced resources.
7. Empty `podSelector: {}` selects all pods in the namespace.
8. Use namespace labels for cross-namespace policies.
9. Test policies thoroughly before production deployment.
10. NetworkPolicies only work at Layer 3/4 (IP/port), not Layer 7 (HTTP).

## Study Resources

### Official Documentation
- [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Declare Network Policy](https://kubernetes.io/docs/tasks/administer-cluster/declare-network-policy/)

### Interactive Learning
- [Network Policy Editor (Cilium)](https://editor.networkpolicy.io/)
- [Kubernetes Network Policy Recipes](https://github.com/ahmetb/kubernetes-network-policy-recipes)

### Tools
- [Calico](https://docs.projectcalico.org/)
- [Cilium](https://cilium.io/)
- [Network Policy Viewer](https://github.com/runoncloud/network-policy-viewer)

## Next Steps

1. Complete the [Network Policy Lab](../../labs/01-cluster-setup/lab-01-network-policies.md)
2. Practice creating default deny policies
3. Experiment with different selector combinations
4. Learn about [CIS Benchmarks](./cis-benchmarks.md) next

## Quick Reference

### Common Commands

```bash
# List NetworkPolicies
kubectl get networkpolicies -n <namespace>
kubectl get netpol -n <namespace>  # Short form

# Describe a NetworkPolicy
kubectl describe networkpolicy <name> -n <namespace>

# Apply a NetworkPolicy
kubectl apply -f network-policy.yaml

# Delete a NetworkPolicy
kubectl delete networkpolicy <name> -n <namespace>

# Get NetworkPolicy YAML
kubectl get networkpolicy <name> -n <namespace> -o yaml

# Test connectivity
kubectl run test --image=busybox -it --rm -- wget -O- http://service:port
```

### Example Label Strategy

```yaml
# Application labels
app: backend
tier: api
environment: production
team: platform

# Network zone labels
network-zone: dmz
network-zone: internal
network-zone: restricted
```

---

[Back to Domain 1 README](./README.md) | [Next: CIS Benchmarks →](./cis-benchmarks.md)
