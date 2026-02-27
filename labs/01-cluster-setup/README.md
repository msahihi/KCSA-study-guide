# Lab Exercises - Domain 1: Cluster Setup

## Overview

This directory contains hands-on lab exercises for Domain 1 (Cluster Setup) of the KCSA exam. These labs provide practical experience with network policies, CIS benchmarks, Ingress security, and Pod Security Standards.

## Lab Environment Requirements

### Prerequisites

Before starting these labs, ensure you have:

1. **Kubernetes Cluster** (v1.30.x recommended)
   - Minimum: 2 nodes (1 control plane, 1 worker)
   - Options: kind, minikube, kubeadm, cloud provider (EKS, GKE, AKS)
   - At least 4GB RAM, 2 CPUs per node

2. **kubectl** installed and configured
   ```bash
   kubectl version --client
   kubectl cluster-info
   ```

3. **Network Plugin with NetworkPolicy Support**
   - Calico (recommended for these labs)
   - Cilium
   - Weave Net
   - Note: Flannel does NOT support NetworkPolicy by default

4. **Ingress Controller**
   - NGINX Ingress Controller (used in labs)
   - Traefik, HAProxy, or similar (can be adapted)

5. **Command-line Tools**
   - openssl (for certificate generation)
   - curl or wget (for testing)
   - jq (for JSON parsing, optional but helpful)

### Setting Up Your Lab Environment

#### Option 1: kind (Kubernetes in Docker)

```bash
# Install kind
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind

# Create cluster with Calico
cat <<EOF | kind create cluster --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
- role: worker
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
EOF

# Install Calico
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.1/manifests/tigera-operator.yaml
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.1/manifests/custom-resources.yaml

# Install NGINX Ingress
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.9.0/deploy/static/provider/kind/deploy.yaml

# Wait for ingress to be ready
kubectl wait --namespace ingress-nginx \
  --for=condition=ready pod \
  --selector=app.kubernetes.io/component=controller \
  --timeout=90s
```

#### Option 2: minikube

```bash
# Install minikube
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube

# Start cluster with Calico
minikube start --cni=calico --nodes=2 --cpus=2 --memory=4096

# Enable ingress addon
minikube addons enable ingress

# Verify
kubectl get nodes
kubectl get pods -n kube-system
```

#### Option 3: Cloud Provider

For AWS EKS, GCP GKE, or Azure AKS, follow the respective cloud provider's documentation to create a cluster with at least 2 nodes.

### Verify Your Setup

```bash
# Check cluster nodes
kubectl get nodes

# Check CNI plugin
kubectl get pods -n kube-system | grep -E "calico|cilium|weave"

# Check Ingress controller
kubectl get pods -n ingress-nginx

# Test NetworkPolicy support
kubectl api-resources | grep networkpolicies

# Check kubectl access
kubectl auth can-i create pods
kubectl auth can-i create networkpolicies
```

## Lab Structure

Each lab follows this structure:

- **Objectives**: What you'll learn
- **Prerequisites**: Required knowledge and resources
- **Estimated Time**: Expected completion time
- **Step-by-Step Exercises**: Detailed instructions with commands
- **Expected Output**: What you should see
- **Verification**: How to confirm success
- **Troubleshooting**: Common issues and solutions
- **Challenge Questions**: Test your understanding
- **Cleanup**: Remove lab resources
- **Solutions**: Expandable solution sections

## Lab Exercises

### [Lab 01: Network Policies](./lab-01-network-policies.md)

**Topics Covered:**
- Creating default deny policies
- Implementing ingress rules
- Configuring egress rules
- Testing policy effectiveness
- Troubleshooting network policies

**Key Skills:**
- Write NetworkPolicy manifests
- Apply pod and namespace selectors
- Configure port restrictions
- Test network connectivity
- Debug policy issues

**Estimated Time:** 60-90 minutes

---

### [Lab 02: CIS Kubernetes Benchmarks](./lab-02-cis-benchmarks.md)

**Topics Covered:**
- Installing and running kube-bench
- Interpreting audit results
- Prioritizing remediation
- Applying security fixes
- Verifying improvements

**Key Skills:**
- Run kube-bench audits
- Analyze security findings
- Remediate common issues
- Configure secure cluster components
- Document exceptions

**Estimated Time:** 90-120 minutes

---

### [Lab 03: Ingress and TLS Security](./lab-03-ingress-security.md)

**Topics Covered:**
- Configuring TLS certificates
- Implementing HTTPS ingress
- Adding authentication
- Configuring rate limiting
- Implementing IP whitelisting

**Key Skills:**
- Generate TLS certificates
- Create Kubernetes secrets
- Configure Ingress resources
- Test HTTPS connections
- Apply security annotations

**Estimated Time:** 60-90 minutes

---

### [Lab 04: Pod Security Standards](./lab-04-pod-security-standards.md)

**Topics Covered:**
- Applying Pod Security Standards
- Configuring security contexts
- Using enforce, audit, and warn modes
- Migrating to restricted standard
- Troubleshooting violations

**Key Skills:**
- Label namespaces with PSS
- Write secure pod specifications
- Configure container security contexts
- Debug PSS violations
- Migrate existing workloads

**Estimated Time:** 60-90 minutes

## Learning Path

### For Beginners

Follow labs in order:
1. Lab 01 (Network Policies) - Foundation
2. Lab 04 (Pod Security Standards) - Essential security
3. Lab 03 (Ingress Security) - External access
4. Lab 02 (CIS Benchmarks) - Comprehensive audit

### For Exam Preparation

Focus on speed and accuracy:
1. Complete each lab once thoroughly
2. Repeat labs with time constraints
3. Practice without looking at solutions
4. Mix concepts (e.g., network policies + PSS)

### For Real-World Application

Extend labs with:
- Multi-tier applications
- Cross-namespace communication
- Production-like scenarios
- Integration with monitoring tools

## Tips for Success

### During Labs

1. **Read Carefully**: Understand each step before executing
2. **Type Commands**: Don't copy-paste blindly; understand what you're doing
3. **Verify Each Step**: Check output and confirm success before proceeding
4. **Take Notes**: Document interesting findings or gotchas
5. **Experiment**: Try variations to deepen understanding

### Troubleshooting

1. **Check Pod Status**: `kubectl get pods -A`
2. **View Pod Logs**: `kubectl logs <pod> -n <namespace>`
3. **Describe Resources**: `kubectl describe <resource> <name>`
4. **Check Events**: `kubectl get events --sort-by='.lastTimestamp'`
5. **Verify Configuration**: Use `kubectl get <resource> -o yaml`

### Time Management

For exam preparation:
- **First Pass**: Learn thoroughly (no time limit)
- **Second Pass**: Aim to complete in 2x estimated time
- **Third Pass**: Complete in 1.5x estimated time
- **Exam Ready**: Complete in estimated time or less

## Common Issues and Solutions

### NetworkPolicy Not Working

**Symptoms**: Pods can communicate despite deny policy

**Solutions**:
1. Check CNI plugin supports NetworkPolicy
   ```bash
   kubectl get pods -n kube-system | grep -E "calico|cilium|weave"
   ```
2. Verify NetworkPolicy exists
   ```bash
   kubectl get networkpolicies -A
   ```
3. Check pod labels match selectors
   ```bash
   kubectl get pods --show-labels
   ```

### Ingress Not Accessible

**Symptoms**: Cannot reach services via Ingress

**Solutions**:
1. Check Ingress controller is running
   ```bash
   kubectl get pods -n ingress-nginx
   ```
2. Verify Ingress resource
   ```bash
   kubectl get ingress -A
   kubectl describe ingress <name>
   ```
3. Check service exists and has endpoints
   ```bash
   kubectl get svc
   kubectl get endpoints
   ```

### Pod Security Violations

**Symptoms**: Pods fail to create with PSS errors

**Solutions**:
1. Check namespace labels
   ```bash
   kubectl get ns <namespace> --show-labels
   ```
2. Use dry-run to see violations
   ```bash
   kubectl apply -f pod.yaml --dry-run=server
   ```
3. Add required security context fields
   ```yaml
   securityContext:
     runAsNonRoot: true
     allowPrivilegeEscalation: false
   ```

### Certificate Issues

**Symptoms**: TLS errors, certificate not trusted

**Solutions**:
1. Verify secret exists
   ```bash
   kubectl get secret <name> -n <namespace>
   ```
2. Check certificate contents
   ```bash
   kubectl get secret <name> -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -text
   ```
3. Ensure Ingress references correct secret
   ```bash
   kubectl get ingress <name> -o yaml | grep secretName
   ```

## Lab Environment Cleanup

After completing all labs:

```bash
# Delete all lab namespaces
kubectl delete namespace lab-netpol
kubectl delete namespace lab-ingress
kubectl delete namespace lab-pss
kubectl delete namespace frontend
kubectl delete namespace backend

# Delete any CRDs or operators installed
kubectl delete -f kube-bench-job.yaml

# If using kind, delete cluster
kind delete cluster

# If using minikube, delete cluster
minikube delete
```

## Additional Resources

### Documentation
- [Kubernetes Official Docs](https://kubernetes.io/docs/home/)
- [kubectl Cheat Sheet](https://kubernetes.io/docs/reference/kubectl/cheatsheet/)

### Tools
- [kubectl](https://kubernetes.io/docs/reference/kubectl/)
- [kind](https://kind.sigs.k8s.io/)
- [minikube](https://minikube.sigs.k8s.io/)
- [k9s](https://k9scli.io/) - Terminal UI for Kubernetes

### Practice Environments
- [Killercoda Kubernetes Playground](https://killercoda.com/playgrounds/scenario/kubernetes)
- [Play with Kubernetes](https://labs.play-with-k8s.com/)

## Getting Help

If you encounter issues:

1. **Check Lab Troubleshooting Sections**: Each lab has specific troubleshooting guidance
2. **Review Documentation**: Links provided throughout labs
3. **Kubernetes Community**:
   - [Kubernetes Slack](https://kubernetes.slack.com/)
   - [Stack Overflow](https://stackoverflow.com/questions/tagged/kubernetes)
4. **KCSA Study Groups**: Join study groups for peer support

## Next Steps

After completing these labs:

1. Review concept documentation in [domains/01-cluster-setup](../../domains/01-cluster-setup/)
2. Practice labs multiple times for speed
3. Create your own scenarios
4. Move to Domain 2: [Cluster Hardening Labs](../02-cluster-hardening/)

## Progress Tracking

Use this checklist to track your progress:

- [ ] Lab environment setup complete
- [ ] Lab 01: Network Policies completed
- [ ] Lab 02: CIS Benchmarks completed
- [ ] Lab 03: Ingress Security completed
- [ ] Lab 04: Pod Security Standards completed
- [ ] All labs completed under time targets
- [ ] Challenge questions answered correctly
- [ ] Lab environment cleaned up

---

[Back to Domain 1 README](../../domains/01-cluster-setup/README.md) | [Back to Main README](../../README.md)
