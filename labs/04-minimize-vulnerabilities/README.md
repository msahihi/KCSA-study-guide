# Domain 4 Labs - Minimize Microservice Vulnerabilities

## Overview

This directory contains hands-on labs for Domain 4 of the KCSA exam, focusing on minimizing vulnerabilities in Kubernetes microservices. These labs provide practical experience with secrets management, admission controllers, runtime security, and image security.

## Lab Environment Requirements

Before starting these labs, ensure you have:

### Required
- Kubernetes cluster v1.30.x with admin access (Kind, Minikube, or cloud-based)
- kubectl CLI tool installed and configured
- Helm 3.x installed
- Access to modify control plane configuration (for some labs)
- At least 4GB RAM and 2 CPU cores available

### Tools to Install
- [Trivy](https://trivy.dev/) - Vulnerability scanner
- [Cosign](https://docs.sigstore.dev/cosign/installation/) - Image signing
- [Falco](https://falco.org/docs/getting-started/installation/) - Runtime security (installed via Helm in labs)
- OPA Gatekeeper (installed via Helm in labs)
- Docker or Podman for building images

### Optional
- Lens or k9s for cluster visualization
- Harbor registry (can be installed in lab)
- jq for JSON processing

## Labs Overview

### [Lab 01 - Secrets Encryption at Rest](./lab-01-secrets-encryption.md)
**Duration**: 45 minutes
**Difficulty**: Intermediate
**Topics**: Encryption configuration, key management, secret rotation

Learn how to enable and configure encryption at rest for Kubernetes Secrets, including key rotation and verification.

**Learning Objectives:**
- Configure encryption at rest for Secrets
- Generate and manage encryption keys
- Verify secrets are encrypted in etcd
- Perform key rotation
- Troubleshoot encryption issues

### [Lab 02 - Admission Controllers](./lab-02-admission-controllers.md)
**Duration**: 60 minutes
**Difficulty**: Intermediate
**Topics**: ValidatingWebhook, MutatingWebhook, custom admission logic

Build and deploy custom admission controllers to enforce security policies at the API server level.

**Learning Objectives:**
- Create ValidatingWebhookConfiguration
- Implement MutatingWebhookConfiguration
- Deploy webhook server with TLS
- Test admission policies
- Debug webhook failures

### [Lab 03 - OPA Gatekeeper](./lab-03-opa-gatekeeper.md)
**Duration**: 75 minutes
**Difficulty**: Intermediate to Advanced
**Topics**: Policy as code, Rego language, ConstraintTemplates

Deploy OPA Gatekeeper and implement comprehensive security policies using the Rego policy language.

**Learning Objectives:**
- Install and configure OPA Gatekeeper
- Create ConstraintTemplates
- Write Rego policies
- Implement common security constraints
- Audit and enforce policies
- Debug policy violations

### [Lab 04 - Falco Runtime Security](./lab-04-falco-runtime.md)
**Duration**: 60 minutes
**Difficulty**: Intermediate
**Topics**: Runtime monitoring, threat detection, custom rules

Deploy Falco and configure runtime security monitoring to detect threats and policy violations.

**Learning Objectives:**
- Install Falco with eBPF driver
- Understand default Falco rules
- Create custom security rules
- Generate and analyze security alerts
- Integrate with notification systems
- Test threat detection scenarios

### [Lab 05 - Image Security](./lab-05-image-security.md)
**Duration**: 90 minutes
**Difficulty**: Intermediate to Advanced
**Topics**: Vulnerability scanning, image signing, registry security, policy enforcement

Implement comprehensive image security including scanning, signing, and policy enforcement.

**Learning Objectives:**
- Scan images for vulnerabilities with Trivy
- Sign images with Cosign
- Verify image signatures
- Build secure container images
- Deploy private registry with Harbor
- Enforce image policies with admission controllers
- Implement CI/CD image security

## Lab Setup

### Quick Start - Create Lab Cluster

```bash
# Using Kind
cat <<EOF | kind create cluster --name kcsa-lab --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: /var/lib/kubelet/seccomp
    containerPath: /var/lib/kubelet/seccomp
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        enable-admission-plugins: NodeRestriction,PodSecurity
- role: worker
- role: worker
EOF

# Verify cluster
kubectl cluster-info
kubectl get nodes
```

### Install Common Tools

```bash
# Install Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Install Trivy
wget https://github.com/aquasecurity/trivy/releases/download/v0.48.0/trivy_0.48.0_Linux-64bit.tar.gz
tar zxvf trivy_0.48.0_Linux-64bit.tar.gz
sudo mv trivy /usr/local/bin/

# Install Cosign
wget https://github.com/sigstore/cosign/releases/download/v2.2.2/cosign-linux-amd64
chmod +x cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign

# Verify installations
helm version
trivy version
cosign version
```

### Create Lab Namespaces

```bash
# Create namespaces for labs
kubectl create namespace lab-secrets
kubectl create namespace lab-admission
kubectl create namespace lab-gatekeeper
kubectl create namespace lab-falco
kubectl create namespace lab-images

# Label namespaces
kubectl label namespace lab-admission policy=enforced
kubectl label namespace lab-gatekeeper policy=restricted
```

## Lab Progression

### Recommended Order

1. **Lab 01 - Secrets Encryption**: Foundation for protecting sensitive data
2. **Lab 02 - Admission Controllers**: Learn webhook-based policy enforcement
3. **Lab 03 - OPA Gatekeeper**: Advanced policy enforcement with Rego
4. **Lab 04 - Falco Runtime Security**: Runtime threat detection
5. **Lab 05 - Image Security**: Comprehensive image security workflow

### Alternative Paths

**Security Foundations Path** (For beginners):
1. Lab 01 - Secrets Encryption
2. Lab 05 - Image Security (basics only)
3. Lab 04 - Falco Runtime Security
4. Lab 02 - Admission Controllers
5. Lab 03 - OPA Gatekeeper

**Policy Enforcement Path** (For policy-focused learning):
1. Lab 02 - Admission Controllers
2. Lab 03 - OPA Gatekeeper
3. Lab 05 - Image Security (policy enforcement section)

## Common Issues and Solutions

### Issue: Cannot modify control plane configuration

**Solution**: Use a cluster where you have control plane access (Kind, Minikube, kubeadm) or skip encryption configuration in managed Kubernetes services.

### Issue: Falco not detecting events

**Solution**:
```bash
# Check Falco driver is loaded
kubectl logs -n falco -l app.kubernetes.io/name=falco | grep -i "driver loaded"

# If using eBPF driver
kubectl describe daemonset falco -n falco | grep driver
```

### Issue: Admission webhook timeouts

**Solution**:
```bash
# Increase webhook timeout
kubectl patch validatingwebhookconfiguration <name> \
  --type='json' \
  -p='[{"op": "replace", "path": "/webhooks/0/timeoutSeconds", "value":10}]'
```

### Issue: Image pull failures

**Solution**:
```bash
# Check image pull secrets
kubectl get secrets
kubectl describe pod <pod-name> | grep -A 5 Events

# Recreate image pull secret
kubectl delete secret regcred
kubectl create secret docker-registry regcred \
  --docker-server=myregistry.io \
  --docker-username=myuser \
  --docker-password=mypassword
```

## Cleanup

### Lab-Specific Cleanup

Each lab includes cleanup instructions in its respective file.

### Complete Lab Environment Cleanup

```bash
# Delete lab namespaces
kubectl delete namespace lab-secrets
kubectl delete namespace lab-admission
kubectl delete namespace lab-gatekeeper
kubectl delete namespace lab-falco
kubectl delete namespace lab-images

# Uninstall Helm releases
helm uninstall falco -n falco
helm uninstall gatekeeper -n gatekeeper-system

# Delete cluster (if using Kind)
kind delete cluster --name kcsa-lab
```

## Additional Practice

### Challenge Exercises

After completing all labs, try these challenge exercises:

1. **Integrated Security Pipeline**: Build a complete CI/CD pipeline that includes:
   - Image scanning with Trivy
   - Image signing with Cosign
   - Admission control with Gatekeeper
   - Runtime monitoring with Falco
   - Secrets management with external vault

2. **Policy as Code**: Create a comprehensive policy library that:
   - Enforces Pod Security Standards
   - Validates resource limits
   - Checks image sources
   - Requires specific labels
   - Blocks privileged workloads

3. **Threat Simulation**: Simulate security incidents and detect them:
   - Container escape attempts
   - Cryptomining activity
   - Data exfiltration
   - Privilege escalation
   - Unauthorized network connections

4. **Multi-Cluster Security**: Implement consistent security policies across multiple clusters using:
   - GitOps (ArgoCD/Flux)
   - Centralized policy management
   - Unified monitoring and alerting

## Study Tips

1. **Hands-On Practice**: Complete each lab at least twice
2. **Time Yourself**: Practice common tasks under time pressure
3. **Documentation**: Bookmark key Kubernetes.io pages
4. **Troubleshooting**: Intentionally break things and practice fixing them
5. **Integration**: Practice combining multiple security controls
6. **Scenarios**: Create realistic security scenarios and practice responding

## Exam Preparation Checklist

After completing these labs, you should be able to:

- [ ] Enable encryption at rest for Secrets
- [ ] Configure and rotate encryption keys
- [ ] Create ValidatingWebhookConfiguration
- [ ] Create MutatingWebhookConfiguration
- [ ] Write Rego policies for OPA Gatekeeper
- [ ] Deploy and configure Falco
- [ ] Create custom Falco rules
- [ ] Scan images for vulnerabilities with Trivy
- [ ] Sign and verify images with Cosign
- [ ] Build secure container images
- [ ] Configure seccomp profiles
- [ ] Apply AppArmor profiles to pods
- [ ] Implement RBAC for Secrets access
- [ ] Integrate security tools with CI/CD
- [ ] Debug admission controller issues
- [ ] Troubleshoot runtime security alerts

## Additional Resources

### Official Documentation
- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/)
- [Encrypting Secret Data at Rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
- [Dynamic Admission Control](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)

### Tools Documentation
- [Trivy Documentation](https://trivy.dev/)
- [Cosign Documentation](https://docs.sigstore.dev/cosign/overview/)
- [Falco Documentation](https://falco.org/docs/)
- [OPA Gatekeeper Documentation](https://open-policy-agent.github.io/gatekeeper/)

### Community Resources
- [CNCF Security TAG](https://github.com/cncf/tag-security)
- [Kubernetes Security Special Interest Group](https://github.com/kubernetes/community/tree/master/sig-security)
- [Falco Community](https://falco.org/community/)

## Support

For questions or issues with these labs:
1. Review the troubleshooting section in each lab
2. Check the Common Issues section above
3. Consult the official documentation
4. Search for similar issues in community forums

---

[Back to Main Labs](../) | [Domain 4 Concepts →](../../domains/04-minimize-vulnerabilities/README.md)
