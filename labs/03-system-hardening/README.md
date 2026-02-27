# Domain 3: System Hardening - Hands-On Labs

## Overview

These hands-on labs provide practical experience with system hardening techniques for Kubernetes environments. You'll learn to secure the host OS, container runtime, and apply kernel-level security controls.

**Prerequisites**:

- Completed Domain 1 and 2 labs
- Local Kubernetes cluster (Kind/Minikube)
- Basic Linux command-line skills
- Understanding of container concepts
- Access to a Linux environment (Ubuntu 22.04 recommended)

**Lab Environment**:

- Kubernetes v1.30.x
- containerd v1.7.x
- Kind v0.22.x or Minikube
- Ubuntu 22.04 LTS (for host hardening exercises)

## Lab Structure

Each lab follows this format:

1. **Objectives**: What you'll learn
1. **Prerequisites**: Required knowledge and setup
1. **Estimated Time**: How long the lab takes
1. **Step-by-Step Instructions**: Detailed commands with explanations
1. **Expected Output**: What you should see
1. **Verification**: How to confirm success
1. **Troubleshooting**: Common issues and solutions
1. **Cleanup**: Reset your environment

## Labs

### [Lab 1: Host Hardening](lab-01-host-hardening.md)

**Duration**: 60 minutes
**Difficulty**: Beginner

Learn to harden Kubernetes nodes:

- Audit system configuration
- Disable unnecessary services
- Configure secure SSH access
- Apply kernel security parameters
- Set file permissions properly
- Run CIS benchmark audits

**Skills Gained**:

- Host OS security fundamentals
- CIS Benchmark compliance
- System auditing techniques
- Security configuration management

---

### [Lab 2: AppArmor Profiles](lab-02-apparmor-profiles.md)

**Duration**: 90 minutes
**Difficulty**: Intermediate

Create and apply AppArmor profiles:

- Load default profiles
- Create custom profiles for nginx
- Apply profiles to pods
- Test profile enforcement
- Debug profile violations
- Use complain mode for development

**Skills Gained**:

- AppArmor profile syntax
- Profile creation and testing
- Kubernetes integration
- Troubleshooting access denials

---

### [Lab 3: Seccomp Profiles](lab-03-seccomp-profiles.md)

**Duration**: 90 minutes
**Difficulty**: Intermediate

Implement syscall filtering:

- Apply RuntimeDefault profile
- Create custom seccomp filters
- Block dangerous syscalls
- Test syscall blocking
- Generate profiles from audit logs
- Handle profile errors

**Skills Gained**:

- Seccomp profile JSON format
- Syscall filtering techniques
- Profile deployment strategies
- Audit log analysis

---

### [Lab 4: Runtime Security](lab-04-runtime-security.md)

**Duration**: 90 minutes
**Difficulty**: Intermediate to Advanced

Secure the container runtime:

- Configure containerd securely
- Test container isolation
- Explore namespaces and cgroups
- Drop capabilities effectively
- Monitor runtime events
- Simulate and prevent container escapes

**Skills Gained**:

- Containerd configuration
- Runtime API security
- Namespace isolation verification
- Runtime security monitoring

## Lab Setup

### Option 1: Kind Cluster (Recommended)

```bash

# Create a multi-node cluster for realistic scenarios

cat <<EOF | kind create cluster --name kcsa-lab-3 --config=-
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

kubectl cluster-info --context kind-kcsa-lab-3
kubectl get nodes
```

```

### Option 2: Minikube

```bash

# Start Minikube with containerd

minikube start --driver=docker --container-runtime=containerd \
  --kubernetes-version=v1.30.0 \
  --nodes=2

# Verify

kubectl get nodes
```

```

### Required Tools

```bash

# Install crictl (CRI CLI)

VERSION="v1.30.0"
wget https://github.com/kubernetes-sigs/cri-tools/releases/download/$VERSION/crictl-$VERSION-linux-amd64.tar.gz
sudo tar zxvf crictl-$VERSION-linux-amd64.tar.gz -C /usr/local/bin
rm -f crictl-$VERSION-linux-amd64.tar.gz

# Configure crictl

cat <<EOF | sudo tee /etc/crictl.yaml
runtime-endpoint: unix:///run/containerd/containerd.sock
image-endpoint: unix:///run/containerd/containerd.sock
timeout: 10
debug: false
EOF

# Verify

crictl version

# Install AppArmor utilities (Ubuntu/Debian)

sudo apt update
sudo apt install -y apparmor-utils

# Verify AppArmor

sudo aa-status

# Install audit tools

sudo apt install -y auditd

# Start auditd

sudo systemctl enable auditd
sudo systemctl start auditd
```

```

### Accessing Worker Nodes

**For Kind clusters**:

```bash

# List nodes

docker ps --format "table {{.Names}}\t{{.Status}}"

# Access control-plane node

docker exec -it kcsa-lab-3-control-plane bash

# Access worker node

docker exec -it kcsa-lab-3-worker bash

# Inside node, you can:
# - View containerd config
# - Load AppArmor profiles
# - Check kernel parameters
# - Install seccomp profiles

```

```

**For Minikube**:

```bash

# SSH into node

minikube ssh

# For multi-node:

minikube ssh -n kcsa-lab-3-m02
```

```

## Lab Tips

### General Tips

1. **Take Notes**: Document interesting findings and gotchas
1. **Read Errors Carefully**: Error messages often tell you exactly what's wrong
1. **Use `--dry-run`**: Test manifests before applying: `kubectl apply -f file.yaml --dry-run=client`
1. **Check Logs**: Always check pod logs when something fails: `kubectl logs <pod>`
1. **Describe Resources**: Use `kubectl describe` to see events: `kubectl describe pod <pod>`

### Security Tips

1. **Test in Dev First**: Never test security profiles in production first
1. **Start Permissive**: Use complain/audit mode before enforcing
1. **Backup Configs**: Save original configurations before modifying
1. **Document Changes**: Keep track of what you change and why
1. **Understand Before Applying**: Don't copy-paste without understanding

### Troubleshooting Tips

1. **Check AppArmor**: `sudo aa-status` shows loaded profiles
1. **Check Seccomp**: `grep Seccomp /proc/<pid>/status` shows seccomp mode
1. **Check Capabilities**: `cat /proc/<pid>/status | grep Cap` shows capabilities
1. **Check Logs**: `sudo dmesg | grep -i denied` shows kernel denials
1. **Check Audit**: `sudo ausearch -m AVC,SECCOMP -ts recent` shows security events

### Common Issues

**Issue**: "Profile not found"

- **Solution**: Ensure profile is loaded on the node where pod is scheduled

**Issue**: "Permission denied"

- **Solution**: Check AppArmor/Seccomp logs, adjust profile or add capability

**Issue**: "OOMKilled"

- **Solution**: Increase memory limits or optimize application

**Issue**: "CrashLoopBackOff"

- **Solution**: Check pod logs, verify image, check security context

## Lab Environment Reset

Between labs, you may want to reset your environment:

```bash

# Delete all pods in default namespace

kubectl delete pods --all

# Delete all custom resources

kubectl delete configmap,secret --all

# For complete reset, delete and recreate cluster

kind delete cluster --name kcsa-lab-3

# Then recreate with setup command above

```

```

## Lab Verification

After completing each lab, verify your understanding:

### Lab 1 Verification

- [ ] Can identify insecure host configurations
- [ ] Can disable unnecessary services
- [ ] Can configure SSH securely
- [ ] Can apply kernel hardening parameters
- [ ] Can run CIS benchmark audits

### Lab 2 Verification

- [ ] Can write basic AppArmor profiles
- [ ] Can load and apply profiles to pods
- [ ] Can test profile enforcement
- [ ] Can debug profile violations
- [ ] Can use complain mode

### Lab 3 Verification

- [ ] Can create seccomp JSON profiles
- [ ] Can apply profiles to pods
- [ ] Can identify blocked syscalls
- [ ] Can troubleshoot profile errors
- [ ] Can generate profiles from audit logs

### Lab 4 Verification

- [ ] Can configure containerd securely
- [ ] Can verify namespace isolation
- [ ] Can drop capabilities properly
- [ ] Can monitor runtime events
- [ ] Can recognize container escape attempts

## Additional Practice

After completing the labs, try these challenges:

### Challenge 1: Secure a Real Application

Take an existing application (e.g., WordPress, Jenkins) and:

1. Apply AppArmor and Seccomp profiles
1. Drop all unnecessary capabilities
1. Set appropriate resource limits
1. Run as non-root user
1. Use read-only root filesystem

### Challenge 2: CIS Benchmark Compliance

Audit your cluster with kube-bench and:

1. Fix all failing host security checks
1. Document why any checks can't be fixed
1. Create a compliance report
1. Automate remediation

### Challenge 3: Break and Fix

Intentionally misconfigure security settings:

1. Create pods with various privilege escalation paths
1. Practice detecting the vulnerabilities
1. Fix the issues using security controls
1. Document your findings

## Next Steps

After completing all Domain 3 labs:

1. Review the [Domain 3 concepts](../../domains/03-system-hardening/README.md)
1. Complete the [Domain 3 practice questions](../../mock-questions/domain-03-questions.md)
1. Move to [Domain 4: Minimize Microservice Vulnerabilities](../../domains/04-minimize-vulnerabilities/README.md)
1. Continue with [Domain 4 Labs](../04-minimize-vulnerabilities/README.md)

## Resources

- [Linux Security Modules Documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/)
- [AppArmor Wiki](https://gitlab.com/apparmor/apparmor/-/wikis/home)
- [Seccomp BPF](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
- [Containerd Documentation](https://containerd.io/docs/)
- [CIS Kubernetes Benchmarks](https://www.cisecurity.org/benchmark/kubernetes)
- [NSA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)

## Feedback

If you encounter issues with these labs:

1. Check the troubleshooting sections
1. Review the expected output
1. Verify your environment matches the prerequisites
1. Consult the domain theory documentation
1. Ask for help in CNCF Slack #kubernetes-security

---

**Remember**: System hardening is about defense-in-depth. No single control is perfect, but multiple layers make attacks significantly harder. Practice these techniques until they become second nature.
