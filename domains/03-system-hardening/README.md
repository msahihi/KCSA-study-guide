# Domain 3: System Hardening (15%)

## Overview

System hardening is the process of securing the underlying infrastructure that runs your Kubernetes workloads. This domain covers securing the host operating system, container runtime, and kernel-level security mechanisms that protect containers from threats.

**Why System Hardening Matters**:

- Containers share the host kernel, making host security critical
- A compromised host can lead to cluster-wide security breaches
- Defense-in-depth requires security at multiple layers
- Runtime security prevents attacks that bypass configuration checks
- Host hardening is a CIS Kubernetes Benchmark requirement

**Exam Weight**: 15% of the KCSA exam (approximately 9 questions)

**Key Principle**: "Secure the foundation before securing the application"

## Topics Covered

### 1. [Host Operating System Security](host-os-security.md)

Learn how to secure the hosts running your Kubernetes nodes:

- Minimize the host OS footprint
- Keep systems updated and patched
- Disable unnecessary services
- Configure secure SSH access
- Implement file system security
- CIS Benchmark compliance for Linux hosts

**Why It Matters**: The host OS is the foundation of container security. A vulnerable host can compromise all containers running on it.

### 2. [Container Runtime Security](runtime-security.md)

Understand how to secure the container runtime (containerd):

- Container runtime architecture
- Runtime configuration security
- Container isolation mechanisms
- Runtime socket security
- CRI security best practices
- Runtime privilege management

**Why It Matters**: The container runtime is the bridge between Kubernetes and containers. Securing it prevents container escape attacks.

### 3. [AppArmor and Seccomp](apparmor-seccomp.md)

Master mandatory access control and syscall filtering:

- AppArmor profiles for containers
- Creating custom AppArmor profiles
- Seccomp profiles and syscall filtering
- Default seccomp profiles
- Kubernetes integration
- Debugging profile issues

**Why It Matters**: These Linux security modules provide fine-grained control over container capabilities and system calls.

### 4. [Kernel Security](kernel-security.md)

Explore kernel-level security mechanisms:

- Namespace isolation
- Control groups (cgroups) for resource limits
- Capabilities management
- Kernel hardening parameters
- SELinux basics (comparison with AppArmor)
- Kernel module management

**Why It Matters**: Understanding kernel security helps you leverage Linux security features and prevent privilege escalation.

## Domain Learning Objectives

By the end of this domain, you will be able to:

1. Harden Linux hosts running Kubernetes nodes
1. Configure and secure container runtimes
1. Create and apply AppArmor profiles to containers
1. Implement seccomp profiles for syscall filtering
1. Understand kernel security mechanisms
1. Apply CIS Benchmark recommendations
1. Debug security profile issues
1. Implement defense-in-depth at the system level

## Key Concepts Summary

### Host Security Layers

```
┌─────────────────────────────────────────┐
│        Kubernetes Workloads             │
├─────────────────────────────────────────┤
│    Container Runtime (containerd)       │
├─────────────────────────────────────────┤
│   Security Modules (AppArmor/Seccomp)   │
├─────────────────────────────────────────┤
│       Linux Kernel (Namespaces)         │
├─────────────────────────────────────────┤
│      Host Operating System              │
└─────────────────────────────────────────┘
```

### Security Controls by Layer

| Layer | Security Controls | Tools |
| ------- | ------------------- | ------- |
| **Host OS** | Updates, patches, minimal services | apt, yum, systemctl |
| **Kernel** | Namespaces, cgroups, capabilities | sysctl, /proc |
| **Security Modules** | AppArmor, Seccomp, SELinux | apparmor, seccomp profiles |
| **Runtime** | Socket security, rootless mode | containerd, crictl |
| **Container** | Read-only rootfs, no privileges | Kubernetes manifests |

### Common Attack Vectors

Understanding attack vectors helps you prioritize hardening:

1. **Container Escape**: Breaking out of container isolation
1. **Privilege Escalation**: Gaining root on the host
1. **Malicious System Calls**: Using syscalls to attack the kernel
1. **Resource Exhaustion**: DoS attacks via uncontrolled resource usage
1. **Kernel Exploits**: Leveraging unpatched kernel vulnerabilities
1. **Runtime Socket Access**: Abusing runtime API for malicious purposes

## CIS Benchmark Alignment

This domain aligns with several CIS Kubernetes Benchmark sections:

- **Section 3**: Control Plane Configuration (Runtime security)
- **Section 4**: Worker Node Security Configuration
  - 4.1: Worker Node Configuration Files
  - 4.2: Kubelet Configuration
- **Section 5**: Policies (AppArmor, Seccomp)
  - 5.1: RBAC and Service Accounts
  - 5.7: General Policies (Security Contexts)

## Practical Skills Required

### For the Exam

You should be comfortable with:

- Reading and understanding AppArmor profiles
- Identifying correct seccomp profile syntax
- Recognizing insecure host configurations
- Understanding namespace isolation concepts
- Evaluating runtime security settings
- Applying security profiles to pods

### For Real-World Use

Beyond the exam, you'll need to:

- Create custom AppArmor profiles for applications
- Debug profile enforcement issues
- Automate host hardening with tools like Ansible
- Monitor runtime security events
- Respond to container escape attempts
- Implement audit logging for system calls

## Hands-On Labs

Complete these labs in order to build practical skills:

1. **[Lab 1: Host Hardening](../../labs/03-system-hardening/lab-01-host-hardening.md)**
   - Configure secure host settings
   - Disable unnecessary services
   - Apply CIS Benchmark recommendations
   - Verify hardening effectiveness

1. **[Lab 2: AppArmor Profiles](../../labs/03-system-hardening/lab-02-apparmor-profiles.md)**
   - Load and apply AppArmor profiles
   - Create custom profiles for containers
   - Test profile enforcement
   - Debug profile issues

1. **[Lab 3: Seccomp Profiles](../../labs/03-system-hardening/lab-03-seccomp-profiles.md)**
   - Apply default seccomp profiles
   - Create custom seccomp filters
   - Test syscall blocking
   - Handle profile errors

1. **[Lab 4: Runtime Security](../../labs/03-system-hardening/lab-04-runtime-security.md)**
   - Secure containerd configuration
   - Test container isolation
   - Monitor runtime events
   - Prevent container escapes

## Quick Reference

### Essential Commands

```bash

# Host security

sudo systemctl list-units --type=service --state=running
sudo ss -tulpn | grep LISTEN
sudo find / -perm -4000 -type f 2>/dev/null

# AppArmor

sudo aa-status
sudo apparmor_parser -r /etc/apparmor.d/profile
sudo aa-enforce /etc/apparmor.d/profile

# Seccomp

docker run --security-opt seccomp=profile.json image
grep Seccomp /proc/PID/status

# Kernel security

cat /proc/sys/kernel/randomize_va_space
sudo sysctl -a | grep kernel
cat /proc/PID/status | grep Cap

# Runtime

sudo systemctl status containerd
crictl info
sudo crictl ps
```

```

### AppArmor Profile Example

```

# include <tunables/global>

profile k8s-nginx flags=(attach_disconnected,mediate_deleted) {

  #include <abstractions/base>

  network inet tcp,
  network inet udp,

  deny /bin/**wl,
  deny /root/** wl,
  deny /etc/shadow r,

  /usr/sbin/nginx mr,
  /var/log/nginx/**w,
  /etc/nginx/** r,
}

```
```

### Seccomp Profile Example

```json

{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["read", "write", "open", "close"],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

```

### Pod with Security Profiles

```yaml

apiVersion: v1
kind: Pod
metadata:
  name: secured-pod
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: localhost/k8s-nginx
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/audit.json
  containers:
  - name: app
    image: nginx:1.27
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      readOnlyRootFilesystem: true
```

```

## Common Pitfalls and Tips

### Pitfalls to Avoid

1. **Over-restricting profiles**: Test thoroughly before enforcing
1. **Ignoring host updates**: Keep kernel and OS patched
1. **Forgetting profile loading**: Profiles must be loaded on all nodes
1. **Wrong profile syntax**: Profile errors can prevent pod startup
1. **Not testing in dev first**: Always test profiles in non-prod
1. **Leaving debug services enabled**: Disable SSH password auth, etc.

### Exam Tips

- Know the difference between AppArmor and Seccomp
- Understand which security controls apply at which layer
- Be able to identify insecure configurations
- Remember that profiles must be on the node before pod creation
- Seccomp profiles use JSON format, AppArmor uses a custom syntax
- Know how to check if AppArmor/Seccomp is enabled

### Best Practices

1. **Defense-in-depth**: Apply security at every layer
1. **Least privilege**: Start with deny-all, allow only what's needed
1. **Test profiles**: Use complain/audit mode before enforce mode
1. **Automate hardening**: Use configuration management tools
1. **Monitor and audit**: Log security events for detection
1. **Regular updates**: Keep host OS and kernel patched
1. **Minimal host OS**: Remove unnecessary packages and services

## Real-World Scenarios

### Scenario 1: Preventing Container Escape

**Problem**: A container vulnerability allows arbitrary code execution.

**Solution**: Multiple layers of defense:

1. Run containers with read-only root filesystem
1. Apply seccomp profile to block dangerous syscalls
1. Use AppArmor to restrict file access
1. Drop all capabilities
1. Run as non-root user

### Scenario 2: Compliance Requirements

**Problem**: Must comply with CIS Kubernetes Benchmark.

**Solution**:

1. Use kube-bench to audit cluster
1. Apply host hardening (Section 4)
1. Configure kubelet securely
1. Enable AppArmor/Seccomp profiles
1. Regular compliance scanning

### Scenario 3: Restricting Network Access

**Problem**: Container should only access specific endpoints.

**Solution**:

1. Network Policies (Layer 3/4)
1. AppArmor network rules (Layer 7)
1. Service mesh policies (application layer)
1. Host firewall rules (iptables/nftables)

## Study Checklist

Before moving to the next domain, ensure you can:

- [ ] List common host hardening techniques
- [ ] Explain the difference between AppArmor and Seccomp
- [ ] Create a basic AppArmor profile
- [ ] Write a simple seccomp filter
- [ ] Apply security profiles to Kubernetes pods
- [ ] Check if AppArmor/Seccomp is enabled on a node
- [ ] Understand namespace isolation concepts
- [ ] Explain how capabilities restrict container privileges
- [ ] Identify insecure runtime configurations
- [ ] Debug why a pod won't start due to profile issues

## Additional Resources

### Official Documentation

- [Kubernetes Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [AppArmor in Kubernetes](https://kubernetes.io/docs/tutorials/security/apparmor/)
- [Seccomp in Kubernetes](https://kubernetes.io/docs/tutorials/security/seccomp/)
- [Container Runtime Interface](https://kubernetes.io/docs/concepts/architecture/cri/)

### Tools and Projects

- [kube-bench](https://github.com/aquasecurity/kube-bench) - CIS Benchmark auditing
- [bane](https://github.com/genuinetools/bane) - AppArmor profile generator
- [oci-seccomp-bpf-hook](https://github.com/containers/oci-seccomp-bpf-hook) - Generate seccomp profiles
- [Falco](https://falco.org/) - Runtime security monitoring

### Learning Resources

- [Linux Security Modules](https://www.kernel.org/doc/html/latest/admin-guide/LSM/index.html)
- [Containerd Security](https://github.com/containerd/containerd/blob/main/docs/SECURITY.md)
- [CIS Benchmarks](https://www.cisecurity.org/benchmark/kubernetes)
- [NSA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)

## Next Steps

After completing this domain:

1. Complete all Domain 3 labs
1. Review the security profiles section in the cheatsheet
1. Move to [Domain 4: Minimize Microservice Vulnerabilities](../04-minimize-vulnerabilities/README.md)
1. Practice creating security profiles for sample applications

---

**Remember**: System hardening is about defense-in-depth. No single security control is perfect, but multiple layers make attacks significantly harder.

**Pro Tip**: Always test security profiles in a development environment first. A misconfigured profile can prevent legitimate workloads from running.
