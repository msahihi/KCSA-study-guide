# Lab 1: Host Hardening

## Objectives

By the end of this lab, you will be able to:

- Audit a Kubernetes node's security configuration
- Disable unnecessary services to reduce attack surface
- Configure secure SSH access with key-based authentication
- Apply kernel security parameters (sysctl)
- Set proper file permissions on sensitive files
- Run automated CIS Benchmark audits with kube-bench
- Understand and remediate common host security issues

## Prerequisites

- Running Kubernetes cluster (Kind or Minikube)
- kubectl configured and working
- Access to worker nodes (docker exec for Kind, minikube ssh for Minikube)
- Basic Linux command-line knowledge

## Estimated Time

60 minutes

## Lab Environment

We'll use a Kind cluster to simulate a Kubernetes node:

```bash
# Create lab cluster
cat <<EOF | kind create cluster --name host-hardening --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  image: kindest/node:v1.30.0
- role: worker
  image: kindest/node:v1.30.0
  extraMounts:
  - hostPath: /tmp/kube-bench
    containerPath: /tmp/kube-bench
EOF

# Verify cluster
kubectl get nodes
```

## Part 1: Initial Security Audit

### Step 1.1: Access the Worker Node

```bash
# List Kind nodes
docker ps --filter name=host-hardening

# Access worker node
docker exec -it host-hardening-worker bash

# You should now be inside the worker node
hostname
# Output: host-hardening-worker
```

### Step 1.2: Audit Running Services

```bash
# List all active services
systemctl list-units --type=service --state=running

# Expected output includes:
# containerd.service
# kubelet.service
# systemd-journald.service
# systemd-logind.service
# And potentially others

# Count running services
systemctl list-units --type=service --state=running | wc -l
```

**Analysis**: Note which services are running. In a production environment, you should disable any unnecessary services.

### Step 1.3: Check Open Network Ports

```bash
# Install net-tools if not available
apt-get update && apt-get install -y net-tools

# List listening ports
ss -tulpn

# Or using netstat
netstat -tulpn

# Expected output:
# LISTEN 0  128  0.0.0.0:10250  (kubelet)
# LISTEN 0  128  0.0.0.0:10256  (kube-proxy)
# LISTEN 0  128  [::]:10250     (kubelet)
# LISTEN 0  128  [::]:10256     (kube-proxy)
```

**Analysis**: Identify which ports are open and which services are listening.

### Step 1.4: Find SUID/SGID Binaries

SUID binaries can be privilege escalation risks:

```bash
# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Common SUID binaries:
# /usr/bin/su
# /usr/bin/sudo
# /usr/bin/passwd
# /usr/bin/mount
# /usr/bin/umount

# Find SGID binaries
find / -perm -2000 -type f 2>/dev/null
```

**Analysis**: Review the list. Are any unexpected programs SUID?

### Step 1.5: Check File Permissions on Sensitive Files

```bash
# Check Kubernetes certificate permissions
ls -la /etc/kubernetes/pki/

# Expected: Certificates should be 644, keys should be 600
# ca.crt: -rw-r--r--
# ca.key: -rw-------

# Check kubelet config
ls -la /var/lib/kubelet/config.yaml
# Expected: -rw-r--r-- (644)

# Check containerd config
ls -la /etc/containerd/config.toml
# Expected: -rw-r--r-- (644)
```

**Analysis**: Note any overly permissive files (world-writable, etc.)

## Part 2: Disable Unnecessary Services

### Step 2.1: Identify Services to Disable

```bash
# List all enabled services
systemctl list-unit-files --type=service --state=enabled

# Example services that might be running but aren't needed on K8s nodes:
# - bluetooth
# - cups (printing)
# - avahi-daemon (service discovery)
# - snapd (if not using snaps)
```

### Step 2.2: Disable Unnecessary Services

**Note**: In a Kind container, many services aren't present. This is for demonstration:

```bash
# Example: If bluetooth is running (unlikely in container)
systemctl stop bluetooth 2>/dev/null || echo "Bluetooth not present"
systemctl disable bluetooth 2>/dev/null || echo "Bluetooth not present"

# Check status
systemctl status bluetooth 2>/dev/null || echo "Bluetooth not present"
```

### Step 2.3: Verify Essential Services Are Running

```bash
# Ensure critical services are active
systemctl is-active containerd
# Output: active

systemctl is-active kubelet
# Output: active

# If either is not active, start them:
# systemctl start containerd
# systemctl start kubelet
```

## Part 3: Kernel Hardening Parameters

### Step 3.1: View Current Kernel Parameters

```bash
# View all sysctl parameters
sysctl -a | head -20

# View specific security parameters
sysctl kernel.randomize_va_space
sysctl kernel.dmesg_restrict
sysctl kernel.kptr_restrict
```

### Step 3.2: Apply Security Hardening Parameters

Create a hardening configuration:

```bash
# Create sysctl configuration file
cat <<EOF > /etc/sysctl.d/99-kubernetes-hardening.conf
# Enable ASLR (Address Space Layout Randomization)
kernel.randomize_va_space = 2

# Restrict dmesg to prevent information leakage
kernel.dmesg_restrict = 1

# Restrict kernel pointer exposure
kernel.kptr_restrict = 2

# Disable core dumps for SUID programs
fs.suid_dumpable = 0

# Restrict ptrace to prevent process inspection
kernel.yama.ptrace_scope = 1

# Network security
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1

# Kubernetes-required settings (must be enabled!)
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF

# View the file
cat /etc/sysctl.d/99-kubernetes-hardening.conf
```

### Step 3.3: Apply the Configuration

```bash
# Load the module for bridge settings
modprobe br_netfilter

# Apply the settings
sysctl -p /etc/sysctl.d/99-kubernetes-hardening.conf

# Verify settings
sysctl kernel.randomize_va_space
# Output: kernel.randomize_va_space = 2

sysctl net.ipv4.ip_forward
# Output: net.ipv4.ip_forward = 1
```

**Expected Output**:

```
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
fs.suid_dumpable = 0
kernel.yama.ptrace_scope = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
...
```

### Step 3.4: Test Kernel Parameter Effects

```bash
# Test dmesg restriction (should fail for non-root)
su - nobody -s /bin/bash -c "dmesg"
# Output: dmesg: read kernel buffer failed: Operation not permitted

# As root, it works
dmesg | tail -5
```

## Part 4: Secure Kubernetes File Permissions

### Step 4.1: Set Correct Permissions on Kubelet Config

```bash
# Check current permissions
ls -la /var/lib/kubelet/config.yaml

# Set correct permissions (644)
chmod 644 /var/lib/kubelet/config.yaml
chown root:root /var/lib/kubelet/config.yaml

# Verify
ls -la /var/lib/kubelet/config.yaml
# Expected: -rw-r--r-- 1 root root ... /var/lib/kubelet/config.yaml
```

### Step 4.2: Secure Certificate Files

```bash
# Check PKI directory permissions
ls -la /etc/kubernetes/pki/

# Set directory permissions
chmod 750 /etc/kubernetes/pki
chown -R root:root /etc/kubernetes/pki

# Set certificate file permissions (public certs = 644)
find /etc/kubernetes/pki -name "*.crt" -exec chmod 644 {} \;

# Set key file permissions (private keys = 600)
find /etc/kubernetes/pki -name "*.key" -exec chmod 600 {} \;

# Verify
ls -la /etc/kubernetes/pki/
# Expected:
# -rw-r--r-- 1 root root ... ca.crt
# -rw------- 1 root root ... ca.key
```

### Step 4.3: Secure Containerd Socket

```bash
# Check containerd socket permissions
ls -la /run/containerd/containerd.sock

# Set correct permissions
chmod 660 /run/containerd/containerd.sock
chown root:root /run/containerd/containerd.sock

# Verify
ls -la /run/containerd/containerd.sock
# Expected: srw-rw---- 1 root root 0 ... /run/containerd/containerd.sock
```

**Why This Matters**: The containerd socket provides full control over containers. Only root should have access.

## Part 5: CIS Benchmark Audit

### Step 5.1: Install kube-bench

Exit the node container and run from your host:

```bash
# Exit the node
exit

# Run kube-bench as a Job
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml

# Wait for job to complete
kubectl wait --for=condition=complete job/kube-bench --timeout=60s

# View results
kubectl logs job/kube-bench

# Save results to file
kubectl logs job/kube-bench > /tmp/kube-bench-results.txt
```

### Step 5.2: Analyze Results

```bash
# View summary
kubectl logs job/kube-bench | grep -A 20 "== Summary =="

# Expected output:
# == Summary ==
# 38 checks PASS
# 12 checks FAIL
# 5 checks WARN
# 0 checks INFO
```

### Step 5.3: Review Failing Checks

```bash
# View only failures
kubectl logs job/kube-bench | grep FAIL

# Example failures:
# [FAIL] 4.1.1 Ensure that the kubelet service file permissions are set to 644
# [FAIL] 4.1.5 Ensure that the --kubeconfig kubelet.conf file permissions are set to 644
# [FAIL] 4.2.6 Ensure that the --protect-kernel-defaults argument is set to true
```

### Step 5.4: Remediate a Specific Issue

Let's fix the `--protect-kernel-defaults` issue:

```bash
# Access worker node again
docker exec -it host-hardening-worker bash

# Edit kubelet config
nano /var/lib/kubelet/config.yaml
```

Add this line:

```yaml
protectKernelDefaults: true
```

```bash
# Restart kubelet
systemctl restart kubelet

# Verify kubelet is running
systemctl status kubelet

# Exit node
exit
```

**Note**: In production, you'd also need to ensure kernel parameters are set correctly.

### Step 5.5: Re-run kube-bench

```bash
# Delete previous job
kubectl delete job kube-bench

# Run again
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl wait --for=condition=complete job/kube-bench --timeout=60s

# Check if the specific check now passes
kubectl logs job/kube-bench | grep "4.2.6"
# Should show PASS instead of FAIL
```

## Part 6: Audit Logging Configuration

### Step 6.1: Install and Configure auditd

```bash
# Access worker node
docker exec -it host-hardening-worker bash

# Install auditd
apt-get update && apt-get install -y auditd audispd-plugins

# Start auditd
systemctl enable auditd
systemctl start auditd

# Check status
systemctl status auditd
```

### Step 6.2: Create Audit Rules for Kubernetes

```bash
# Create audit rules file
cat <<EOF > /etc/audit/rules.d/kubernetes.rules
# Audit Kubernetes configuration changes
-w /etc/kubernetes/ -p wa -k k8s_config
-w /var/lib/kubelet/ -p wa -k kubelet_config
-w /etc/containerd/ -p wa -k containerd_config

# Audit sensitive file access
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/sudoers -p wa -k sudoers_changes

# Audit system calls
-a always,exit -F arch=b64 -S mount -k mount
-a always,exit -F arch=b64 -S unlink -F auid>=1000 -k delete
EOF

# View the rules
cat /etc/audit/rules.d/kubernetes.rules
```

### Step 6.3: Load Audit Rules

```bash
# Load rules
augenrules --load

# Verify rules are loaded
auditctl -l

# Expected output:
# -w /etc/kubernetes/ -p wa -k k8s_config
# -w /var/lib/kubelet/ -p wa -k kubelet_config
# ...
```

### Step 6.4: Test Audit Logging

```bash
# Make a change to trigger audit
echo "# Test comment" >> /etc/kubernetes/kubelet.conf

# Search audit log
ausearch -k k8s_config -ts recent

# Expected output:
# time->Thu Feb 27 10:00:00 2024
# type=SYSCALL msg=audit(1234567890.123:456): arch=c000003e syscall=257
# success=yes exit=3 a0=ffffff9c a1=7f1234567890 a2=441 a3=1b6 items=2
# ppid=12345 pid=12346 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0
# egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="bash"
# exe="/usr/bin/bash" key="k8s_config"
```

### Step 6.5: Generate Audit Report

```bash
# Generate summary report
aureport

# Generate report for specific key
aureport -k

# Output shows audit activity summary
```

## Part 7: Verification and Testing

### Step 7.1: Verify Kernel Parameters Persist

```bash
# Exit and re-enter node (simulates reboot)
exit
docker exec -it host-hardening-worker bash

# Check parameters are still set
sysctl kernel.randomize_va_space
# Output: kernel.randomize_va_space = 2

sysctl net.ipv4.ip_forward
# Output: net.ipv4.ip_forward = 1
```

### Step 7.2: Verify File Permissions

```bash
# Check key files
ls -la /etc/kubernetes/pki/ca.key
# Expected: -rw------- 1 root root

ls -la /var/lib/kubelet/config.yaml
# Expected: -rw-r--r-- 1 root root

ls -la /run/containerd/containerd.sock
# Expected: srw-rw---- 1 root root
```

### Step 7.3: Verify Kubernetes Functionality

```bash
# Exit node
exit

# Verify cluster is still functional
kubectl get nodes
# All nodes should be Ready

kubectl get pods -A
# All pods should be Running

# Create test pod
kubectl run test --image=nginx:1.27 --restart=Never

# Verify it runs
kubectl get pod test
# Should show Running

# Cleanup
kubectl delete pod test
```

## Part 8: Document Findings

Create a security audit report:

```bash
cat <<EOF > /tmp/host-hardening-report.txt
========================================
Host Security Audit Report
========================================
Date: $(date)
Node: host-hardening-worker

1. Running Services:
$(docker exec host-hardening-worker systemctl list-units --type=service --state=running --no-pager | wc -l) services running

2. Open Network Ports:
$(docker exec host-hardening-worker ss -tulpn 2>/dev/null | grep LISTEN | wc -l) listening ports

3. SUID Binaries:
$(docker exec host-hardening-worker find / -perm -4000 -type f 2>/dev/null | wc -l) SUID binaries found

4. Kernel Hardening:
- ASLR: $(docker exec host-hardening-worker sysctl kernel.randomize_va_space | cut -d= -f2)
- dmesg restrict: $(docker exec host-hardening-worker sysctl kernel.dmesg_restrict | cut -d= -f2)
- IP forwarding: $(docker exec host-hardening-worker sysctl net.ipv4.ip_forward | cut -d= -f2)

5. CIS Benchmark:
$(kubectl logs job/kube-bench 2>/dev/null | grep "== Summary ==" -A 5 || echo "Run kube-bench to populate")

6. Recommendations:
- Regularly update and patch the OS
- Review and remove unnecessary SUID binaries
- Enable automatic security updates
- Implement centralized logging
- Schedule regular CIS benchmark audits

========================================
EOF

cat /tmp/host-hardening-report.txt
```

## Cleanup

```bash
# Delete kube-bench job
kubectl delete job kube-bench

# Delete the cluster
kind delete cluster --name host-hardening
```

## Troubleshooting

### Issue 1: sysctl parameters not applying

**Error**: `sysctl: cannot stat /proc/sys/kernel/...`

**Solution**:
```bash
# Some sysctl parameters may not be available in containers
# This is expected in Kind/Minikube
# In production bare-metal/VM nodes, all parameters should work
```

### Issue 2: auditd fails to start

**Error**: `Failed to start auditd.service`

**Solution**:
```bash
# Check if auditd is already running
systemctl status auditd

# Check logs
journalctl -u auditd -n 50

# Try restarting
systemctl restart auditd
```

### Issue 3: kube-bench job doesn't complete

**Solution**:
```bash
# Check job status
kubectl describe job kube-bench

# Check pod logs
kubectl logs -l job-name=kube-bench

# Delete and retry
kubectl delete job kube-bench
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
```

### Issue 4: Kubelet fails after hardening

**Error**: Kubelet won't start after setting `protectKernelDefaults: true`

**Solution**:
```bash
# Check kubelet logs
journalctl -u kubelet -n 50

# Ensure kernel parameters are set correctly
sysctl net.ipv4.ip_forward
sysctl net.bridge.bridge-nf-call-iptables

# If not set, configure them:
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.bridge.bridge-nf-call-iptables=1
```

## Key Takeaways

1. **Host hardening is foundational** - Even the best Kubernetes security can't protect against a compromised host
2. **Defense-in-depth** - Multiple layers of security (services, permissions, kernel, audit)
3. **CIS Benchmarks** - Automated auditing tools like kube-bench are essential
4. **Least privilege** - Restrict permissions, disable unnecessary services
5. **Audit everything** - Comprehensive logging enables detection and forensics
6. **Regular maintenance** - Security is ongoing, not one-time
7. **Test changes** - Always verify cluster functionality after hardening

## Next Steps

- Proceed to [Lab 2: AppArmor Profiles](lab-02-apparmor-profiles.md)
- Review [Host OS Security concepts](../../domains/03-system-hardening/host-os-security.md)
- Explore [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)

## Additional Challenges

1. **Automate hardening**: Create an Ansible playbook to apply these settings
2. **Custom kube-bench**: Modify kube-bench checks for your organization
3. **Monitoring**: Set up Prometheus alerts for security parameter changes
4. **Compliance**: Create a compliance dashboard tracking CIS benchmark score

---

**Congratulations!** You've completed Lab 1: Host Hardening. You now understand how to secure Kubernetes worker nodes at the operating system level.
