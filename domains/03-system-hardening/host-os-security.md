# Host Operating System Security

## Introduction

The host operating system is the foundation of your Kubernetes security posture. Since containers share the host kernel, a compromised host can lead to cluster-wide breaches. Host OS security focuses on minimizing attack surface, maintaining system integrity, and implementing defense-in-depth.

**Key Concept**: "A chain is only as strong as its weakest link" - even perfect Kubernetes configuration won't protect you if the underlying host is vulnerable.

## Why Host OS Security Matters

### The Shared Kernel Risk

Unlike virtual machines, containers share the host kernel:

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  Container  │  │  Container  │  │  Container  │
│    App A    │  │    App B    │  │    App C    │
└─────────────┘  └─────────────┘  └─────────────┘
       │                │                │
       └────────────────┴────────────────┘
                       │
              ┌────────▼────────┐
              │  Shared Kernel  │
              └─────────────────┘
                       │
              ┌────────▼────────┐
              │   Host OS       │
              └─────────────────┘
```

**Implications**:

- Kernel vulnerability affects ALL containers
- Host compromise = cluster compromise
- Container escape leads to host access
- Resource limits depend on kernel enforcement

### Attack Surface

Common host vulnerabilities:

1. **Unpatched systems**: Known CVEs in kernel/packages
1. **Unnecessary services**: Extra attack vectors
1. **Weak access controls**: Poor SSH/sudo configuration
1. **Insecure defaults**: Default passwords, open ports
1. **Excessive permissions**: SUID binaries, world-writable files

## Host Hardening Fundamentals

### 1. Minimal Operating System

Use minimal OS distributions designed for containers:

**Recommended Options**:

| OS | Description | Use Case |
| ---- | ------------- | ---------- |
| **Ubuntu Minimal** | Stripped-down Ubuntu | General purpose |
| **Flatcar Container Linux** | Immutable, auto-updating | Production clusters |
| **Bottlerocket** | AWS-optimized, minimal | AWS EKS |
| **RancherOS** | Entire OS runs in Docker | Rancher users |
| **Talos Linux** | API-managed, no SSH | Advanced security |

**Why Minimal?**

- Fewer packages = smaller attack surface
- Reduced maintenance burden
- Faster updates and patches
- Lower resource overhead

**Example: Package Comparison**

```bash

# Full Ubuntu Server

$ dpkg -l | wc -l
2847

# Ubuntu Minimal

$ dpkg -l | wc -l
598

# Bottlerocket (immutable, read-only)
# No package manager - can't install additional software!

```

```

### 2. System Updates and Patching

Keep the host OS and kernel updated:

**Check Current Version**:

```bash

# Kernel version

uname -r

# Output: 5.15.0-76-generic

# OS version

cat /etc/os-release

# Output:
# NAME="Ubuntu"
# VERSION="22.04.3 LTS (Jammy Jellyfish)"

# Check for available updates

sudo apt update
apt list --upgradable
```

```

**Update System**:

```bash

# Update package lists

sudo apt update

# Upgrade all packages

sudo apt upgrade -y

# Upgrade with dist-upgrade (handles dependencies better)

sudo apt dist-upgrade -y

# Reboot if kernel was updated

sudo reboot
```

```

**Automated Updates**:

```bash

# Install unattended-upgrades

sudo apt install unattended-upgrades -y

# Enable automatic security updates

sudo dpkg-reconfigure --priority=low unattended-upgrades

# Configure automatic updates

sudo nano /etc/apt/apt.conf.d/50unattended-upgrades
```

```

Example configuration:

```conf

Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
```

```

**Best Practices**:

- Enable automatic security updates
- Schedule maintenance windows for reboots
- Test updates in staging first
- Monitor CVE feeds for critical vulnerabilities
- Use tools like `needrestart` to check which services need restart

### 3. Disable Unnecessary Services

Reduce attack surface by disabling unused services:

**List Running Services**:

```bash

# List all running services

sudo systemctl list-units --type=service --state=running

# Example output:
# UNIT                     LOAD   ACTIVE SUB     DESCRIPTION
# ssh.service              loaded active running OpenBSD Secure Shell server
# containerd.service       loaded active running containerd container runtime
# kubelet.service          loaded active running kubelet

```

```

**Common Services to Disable**:

```bash

# Print services (if not using printing)

sudo systemctl stop cups
sudo systemctl disable cups

# Bluetooth (on servers)

sudo systemctl stop bluetooth
sudo systemctl disable bluetooth

# Avahi/Bonjour (service discovery)

sudo systemctl stop avahi-daemon
sudo systemctl disable avahi-daemon

# Snapd (if not needed)

sudo systemctl stop snapd
sudo systemctl disable snapd
```

```

**Essential Services for Kubernetes**:

Keep these enabled:

- `ssh` (if remote access needed)
- `containerd` (container runtime)
- `kubelet` (Kubernetes node agent)
- `systemd-resolved` (DNS resolution)
- `systemd-networkd` or `NetworkManager` (networking)

**Verify Service Status**:

```bash

# Check if service is enabled

sudo systemctl is-enabled ssh

# Output: enabled

# Check if service is active

sudo systemctl is-active ssh

# Output: active

```

```

### 4. Secure SSH Access

SSH is often the only remote access method - secure it properly:

**Edit SSH Configuration**:

```bash

sudo nano /etc/ssh/sshd_config
```

```

**Hardened SSH Configuration**:

```

# Disable root login

PermitRootLogin no

# Disable password authentication (use keys only)

PasswordAuthentication no
PubkeyAuthentication yes

# Disable empty passwords

PermitEmptyPasswords no

# Use strong ciphers only

Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Limit SSH protocol version

Protocol 2

# Set login grace time

LoginGraceTime 60

# Maximum authentication attempts

MaxAuthTries 3

# Disable X11 forwarding (if not needed)

X11Forwarding no

# Disable TCP forwarding (if not needed)

AllowTcpForwarding no

# Use specific users only

AllowUsers ubuntu admin

# Enable logging

SyslogFacility AUTH
LogLevel VERBOSE

```
```

**Apply Changes**:

```bash

# Test configuration

sudo sshd -t

# Restart SSH service

sudo systemctl restart sshd
```

```

**SSH Key Authentication**:

```bash

# On your local machine, generate key pair

ssh-keygen -t ed25519 -C "your_email@example.com"

# Copy public key to server

ssh-copy-id -i ~/.ssh/id_ed25519.pub user@server

# Test key-based login

ssh -i ~/.ssh/id_ed25519 user@server
```

```

**Additional SSH Security**:

```bash

# Install fail2ban to prevent brute force

sudo apt install fail2ban -y

# Configure fail2ban for SSH

sudo nano /etc/fail2ban/jail.local
```

```

```ini

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
```

```

```bash

# Start fail2ban

sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Check banned IPs

sudo fail2ban-client status sshd
```

```

### 5. File System Security

Protect critical files and directories:

**Set Secure Permissions**:

```bash

# Secure SSH directory

chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys

# Secure sensitive system files

sudo chmod 600 /etc/shadow
sudo chmod 600 /etc/gshadow
sudo chmod 644 /etc/passwd
sudo chmod 644 /etc/group

# Kubernetes configuration

chmod 600 ~/.kube/config
```

```

**Find SUID/SGID Binaries**:

SUID binaries run with owner privileges - potential privilege escalation risk:

```bash

# Find all SUID binaries

sudo find / -perm -4000 -type f 2>/dev/null

# Find all SGID binaries

sudo find / -perm -2000 -type f 2>/dev/null

# Example output:
# /usr/bin/sudo
# /usr/bin/passwd
# /usr/bin/chsh
# /usr/bin/newgrp

```

```

**Remove Unnecessary SUID Bits**:

```bash

# Remove SUID from unnecessary binaries

sudo chmod u-s /path/to/binary

# Example: If you don't use 'at' command

sudo chmod u-s /usr/bin/at
```

```

**World-Writable Files**:

```bash

# Find world-writable files (dangerous!)

sudo find / -perm -002 -type f 2>/dev/null

# Find world-writable directories

sudo find / -perm -002 -type d 2>/dev/null

# Fix permissions

sudo chmod o-w /path/to/file
```

```

**Read-Only Mount Points**:

Mount certain directories as read-only:

```bash

# Edit /etc/fstab

sudo nano /etc/fstab
```

```

```

# Mount /boot as read-only

UUID=xxxx /boot ext4 ro,defaults 0 2

# Mount /tmp with noexec,nosuid

tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0

```
```

```bash

# Remount with new options

sudo mount -o remount /boot
```

```

### 6. Kernel Hardening

Configure kernel parameters for security:

**View Current Settings**:

```bash

# View all kernel parameters

sudo sysctl -a

# View specific parameter

sudo sysctl kernel.dmesg_restrict
```

```

**Apply Kernel Hardening**:

```bash

# Edit sysctl configuration

sudo nano /etc/sysctl.d/99-kubernetes-hardening.conf
```

```

**Recommended Kernel Parameters**:

```conf

# Prevent kernel information leaks

kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2

# Enable ASLR (Address Space Layout Randomization)

kernel.randomize_va_space = 2

# Restrict core dumps

kernel.core_uses_pid = 1
fs.suid_dumpable = 0

# Enable SYN flood protection

net.ipv4.tcp_syncookies = 1

# Disable IPv4 forwarding (if not routing)
# Note: Kubernetes nodes need IP forwarding enabled!
# net.ipv4.ip_forward = 0

# Disable IPv6 (if not used)

net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Ignore ICMP redirects

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# Disable source packet routing

net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Log martian packets

net.ipv4.conf.all.log_martians = 1

# Restrict ptrace to prevent process inspection

kernel.yama.ptrace_scope = 1

# Restrict access to kernel logs

kernel.dmesg_restrict = 1
```

```

**Apply Settings**:

```bash

# Apply immediately

sudo sysctl -p /etc/sysctl.d/99-kubernetes-hardening.conf

# Verify setting

sudo sysctl kernel.randomize_va_space

# Output: kernel.randomize_va_space = 2

```

```

**Important Note for Kubernetes**:

Some settings affect Kubernetes functionality:

```conf

# These MUST be enabled for Kubernetes

net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
```

```

### 7. Audit and Logging

Enable comprehensive logging for security monitoring:

**Auditd Configuration**:

```bash

# Install auditd

sudo apt install auditd audispd-plugins -y

# Start auditd

sudo systemctl enable auditd
sudo systemctl start auditd
```

```

**Add Audit Rules**:

```bash

# Edit audit rules

sudo nano /etc/audit/rules.d/kubernetes.rules
```

```

```bash

# Audit file access to sensitive files

-w /etc/shadow -p wa -k shadow_file
-w /etc/passwd -p wa -k passwd_file
-w /etc/sudoers -p wa -k sudoers_file

# Audit Kubernetes configuration changes

-w /etc/kubernetes/ -p wa -k k8s_config
-w /var/lib/kubelet/ -p wa -k kubelet_config

# Audit container runtime

-w /etc/containerd/ -p wa -k containerd_config
-w /var/lib/containerd/ -p wa -k containerd_data

# Audit system calls

-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b64 -S mount -k mount
-a always,exit -F arch=b64 -S unlink -k delete

# Audit network connections

-a always,exit -F arch=b64 -S socket -S connect -k network
```

```

```bash

# Reload audit rules

sudo augenrules --load

# Check audit rules

sudo auditctl -l

# Search audit logs

sudo ausearch -k k8s_config

# Generate audit report

sudo aureport
```

```

**Centralized Logging**:

Forward logs to a central server:

```bash

# Install rsyslog

sudo apt install rsyslog -y

# Configure remote logging

sudo nano /etc/rsyslog.d/50-remote.conf
```

```

```

# Forward all logs to remote syslog server

*.* @192.168.1.100:514  # UDP

# OR

*.* @@192.168.1.100:514  # TCP (more reliable)

```
```

```bash

# Restart rsyslog

sudo systemctl restart rsyslog
```

```

## CIS Benchmark Compliance

The CIS Kubernetes Benchmark includes host security recommendations:

### Section 4.1: Worker Node Configuration Files

**4.1.1 Ensure kubelet configuration files have permissions of 644 or more restrictive**:

```bash

sudo chmod 644 /var/lib/kubelet/config.yaml
```

```

**4.1.2 Ensure kubelet configuration files are owned by root:root**:

```bash

sudo chown root:root /var/lib/kubelet/config.yaml
```

```

**4.1.3 Ensure Kubernetes PKI directory has permissions of 750 or more restrictive**:

```bash

sudo chmod -R 750 /etc/kubernetes/pki
```

```

**4.1.4 Ensure certificate authority file permissions are 600 or more restrictive**:

```bash

sudo chmod 600 /etc/kubernetes/pki/ca.crt
sudo chmod 600 /etc/kubernetes/pki/ca.key
```

```

### Section 4.2: Kubelet Configuration

These are configured in `/var/lib/kubelet/config.yaml`:

```yaml

apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration

# 4.2.1 Ensure anonymous auth is disabled

authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true

# 4.2.2 Ensure authorization mode is not AlwaysAllow

authorization:
  mode: Webhook

# 4.2.6 Ensure protect-kernel-defaults is set

protectKernelDefaults: true

# 4.2.10 Ensure TLS cert file is set

tlsCertFile: /var/lib/kubelet/pki/kubelet.crt
tlsPrivateKeyFile: /var/lib/kubelet/pki/kubelet.key
```

```

### Automated CIS Scanning

Use kube-bench to audit your hosts:

```bash

# Run kube-bench as a Job

kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml

# View results

kubectl logs job/kube-bench

# Example output:
# [INFO] 4 Worker Node Security Configuration
# [PASS] 4.1.1 Ensure kubelet config file permissions are set to 644
# [FAIL] 4.1.5 Ensure kubelet service file permissions are set to 644
# [PASS] 4.2.1 Ensure anonymous-auth is set to false

```

```

## Host Security Checklist

Use this checklist for hardening Kubernetes nodes:

### Initial Setup

- [ ] Use minimal OS distribution
- [ ] Apply all security updates
- [ ] Remove unnecessary packages
- [ ] Disable unnecessary services
- [ ] Configure secure SSH (keys only, no root)
- [ ] Set up firewall (ufw/iptables)

### File System Security

- [ ] Set secure file permissions on sensitive files
- [ ] Audit SUID/SGID binaries
- [ ] Configure read-only mount points where appropriate
- [ ] Enable file system auditing

### Kernel Hardening

- [ ] Apply kernel hardening parameters
- [ ] Enable ASLR
- [ ] Disable unnecessary kernel modules
- [ ] Configure kernel module signing

### Access Control

- [ ] Implement sudo policy
- [ ] Use PAM for authentication controls
- [ ] Configure user account policies
- [ ] Enable fail2ban or similar

### Monitoring and Logging

- [ ] Enable auditd
- [ ] Configure centralized logging
- [ ] Set up log rotation
- [ ] Monitor security events

### Kubernetes-Specific

- [ ] Secure kubelet configuration
- [ ] Set proper file ownership for K8s files
- [ ] Enable kubelet authentication/authorization
- [ ] Configure TLS for kubelet

### Ongoing Maintenance

- [ ] Regular security updates
- [ ] Periodic CIS benchmark audits
- [ ] Review audit logs
- [ ] Update security policies

## Common Issues and Solutions

### Issue 1: Pods Failing After Kernel Hardening

**Problem**: Pods fail to start after applying `protectKernelDefaults: true`

**Cause**: Kubelet checks if kernel parameters match expected values

**Solution**: Ensure kernel parameters are set correctly:

```bash

# Required kernel settings for Kubernetes

sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.bridge.bridge-nf-call-iptables=1

# Make permanent

echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
echo "net.bridge.bridge-nf-call-iptables=1" | sudo tee -a /etc/sysctl.conf
```

```

### Issue 2: SSH Key Authentication Not Working

**Problem**: Can't login with SSH keys after hardening

**Solution**: Check permissions and configuration:

```bash

# On server

chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys

# Check SSH logs

sudo tail -f /var/log/auth.log

# Test SSH config

sudo sshd -t
```

```

### Issue 3: Automatic Updates Breaking Cluster

**Problem**: Kernel update causes node issues

**Solution**: Implement controlled update process:

```bash

# Drain node before update

kubectl drain node-1 --ignore-daemonsets --delete-emptydir-data

# Apply updates

sudo apt update && sudo apt upgrade -y

# Reboot

sudo reboot

# Uncordon node after reboot

kubectl uncordon node-1
```

```

## Best Practices Summary

1. **Minimize Attack Surface**: Use minimal OS, disable unnecessary services
1. **Keep Updated**: Enable automatic security updates, monitor CVEs
1. **Defense in Depth**: Multiple layers of security (firewall, SELinux/AppArmor, audit)
1. **Least Privilege**: Restrict access, use sudo instead of root, key-based SSH
1. **Audit Everything**: Enable comprehensive logging and monitoring
1. **Regular Audits**: Use kube-bench, scan for vulnerabilities
1. **Immutable Infrastructure**: Consider immutable OS like Bottlerocket or Talos
1. **Incident Response**: Have a plan for responding to compromised hosts

## Next Steps

After understanding host OS security, proceed to:

- [Container Runtime Security](runtime-security.md) - Securing containerd
- [AppArmor and Seccomp](apparmor-seccomp.md) - Application-level restrictions
- [Lab 1: Host Hardening](../../labs/03-system-hardening/lab-01-host-hardening.md) - Hands-on practice

---

**Key Takeaway**: The host OS is the foundation of your security. No amount of Kubernetes security configuration can protect against a compromised host. Invest time in proper host hardening.
