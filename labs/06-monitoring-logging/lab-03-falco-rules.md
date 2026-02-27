# Lab 3: Custom Falco Rules

## Objectives

- Write custom Falco rules for specific threats
- Use macros and lists effectively
- Test and verify rule triggers
- Tune rules to reduce false positives
- Implement rule priorities and exceptions

**Duration**: 75 minutes | **Difficulty**: Advanced

## Prerequisites

- Completed Labs 1 and 2
- Falco installed and running
- Understanding of Falco rule syntax

## Part 1: Rule Basics (20 minutes)

### Step 1: Create Custom Rules ConfigMap

```bash

# Create custom rules file

cat <<'EOF' > custom-rules.yaml
customRules:
  custom-rules.yaml: |-

    # Define reusable macros

    - macro: spawned_process
      condition: evt.type = execve and evt.dir=<

    - macro: container
      condition: container.id != host

    # Define reusable lists

    - list: sensitive_binaries
      items: [ssh, sshd, nc, ncat, netcat]

    # Simple custom rule

    - rule: Suspicious Binary Executed
      desc: Detect execution of suspicious binaries in containers
      condition: >
        spawned_process and
        container and
        proc.name in (sensitive_binaries)
      output: >
        Suspicious binary executed in container
        (user=%user.name container=%container.name
         proc=%proc.name cmdline=%proc.cmdline)
      priority: WARNING
      tags: [container, process]
EOF

# Upgrade Falco with custom rules

helm upgrade falco falcosecurity/falco \
  --namespace falco \
  --reuse-values \
  -f custom-rules.yaml

# Wait for pods to restart

kubectl rollout status daemonset/falco -n falco
```

```

### Step 2: Verify Custom Rule Loaded

```bash

# Check if custom rule is loaded

FALCO_POD=$(kubectl get pods -n falco -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].metadata.name}')

kubectl exec -n falco $FALCO_POD -- falco --list | grep "Suspicious Binary"
```

```

### Step 3: Test Custom Rule

```bash

# Create test pod

kubectl run test-custom --image=alpine:3.19 --command -- sleep 3600

# Wait for pod

kubectl wait --for=condition=Ready pod/test-custom --timeout=60s

# Trigger the rule (install and run nc)

kubectl exec test-custom -- sh -c "apk add --no-cache netcat-openbsd && nc -l 9999 &"

# Check Falco logs

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=50 | grep "Suspicious Binary"
```

```

**Verification**:

- [ ] Custom rule loaded successfully
- [ ] Rule triggers on netcat execution
- [ ] Alert contains expected fields

## Part 2: Advanced Rules (25 minutes)

### Step 4: Package Manager Detection Rule

```bash

cat <<'EOF' > advanced-rules.yaml
customRules:
  custom-rules.yaml: |-

    # Macros

    - macro: spawned_process
      condition: evt.type = execve and evt.dir=<

    - macro: container
      condition: container.id != host

    # Lists

    - list: package_managers
      items: [apt, apt-get, yum, dnf, pip, pip3, npm, gem, apk]

    - list: allowed_namespaces
      items: [kube-system, kube-public, development]

    # Rule 1: Package manager in production

    - rule: Package Manager in Production Container
      desc: Package manager executed in non-dev container
      condition: >
        spawned_process and
        container and
        proc.name in (package_managers) and
        not k8s.ns.name in (allowed_namespaces)
      output: >
        Package manager executed (user=%user.name container=%container.name
         proc=%proc.name cmdline=%proc.cmdline namespace=%k8s.ns.name)
      priority: WARNING
      tags: [container, software, production]

    # Rule 2: Crypto mining detection

    - list: crypto_miners
      items: [xmrig, minerd, ethminer, cpuminer]

    - rule: Cryptocurrency Mining Detected
      desc: Known crypto mining process detected
      condition: >
        spawned_process and
        container and
        (proc.name in (crypto_miners) or
         proc.cmdline contains "stratum+tcp")
      output: >
        Crypto mining detected! (container=%container.name
         proc=%proc.name cmdline=%proc.cmdline)
      priority: CRITICAL
      tags: [malware, crypto]

    # Rule 3: SSH in container

    - rule: SSH Server in Container
      desc: SSH server process started in container
      condition: >
        spawned_process and
        container and
        proc.name = sshd and
        not k8s.pod.label.ssh-enabled = "true"
      output: >
        SSH server started in container (container=%container.name
         pod=%k8s.pod.name namespace=%k8s.ns.name)
      priority: WARNING
      tags: [container, ssh]

    # Rule 4: File download and execute

    - macro: remote_download_tools
      condition: proc.name in (wget, curl, fetch)

    - rule: Binary Downloaded and Executed
      desc: File downloaded to /tmp and executed
      condition: >
        spawned_process and
        container and
        proc.pname in (wget, curl, fetch) and
        proc.exe startswith /tmp/
      output: >
        Binary downloaded and executed (file=%proc.exe
         downloader=%proc.pname container=%container.name)
      priority: CRITICAL
      tags: [malware, execution]

    # Rule 5: Sensitive mount

    - rule: Container with Sensitive Mount
      desc: Container mounting sensitive host paths
      condition: >
        container and
        mount and
        (mount.source startswith /proc or
         mount.source startswith /var/run/docker.sock or
         mount.source startswith /etc/kubernetes)
      output: >
        Sensitive path mounted (container=%container.name
         mount=%mount.source)
      priority: WARNING
      tags: [container, mount]
EOF

# Apply advanced rules

helm upgrade falco falcosecurity/falco \
  --namespace falco \
  --reuse-values \
  -f advanced-rules.yaml

# Wait for rollout

kubectl rollout status daemonset/falco -n falco
```

```

### Step 5: Test Advanced Rules

**Test 1: Package Manager Detection**

```bash

# Should trigger in default namespace (not in allowed list)

kubectl run test-pkg --image=ubuntu:22.04 --command -- sleep 3600
kubectl wait --for=condition=Ready pod/test-pkg --timeout=60s

kubectl exec test-pkg -- apt-get update

# Check logs

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20 | grep "Package Manager"
```

```

**Test 2: Crypto Mining Detection**

```bash

# Simulate crypto miner

kubectl exec test-pkg -- sh -c "echo '#!/bin/sh' > /tmp/xmrig && chmod +x /tmp/xmrig && /tmp/xmrig || true"

# Check logs

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20 | grep "Crypto"
```

```

**Verification**:

- [ ] Package manager rule triggers
- [ ] Crypto mining rule works
- [ ] All advanced rules loaded

## Part 3: Rule Tuning (15 minutes)

### Step 6: Add Exceptions

```bash

cat <<'EOF' > tuned-rules.yaml
customRules:
  custom-rules.yaml: |-
    - macro: spawned_process
      condition: evt.type = execve and evt.dir=<

    - macro: container
      condition: container.id != host

    - list: package_managers
      items: [apt, apt-get, yum, dnf, pip, npm]

    # Tuned rule with exceptions

    - rule: Package Manager in Container
      desc: Package manager executed (with exceptions)
      condition: >
        spawned_process and
        container and
        proc.name in (package_managers) and
        not k8s.ns.name in (kube-system, development, staging) and
        not k8s.pod.label.build = "true" and
        not container.image.repository contains "builder"
      output: >
        Package manager in container (user=%user.name
         container=%container.name proc=%proc.name
         namespace=%k8s.ns.name image=%container.image.repository)
      priority: WARNING
      tags: [container, software]

      # Using exceptions (alternative syntax)

      exceptions:
        - name: allowed_ci_builds
          fields: [k8s.ns.name, k8s.pod.label.app]
          comps: [=, =]
          values:
            - [ci-system, builder]
            - [ci-system, build-agent]

    # Rate-limited rule (reduced noise)

    - rule: Outbound Connection
      desc: Container making outbound connection
      condition: >
        evt.type=connect and evt.dir=< and
        container and
        fd.typechar=4 and fd.sip != "0.0.0.0"
      output: "Outbound connection (dst=%fd.sip:%fd.dport container=%container.name)"
      priority: INFO

      # This would be noisy, so use sparingly or add filters

EOF

helm upgrade falco falcosecurity/falco -n falco --reuse-values -f tuned-rules.yaml
kubectl rollout status daemonset/falco -n falco
```

```

### Step 7: Test Exceptions

```bash

# This should NOT trigger (in development namespace)

kubectl create namespace development
kubectl run test-dev --image=ubuntu:22.04 -n development --command -- sleep 3600
kubectl wait --for=condition=Ready pod/test-dev -n development --timeout=60s
kubectl exec -n development test-dev -- apt-get update

# This SHOULD trigger (in default namespace)

kubectl exec test-pkg -- apt-get update

# Check logs

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=30 | grep "Package Manager"
```

```

**Verification**:

- [ ] Exception for development namespace works
- [ ] Non-excepted namespaces still trigger
- [ ] Rules are properly tuned

## Part 4: Priority and Organization (15 minutes)

### Step 8: Implement Rule Priorities

```bash

cat <<'EOF' > priority-rules.yaml
customRules:
  custom-rules.yaml: |-
    - macro: spawned_process
      condition: evt.type = execve and evt.dir=<

    - macro: container
      condition: container.id != host

    # CRITICAL priority - immediate response needed

    - rule: Container Escape Attempt
      desc: Potential container escape detected
      condition: >
        spawned_process and
        container and
        (proc.cmdline contains "docker" or
         proc.cmdline contains "runc" or
         proc.cmdline contains "/var/run/docker.sock")
      output: "Container escape attempt! (container=%container.name cmdline=%proc.cmdline)"
      priority: CRITICAL
      tags: [container_escape, critical]

    # ERROR priority - security violation

    - rule: Write to System Binary Directory
      desc: Attempt to write to system binary directory
      condition: >
        open_write and
        container and
        fd.directory in (/bin, /sbin, /usr/bin, /usr/sbin)
      output: "Write to binary dir (file=%fd.name container=%container.name)"
      priority: ERROR
      tags: [filesystem, binary]

    # WARNING priority - suspicious activity

    - rule: Shell Spawned by Non-Shell Process
      desc: Shell spawned by unexpected parent
      condition: >
        spawned_process and
        container and
        proc.name in (bash, sh, zsh) and
        not proc.pname in (bash, sh, zsh, sshd, sudo, su, systemd)
      output: "Unexpected shell spawn (shell=%proc.name parent=%proc.pname container=%container.name)"
      priority: WARNING
      tags: [shell, suspicious]

    # NOTICE priority - notable but not necessarily bad

    - rule: Container Started with Unusual User
      desc: Container running as unexpected UID
      condition: >
        spawned_process and
        container and
        user.uid = 1337
      output: "Container with unusual UID (uid=%user.uid container=%container.name)"
      priority: NOTICE
      tags: [container, user]

    # INFO priority - informational

    - rule: New Container Started
      desc: A new container was started
      condition: >
        container_started and
        container
      output: "New container (name=%container.name image=%container.image.repository)"
      priority: INFO
      tags: [container, lifecycle]
EOF

helm upgrade falco falcosecurity/falco -n falco --reuse-values -f priority-rules.yaml
kubectl rollout status daemonset/falco -n falco
```

```

### Step 9: Test Priority Levels

```bash

# Test CRITICAL: Container escape attempt

kubectl exec test-pkg -- sh -c "ls /var/run/docker.sock || true"

# Test WARNING: Shell spawn

kubectl run test-shell --image=alpine:3.19 --command -- sh -c "sleep 10 && /bin/sh"

# Filter logs by priority

echo "=== CRITICAL alerts ==="
kubectl logs -n falco -l app.kubernetes.io/name=falco | jq 'select(.priority=="Critical")'

echo "=== WARNING alerts ==="
kubectl logs -n falco -l app.kubernetes.io/name=falco | jq 'select(.priority=="Warning")' | tail -5
```

```

**Verification**:

- [ ] Different priorities work correctly
- [ ] Can filter alerts by priority
- [ ] Priority reflects severity accurately

## Part 5: Complex Detection (Optional Challenge)

### Step 10: Multi-Stage Attack Detection

```bash

cat <<'EOF' > complex-rules.yaml
customRules:
  custom-rules.yaml: |-
    - macro: spawned_process
      condition: evt.type = execve and evt.dir=<

    - macro: container
      condition: container.id != host

    # Stage 1: Reconnaissance

    - rule: Network Scanning Activity
      desc: Potential network scanning detected
      condition: >
        spawned_process and
        container and
        proc.name in (nmap, masscan, zmap, nc, ncat) and
        proc.cmdline contains "-p"
      output: "Network scanning (tool=%proc.name cmdline=%proc.cmdline container=%container.name)"
      priority: WARNING
      tags: [network, recon]

    # Stage 2: Exploitation

    - rule: Reverse Shell Indicators
      desc: Reverse shell patterns detected
      condition: >
        spawned_process and
        container and
        ((proc.name in (bash, sh) and proc.cmdline contains "-i") or
         (proc.name in (nc, ncat, netcat) and (proc.cmdline contains "-e" or proc.cmdline contains "-c")))
      output: "Reverse shell detected! (proc=%proc.name cmdline=%proc.cmdline container=%container.name)"
      priority: CRITICAL
      tags: [shell, exploitation]

    # Stage 3: Persistence

    - rule: Cron Job Creation
      desc: Cron job created in container
      condition: >
        open_write and
        container and
        (fd.name startswith "/etc/cron" or
         fd.name startswith "/var/spool/cron")
      output: "Cron job created (file=%fd.name container=%container.name)"
      priority: ERROR
      tags: [persistence, cron]

    # Stage 4: Privilege Escalation

    - rule: SetUID Binary Creation
      desc: SetUID binary created
      condition: >
        chmod and
        container and
        evt.arg.mode contains "S_ISUID"
      output: "SetUID binary created (file=%evt.arg.filename container=%container.name)"
      priority: CRITICAL
      tags: [privilege_escalation, setuid]
EOF

helm upgrade falco falcosecurity/falco -n falco --reuse-values -f complex-rules.yaml
kubectl rollout status daemonset/falco -n falco
```

```

**Verification**:

- [ ] Complex rules loaded
- [ ] Can detect multi-stage attacks
- [ ] Rules cover attack lifecycle

## Troubleshooting

### Issue 1: Rule Not Triggering

```bash

# Verify rule is loaded

kubectl exec -n falco $FALCO_POD -- falco --list | grep "<rule-name>"

# Check rule syntax

kubectl exec -n falco $FALCO_POD -- falco --validate /etc/falco/falco_rules.yaml

# Check Falco logs for errors

kubectl logs -n falco -l app.kubernetes.io/name=falco | grep -i error

# Test with simple condition
# Simplify the rule condition to see if basic detection works

```

```

### Issue 2: Too Many False Positives

```bash

# Solutions:
# 1. Add namespace exceptions
# 2. Add pod label exceptions
# 3. Increase specificity of condition
# 4. Adjust priority to INFO or NOTICE
# 5. Use exceptions block

```

```

### Issue 3: Custom Rules Not Loading

```bash

# Check ConfigMap

kubectl get configmap -n falco

# Verify Helm values

helm get values falco -n falco

# Check pod configuration

kubectl describe pod -n falco -l app.kubernetes.io/name=falco | grep -A 10 "Mounts"

# Force pod restart

kubectl rollout restart daemonset/falco -n falco
```

```

## Verification Checklist

- [ ] Can write basic custom rules
- [ ] Can use macros and lists
- [ ] Can test rule triggers
- [ ] Can add exceptions to reduce false positives
- [ ] Can set appropriate priorities
- [ ] Can organize rules by category
- [ ] Can create complex multi-condition rules

## Cleanup

```bash

# Remove test pods

kubectl delete pod test-custom test-pkg test-shell --ignore-not-found
kubectl delete pod test-dev -n development --ignore-not-found
kubectl delete namespace development --ignore-not-found
```

```

## Challenge Exercises

1. **Custom Detection**: Create rules to detect:

   - Container accessing cloud metadata API (169.254.169.254)
   - Sudo usage in containers
   - File download from internet
   - Database credential files being read

1. **Rule Optimization**: Take a noisy rule and add 5 different exceptions to reduce false positives

1. **Attack Simulation**: Simulate a complete attack chain and verify all stages are detected by your rules

## Key Takeaways

- Custom rules extend Falco's detection capabilities
- Macros and lists improve rule maintainability
- Exceptions are critical for reducing false positives
- Priority indicates severity and required response
- Testing is essential before deploying rules
- Complex conditions can detect sophisticated attacks

## Next Steps

- Proceed to [Lab 4: Log Aggregation](lab-04-log-aggregation.md)
- Review [Runtime Detection theory](../../domains/06-monitoring-logging/runtime-detection.md)
- Explore community Falco rules for more examples

---

**Congratulations!** You can now create custom Falco rules tailored to your security needs.
