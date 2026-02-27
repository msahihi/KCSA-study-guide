# Runtime Detection and Response

## Introduction

Runtime detection identifies malicious activity as it happens, enabling immediate response before significant damage occurs. Unlike static security controls that prevent known bad configurations, runtime detection catches attacks in progress, including zero-day exploits and sophisticated threats.

**Why Runtime Detection Matters**:

- **Real-time visibility**: See what's actually happening, not just what's configured
- **Zero-day protection**: Detect novel attacks without signatures
- **Immediate response**: Stop attacks as they happen
- **Compliance**: Many standards require runtime monitoring
- **Incident investigation**: Provides detailed forensic data
- **Defense-in-depth**: Complements configuration security

**Key Principle**: "Configuration is intent, runtime is reality"

## Falco: The Standard for Kubernetes Runtime Security

Falco is a CNCF graduated project and the de facto standard for Kubernetes runtime security monitoring. It's heavily featured in the KCSA exam.

### Falco Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Falco Architecture                       │
└─────────────────────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────────────┐
    │               Falco Application Layer                     │
    │                                                           │
    │  ┌────────────┐    ┌──────────────┐    ┌──────────────┐ │
    │  │  Rules     │───▶│ Rules Engine │───▶│   Outputs    │ │
    │  │  (YAML)    │    │  (Matching)  │    │ (Alerts)     │ │
    │  └────────────┘    └──────────────┘    └──────────────┘ │
    │                            │                              │
    └────────────────────────────┼──────────────────────────────┘
                                 │
    ┌────────────────────────────▼──────────────────────────────┐
    │               Falco Libraries (libsinsp/libscap)          │
    │         (Parse and enrich system call information)        │
    └────────────────────────────┬──────────────────────────────┘
                                 │
              ┌──────────────────┴──────────────────┐
              │                                     │
    ┌─────────▼─────────┐              ┌───────────▼──────────┐
    │  Kernel Module    │              │    eBPF Probe        │
    │  (Default Driver) │              │  (Modern Driver)     │
    │                   │              │                      │
    │  • Ring buffer    │              │  • eBPF maps         │
    │  • System calls   │              │  • System calls      │
    └─────────┬─────────┘              └───────────┬──────────┘
              │                                    │
              └──────────────────┬─────────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │     Linux Kernel         │
                    │   (System Call Table)    │
                    └──────────────────────────┘
```

### How Falco Works

1. **Capture**: Kernel module or eBPF probe captures all system calls
1. **Enrich**: Libraries add context (container, pod, namespace, Kubernetes metadata)
1. **Evaluate**: Rules engine checks events against rules
1. **Alert**: Matching events trigger outputs (logs, webhooks, alerts)

### Falco Drivers

Falco uses one of two drivers to capture system calls:

| Driver | Type | Pros | Cons | When to Use |
| -------- | ------ | ------ | ------ | ------------- |
| **Kernel Module** | Loadable kernel module | Fast, stable, complete | Requires kernel headers | Default choice |
| **eBPF Probe** | Extended BPF program | No kernel module needed | Requires newer kernel (4.14+) | Restricted environments |

```bash
# Check which driver is loaded

falco --list-events

# Or check from pod

kubectl logs -n falco -l app.kubernetes.io/name=falco | grep -i "driver"
```

## Falco Rules Language

### Rule Structure

A Falco rule consists of several components:

```yaml
- rule: Shell in Container
  desc: A shell was spawned in a container
  condition: >
    spawned_process and
    container and
    proc.name in (bash, sh, zsh, ksh, csh)
  output: >
    Shell spawned in container
    (user=%user.name
     container=%container.name
     proc=%proc.cmdline
     parent=%proc.pname
     cmdline=%proc.cmdline)
  priority: WARNING
  tags: [container, shell, mitre_execution]
```

**Components**:

- **rule**: Unique rule name
- **desc**: Human-readable description
- **condition**: Boolean expression that triggers the rule
- **output**: Alert message with context (supports field interpolation)
- **priority**: Severity level (DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL, ALERT, EMERGENCY)
- **tags**: Categorization labels
- **enabled**: Whether rule is active (default: true)
- **warn_evttypes**: Reduce false positives with event type hints

### Conditions

Conditions are boolean expressions using fields and operators:

#### Field Types

```yaml
# Process fields

proc.name           # Process name
proc.cmdline        # Full command line
proc.pname          # Parent process name
proc.pid            # Process ID
proc.ppid           # Parent process ID

# User fields

user.name           # Username
user.uid            # User ID
user.loginname      # Login name

# Container fields

container.id        # Container ID
container.name      # Container name
container.image     # Container image

# Kubernetes fields

k8s.ns.name         # Namespace
k8s.pod.name        # Pod name
k8s.deployment.name # Deployment name

# File/Network fields

fd.name             # File descriptor name (file or socket)
fd.directory        # Directory of file
fd.sip              # Source IP (network)
fd.dip              # Destination IP
fd.sport            # Source port
fd.dport            # Destination port

# Event fields

evt.type            # System call type (open, execve, etc.)
evt.dir             # Direction (< for enter, > for exit)
evt.time            # Timestamp
```

#### Operators

```yaml
# Comparison

=, !=               # Equals, not equals
<, >, <=, >=        # Less than, greater than
in, not in          # List membership
contains            # String contains
startswith          # String starts with
endswith            # String ends with
glob                # Glob pattern matching

# Logical

and, or, not        # Boolean logic

# Parentheses

()                  # Grouping
```

#### Example Conditions

```yaml
# Shell in container

spawned_process and container and proc.name in (bash, sh)

# Reading sensitive file

open_read and fd.name in (/etc/shadow, /etc/sudoers)

# Outbound network connection

outbound and not fd.sip in (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)

# Container running as root

container and user.uid=0

# Privileged container

container and container.privileged=true

# Complex: suspicious exec in production

spawned_process and
container and
k8s.ns.name startswith "prod-" and
proc.name in (bash, sh, nc, ncat) and
not k8s.pod.label.app="debug-tools"
```

### Macros

Macros are reusable condition snippets that make rules cleaner:

```yaml
# Define macros

- macro: spawned_process
  condition: evt.type = execve and evt.dir=<

- macro: container
  condition: container.id != host

- macro: open_read
  condition: evt.type in (open, openat) and evt.is_open_read=true and fd.typechar='f'

- macro: open_write
  condition: evt.type in (open, openat) and evt.is_open_write=true and fd.typechar='f'

- macro: outbound
  condition: evt.type=connect and evt.dir=< and fd.typechar=4

# Use macros in rules

- rule: Write to Sensitive File
  condition: >
    open_write and
    container and
    fd.name in (/etc/passwd, /etc/shadow)
  output: "Write to sensitive file (file=%fd.name user=%user.name)"
  priority: ERROR
```

**Benefits of macros**:

- Reduce repetition
- Improve readability
- Centralize common logic
- Make rules easier to maintain

### Lists

Lists define reusable collections of values:

```yaml
# Define lists

- list: shell_binaries
  items: [bash, sh, zsh, ksh, csh, tcsh]

- list: sensitive_files
  items: [/etc/shadow, /etc/sudoers, /etc/pam.conf, /etc/security/pwquality.conf]

- list: trusted_images
  items:
    - gcr.io/my-company/
    - docker.io/library/nginx
    - registry.k8s.io/

- list: known_malicious_ips
  items: [192.0.2.1, 198.51.100.1, 203.0.113.1]

# Use lists in rules

- rule: Shell in Container
  condition: >
    spawned_process and
    container and
    proc.name in (shell_binaries)
  priority: WARNING

- rule: Connection to Malicious IP
  condition: >
    outbound and
    container and
    fd.sip in (known_malicious_ips)
  priority: CRITICAL
```

**Benefits of lists**:

- Easy to update without changing rules
- Can append to lists from multiple files
- Improve maintainability

### Appending to Existing Rules

You can override or append to default Falco rules:

```yaml
# Append items to existing list

- list: shell_binaries
  append: true
  items: [fish, elvish]

# Append to macro condition

- macro: sensitive_files
  append: true
  condition: or fd.name in (/app/secrets/api-key.txt)

# Override existing rule

- rule: Shell in Container
  condition: >
    spawned_process and
    container and
    proc.name in (shell_binaries) and
    not k8s.ns.name in (development, staging)
  append: false  # Replace entirely

# Add exception to existing rule

- rule: Shell in Container
  exceptions:
    - name: allow_debug_pods
      fields: [k8s.pod.label.app]
      comps: [=]
      values: [["debug-tools"]]
```

## Common Falco Rules

### Container Security

```yaml
# Detect shell in container

- rule: Shell Spawned in Container
  desc: A shell was spawned in a container
  condition: >
    spawned_process and
    container and
    proc.name in (shell_binaries)
  output: >
    Shell spawned in container
    (user=%user.name container=%container.name
     proc=%proc.cmdline parent=%proc.pname)
  priority: WARNING

# Detect privileged container

- rule: Launch Privileged Container
  desc: Detect the initial process started in a privileged container
  condition: >
    container_started and
    container and
    container.privileged=true and
    not trusted_containers
  output: >
    Privileged container started
    (user=%user.name container=%container.name
     image=%container.image.repository)
  priority: WARNING

# Detect sensitive mount

- rule: Sensitive Mount by Container
  desc: Container mounting sensitive filesystem paths
  condition: >
    container and
    mount and
    (mount.source startswith /proc or
     mount.source startswith /var/run/docker.sock)
  output: >
    Sensitive mount by container
    (container=%container.name source=%mount.source)
  priority: WARNING
```

### File System Activity

```yaml
# Detect sensitive file read

- rule: Read Sensitive File
  desc: Detect reads to sensitive files
  condition: >
    open_read and
    container and
    fd.name in (sensitive_files)
  output: >
    Sensitive file read
    (file=%fd.name user=%user.name container=%container.name
     proc=%proc.cmdline)
  priority: WARNING

# Detect file created in container

- rule: Write Below Binary Dir
  desc: Detect write/create operations below binary directories
  condition: >
    open_write and
    container and
    fd.directory in (/bin, /sbin, /usr/bin, /usr/sbin)
  output: >
    File created in binary directory
    (file=%fd.name container=%container.name user=%user.name)
  priority: ERROR

# Detect modification to system files

- rule: Modify System Configuration
  desc: Detect modifications to critical system configuration files
  condition: >
    open_write and
    container and
    fd.name in (/etc/passwd, /etc/shadow, /etc/sudoers, /etc/group)
  output: >
    System configuration file modified
    (file=%fd.name user=%user.name container=%container.name)
  priority: ERROR
```

### Network Activity

```yaml
# Detect outbound connection to suspicious IP

- rule: Outbound Connection to Suspicious IP
  desc: Detect outbound connections to known malicious IPs
  condition: >
    outbound and
    container and
    fd.sip in (known_malicious_ips)
  output: >
    Outbound connection to suspicious IP
    (dest=%fd.sip port=%fd.dport container=%container.name)
  priority: CRITICAL

# Detect unexpected network tool

- rule: Network Tool Launched in Container
  desc: Network tools like nc, nmap shouldn't run in containers
  condition: >
    spawned_process and
    container and
    proc.name in (nc, ncat, nmap, netcat, socat)
  output: >
    Network tool launched
    (tool=%proc.name user=%user.name container=%container.name)
  priority: WARNING

# Detect reverse shell

- rule: Reverse Shell
  desc: Detect reverse shell connections
  condition: >
    spawned_process and
    container and
    ((proc.name = bash and proc.cmdline contains "-i") or
     (proc.name = sh and proc.cmdline contains "-i") or
     (proc.name in (nc, ncat) and (proc.cmdline contains "-e" or proc.cmdline contains "-c")))
  output: >
    Reverse shell detected
    (cmdline=%proc.cmdline user=%user.name container=%container.name)
  priority: CRITICAL
```

### Process Execution

```yaml
# Detect unexpected process execution

- rule: Unexpected Process in Container
  desc: Process not in allowed list was executed
  condition: >
    spawned_process and
    container and
    not proc.name in (allowed_processes)
  output: >
    Unexpected process spawned
    (proc=%proc.name cmdline=%proc.cmdline container=%container.name)
  priority: NOTICE

# Detect process with suspicious arguments

- rule: Suspicious Process Arguments
  desc: Detect processes with potentially malicious arguments
  condition: >
    spawned_process and
    container and
    (proc.cmdline contains "wget" or
     proc.cmdline contains "curl" or
     proc.cmdline contains "/tmp/")
  output: >
    Suspicious process arguments
    (cmdline=%proc.cmdline user=%user.name container=%container.name)
  priority: WARNING

# Detect debugger attached

- rule: Debugger Attached to Process
  desc: Detect debugger (ptrace) attached to a process
  condition: >
    evt.type=ptrace and
    evt.dir=> and
    container
  output: >
    Debugger attached to process
    (target_proc=%proc.name user=%user.name container=%container.name)
  priority: WARNING
```

### Crypto Mining Detection

```yaml
# Detect known crypto mining processes

- rule: Detect Crypto Mining
  desc: Detect cryptocurrency mining processes
  condition: >
    spawned_process and
    container and
    (proc.name in (xmrig, minergate, ethminer, minerd, cpuminer) or
     proc.cmdline contains "stratum+tcp" or
     proc.cmdline contains "pool.minergate.com")
  output: >
    Cryptocurrency mining detected
    (proc=%proc.name cmdline=%proc.cmdline container=%container.name)
  priority: CRITICAL

# Detect crypto mining network connections

- rule: Crypto Mining Connection
  desc: Outbound connection to known mining pool
  condition: >
    outbound and
    container and
    (fd.sip_name contains "pool.minergate.com" or
     fd.dport in (3333, 4444, 5555, 7777, 9999, 14444, 45700))
  output: >
    Connection to mining pool detected
    (dest=%fd.sip:%fd.dport container=%container.name)
  priority: CRITICAL
```

## Installing Falco

### Installation Methods

#### 1. Helm (Recommended)

```bash
# Add Falco Helm repository

helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# Install Falco

helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --set tty=true

# Verify installation

kubectl get pods -n falco
kubectl logs -n falco -l app.kubernetes.io/name=falco
```

#### 2. DaemonSet (Manual)

```yaml
# falco-daemonset.yaml

apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: falco
  namespace: falco
spec:
  selector:
    matchLabels:
      app: falco
  template:
    metadata:
      labels:
        app: falco
    spec:
      serviceAccountName: falco
      hostNetwork: true
      hostPID: true
      containers:
      - name: falco
        image: falcosecurity/falco:0.37.1
        securityContext:
          privileged: true
        volumeMounts:
        - name: dev
          mountPath: /host/dev
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: boot
          mountPath: /host/boot
          readOnly: true
        - name: lib-modules
          mountPath: /host/lib/modules
          readOnly: true
        - name: usr
          mountPath: /host/usr
          readOnly: true
        - name: etc
          mountPath: /host/etc
          readOnly: true
      volumes:
      - name: dev
        hostPath:
          path: /dev
      - name: proc
        hostPath:
          path: /proc
      - name: boot
        hostPath:
          path: /boot
      - name: lib-modules
        hostPath:
          path: /lib/modules
      - name: usr
        hostPath:
          path: /usr
      - name: etc
        hostPath:
          path: /etc
```

### Configuration

```yaml
# values.yaml for Helm

falco:

  # Rules files to load

  rules_file:
    - /etc/falco/falco_rules.yaml
    - /etc/falco/falco_rules.local.yaml
    - /etc/falco/k8s_audit_rules.yaml
    - /etc/falco/rules.d

  # Output settings

  json_output: true
  json_include_output_property: true

  # Logging

  log_stderr: true
  log_syslog: false
  log_level: info

  # Performance

  syscall_event_drops:
    threshold: 0.1
    actions:
      - log
      - alert

# Custom rules

customRules:
  custom-rules.yaml: |-
    - rule: My Custom Rule
      desc: Custom detection rule
      condition: spawned_process and container and proc.name = "suspicious-binary"
      output: "Custom rule triggered (container=%container.name)"
      priority: WARNING

# Output destinations

falcosidekick:
  enabled: true
  webui:
    enabled: true
```

## Falco Outputs

### Output Formats

#### 1. Text Output (Default)

```
15:04:05.123456789: Warning Shell spawned in container (user=root container=nginx-pod proc=bash parent=containerd-shim cmdline=bash)

```

#### 2. JSON Output

```json
{
  "output": "Shell spawned in container (user=root container=nginx-pod proc=bash)",
  "priority": "Warning",
  "rule": "Shell Spawned in Container",
  "time": "2024-01-15T15:04:05.123456789Z",
  "output_fields": {
    "user.name": "root",
    "container.name": "nginx-pod",
    "proc.name": "bash",
    "proc.cmdline": "bash",
    "proc.pname": "containerd-shim"
  }
}
```

### Output Destinations

#### 1. Standard Output (Default)

```yaml
# Falco config

log_stderr: true
json_output: true
```

View with kubectl:

```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco -f
```

#### 2. File Output

```yaml
file_output:
  enabled: true
  keep_alive: false
  filename: /var/log/falco/events.log
```

#### 3. Webhook Output

```yaml
http_output:
  enabled: true
  url: "http://alertmanager:9093/api/v1/alerts"
  user_agent: "falco/0.37.0"
  ca_cert: "/etc/ssl/ca.crt"
```

#### 4. Syslog Output

```yaml
syslog_output:
  enabled: true
```

#### 5. Falcosidekick (Output Router)

Falcosidekick routes Falco alerts to multiple destinations:

```yaml
# Helm values for Falcosidekick

falcosidekick:
  enabled: true
  config:
    slack:
      webhookurl: "https://hooks.slack.com/services/xxx"
      minimumpriority: "warning"

    alertmanager:
      hostport: "http://alertmanager:9093"

    elasticsearch:
      hostport: "http://elasticsearch:9200"
      index: "falco"

    loki:
      hostport: "http://loki:3100"
```

**Supported outputs**:

- Slack, MS Teams, Discord
- AlertManager, Prometheus
- Elasticsearch, Loki
- AWS SNS, S3
- GCP Pub/Sub
- Webhooks
- Many more

## Custom Rule Creation

### Process for Creating Rules

1. **Identify the threat**: What are you trying to detect?
1. **Understand the behavior**: How does it manifest in system calls?
1. **Write the condition**: Translate behavior to Falco syntax
1. **Test the rule**: Trigger the behavior and verify detection
1. **Tune for accuracy**: Reduce false positives
1. **Document**: Add clear descriptions

### Example: Detect SSH in Container

**Threat**: SSH server running in container (usually unnecessary)

**Behavior**: sshd process starts

```yaml
# Step 1: Basic detection

- rule: SSH Server in Container
  desc: Detect SSH server process in container
  condition: >
    spawned_process and
    container and
    proc.name = sshd
  output: "SSH server started in container (container=%container.name)"
  priority: WARNING

# Step 2: Add exceptions for legitimate uses

- list: ssh_allowed_containers
  items: [bastion-host, jump-server]

- rule: SSH Server in Container
  desc: Detect SSH server process in container
  condition: >
    spawned_process and
    container and
    proc.name = sshd and
    not container.name in (ssh_allowed_containers)
  output: "SSH server started in container (container=%container.name pod=%k8s.pod.name)"
  priority: WARNING
  tags: [container, ssh, pci_dss_10.2.5]
```

### Example: Detect Package Manager Execution

**Threat**: Package managers used in production containers (supply chain attack indicator)

```yaml
- list: package_managers
  items: [apt, apt-get, yum, dnf, rpm, dpkg, pip, pip3, npm, gem]

- rule: Package Manager Executed in Container
  desc: Detect package manager execution in running container
  condition: >
    spawned_process and
    container and
    proc.name in (package_managers) and
    not k8s.ns.name in (development, build)
  output: >
    Package manager executed in container
    (container=%container.name proc=%proc.name cmdline=%proc.cmdline
     namespace=%k8s.ns.name)
  priority: WARNING
  tags: [container, software, mitre_persistence]
```

### Example: Detect Binary Download and Execute

**Threat**: Downloading and executing binaries (common attack pattern)

```yaml
- rule: Download and Execute
  desc: Detect downloading file to /tmp and executing it
  condition: >
    spawned_process and
    container and
    proc.pname in (wget, curl, fetch) and
    proc.exe startswith /tmp/
  output: >
    Binary downloaded and executed
    (file=%proc.exe downloader=%proc.pname container=%container.name
     cmdline=%proc.cmdline)
  priority: CRITICAL
  tags: [container, mitre_execution]
```

## Response Automation

### Alert Response Patterns

#### 1. Log and Alert (Passive)

```yaml
# Just log the event

- rule: Suspicious Activity
  output: "Alert logged to Elasticsearch and Slack"
  priority: WARNING
```

#### 2. Log, Alert, and Investigate (Active Monitoring)

```bash
# On alert, gather additional context
#!/bin/bash
# triggered by Falco alert

CONTAINER_ID=$1
POD_NAME=$2

# Capture pod state

kubectl describe pod $POD_NAME > /var/log/incidents/$POD_NAME.txt

# Capture logs

kubectl logs $POD_NAME > /var/log/incidents/$POD_NAME-logs.txt

# Network connections

kubectl exec $POD_NAME -- netstat -antp > /var/log/incidents/$POD_NAME-network.txt
```

#### 3. Automated Response (Active Defense)

```bash
#!/bin/bash
# Kill pod on critical alert

PRIORITY=$1
NAMESPACE=$2
POD_NAME=$3

if [ "$PRIORITY" == "CRITICAL" ]; then

  # Capture forensics first

  kubectl logs -n $NAMESPACE $POD_NAME > /var/log/forensics/$POD_NAME.log
  kubectl describe pod -n $NAMESPACE $POD_NAME > /var/log/forensics/$POD_NAME.yaml

  # Terminate pod

  kubectl delete pod -n $NAMESPACE $POD_NAME

  # Alert security team

  curl -X POST https://slack.com/webhook -d "{'text':'Pod $POD_NAME terminated due to critical alert'}"
fi
```

### Integration with Kubernetes

#### Kubernetes Response Controller

```yaml
# Example: Kubernetes controller that watches Falco events

apiVersion: apps/v1
kind: Deployment
metadata:
  name: falco-response-controller
spec:
  template:
    spec:
      serviceAccountName: falco-response
      containers:
      - name: controller
        image: custom/falco-response-controller:latest
        env:
        - name: FALCO_WEBHOOK_URL
          value: "http://falcosidekick:2801"
---

# ServiceAccount with permission to delete pods

apiVersion: v1
kind: ServiceAccount
metadata:
  name: falco-response
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: falco-response
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "delete"]
- apiGroups: [""]
  resources: ["pods/log"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: falco-response
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: falco-response
subjects:
- kind: ServiceAccount
  name: falco-response
  namespace: falco
```

## Performance Tuning

### Falco Performance Considerations

Falco can impact system performance if misconfigured:

| Factor | Impact | Optimization |
| -------- | -------- | -------------- |
| **Rule count** | More rules = more processing | Disable unused rules |
| **Event rate** | High syscall rate = high CPU | Use event type hints |
| **Output volume** | Excessive alerts = I/O load | Tune to reduce false positives |
| **Driver type** | Kernel module vs eBPF | Use kernel module when possible |

### Optimization Strategies

#### 1. Disable Unused Rules

```yaml
# In custom rules file

- rule: Unused Default Rule
  enabled: false
```

#### 2. Use Event Type Hints

```yaml
# Without hint - checks all syscall types

- rule: Slow Rule
  condition: container and proc.name = bash

# With hint - only checks execve syscalls

- rule: Fast Rule
  condition: container and proc.name = bash
  warn_evttypes:
    - execve
```

#### 3. Tune Output Rate

```yaml
# Rate limit specific rules

- rule: Noisy Rule
  condition: ...
  output: ...
  priority: INFO
  skip_if_unknown_filter: true

  # Rate limiting

  rate_limiter:
    enabled: true
    seconds: 60
    max_burst: 10
```

#### 4. Use Appropriate Priority

Only alert on what matters:

```yaml
# Too noisy - fires on every file read

- rule: Bad Rule
  condition: open_read
  priority: WARNING

# Better - only sensitive files

- rule: Good Rule
  condition: open_read and fd.name in (sensitive_files)
  priority: WARNING
```

### Monitoring Falco Performance

```bash
# Check Falco metrics

kubectl logs -n falco -l app.kubernetes.io/name=falco | grep -i "drops"

# Check CPU/memory usage

kubectl top pods -n falco

# Falco internal metrics (if enabled)

curl http://falco-pod:8765/metrics
```

## Troubleshooting

### Common Issues

#### Falco Not Starting

```bash
# Check pod status

kubectl get pods -n falco

# Check logs

kubectl logs -n falco -l app.kubernetes.io/name=falco

# Common causes:
# - Kernel headers not available
# - Driver failed to load
# - Configuration errors

```

**Solutions**:

```bash
# Check if driver loaded

kubectl exec -n falco <pod> -- falco --list

# Try eBPF instead of kernel module

helm upgrade falco falcosecurity/falco -n falco --set driver.kind=ebpf
```

#### No Events Detected

```bash
# Verify Falco is receiving events

kubectl exec -n falco <pod> -- falco --list

# Check if rules are loaded

kubectl exec -n falco <pod> -- cat /etc/falco/falco_rules.yaml
```

**Test with known-bad action**:

```bash
# Should trigger "Shell in Container" rule

kubectl exec <some-pod> -- bash -c "echo test"

# Check Falco logs

kubectl logs -n falco -l app.kubernetes.io/name=falco | grep "Shell"
```

#### High False Positive Rate

```yaml
# Add exceptions

- rule: Shell in Container
  exceptions:
    - name: known_debug_pods
      fields: [k8s.pod.name]
      comps: [=]
      values: [["debug-pod-.*"]]

# Or modify condition

- rule: Shell in Container
  condition: >
    spawned_process and
    container and
    proc.name in (shell_binaries) and
    not k8s.ns.name in (development, staging) and
    not k8s.pod.label.debug = "true"
  append: false
```

## Exam Tips

For the KCSA exam, know:

1. **Falco architecture**: Drivers, libraries, rules engine
1. **Rule syntax**: Conditions, macros, lists, outputs
1. **Common rules**: Shell in container, sensitive file access, privilege escalation
1. **Installation**: Helm, DaemonSet requirements (privileged, host mounts)
1. **Output formats**: Text, JSON
1. **Rule components**: condition, output, priority, tags
1. **Performance**: Event type hints, rule tuning

**Practice**:

- Read and interpret Falco rules
- Identify what events trigger rules
- Write simple custom rules
- Understand rule precedence and exceptions
- Troubleshoot why rules aren't triggering

## Summary

**Key Takeaways**:

1. Falco is the standard for Kubernetes runtime security
1. Falco uses kernel modules or eBPF to capture system calls
1. Rules consist of conditions, outputs, and priorities
1. Macros and lists make rules reusable and maintainable
1. Custom rules detect application-specific threats
1. Response can be automated for critical alerts
1. Tune rules to balance detection and false positives
1. Falcosidekick routes alerts to multiple destinations

**Best Practices**:

- Start with default rules, add custom rules as needed
- Use macros and lists for maintainability
- Tune aggressively to prevent alert fatigue
- Test rules before deploying to production
- Use appropriate priorities
- Automate response for critical threats
- Monitor Falco performance

**Next Steps**:

- Complete [Lab 2: Falco Deployment](../../labs/06-monitoring-logging/lab-02-falco-deployment.md)
- Continue to [Lab 3: Custom Falco Rules](../../labs/06-monitoring-logging/lab-03-falco-rules.md)
- Continue to [Security Monitoring](security-monitoring.md)
