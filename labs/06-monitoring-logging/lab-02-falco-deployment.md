# Lab 2: Falco Deployment

## Objectives

By the end of this lab, you will:

- Install Falco using Helm
- Verify Falco is capturing system calls
- Understand default Falco rules
- View and interpret Falco alerts
- Test Falco detection capabilities

**Duration**: 45 minutes

**Difficulty**: Intermediate

## Prerequisites

- Completed Lab 1 (Audit Logging)
- Running Kubernetes cluster (v1.30.x)
- Helm 3.x installed
- kubectl configured
- Cluster-admin privileges

## Part 1: Install Falco (15 minutes)

### Step 1: Add Falco Helm Repository

```bash

# Add the Falcosecurity Helm repository

helm repo add falcosecurity https://falcosecurity.github.io/charts

# Update Helm repositories

helm repo update

# Verify Falco chart is available

helm search repo falco
```

```

**Expected Output**:

```

NAME                          CHART VERSION   APP VERSION   DESCRIPTION
falcosecurity/falco          4.0.0           0.37.1        Falco - Runtime Security

```
```

### Step 2: Create Falco Namespace

```bash

# Create namespace for Falco

kubectl create namespace falco

# Verify namespace created

kubectl get namespace falco
```

```

### Step 3: Install Falco

```bash

# Install Falco with recommended settings

helm install falco falcosecurity/falco \
  --namespace falco \
  --set tty=true \
  --set falco.json_output=true \
  --set falco.json_include_output_property=true \
  --set falco.log_stderr=true \
  --set falco.log_level=info

# Watch Falco pods start

kubectl get pods -n falco -w
```

```

**Expected**: Falco should start as a DaemonSet with one pod per node.

### Step 4: Verify Installation

```bash

# Check Falco pods are running

kubectl get pods -n falco

# Check Falco DaemonSet

kubectl get daemonset -n falco

# View Falco version

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20 | grep "Falco version"
```

```

**Expected Output**:

```

Falco version: 0.37.1

```
```

### Step 5: Check Falco Driver

```bash

# Check which driver Falco is using

kubectl logs -n falco -l app.kubernetes.io/name=falco | grep -i driver

# Verify syscalls are being captured

kubectl logs -n falco -l app.kubernetes.io/name=falco | grep "Events detected"
```

```

**Expected**: Should see either kernel module or eBPF probe loaded successfully.

**Verification**:

- [ ] Falco pods are running (one per node)
- [ ] Driver loaded successfully
- [ ] No error messages in logs
- [ ] Falco is detecting events

## Part 2: Explore Default Falco Rules (15 minutes)

### Step 6: List Loaded Rules

```bash

# Get one Falco pod name

FALCO_POD=$(kubectl get pods -n falco -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].metadata.name}')

# List all loaded rules

kubectl exec -n falco $FALCO_POD -- falco --list | grep "^-"

# Count total rules

kubectl exec -n falco $FALCO_POD -- falco --list | grep "^-" | wc -l
```

```

**Expected**: Should see 50+ default rules.

### Step 7: Examine Specific Rules

```bash

# View Falco rules configuration

kubectl exec -n falco $FALCO_POD -- cat /etc/falco/falco_rules.yaml | head -100

# Look for specific rule

kubectl exec -n falco $FALCO_POD -- grep -A 10 "Shell in Container" /etc/falco/falco_rules.yaml
```

```

### Step 8: Understand Common Default Rules

View documentation of key rules:

```bash

# Get pod for exec

FALCO_POD=$(kubectl get pods -n falco -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].metadata.name}')

# View specific rules

kubectl exec -n falco $FALCO_POD -- grep -A 15 "rule: Terminal shell in container" /etc/falco/falco_rules.yaml
```

```

**Common Default Rules**:

| Rule Name | What It Detects | Priority |
| ----------- | ---------------- | ---------- |
| Terminal shell in container | Shell (bash, sh) spawned | Notice |
| Write below binary dir | Files written to /bin, /usr/bin | Error |
| Read sensitive file | Reading /etc/shadow, /etc/sudoers | Warning |
| Outbound Connection to C2 | Known malicious IPs | Critical |
| Launch Privileged Container | Privileged container started | Info |

**Verification**:

- [ ] Can list all loaded rules
- [ ] Can view rule definitions
- [ ] Understand common default rules

## Part 3: Test Falco Detection (15 minutes)

### Step 9: Create Test Pod

```bash

# Create a simple test pod

kubectl run test-pod --image=nginx:1.27 -n default

# Wait for pod to be ready

kubectl wait --for=condition=Ready pod/test-pod -n default --timeout=60s

# Verify pod is running

kubectl get pod test-pod
```

```

### Step 10: Trigger Falco Alerts

**Test 1: Shell in Container**

```bash

# Exec into pod (should trigger "Terminal shell in container")

kubectl exec -it test-pod -- /bin/bash

# In the container shell, just type:

exit

# Check Falco logs for the alert

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=50 | grep -i "shell"
```

```

**Expected Alert**:

```json

{
  "output": "Notice A shell was spawned in a container with an attached terminal (user=root user_loginuid=0 k8s.ns=default k8s.pod=test-pod container=test-pod shell=bash parent=runc cmdline=bash terminal=34816 container_id=abc123)",
  "priority": "Notice",
  "rule": "Terminal shell in container",
  "time": "2024-01-15T10:30:00.123456789Z",
  "output_fields": {
    "container.id": "abc123",
    "container.name": "test-pod",
    "evt.time": "10:30:00",
    "k8s.ns.name": "default",
    "k8s.pod.name": "test-pod",
    "proc.cmdline": "bash",
    "user.name": "root"
  }
}
```

```

**Test 2: Sensitive File Read**

```bash

# Try to read /etc/shadow

kubectl exec test-pod -- cat /etc/shadow

# Check Falco logs

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=50 | grep -i "sensitive"
```

```

**Test 3: Write to Binary Directory**

```bash

# Try to write to /bin

kubectl exec test-pod -- sh -c "touch /bin/malicious || true"

# Check Falco logs

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=50 | grep -i "binary"
```

```

**Test 4: Network Tool Execution**

```bash

# Install and run nc (netcat)

kubectl exec test-pod -- sh -c "apt-get update && apt-get install -y netcat-openbsd && nc -l 12345 &" || true

# Check Falco logs

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=50 | grep -i "network"
```

```

### Step 11: Real-time Alert Monitoring

Open a new terminal and stream Falco alerts:

```bash

# Terminal 1: Stream Falco logs

kubectl logs -n falco -l app.kubernetes.io/name=falco -f
```

```

In another terminal, trigger various events:

```bash

# Terminal 2: Trigger events

kubectl exec test-pod -- bash -c "echo 'test' > /tmp/file"
kubectl exec test-pod -- bash -c "ls /etc/shadow"
kubectl exec test-pod -- bash -c "whoami"
```

```

Watch Terminal 1 for real-time alerts.

**Verification**:

- [ ] Shell in container alert triggered
- [ ] Sensitive file read detected (if successful)
- [ ] Alerts are in JSON format
- [ ] Can see real-time alerts

## Part 4: Analyze Falco Output (Optional)

### Step 12: Parse Falco JSON Output

```bash

# Get all Warning and higher priority alerts

kubectl logs -n falco -l app.kubernetes.io/name=falco | \
  jq -r 'select(.priority == "Warning" or .priority == "Error" or .priority == "Critical") | 
         {time: .time, priority: .priority, rule: .rule, container: .output_fields."container.name"}'

# Count alerts by priority

kubectl logs -n falco -l app.kubernetes.io/name=falco | \
  jq -r '.priority' | sort | uniq -c

# Count alerts by rule

kubectl logs -n falco -l app.kubernetes.io/name=falco | \
  jq -r '.rule' | sort | uniq -c | sort -rn

# Find alerts for specific pod

kubectl logs -n falco -l app.kubernetes.io/name=falco | \
  jq 'select(.output_fields."k8s.pod.name" == "test-pod")'
```

```

### Step 13: Create Falco Alert Parser Script

```bash

cat > ~/falco-alerts.sh <<'EOF'

#!/bin/bash
# Falco Alert Parser

NAMESPACE="falco"

case "$1" in
  critical)
    echo "=== Critical Alerts ==="
    kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=falco | \
      jq -r 'select(.priority == "Critical") | 
             "\(.time) [\(.priority)] \(.rule) - \(.output_fields."k8s.pod.name")"'
    ;;
  
  summary)
    echo "=== Alert Summary ==="
    echo "Total alerts:"
    kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=falco | jq -r '.rule' | wc -l
    echo ""
    echo "Alerts by priority:"
    kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=falco | \
      jq -r '.priority' | sort | uniq -c
    echo ""
    echo "Top 10 triggered rules:"
    kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=falco | \
      jq -r '.rule' | sort | uniq -c | sort -rn | head -10
    ;;
  
  pod)
    if [ -z "$2" ]; then
      echo "Usage: $0 pod <pod-name>"
      exit 1
    fi
    echo "=== Alerts for pod: $2 ==="
    kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=falco | \
      jq --arg pod "$2" \
         'select(.output_fields."k8s.pod.name" == $pod) |
          "\(.time) [\(.priority)] \(.rule)"'
    ;;
  
  *)
    echo "Usage: $0 {critical|summary|pod <name>}"
    exit 1
    ;;
esac
EOF

chmod +x ~/falco-alerts.sh

# Test the script

~/falco-alerts.sh summary
```

```

**Verification**:

- [ ] Can parse JSON alerts
- [ ] Can filter by priority
- [ ] Can count alerts by rule
- [ ] Script works correctly

## Troubleshooting

### Issue 1: Falco Pods Not Starting

**Symptoms**: Pods in CrashLoopBackOff or Error state

**Solutions**:

```bash

# Check pod status

kubectl describe pod -n falco -l app.kubernetes.io/name=falco

# Check logs

kubectl logs -n falco -l app.kubernetes.io/name=falco

# Common causes:
# 1. Kernel headers not available
# Try eBPF driver instead:

helm upgrade falco falcosecurity/falco -n falco --set driver.kind=ebpf

# 2. Insufficient permissions
# Check ServiceAccount and SecurityContext in pod spec

```

```

### Issue 2: No Events Detected

**Symptoms**: Falco running but no alerts generated

**Solutions**:

```bash

# Verify driver loaded

kubectl logs -n falco -l app.kubernetes.io/name=falco | grep -i driver

# Test with obvious event

kubectl exec test-pod -- bash -c "ls"

# Check if events are being processed

kubectl logs -n falco -l app.kubernetes.io/name=falco | grep "Events detected"

# Ensure JSON output is enabled

helm get values falco -n falco
```

```

### Issue 3: Can't Parse JSON Output

**Symptoms**: jq errors when parsing logs

**Solutions**:

```bash

# Check if JSON output is enabled

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=1

# Should be valid JSON, test:

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=1 | jq .

# If not JSON, enable in Helm values:

helm upgrade falco falcosecurity/falco -n falco \
  --set falco.json_output=true \
  --set falco.json_include_output_property=true
```

```

## Verification Checklist

Before proceeding, verify:

- [ ] Falco is installed and running
- [ ] Driver (kernel module or eBPF) loaded successfully
- [ ] Can list loaded Falco rules
- [ ] Shell in container triggers alert
- [ ] Alerts are in JSON format
- [ ] Can parse alerts with jq
- [ ] Can monitor alerts in real-time

## Cleanup

```bash

# Remove test pod

kubectl delete pod test-pod

# Keep Falco installed for next lab
# To uninstall Falco:
# helm uninstall falco -n falco
# kubectl delete namespace falco

```

```

## Challenge Exercises

1. **Rule Exploration**: Identify 10 default Falco rules and explain what each detects

1. **Alert Frequency**: Determine which default rules trigger most frequently in your cluster

1. **False Positives**: Identify any false positive alerts and think about how to reduce them

1. **Coverage**: What types of threats do the default rules NOT cover?

## Key Takeaways

- Falco monitors system calls in real-time
- Default rules cover many common security threats
- Alerts are structured JSON for easy parsing
- Falco runs as DaemonSet (one pod per node)
- Driver (kernel module or eBPF) is required
- Real-time monitoring enables immediate response

## Next Steps

- Proceed to [Lab 3: Custom Falco Rules](lab-03-falco-rules.md)
- Review [Runtime Detection theory](../../domains/06-monitoring-logging/runtime-detection.md)
- Explore Falco rules repository for more examples

---

**Congratulations!** You've successfully deployed Falco and learned to interpret its alerts. In the next lab, you'll create custom detection rules.
