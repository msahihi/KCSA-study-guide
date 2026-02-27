# Behavioral Analytics

## Introduction

Behavioral analytics is the process of identifying security threats by detecting deviations from normal behavior patterns. Unlike signature-based detection that looks for known bad patterns, behavioral analytics identifies anomalies that could indicate novel or sophisticated attacks.

**Why Behavioral Analytics Matter**:

- **Zero-day detection**: Catches unknown attacks without signatures
- **Insider threats**: Detects legitimate users behaving suspiciously
- **Advanced persistent threats (APTs)**: Identifies subtle, long-term attacks
- **Lateral movement**: Detects attackers moving through your network
- **Data exfiltration**: Identifies unusual data transfer patterns
- **Reduced false positives**: Context-aware detection vs. simple rules

**Key Principle**: "Know what normal looks like, detect what doesn't fit"

## Fundamentals of Behavioral Analytics

### Normal vs. Abnormal Behavior

Understanding what's normal is prerequisite to detecting anomalies:

```
Normal Behavior (Baseline)
├── Temporal patterns (when things happen)
│   ├── Working hours vs. off-hours
│   ├── Day of week patterns
│   └── Seasonal variations
├── Volume patterns (how much activity)
│   ├── API call rates
│   ├── Resource creation rates
│   └── Data transfer volumes
├── Access patterns (who accesses what)
│   ├── User-to-resource mappings
│   ├── Service account usage
│   └── Authentication sources
└── Technical patterns (how things work)
    ├── User agents and tools
    ├── API call sequences
    └── Resource configurations
```

### Anomaly Types

| Anomaly Type | Description | Example |
| -------------- | ------------- | --------- |
| **Point Anomaly** | Single unusual event | One failed auth, then success |
| **Contextual Anomaly** | Unusual in context | Login from new location |
| **Collective Anomaly** | Pattern across events | Gradual privilege escalation |
| **Temporal Anomaly** | Unusual timing | Access at 3 AM |
| **Volume Anomaly** | Unusual quantity | 1000x normal API calls |

### Detection Techniques

#### 1. Statistical Analysis

Use statistical methods to identify outliers:

```bash

# Example: Find pods using unusual CPU
# 1. Collect normal CPU usage (baseline)

kubectl top pods -A > baseline.txt

# 2. Current usage

kubectl top pods -A > current.txt

# 3. Compare (simplified - real tools use standard deviations)

diff baseline.txt current.txt
```

```

**Statistical Concepts**:

- **Mean**: Average value
- **Standard Deviation**: How spread out values are
- **Outliers**: Values beyond 2-3 standard deviations
- **Percentiles**: Values at 95th, 99th percentile

#### 2. Threshold-Based Detection

Simple but effective for known ranges:

```yaml

# Example: Alert on excessive API calls

alert: ExcessiveAPICalls
condition: |
  rate(apiserver_request_total[5m]) > 1000
description: "API call rate exceeds normal threshold"
```

```

**Pros**: Easy to understand and implement
**Cons**: Requires manual threshold tuning

#### 3. Pattern Matching

Detect unusual sequences of events:

```

Normal Pattern:
  Login → List Pods → Get Pod → View Logs → Logout

Suspicious Pattern:
  Login → List Secrets → Get Secret → Get Secret → Get Secret → ...
  (Excessive secret access suggests data exfiltration)

```
```

#### 4. Machine Learning (Advanced)

ML can learn complex patterns automatically:

**Approaches**:

- **Supervised**: Train on labeled data (attack/normal)
- **Unsupervised**: Detect anomalies without labels (clustering)
- **Semi-supervised**: Mix of both

**Common Algorithms**:

- Isolation Forest (anomaly detection)
- K-means clustering (group similar behavior)
- Neural networks (complex pattern recognition)

**Note**: ML is advanced topic, not deep focus for KCSA

## Establishing Baselines

### What to Baseline

#### API Activity Baselines

```bash

# Most frequent API endpoints

cat audit.log | jq -r '.requestURI' | sort | uniq -c | sort -rn | head -20

# API calls by user

cat audit.log | jq -r '.user.username' | sort | uniq -c | sort -rn

# API calls by verb (get, list, create, etc.)

cat audit.log | jq -r '.verb' | sort | uniq -c

# API calls by resource type

cat audit.log | jq -r '.objectRef.resource' | sort | uniq -c | sort -rn
```

```

**Normal baseline includes**:

- Which users access which resources
- Typical API call rates
- Common request patterns
- Source IP ranges

#### Resource Baselines

```bash

# Normal pod count per namespace

kubectl get pods -A --no-headers | awk '{print $1}' | sort | uniq -c

# Normal container images in use

kubectl get pods -A -o jsonpath='{.items[*].spec.containers[*].image}' | \
  tr ' ' '\n' | sort | uniq -c | sort -rn

# Normal service accounts

kubectl get sa -A --no-headers | wc -l

# Normal privileged workloads (should be few or zero)

kubectl get pods -A -o json | \
  jq '[.items[] | select(.spec.containers[].securityContext.privileged==true)] | length'
```

```

#### Network Baselines

```bash

# With Falco - normal outbound connections

kubectl logs -n falco -l app.kubernetes.io/name=falco | \
  grep "Outbound connection" | \
  awk '{print $NF}' | sort | uniq -c

# Normal service communication patterns
# (requires service mesh or network monitoring)

kubectl get pods -A -o wide
```

```

#### Authentication Baselines

```bash

# Normal authentication sources (from audit logs)

cat audit.log | jq -r '.sourceIPs[]' | sort | uniq -c | sort -rn

# Normal user agents

cat audit.log | jq -r '.userAgent' | sort | uniq -c | sort -rn

# Normal service account usage

cat audit.log | jq -r '.user.username' | \
  grep "system:serviceaccount" | sort | uniq -c | sort -rn
```

```

### Baseline Collection Period

**Recommendations**:

- **Minimum**: 1 week (captures weekly patterns)
- **Better**: 4 weeks (captures monthly variations)
- **Best**: 3 months (captures seasonal patterns)
- **Update**: Regularly (systems change over time)

**Considerations**:

- Include normal business cycles
- Exclude known incidents/anomalies
- Account for maintenance windows
- Update after major changes

### Baseline Storage

Store baselines for comparison:

```bash

# Example baseline storage structure

/var/lib/baselines/
├── api-activity/
│   ├── 2024-01-01.json
│   ├── 2024-01-02.json
│   └── summary.json
├── resource-counts/
│   ├── pods-per-namespace.txt
│   └── images-in-use.txt
└── network/
    └── allowed-destinations.txt
```

```

## Behavioral Indicators of Compromise (BIoCs)

### Account Compromise Indicators

#### Unusual Authentication Patterns

```bash

# Multiple failed auth attempts followed by success

cat audit.log | jq -r 'select(.objectRef.resource=="tokenreviews") |
  "\(.requestReceivedTimestamp) \(.user.username) \(.responseStatus.code)"'

# Authentication from new/unusual location

cat audit.log | jq 'select(.sourceIPs[0] | in(["1.2.3.4", "5.6.7.8"]) | not)'

# Authentication outside business hours

cat audit.log | jq 'select(.requestReceivedTimestamp | strptime("%Y-%m-%dT%H:%M:%S") |
  .hour < 6 or .hour > 22)'  # Before 6 AM or after 10 PM
```

```

**Indicators**:

- Login from unusual IP address or location
- Login at unusual time (e.g., 3 AM)
- Multiple failed attempts followed by success
- Simultaneous logins from different locations
- Dormant account suddenly active
- Unusual user agent (e.g., curl instead of kubectl)

#### Privilege Escalation Attempts

```bash

# Attempts to create privileged pods

cat audit.log | jq 'select(.verb=="create" and
  .objectRef.resource=="pods" and
  .requestObject.spec.containers[].securityContext.privileged==true)'

# Attempts to modify RBAC

cat audit.log | jq 'select(.verb!="get" and .verb!="list" and
  .objectRef.apiGroup=="rbac.authorization.k8s.io")'

# Attempts to create new service accounts with bindings

cat audit.log | jq 'select(.verb=="create" and
  (.objectRef.resource=="serviceaccounts" or
   .objectRef.resource=="rolebindings" or
   .objectRef.resource=="clusterrolebindings"))'
```

```

**Indicators**:

- Creating privileged pods
- Modifying RBAC policies
- Creating new service accounts with high permissions
- Binding to cluster-admin role
- Attempting access to unauthorized resources

### Container Compromise Indicators

#### Suspicious Runtime Activity

```yaml

# Falco rules for container compromise

- rule: Shell Spawned in Container
  desc: Detect shell execution in container
  condition: >
    spawned_process and
    container and
    proc.name in (bash, sh, zsh, ksh, csh)
  priority: WARNING

- rule: Suspicious File Read
  desc: Attempt to read sensitive files
  condition: >
    open_read and
    container and
    fd.name in (/etc/shadow, /etc/sudoers, /etc/pam.conf)
  priority: WARNING

- rule: Outbound Connection to Suspicious IP
  desc: Container connecting to known malicious IP
  condition: >
    outbound and
    container and
    fd.sip in (known_malicious_ips)
  priority: CRITICAL
```

```

**Indicators**:

- Shell spawned in container (especially if no shell expected)
- Reading sensitive files (/etc/shadow, /etc/sudoers)
- Downloading and executing binaries
- Outbound connections to unusual destinations
- Port scanning activity
- Cryptocurrency mining processes

#### Resource Abuse

```bash

# With Prometheus/metrics
# Unusual CPU usage spike

kubectl top pods -A | awk '{if($3 ~ /[0-9]+m/ && $3+0 > 1000) print $0}'

# Memory usage spike

kubectl top pods -A | awk '{if($4 ~ /[0-9]+Mi/ && $4+0 > 2000) print $0}'

# Pod restart patterns (crash loops might indicate exploitation attempts)

kubectl get pods -A | grep -E "CrashLoopBackOff|Error"
```

```

**Indicators**:

- Sudden CPU/memory spike
- Excessive network traffic
- Unusual disk I/O
- Process running crypto mining software

### Data Exfiltration Indicators

#### Excessive Data Access

```bash

# Excessive secret reading

cat audit.log | jq -r 'select(.objectRef.resource=="secrets") |
  "\(.user.username) \(.objectRef.name)"' | \
  sort | uniq -c | sort -rn | head -10

# Accessing many resources in short time

cat audit.log | jq -r 'select(.verb=="get" or .verb=="list") |
  "\(.user.username) \(.requestReceivedTimestamp)"' | \
  uniq -c | sort -rn
```

```

**Indicators**:

- User accessing many secrets in short period
- Downloading large amounts of data
- Accessing resources they don't normally use
- Bulk export of configurations
- Multiple get requests for different secrets

#### Unusual Network Patterns

```bash

# With Falco - connections to external IPs

kubectl logs -n falco -l app.kubernetes.io/name=falco | \
  grep "Outbound connection" | \
  grep -v "10\.\|172\.\|192\.168\."  # Exclude internal IPs
```

```

**Indicators**:

- Large outbound data transfers
- Connections to unknown external IPs
- Connections to file sharing services
- Connections to TOR exit nodes
- DNS queries to data exfiltration services

### Lateral Movement Indicators

#### Cross-Namespace Access

```bash

# Users accessing multiple namespaces

cat audit.log | jq -r 'select(.objectRef.namespace!=null) |
  "\(.user.username) \(.objectRef.namespace)"' | \
  sort | uniq | \
  awk '{users[$1]++} END {for(u in users) if(users[u]>5) print u, users[u]}'
```

```

**Indicators**:

- User accessing unusual namespaces
- Service account used outside its namespace
- Pod-to-pod connections across trust boundaries
- Scanning for services in other namespaces

#### Service Discovery

```bash

# Excessive list/watch operations

cat audit.log | jq 'select(.verb=="list" or .verb=="watch") |
  {user: .user.username, resource: .objectRef.resource, count: 1}' | \
  jq -s 'group_by(.user) | map({user: .[0].user, count: length})'
```

```

**Indicators**:

- Enumeration of services and endpoints
- Discovery of running pods
- Listing secrets across namespaces
- Port scanning activity

## Implementing Behavioral Analytics

### Using Prometheus for Metrics-Based Detection

#### Anomaly Detection with PromQL

```yaml

# Alert on unusual API request rate

- alert: UnusualAPIRequestRate
  expr: |
    rate(apiserver_request_total[5m]) >
    (avg_over_time(apiserver_request_total[1d] offset 1d) * 2)
  for: 10m
  annotations:
    summary: "API request rate is 2x normal"

# Alert on unusual pod creation rate

- alert: RapidPodCreation
  expr: |
    increase(kube_pod_created[5m]) > 50
  annotations:
    summary: "More than 50 pods created in 5 minutes"

# Alert on unusual authentication failures

- alert: HighAuthFailureRate
  expr: |
    rate(apiserver_request_total{code=~"401|403"}[5m]) > 10
  for: 5m
  annotations:
    summary: "High authentication failure rate detected"
```

```

### Using Audit Logs for Behavior Analysis

#### Pattern Detection Scripts

```bash

#!/bin/bash
# detect-anomalies.sh - Simple anomaly detection

# Baseline file (created during normal operations)

BASELINE="/var/lib/baselines/normal-activity.json"
CURRENT_LOG="/var/log/kubernetes/audit.log"

# Count API calls per user

current_counts=$(cat $CURRENT_LOG | \
  jq -r '.user.username' | sort | uniq -c)

# Compare with baseline

while read count user; do
  baseline_count=$(grep "\"$user\"" $BASELINE | jq -r '.count')

  # Alert if current count is 3x baseline

  if [ $count -gt $((baseline_count * 3)) ]; then
    echo "ALERT: User $user has $count requests (baseline: $baseline_count)"
  fi
done <<< "$current_counts"
```

```

### Using Falco for Runtime Behavior

Falco can detect runtime behavioral anomalies:

```yaml

# Detect processes that don't normally run

- rule: Unexpected Process Spawned
  desc: A process not in the allowed list was spawned
  condition: >
    spawned_process and
    container and
    not proc.name in (allowed_processes)
  output: >
    Unexpected process in container
    (user=%user.name process=%proc.name container=%container.name)
  priority: WARNING

- list: allowed_processes
  items: [nginx, node, python, java]

# Detect unusual file access

- rule: Unusual File Access
  desc: Container accessing files it normally doesn't
  condition: >
    open_read and
    container and
    fd.name startswith "/etc/" and
    not fd.name in (normal_file_access)
  priority: INFO

- list: normal_file_access
  items: [/etc/nginx/nginx.conf, /etc/hosts, /etc/resolv.conf]
```

```

## Alert Tuning and False Positives

### Common False Positive Causes

1. **Incomplete baselines**: Baseline doesn't capture all normal behavior
1. **Environmental changes**: New features or deployments
1. **Over-sensitive thresholds**: Thresholds set too tight
1. **Seasonal patterns**: Not accounting for time-based variations
1. **Testing activity**: QA/staging environment activity
1. **Automated systems**: CI/CD, monitoring tools

### Tuning Strategies

#### 1. Adjust Thresholds

```yaml

# Before (too sensitive)

- alert: HighAPICalls
  expr: rate(apiserver_request_total[5m]) > 100

# After (more reasonable)

- alert: HighAPICalls
  expr: rate(apiserver_request_total[5m]) > 500
  for: 15m  # Must persist for 15 minutes
```

```

#### 2. Add Context

```yaml

# Add allow-lists

- rule: Shell in Container
  condition: >
    spawned_process and
    container and
    proc.name in (bash, sh) and
    not container.name in (debug_containers) and  # Allow debug pods
    not k8s.ns.name in (development, staging)      # Allow in dev/staging
  priority: WARNING
```

```

#### 3. Implement Severity Levels

```yaml

# Info - expected but worth noting

- rule: Config File Modified
  priority: INFO

# Notice - unusual but might be legitimate

- rule: Off-Hours Access
  priority: NOTICE

# Warning - likely needs investigation

- rule: Privileged Pod Created
  priority: WARNING

# Error - almost certainly problematic

- rule: Unknown Process in Container
  priority: ERROR

# Critical - immediate response required

- rule: Container Escape Attempt
  priority: CRITICAL
```

```

#### 4. Correlation and Enrichment

Don't alert on single event - correlate multiple signals:

```python

# Pseudo-code for correlation

if (failed_auth_attempts > 5 and
    successful_auth and
    source_ip_is_new and
    time_is_unusual):
    severity = CRITICAL
elif (failed_auth_attempts > 5 and successful_auth):
    severity = WARNING
else:
    severity = INFO
```

```

### Alert Fatigue Prevention

**Best Practices**:

1. **Start conservative**: Fewer, high-confidence alerts
1. **Tune continuously**: Review and adjust weekly
1. **Use alert routing**: Send different severities to different channels
1. **Implement alert suppression**: Don't repeatedly alert on same issue
1. **Provide context**: Include enough information for quick triage
1. **Document false positives**: Track and eliminate recurring FPs
1. **Regular review**: Disable rules that never provide value

```yaml

# Example alert with good context

- rule: Suspicious Activity Detected
  output: >
    SUSPICIOUS: Shell spawned in production container
    (user=%user.name
     container=%container.name
     pod=%k8s.pod.name
     namespace=%k8s.ns.name
     command=%proc.cmdline
     parent=%proc.pname
     timestamp=%evt.time)
  priority: WARNING
```

```

## Integration with SIEM

### Sending Data to SIEM

Most SIEM systems can ingest:

- Kubernetes audit logs (via syslog, HTTP, or file collection)
- Falco alerts (via webhook or syslog)
- Prometheus metrics (via exporters)

#### Example: Falco to Splunk

```yaml

# Falco config for Splunk HEC (HTTP Event Collector)

http_output:
  enabled: true
  url: "https://splunk.example.com:8088/services/collector/event"
  user_agent: "falco/0.37.0"
  ca_cert: "/etc/ssl/splunk-ca.crt"
  insecure: false
json_output: true
json_include_output_property: true
```

```

#### Example: Audit Logs to ELK

```yaml

# Filebeat config for audit logs

filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/kubernetes/audit.log
  json.keys_under_root: true
  json.add_error_key: true
  fields:
    log_type: k8s-audit

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "k8s-audit-%{+yyyy.MM.dd}"
```

```

### SIEM Correlation Examples

#### Correlation Rule 1: Account Compromise

```

IF (failed_auth_attempts > 5 in last 5 minutes)
AND (successful_auth from same user)
AND (source_ip NOT IN known_user_ips)
THEN alert "Possible account compromise"

```
```

#### Correlation Rule 2: Data Exfiltration

```

IF (secret_access_count > 20 in last 1 hour)
AND (large_outbound_transfer)
AND (destination_ip NOT IN whitelist)
THEN alert "Possible data exfiltration"
```

```

#### Correlation Rule 3: Lateral Movement

```

IF (new_pod_exec from user)
AND (user accessed multiple namespaces in last hour)
AND (outbound_connections to internal IPs)
THEN alert "Possible lateral movement"

```
```

## Real-World Scenarios

### Scenario 1: Detecting Crypto Mining

**Normal Behavior**:

- Pods use 10-20% CPU on average
- Limited outbound connections

**Anomalous Behavior**:

- New pod created outside normal deployment process
- Pod consistently uses 95-100% CPU
- Outbound connection to mining pool domain

**Detection**:

```yaml

# Falco rule

- rule: Cryptocurrency Mining
  desc: Detect crypto mining activity
  condition: >
    spawned_process and
    container and
    proc.name in (xmrig, minergate, ethminer, minerd)
  priority: CRITICAL

# Prometheus alert

- alert: HighCPUUsage
  expr: |
    rate(container_cpu_usage_seconds_total[5m]) > 0.9
  for: 1h
```

```

### Scenario 2: Insider Threat

**Normal Behavior**:

- Developer accesses 2-3 namespaces daily
- Reads 5-10 secrets per day
- Works 9 AM - 5 PM

**Anomalous Behavior**:

- Accessed 15 namespaces in 2 hours
- Read 50 secrets
- Activity at 2 AM

**Detection**:

```bash

# Audit log analysis

cat audit.log | jq 'select(.user.username=="developer@example.com") |
  select(.requestReceivedTimestamp | strptime("%Y-%m-%dT%H:%M:%S") | .hour < 6 or .hour > 22) |
  select(.objectRef.resource=="secrets")'
```

```

### Scenario 3: Container Escape

**Normal Behavior**:

- Application containers run defined processes only
- No host filesystem access
- No privileged operations

**Anomalous Behavior**:

- Shell spawned in container
- Attempt to mount host filesystem
- Privilege escalation attempts

**Detection**:

```yaml

# Falco rules

- rule: Container Escape - Host Mount
  condition: >
    container and
    mount and
    (mount.source startswith /host or
     mount.source startswith /proc or
     mount.source startswith /sys)
  priority: CRITICAL

- rule: Container Escape - Privileged
  condition: >
    container and
    container.privileged=true and
    not container.name in (privileged_whitelist)
  priority: CRITICAL
```

```

## Exam Tips

For the KCSA exam, understand:

1. **Difference between signature-based and behavior-based detection**
1. **What to baseline**: API activity, resource counts, network patterns
1. **Common behavioral indicators**: Unusual times, locations, volumes
1. **False positive management**: Tuning, allow-lists, correlation
1. **Integration with monitoring**: Prometheus, audit logs, Falco
1. **Basic anomaly detection**: Statistical outliers, thresholds

**Practice**:

- Identify normal vs. anomalous behavior in scenarios
- Tune Falco rules to reduce false positives
- Analyze audit logs for behavioral patterns
- Correlate multiple signals for detection

## Summary

**Key Takeaways**:

1. Behavioral analytics detects unknown threats by finding anomalies
1. Establish baselines of normal behavior first
1. Multiple behavioral indicators are more reliable than single events
1. Tune aggressively to prevent alert fatigue
1. Integrate multiple data sources (audit logs, metrics, runtime events)
1. Update baselines as your environment evolves
1. Behavioral analytics complements signature-based detection

**Best Practices**:

- Collect baseline for at least 1 month
- Use multiple detection techniques
- Correlate signals for higher confidence
- Continuously tune and update
- Document and track false positives
- Have clear escalation paths

**Next Steps**:

- Continue to [Runtime Detection and Response](runtime-detection.md)
- Practice establishing baselines in your environment
- Learn to tune detection rules effectively
