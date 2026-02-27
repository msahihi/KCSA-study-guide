# Domain 6: Monitoring, Logging, and Runtime Security (15%)

## Overview

Monitoring, logging, and runtime security are essential for detecting, investigating, and responding to security threats in Kubernetes environments. This domain covers how to observe system behavior, detect anomalies, audit cluster activity, and respond to security incidents in real-time.

**Why Monitoring and Runtime Security Matter**:

- Configuration security is not enough - you need runtime detection
- Attackers can bypass static security controls
- Early detection significantly reduces incident impact
- Audit logs provide evidence for forensics and compliance
- Behavioral analytics can detect zero-day attacks
- Runtime security completes the defense-in-depth strategy

**Exam Weight**: 15% of the KCSA exam (approximately 9 questions)

**Key Principle**: "Trust, but verify - monitor everything, detect anomalies, respond quickly"

## Topics Covered

### 1. [Audit Logging](audit-logging.md)

Learn how to configure and analyze Kubernetes audit logs:

- Kubernetes audit architecture
- Audit policy configuration
- Audit levels and stages
- Log backend configuration
- Analyzing audit logs
- Audit log use cases
- Common audit policy patterns

**Why It Matters**: Audit logs provide a complete record of all API server requests, essential for security monitoring, compliance, and forensic investigations.

### 2. [Behavioral Analytics](behavioral-analytics.md)

Understand how to detect anomalies through behavior analysis:

- Normal vs. abnormal behavior patterns
- Baseline establishment
- Anomaly detection techniques
- Machine learning basics for security
- Alert tuning and false positives
- Behavioral indicators of compromise
- Integration with SIEM systems

**Why It Matters**: Behavioral analytics can detect sophisticated attacks that bypass signature-based detection, including insider threats and zero-day exploits.

### 3. [Runtime Detection and Response](runtime-detection.md)

Master runtime security with Falco:

- Falco architecture and components
- Installation and configuration
- Falco rules language
- Custom rule creation
- Event prioritization
- Response automation
- Integration with alerting systems

**Why It Matters**: Runtime detection identifies malicious activity as it happens, enabling immediate response before damage occurs.

### 4. [Security Monitoring](security-monitoring.md)

Implement comprehensive security monitoring:

- Log aggregation with EFK/ELK stack
- Metrics collection with Prometheus
- Security dashboards and visualization
- Alert correlation and enrichment
- Incident response workflows
- Integration patterns
- Compliance reporting

**Why It Matters**: Effective security monitoring provides visibility across the entire cluster, enabling quick detection and response to security incidents.

## Domain Learning Objectives

By the end of this domain, you will be able to:

1. Configure Kubernetes audit logging with appropriate policies
1. Analyze audit logs to detect security incidents
1. Install and configure Falco for runtime security
1. Create custom Falco rules for specific threats
1. Establish behavior baselines and detect anomalies
1. Implement log aggregation and analysis pipelines
1. Build security monitoring dashboards
1. Integrate detection tools with response systems
1. Perform security incident investigation
1. Implement compliance monitoring and reporting

## Key Concepts Summary

### Security Monitoring Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    SIEM / Alert Manager                   │
│              (Aggregation & Correlation)                  │
└────────────────────┬─────────────────────────────────────┘
                     │
        ┌────────────┼────────────┬───────────────┐
        │            │            │               │
┌───────▼─────┐ ┌───▼─────┐ ┌───▼────┐ ┌────────▼────────┐
│   Audit     │ │  Falco  │ │  App   │ │   Metrics       │
│   Logs      │ │ (Runtime│ │  Logs  │ │  (Prometheus)   │
│ (API Server)│ │Security)│ │        │ │                 │
└─────────────┘ └─────────┘ └────────┘ └─────────────────┘
        │            │            │               │
        └────────────┼────────────┴───────────────┘
                     │
┌────────────────────▼──────────────────────────────────────┐
│              Kubernetes Cluster                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐               │
│  │   Pods   │  │  Nodes   │  │  API     │               │
│  └──────────┘  └──────────┘  │  Server  │               │
└───────────────────────────────┴──────────────────────────┘
```

### Security Monitoring Layers

| Layer | What to Monitor | Tools | Purpose |
| ------- | ---------------- | ------- | --------- |
| **API Server** | API requests, authentication | Audit logs | Track all cluster changes |
| **Runtime** | System calls, process execution | Falco | Detect malicious behavior |
| **Application** | App-specific logs | Fluentd, Fluent Bit | Debug and security events |
| **Network** | Traffic patterns, connections | Network policies, service mesh | Detect lateral movement |
| **Infrastructure** | Resource usage, node health | Prometheus, Node Exporter | Capacity and availability |

### Detection Capabilities by Tool

| Tool | Detection Type | Strengths | Use Cases |
| ------ | --------------- | ----------- | ----------- |
| **Audit Logs** | API activity | Complete API record, compliance | Who did what when |
| **Falco** | Runtime behavior | Real-time, syscall-level | Container escape, privilege escalation |
| **Metrics** | Resource patterns | Trends, anomalies | Resource abuse, DoS |
| **App Logs** | Application events | Business logic | Application-specific attacks |

### Common Security Events to Monitor

1. **Authentication & Authorization**
   - Failed login attempts
   - Privilege escalation attempts
   - Service account token usage
   - RBAC policy violations

1. **Container Security**
   - Container escape attempts
   - Privileged container creation
   - Host filesystem access
   - Sensitive file access

1. **Network Activity**
   - Unexpected outbound connections
   - Connection to known malicious IPs
   - Lateral movement attempts
   - Port scanning activity

1. **System Activity**
   - Unauthorized process execution
   - Shell spawned in container
   - Binary downloads and execution
   - Crypto mining indicators

1. **Configuration Changes**
   - Security policy modifications
   - New privileged resources
   - Network policy changes
   - Secret access patterns

## Falco Overview

Falco is the de facto standard for Kubernetes runtime security and is heavily featured in the KCSA exam.

### Falco Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Falco Components                       │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──────────────┐         ┌──────────────┐             │
│  │  Falco CLI   │────────▶│ Rules Engine │             │
│  │  (Frontend)  │         │  (Detection) │             │
│  └──────────────┘         └──────┬───────┘             │
│                                   │                      │
│                          ┌────────▼───────┐             │
│                          │  Libs/Drivers  │             │
│                          │  (Data Source) │             │
│                          └────────┬───────┘             │
│                                   │                      │
└───────────────────────────────────┼─────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    │                               │
            ┌───────▼────────┐            ┌────────▼────────┐
            │  Kernel Module │            │  eBPF Probe     │
            │  (Default)     │            │  (Modern)       │
            └────────────────┘            └─────────────────┘
                    │                               │
                    └───────────────┬───────────────┘
                                    │
                            ┌───────▼────────┐
                            │  Linux Kernel  │
                            │  (System Calls)│
                            └────────────────┘
```

### Key Falco Concepts

**Rules**: Conditions that trigger alerts

```yaml
- rule: Shell Spawned in Container
  desc: A shell was spawned in a container
  condition: >
    spawned_process and
    container and
    proc.name in (shell_binaries)
  output: Shell spawned in container (user=%user.name container=%container.name)
  priority: WARNING
```

**Macros**: Reusable condition snippets

```yaml
- macro: spawned_process
  condition: evt.type = execve and evt.dir=<
```

**Lists**: Reusable collections

```yaml
- list: shell_binaries
  items: [bash, sh, zsh, csh]
```

### Falco Detection Methods

1. **System Call Monitoring**: Captures all syscalls via kernel module or eBPF
1. **Kubernetes Audit Events**: Integrates with K8s audit logs
1. **Cloud Trail Events**: AWS/GCP/Azure cloud API monitoring

## Audit Logging Deep Dive

### Audit Policy Stages

| Stage | When | Use Case |
| ------- | ------ | ---------- |
| **RequestReceived** | As soon as request arrives | Capture all attempts |
| **ResponseStarted** | After response headers sent | Long-running requests |
| **ResponseComplete** | After full response sent | Complete transaction record |
| **Panic** | When panic occurs | Error investigation |

### Audit Levels

| Level | Information Logged | Use Case |
| ------- | ------------------- | ---------- |
| **None** | Nothing | Exclude noisy endpoints |
| **Metadata** | Request metadata only | Basic tracking |
| **Request** | Metadata + request body | Sensitive operations |
| **RequestResponse** | Everything | Full audit trail |

### Essential Audit Policy Pattern

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:

  # Log secret access at request level

  - level: RequestResponse
    resources:
    - group: ""
      resources: ["secrets"]

  # Log authentication at metadata level

  - level: Metadata
    omitStages: ["RequestReceived"]

  # Don't log health checks

  - level: None
    users: ["system:kube-proxy"]
    verbs: ["watch"]
    resources:
    - group: ""
      resources: ["endpoints", "services"]
```

## Practical Skills Required

### For the Exam

You should be comfortable with:

- Reading and understanding audit policies
- Identifying what will be logged given a policy
- Recognizing Falco rule syntax and structure
- Understanding when different detection methods apply
- Analyzing audit log entries
- Identifying security events from logs
- Knowing common Falco rules and what they detect

### For Real-World Use

Beyond the exam, you'll need to:

- Configure complete audit pipelines
- Tune Falco rules to reduce false positives
- Integrate monitoring tools with incident response
- Build security dashboards and reports
- Perform forensic investigations
- Automate response to security events
- Establish security monitoring baselines

## Hands-On Labs

Complete these labs in order to build practical skills:

1. **[Lab 1: Audit Logging Configuration](../../labs/06-monitoring-logging/lab-01-audit-logging.md)**
   - Enable Kubernetes audit logging
   - Configure audit policies
   - Analyze audit log output
   - Track security-relevant events

1. **[Lab 2: Falco Deployment](../../labs/06-monitoring-logging/lab-02-falco-deployment.md)**
   - Install Falco on Kubernetes
   - Configure Falco output
   - Verify Falco is detecting events
   - Explore default rules

1. **[Lab 3: Custom Falco Rules](../../labs/06-monitoring-logging/lab-03-falco-rules.md)**
   - Create custom detection rules
   - Test rule triggers
   - Tune rules for accuracy
   - Implement rule priorities

1. **[Lab 4: Log Aggregation](../../labs/06-monitoring-logging/lab-04-log-aggregation.md)**
   - Deploy log collection stack
   - Configure Fluentd/Fluent Bit
   - Set up Elasticsearch for storage
   - Create Kibana dashboards

1. **[Lab 5: Security Monitoring Dashboard](../../labs/06-monitoring-logging/lab-05-security-monitoring.md)**
   - Integrate multiple data sources
   - Build security dashboards
   - Configure alert rules
   - Simulate and detect attacks

## Quick Reference

### Essential Commands

```bash
# Audit logs (if configured to log to file)

sudo cat /var/log/kubernetes/audit.log | jq
kubectl get pods -v=8  # See audit events in kubectl

# Falco

kubectl get pods -n falco
kubectl logs -n falco -l app.kubernetes.io/name=falco
falco --list  # List all loaded rules
falco --list-events  # Show supported events

# Log collection

kubectl get pods -n logging
kubectl logs -n logging -l app=fluentd
kubectl logs <pod> --previous  # Previous container logs

# Prometheus metrics

kubectl get servicemonitor -A
kubectl port-forward -n monitoring svc/prometheus 9090:9090

# Check audit policy

kubectl get pod kube-apiserver-controlplane -n kube-system -o yaml | grep audit
```

### Sample Audit Policy

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages:
  - "RequestReceived"
rules:

  # Log pod exec/attach at metadata level

  - level: Metadata
    resources:
    - group: ""
      resources: ["pods/exec", "pods/attach"]

  # Log secret access with full details

  - level: RequestResponse
    resources:
    - group: ""
      resources: ["secrets"]

  # Log RBAC changes

  - level: RequestResponse
    verbs: ["create", "update", "patch", "delete"]
    resources:
    - group: "rbac.authorization.k8s.io"
      resources: ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]

  # Don't log read-only requests

  - level: None
    verbs: ["get", "list", "watch"]
```

### Common Falco Rules

```yaml
# Detect shell in container

- rule: Shell in Container
  desc: A shell was spawned in a container
  condition: >
    spawned_process and
    container and
    proc.name in (bash, sh, zsh)
  output: Shell spawned (user=%user.name container=%container.name)
  priority: WARNING

# Detect sensitive file read

- rule: Read Sensitive File
  desc: Attempt to read sensitive files
  condition: >
    open_read and
    container and
    fd.name in (/etc/shadow, /etc/sudoers)
  output: Sensitive file read (file=%fd.name user=%user.name)
  priority: WARNING

# Detect privilege escalation

- rule: Set Privileged Container
  desc: Privileged container started
  condition: >
    container and
    container.privileged=true and
    not trusted_containers
  output: Privileged container started (container=%container.name)
  priority: CRITICAL
```

### Analyzing Audit Logs with jq

```bash
# Find all secret access

cat audit.log | jq 'select(.objectRef.resource=="secrets")'

# Find failed authentication

cat audit.log | jq 'select(.responseStatus.code>=400 and .verb=="create" and .objectRef.resource=="tokenreviews")'

# Track who created privileged pods

cat audit.log | jq 'select(.verb=="create" and .objectRef.resource=="pods" and .requestObject.spec.containers[].securityContext.privileged==true) | {user:.user.username, pod:.objectRef.name}'

# Find all actions by a specific user

cat audit.log | jq 'select(.user.username=="suspicious-user")'
```

## Common Pitfalls and Tips

### Pitfalls to Avoid

1. **Log overload**: Logging everything creates too much noise
1. **Missing audit backend**: Logs go nowhere if not configured
1. **Ignoring false positives**: Leads to alert fatigue
1. **No log retention**: Logs deleted before incidents are detected
1. **Delayed detection**: Monitoring not real-time enough
1. **Missing context**: Logs without correlation are hard to investigate
1. **No response plan**: Detection without response is incomplete

### Exam Tips

- Know the four audit levels and when to use each
- Understand audit policy rule precedence (first match wins)
- Be familiar with common Falco rule structures
- Know what events Falco can detect via syscalls
- Understand the difference between audit logs and application logs
- Remember that audit logs can impact API server performance
- Know that Falco requires kernel headers or eBPF support

### Best Practices

1. **Defense-in-depth**: Use multiple detection layers
1. **Tune aggressively**: Reduce false positives early
1. **Automate response**: Manual response is too slow
1. **Retain logs**: Keep audit logs for compliance periods
1. **Encrypt logs**: Logs contain sensitive information
1. **Monitor the monitors**: Ensure monitoring stack is healthy
1. **Test detection**: Regularly verify rules trigger correctly
1. **Document baselines**: Know what normal looks like
1. **Incident playbooks**: Prepare response procedures
1. **Regular review**: Update rules as threats evolve

## Real-World Scenarios

### Scenario 1: Detecting Cryptocurrency Mining

**Problem**: Cryptocurrency mining malware is consuming cluster resources.

**Detection Strategy**:

```yaml
# Falco rule for crypto mining

- rule: Cryptocurrency Mining Activity
  desc: Detect common crypto mining processes
  condition: >
    spawned_process and
    container and
    proc.name in (xmrig, minerd, ethminer)
  output: Crypto mining detected (container=%container.name proc=%proc.cmdline)
  priority: CRITICAL
```

**Additional Indicators**:

- Prometheus: High CPU usage patterns
- Network: Outbound connections to mining pools
- Audit logs: Unexpected container deployments

### Scenario 2: Insider Threat Detection

**Problem**: A user with legitimate access is exfiltrating secrets.

**Detection Strategy**:

- Audit logs: Track all secret access
- Behavioral analytics: Unusual access patterns
- Time-based analysis: Access outside normal hours
- Volume analysis: Excessive secret reads

```bash
# Find excessive secret access

cat audit.log | jq 'select(.objectRef.resource=="secrets") | .user.username' | sort | uniq -c | sort -rn
```

### Scenario 3: Container Escape Attempt

**Problem**: Attacker attempting to escape container to host.

**Detection Strategy**:

```yaml
# Falco rules for container escape

- rule: Container Escape - Mount Host
  desc: Detect host filesystem mount
  condition: >
    container and
    mount and
    mount.source startswith /host
  priority: CRITICAL

- rule: Container Escape - Privileged
  desc: Detect privileged container creation
  condition: >
    container.privileged=true and
    not trusted_containers
  priority: CRITICAL
```

**Response Actions**:

1. Immediate pod termination
1. Node isolation
1. Forensic image capture
1. Audit log analysis

### Scenario 4: Compliance Audit

**Problem**: Must demonstrate security monitoring for SOC 2 compliance.

**Requirements**:

1. All API activity logged (audit logs)
1. Privileged operations tracked (audit policy + Falco)
1. Secret access monitored (audit logs)
1. Logs retained for 1 year (log storage)
1. Real-time alerting (Falco + AlertManager)
1. Regular security reports (dashboards)

**Implementation**:

- Enable comprehensive audit policy
- Deploy Falco with compliance rules
- Configure log aggregation and retention
- Build compliance dashboards
- Automate monthly reports

## Behavioral Analytics Indicators

### Indicators of Compromise (IoCs)

**Account Indicators**:

- Multiple failed authentication attempts
- Account access from unusual locations/times
- Dormant account suddenly active
- Privilege escalation attempts

**Runtime Indicators**:

- Shells spawned in containers
- Unexpected process execution
- Sensitive file access
- Network connections to known bad IPs

**Resource Indicators**:

- Sudden resource usage spikes
- Pods communicating with external networks
- Unusual data transfer volumes
- Container image from unknown registry

**Configuration Indicators**:

- Security policy disabled or modified
- Privileged workload created
- Network policy removed
- New service account with high privileges

### Establishing Baselines

```bash
# Normal pod count by namespace

kubectl get pods -A --no-headers | awk '{print $1}' | sort | uniq -c

# Normal container images in use

kubectl get pods -A -o jsonpath='{.items[*].spec.containers[*].image}' | tr ' ' '\n' | sort | uniq -c

# Normal service accounts

kubectl get sa -A --no-headers | wc -l

# Normal API call rates (from audit logs)

cat audit.log | jq -r '.requestURI' | sort | uniq -c | sort -rn | head -20
```

## Integration Patterns

### Falco + AlertManager + Slack

```yaml
# Falco output to AlertManager

json_output: true
json_include_output_property: true
http_output:
  enabled: true
  url: "http://alertmanager:9093/api/v1/alerts"

# AlertManager route to Slack

route:
  routes:
  - match:
      priority: CRITICAL
    receiver: slack-critical
receivers:
- name: slack-critical
  slack_configs:
  - api_url: 'https://hooks.slack.com/services/xxx'
    channel: '#security-alerts'
```

### Audit Logs + Elasticsearch + Kibana

```yaml
# Fluentd config for audit logs

<source>
  @type tail
  path /var/log/kubernetes/audit.log
  pos_file /var/log/audit.log.pos
  tag k8s.audit
  <parse>
    @type json
    time_key timestamp
  </parse>
</source>

<match k8s.audit>
  @type elasticsearch
  host elasticsearch
  port 9200
  index_name k8s-audit-%Y.%m.%d
  type_name audit
</match>
```

### Prometheus + Falco Exporter

```yaml
# ServiceMonitor for Falco metrics

apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: falco
  namespace: falco
spec:
  selector:
    matchLabels:
      app: falco-exporter
  endpoints:
  - port: metrics
    interval: 30s
```

## Study Checklist

Before moving to the next domain, ensure you can:

- [ ] Explain the purpose of Kubernetes audit logging
- [ ] Write an audit policy for specific use cases
- [ ] Identify which audit level is appropriate for different resources
- [ ] Understand how Falco detects runtime threats
- [ ] Read and interpret Falco rules
- [ ] Create a simple custom Falco rule
- [ ] Analyze audit logs to find security events
- [ ] Explain the difference between audit logs and application logs
- [ ] Describe how to establish behavioral baselines
- [ ] Integrate Falco with alerting systems
- [ ] Build a basic security monitoring dashboard
- [ ] Perform a simple security incident investigation

## Additional Resources

### Official Documentation

- [Kubernetes Auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Falco Documentation](https://falco.org/docs/)
- [Falco Rules](https://falco.org/docs/rules/)
- [Logging Architecture](https://kubernetes.io/docs/concepts/cluster-administration/logging/)

### Tools and Projects

- [Falco](https://falco.org/) - Runtime security monitoring
- [Falcosidekick](https://github.com/falcosecurity/falcosidekick) - Falco output router
- [k8s-audit-logs-analyzer](https://github.com/sysdiglabs/kube-audit-rest) - Audit log analysis
- [Elasticsearch/Kibana](https://www.elastic.co/elastic-stack/) - Log aggregation and visualization
- [Prometheus](https://prometheus.io/) - Metrics and alerting

### Learning Resources

- [Kubernetes Audit Log Examples](https://github.com/kubernetes/kubernetes/tree/master/cluster/gce/gci/configure-helper.sh)
- [Falco Official Guide](https://falco.org/docs/)

### Practice Resources

- [Falco Playground](https://play.falco.org/)
- [Falco Getting Started](https://falco.org/docs/getting-started/)
- [KCSA Practice Questions](https://killer.sh/kcsa)

## Next Steps

After completing this domain:

1. Complete all Domain 6 labs in sequence
1. Practice writing audit policies and Falco rules
1. Review all KCSA domains to prepare for the exam
1. Take practice exams and identify weak areas
1. Build a complete security monitoring solution as a capstone project

---

**Remember**: Detection is only valuable if you can respond effectively. Always have an incident response plan ready.

**Pro Tip**: Start with Falco's default rules and tune them for your environment. Don't write everything from scratch - the community rules are battle-tested.

**Exam Focus**: The KCSA exam focuses heavily on understanding audit policies and Falco rule structure. Practice reading and interpreting both.
