# Security Monitoring

## Introduction

Security monitoring integrates multiple data sources to provide comprehensive visibility into cluster security. It combines audit logs, runtime detection, metrics, and application logs to detect, investigate, and respond to security threats.

**Why Security Monitoring Matters**:

- **Complete visibility**: See security events across all layers
- **Correlation**: Connect related events for better detection
- **Investigation**: Quickly understand what happened during incidents
- **Compliance**: Demonstrate security controls for audits
- **Metrics**: Track security posture over time
- **Alerting**: Notify teams of security issues immediately

**Key Principle**: "You can't protect what you can't see"

## Security Monitoring Architecture

### Reference Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                    Visualization & Alerting                     │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐   │
│  │   Grafana    │  │    Kibana    │  │   AlertManager     │   │
│  │ (Dashboards) │  │  (Log Search)│  │  (Alert Routing)   │   │
│  └──────┬───────┘  └──────┬───────┘  └─────────┬──────────┘   │
└─────────┼──────────────────┼────────────────────┼──────────────┘
          │                  │                    │
┌─────────┼──────────────────┼────────────────────┼──────────────┐
│         │    Storage & Processing Layer         │              │
│  ┌──────▼───────┐  ┌──────▼───────┐  ┌─────────▼──────────┐   │
│  │  Prometheus  │  │Elasticsearch │  │    Loki (Logs)     │   │
│  │  (Metrics)   │  │    (Logs)    │  │                    │   │
│  └──────▲───────┘  └──────▲───────┘  └─────────▲──────────┘   │
└─────────┼──────────────────┼────────────────────┼──────────────┘
          │                  │                    │
┌─────────┼──────────────────┼────────────────────┼──────────────┐
│         │     Collection & Processing Layer     │              │
│  ┌──────┴───────┐  ┌──────┴───────┐  ┌─────────┴──────────┐   │
│  │   Exporters  │  │   Fluentd/   │  │   Fluent Bit       │   │
│  │ (Prometheus) │  │  Fluent Bit  │  │   (Log Shipper)    │   │
│  └──────▲───────┘  └──────▲───────┘  └─────────▲──────────┘   │
└─────────┼──────────────────┼────────────────────┼──────────────┘
          │                  │                    │
┌─────────┼──────────────────┼────────────────────┼──────────────┐
│         │         Data Sources Layer            │              │
│  ┌──────┴───────┐  ┌──────┴───────┐  ┌─────────┴──────────┐   │
│  │ Kubernetes   │  │  Falco       │  │  Audit Logs        │   │
│  │ Metrics      │  │  (Runtime)   │  │  (API Server)      │   │
│  │              │  │              │  │                    │   │
│  └──────────────┘  └──────────────┘  └────────────────────┘   │
└────────────────────────────────────────────────────────────────┘
          │                  │                    │
┌─────────┴──────────────────┴────────────────────┴──────────────┐
│                    Kubernetes Cluster                           │
└────────────────────────────────────────────────────────────────┘
```

### Components Overview

| Component | Purpose | Data Type | Use Cases |
| ----------- | --------- | ----------- | ----------- |
| **Prometheus** | Metrics storage & query | Time-series metrics | Resource usage, API rates, alert metrics |
| **Elasticsearch** | Log storage & search | Structured logs | Audit logs, Falco alerts, app logs |
| **Loki** | Log aggregation | Logs (lightweight) | Application logs, container logs |
| **Grafana** | Visualization | Dashboards | Security dashboards, metrics viz |
| **Kibana** | Log exploration | Log search/viz | Audit log investigation |
| **AlertManager** | Alert routing | Alerts | Team notifications, escalations |
| **Fluentd/Fluent Bit** | Log collection | Log forwarding | Collect and route logs |

## Log Aggregation

### Why Aggregate Logs

**Benefits**:

- Centralized search across all sources
- Correlation of related events
- Long-term retention and archival
- Efficient querying and analysis
- Compliance and auditing

### Log Collection Architecture

#### Using Fluentd

Fluentd is a data collector for unified logging:

```yaml
# fluentd-daemonset.yaml

apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: fluentd
  namespace: logging
spec:
  selector:
    matchLabels:
      app: fluentd
  template:
    metadata:
      labels:
        app: fluentd
    spec:
      serviceAccountName: fluentd
      containers:
      - name: fluentd
        image: fluent/fluentd-kubernetes-daemonset:v1-debian-elasticsearch
        env:
        - name: FLUENT_ELASTICSEARCH_HOST
          value: "elasticsearch.logging.svc.cluster.local"
        - name: FLUENT_ELASTICSEARCH_PORT
          value: "9200"
        - name: FLUENT_ELASTICSEARCH_SCHEME
          value: "http"
        - name: FLUENT_UID
          value: "0"
        volumeMounts:
        - name: varlog
          mountPath: /var/log
        - name: varlibdockercontainers
          mountPath: /var/lib/docker/containers
          readOnly: true
        - name: config
          mountPath: /fluentd/etc/fluent.conf
          subPath: fluent.conf
      volumes:
      - name: varlog
        hostPath:
          path: /var/log
      - name: varlibdockercontainers
        hostPath:
          path: /var/lib/docker/containers
      - name: config
        configMap:
          name: fluentd-config
```

#### Fluentd Configuration

```xml
# fluent.conf

<source>
  @type tail
  path /var/log/containers/*.log
  pos_file /var/log/fluentd-containers.log.pos
  tag kubernetes.*
  read_from_head true
  <parse>
    @type json
    time_format %Y-%m-%dT%H:%M:%S.%NZ
  </parse>
</source>

# Kubernetes metadata enrichment

<filter kubernetes.**>
  @type kubernetes_metadata
  @id filter_kube_metadata
</filter>

# Parse audit logs

<source>
  @type tail
  path /var/log/kubernetes/audit.log
  pos_file /var/log/fluentd-audit.log.pos
  tag k8s.audit
  <parse>
    @type json
  </parse>
</source>

# Parse Falco alerts

<source>
  @type http
  port 9880
  bind 0.0.0.0
  tag falco.alerts
  <parse>
    @type json
  </parse>
</source>

# Enrich with security context

<filter k8s.**>
  @type record_transformer
  <record>
    cluster_name "production-cluster"
    security_context true
  </record>
</filter>

# Output to Elasticsearch

<match k8s.audit>
  @type elasticsearch
  @id out_es_audit
  host elasticsearch.logging.svc.cluster.local
  port 9200
  logstash_format true
  logstash_prefix k8s-audit
  include_tag_key true
  type_name _doc
  <buffer>
    @type file
    path /var/log/fluentd-buffers/audit.buffer
    flush_mode interval
    retry_type exponential_backoff
    flush_interval 5s
  </buffer>
</match>

<match falco.alerts>
  @type elasticsearch
  @id out_es_falco
  host elasticsearch.logging.svc.cluster.local
  port 9200
  logstash_format true
  logstash_prefix falco
  include_tag_key true
  type_name _doc
</match>

<match kubernetes.**>
  @type elasticsearch
  @id out_es_kubernetes
  host elasticsearch.logging.svc.cluster.local
  port 9200
  logstash_format true
  logstash_prefix kubernetes
  include_tag_key true
  type_name _doc
</match>
```

#### Using Fluent Bit (Lightweight)

Fluent Bit is more resource-efficient than Fluentd:

```yaml
# fluent-bit-daemonset.yaml

apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: fluent-bit
  namespace: logging
spec:
  selector:
    matchLabels:
      app: fluent-bit
  template:
    metadata:
      labels:
        app: fluent-bit
    spec:
      containers:
      - name: fluent-bit
        image: fluent/fluent-bit:2.2
        volumeMounts:
        - name: varlog
          mountPath: /var/log
        - name: config
          mountPath: /fluent-bit/etc/
      volumes:
      - name: varlog
        hostPath:
          path: /var/log
      - name: config
        configMap:
          name: fluent-bit-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluent-bit-config
  namespace: logging
data:
  fluent-bit.conf: |
    [SERVICE]
        Flush         5
        Log_Level     info

    [INPUT]
        Name              tail
        Path              /var/log/containers/*.log
        Parser            docker
        Tag               kube.*
        Refresh_Interval  5

    [INPUT]
        Name              tail
        Path              /var/log/kubernetes/audit.log
        Parser            json
        Tag               audit.*

    [FILTER]
        Name                kubernetes
        Match               kube.*
        Kube_URL            https://kubernetes.default.svc:443
        Kube_CA_File        /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        Kube_Token_File     /var/run/secrets/kubernetes.io/serviceaccount/token

    [OUTPUT]
        Name            es
        Match           *
        Host            elasticsearch.logging.svc.cluster.local
        Port            9200
        Logstash_Format On
        Logstash_Prefix fluent-bit
        Retry_Limit     5
```

### Elasticsearch Deployment

```yaml
# elasticsearch.yaml

apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: elasticsearch
  namespace: logging
spec:
  serviceName: elasticsearch
  replicas: 3
  selector:
    matchLabels:
      app: elasticsearch
  template:
    metadata:
      labels:
        app: elasticsearch
    spec:
      containers:
      - name: elasticsearch
        image: docker.elastic.co/elasticsearch/elasticsearch:8.12.0
        ports:
        - containerPort: 9200
          name: http
        - containerPort: 9300
          name: transport
        env:
        - name: cluster.name
          value: k8s-logs
        - name: node.name
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: discovery.seed_hosts
          value: "elasticsearch-0.elasticsearch,elasticsearch-1.elasticsearch,elasticsearch-2.elasticsearch"
        - name: cluster.initial_master_nodes
          value: "elasticsearch-0,elasticsearch-1,elasticsearch-2"
        - name: ES_JAVA_OPTS
          value: "-Xms512m -Xmx512m"
        - name: xpack.security.enabled
          value: "false"  # Enable in production
        volumeMounts:
        - name: data
          mountPath: /usr/share/elasticsearch/data
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 10Gi
---
apiVersion: v1
kind: Service
metadata:
  name: elasticsearch
  namespace: logging
spec:
  clusterIP: None
  selector:
    app: elasticsearch
  ports:
  - port: 9200
    name: http
  - port: 9300
    name: transport
```

## Metrics Collection

### Prometheus for Security Metrics

#### Prometheus Deployment

```yaml
# prometheus.yaml

apiVersion: apps/v1
kind: Deployment
metadata:
  name: prometheus
  namespace: monitoring
spec:
  replicas: 1
  selector:
    matchLabels:
      app: prometheus
  template:
    metadata:
      labels:
        app: prometheus
    spec:
      serviceAccountName: prometheus
      containers:
      - name: prometheus
        image: prom/prometheus:v2.49.0
        args:
        - '--config.file=/etc/prometheus/prometheus.yml'
        - '--storage.tsdb.path=/prometheus'
        - '--storage.tsdb.retention.time=30d'
        ports:
        - containerPort: 9090
        volumeMounts:
        - name: config
          mountPath: /etc/prometheus
        - name: storage
          mountPath: /prometheus
      volumes:
      - name: config
        configMap:
          name: prometheus-config
      - name: storage
        persistentVolumeClaim:
          claimName: prometheus-storage
```

#### Prometheus Configuration

```yaml
# prometheus-config.yaml

apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: monitoring
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
      evaluation_interval: 15s

    # Alert rules

    rule_files:
      - /etc/prometheus/alerts.yml

    # Alertmanager configuration

    alerting:
      alertmanagers:
      - static_configs:
        - targets:
          - alertmanager:9093

    # Scrape configurations

    scrape_configs:

      # Kubernetes API server

      - job_name: 'kubernetes-apiservers'
        kubernetes_sd_configs:
        - role: endpoints
        scheme: https
        tls_config:
          ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
        relabel_configs:
        - source_labels: [__meta_kubernetes_namespace, __meta_kubernetes_service_name, __meta_kubernetes_endpoint_port_name]
          action: keep
          regex: default;kubernetes;https

      # Kubernetes nodes

      - job_name: 'kubernetes-nodes'
        kubernetes_sd_configs:
        - role: node
        scheme: https
        tls_config:
          ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
        relabel_configs:
        - action: labelmap
          regex: __meta_kubernetes_node_label_(.+)

      # Kubernetes pods

      - job_name: 'kubernetes-pods'
        kubernetes_sd_configs:
        - role: pod
        relabel_configs:
        - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
          action: keep
          regex: true
        - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
          action: replace
          target_label: __metrics_path__
          regex: (.+)
        - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
          action: replace
          regex: ([^:]+)(?::\d+)?;(\d+)
          replacement: $1:$2
          target_label: __address__

      # Falco exporter

      - job_name: 'falco'
        static_configs:
        - targets: ['falco-exporter:9376']

  alerts.yml: |
    groups:
    - name: security
      interval: 30s
      rules:

      # High authentication failure rate

      - alert: HighAuthFailureRate
        expr: rate(apiserver_request_total{code=~"401|403"}[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High authentication failure rate"
          description: "Authentication failures: {{ $value }} per second"

      # Excessive API requests

      - alert: ExcessiveAPIRequests
        expr: rate(apiserver_request_total[5m]) > 1000
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Excessive API request rate"
          description: "API requests: {{ $value }} per second"

      # Privileged pod creation

      - alert: PrivilegedPodCreated
        expr: increase(kube_pod_container_status_running{container_security_context_privileged="true"}[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Privileged pod created"
          description: "Privileged pod detected in {{ $labels.namespace }}/{{ $labels.pod }}"

      # Falco critical alerts

      - alert: FalcoCriticalAlert
        expr: increase(falco_events{priority="Critical"}[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Falco critical alert"
          description: "Critical security event detected: {{ $labels.rule }}"

      # Unusual pod restart rate

      - alert: HighPodRestartRate
        expr: rate(kube_pod_container_status_restarts_total[15m]) > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High pod restart rate"
          description: "Pod {{ $labels.namespace }}/{{ $labels.pod }} restarting frequently"
```

### Security-Relevant Metrics

#### API Server Metrics

```promql
# Total API requests

sum(rate(apiserver_request_total[5m]))

# API requests by code

sum(rate(apiserver_request_total[5m])) by (code)

# Authentication failures

sum(rate(apiserver_request_total{code=~"401|403"}[5m]))

# API request latency (99th percentile)

histogram_quantile(0.99, sum(rate(apiserver_request_duration_seconds_bucket[5m])) by (le))

# Requests by user

sum(rate(apiserver_request_total[5m])) by (user)

# Requests by resource type

sum(rate(apiserver_request_total[5m])) by (resource)
```

#### Pod/Container Metrics

```promql
# Privileged containers running

count(kube_pod_container_status_running{container_security_context_privileged="true"})

# Containers running as root

count(kube_pod_container_status_running{container_security_context_run_as_user="0"})

# Pod restart rate

rate(kube_pod_container_status_restarts_total[5m])

# CPU usage by pod

sum(rate(container_cpu_usage_seconds_total[5m])) by (namespace, pod)

# Memory usage by pod

sum(container_memory_usage_bytes) by (namespace, pod)
```

#### Falco Metrics

```promql
# Total Falco alerts

sum(increase(falco_events[5m]))

# Falco alerts by priority

sum(increase(falco_events[5m])) by (priority)

# Falco alerts by rule

sum(increase(falco_events[5m])) by (rule)

# Critical alerts rate

rate(falco_events{priority="Critical"}[5m])
```

## Security Dashboards

### Grafana Dashboard Examples

#### Security Overview Dashboard

```json
{
  "dashboard": {
    "title": "Kubernetes Security Overview",
    "panels": [
      {
        "title": "API Authentication Failures",
        "targets": [
          {
            "expr": "sum(rate(apiserver_request_total{code=~\"401|403\"}[5m]))"
          }
        ],
        "type": "graph"
      },
      {
        "title": "Falco Alerts by Priority",
        "targets": [
          {
            "expr": "sum(increase(falco_events[5m])) by (priority)"
          }
        ],
        "type": "graph"
      },
      {
        "title": "Privileged Pods Running",
        "targets": [
          {
            "expr": "count(kube_pod_container_status_running{container_security_context_privileged=\"true\"})"
          }
        ],
        "type": "singlestat"
      },
      {
        "title": "Secret Access Rate",
        "targets": [
          {
            "expr": "sum(rate(apiserver_request_total{resource=\"secrets\"}[5m]))"
          }
        ],
        "type": "graph"
      }
    ]
  }
}
```

#### Audit Log Dashboard (Kibana)

```json
{
  "title": "Kubernetes Audit Logs",
  "visualizations": [
    {
      "title": "Audit Events Over Time",
      "type": "histogram",
      "field": "@timestamp"
    },
    {
      "title": "Top Users by Request Count",
      "type": "pie",
      "field": "user.username",
      "size": 10
    },
    {
      "title": "Failed Requests",
      "type": "table",
      "query": "responseStatus.code:>=400",
      "fields": ["user.username", "verb", "objectRef.resource", "responseStatus.code"]
    },
    {
      "title": "Secret Access",
      "type": "table",
      "query": "objectRef.resource:secrets",
      "fields": ["user.username", "verb", "objectRef.name", "requestReceivedTimestamp"]
    }
  ]
}
```

### Key Dashboard Panels

| Panel | Metric/Query | Purpose |
| ------- | ------------- | --------- |
| **Auth Failures** | `apiserver_request_total{code=~"401"}` or `code=~"403"` | Detect brute force attacks |
| **Falco Alerts** | `falco_events` by priority | Runtime security overview |
| **API Request Rate** | `apiserver_request_total` | Detect DoS or abuse |
| **Secret Access** | Audit logs where `resource=secrets` | Track sensitive data access |
| **Privileged Pods** | `kube_pod_*{privileged="true"}` | Monitor risky workloads |
| **Pod Exec Events** | Audit logs where `subresource=exec` | Track interactive access |
| **Network Policy Violations** | Falco network events | Detect lateral movement |
| **Container Restarts** | `kube_pod_container_status_restarts_total` | Possible exploit attempts |

## Alert Correlation

### Why Correlate Alerts

Single alerts can be noisy or ambiguous. Correlation improves accuracy:

**Example Scenario**: Credential Theft

Single events (noisy):

- ✗ Failed authentication (could be typo)
- ✗ Secret accessed (legitimate usage)
- ✗ New IP address (mobile user)

Correlated events (high confidence):

- ✓ Multiple failed auth + success from new IP + secret access + unusual time = **Credential compromise**

### Correlation Techniques

#### 1. Time-Based Correlation

Events occurring close in time are related:

```yaml
# AlertManager correlation example

route:
  group_by: ['namespace', 'pod']
  group_wait: 10s        # Wait 10s for related alerts
  group_interval: 5m     # Group alerts within 5 min
  repeat_interval: 4h    # Don't repeat for 4 hours

  routes:
  - match:
      severity: critical
    receiver: pagerduty
    group_by: ['cluster', 'alertname']
```

#### 2. Entity-Based Correlation

Events related to same entity (user, pod, IP):

```promql
# Find pods with multiple security issues

(
  count(falco_events{pod="nginx-123"}) > 0
  and
  rate(kube_pod_container_status_restarts_total{pod="nginx-123"}[5m]) > 0
  and
  rate(apiserver_request_total{pod="nginx-123",code=~"4.."}[5m]) > 0
)
```

#### 3. Pattern-Based Correlation

Specific sequences indicate attacks:

```
Attack Pattern: Container Escape

1. Shell spawned in container (Falco)
1. Privileged process execution (Falco)
1. Host filesystem mount (Falco)
1. Node SSH access (Audit logs)
⚠️ High confidence container escape attempt

```

### Implementing Correlation

#### Using Prometheus Recording Rules

```yaml
# prometheus-rules.yaml

groups:
- name: security_correlation
  interval: 30s
  rules:

  # Record high-risk pods

  - record: security:pod:risk_score
    expr: |
      (
        count(falco_events{priority=~"Critical|Warning"}) by (pod) * 10
        +
        rate(kube_pod_container_status_restarts_total[5m]) by (pod) * 5
        +
        (kube_pod_container_status_running{container_security_context_privileged="true"}) by (pod) * 20
      )

  # Alert on high risk score

  - alert: HighRiskPod
    expr: security:pod:risk_score > 30
    labels:
      severity: critical
    annotations:
      summary: "High-risk pod detected"
      description: "Pod {{ $labels.pod }} has risk score {{ $value }}"
```

#### Using External Correlation Tools

```python
# Example: Python correlation script

import json
from datetime import datetime, timedelta

def correlate_events(falco_alerts, audit_logs, metrics):
    """
    Correlate events from multiple sources
    """
    incidents = []

    for falco_alert in falco_alerts:
        if falco_alert['priority'] == 'Critical':
            pod = falco_alert['output_fields']['k8s.pod.name']
            alert_time = datetime.fromisoformat(falco_alert['time'])

            # Look for related events within 5 minutes

            related_audit = [
                log for log in audit_logs
                if log['objectRef']['name'] == pod
                and abs(datetime.fromisoformat(log['timestamp']) - alert_time) < timedelta(minutes=5)
            ]

            related_metrics = [
                m for m in metrics
                if m['pod'] == pod
                and m['timestamp'] > alert_time - timedelta(minutes=5)
            ]

            if related_audit or related_metrics:
                incidents.append({
                    'pod': pod,
                    'falco_alert': falco_alert,
                    'audit_events': related_audit,
                    'metrics': related_metrics,
                    'confidence': 'high'
                })

    return incidents
```

## Incident Response Workflows

### Automated Response Workflow

```
┌─────────────────────────────────────────────────────────┐
│              Security Event Detected                     │
│         (Falco, Audit Logs, Metrics)                    │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│         1. Triage & Classification                       │
│    • Check severity                                     │
│    • Correlate with other events                       │
│    • Calculate confidence                              │
└────────────────────┬────────────────────────────────────┘
                     │
        ┌────────────┴────────────┐
        │                         │
        ▼                         ▼
┌───────────────────┐   ┌────────────────────┐
│  Low Confidence   │   │  High Confidence   │
│     • Log only    │   │  • Immediate action│
│     • Monitor     │   └────────┬───────────┘
└───────────────────┘            │
                                 ▼
                    ┌────────────────────────────┐
                    │   2. Evidence Collection    │
                    │  • Pod logs                │
                    │  • Pod manifest            │
                    │  • Network connections     │
                    │  • Process list            │
                    └────────────┬───────────────┘
                                 │
                                 ▼
                    ┌────────────────────────────┐
                    │   3. Containment           │
                    │  • Isolate pod/node        │
                    │  • Block network           │
                    │  • Terminate workload      │
                    └────────────┬───────────────┘
                                 │
                                 ▼
                    ┌────────────────────────────┐
                    │   4. Notification          │
                    │  • Alert security team     │
                    │  • Create ticket           │
                    │  • Escalate if needed      │
                    └────────────┬───────────────┘
                                 │
                                 ▼
                    ┌────────────────────────────┐
                    │   5. Investigation         │
                    │  • Manual analysis         │
                    │  • Root cause              │
                    │  • Impact assessment       │
                    └────────────┬───────────────┘
                                 │
                                 ▼
                    ┌────────────────────────────┐
                    │   6. Remediation           │
                    │  • Patch vulnerabilities   │
                    │  • Update policies         │
                    │  • Improve detection       │
                    └────────────────────────────┘

```

### Response Automation Example

```yaml
# falco-response-engine.yaml

apiVersion: v1
kind: ConfigMap
metadata:
  name: response-rules
  namespace: falco
data:
  rules.yaml: |
    rules:

      # Terminate pod on critical alert

      - name: terminate_pod
        condition:
          priority: Critical
          rule: ["Container Escape", "Reverse Shell"]
        actions:
          - type: capture_logs
          - type: capture_manifest
          - type: delete_pod
          - type: alert_slack

      # Isolate pod on suspicious activity

      - name: isolate_pod
        condition:
          priority: Warning
          consecutive_alerts: 3
        actions:
          - type: apply_network_policy
            policy: deny-all
          - type: alert_pagerduty

      # Just alert on info

      - name: log_only
        condition:
          priority: ["Info", "Notice"]
        actions:
          - type: log
          - type: metrics
```

## Compliance Reporting

### Security Compliance Metrics

```promql
# Example compliance metrics

# 1. All privileged pods (should be 0 or small)

count(kube_pod_container_status_running{container_security_context_privileged="true"})

# 2. Pods without resource limits

count(kube_pod_container_info) -
count(kube_pod_container_resource_limits)

# 3. Audit log coverage (should be 100%)

sum(rate(apiserver_audit_event_total[24h])) /
sum(rate(apiserver_request_total[24h]))

# 4. Security alert response time (should be < 15min)

histogram_quantile(0.95,
  rate(alert_response_duration_seconds_bucket[24h])
)

# 5. Falco uptime (should be > 99%)

avg_over_time(up{job="falco"}[30d])
```

### Compliance Dashboard

Key metrics for compliance reports:

| Metric | Standard | Target | Query |
| -------- | ---------- | -------- | ------- |
| **Audit Coverage** | SOC 2, PCI-DSS | 100% | API requests with audit events |
| **Privileged Workloads** | CIS Benchmark | 0 | Count privileged pods |
| **Alert Response Time** | SOC 2 | < 15 min | p95 alert response time |
| **Security Scan Rate** | PCI-DSS | Daily | Last scan timestamp |
| **Patch Compliance** | CIS | < 30 days | CVEs older than 30 days |
| **Runtime Monitoring** | CIS | 99.9% | Falco uptime |

## Exam Tips

For the KCSA exam, understand:

1. **Log aggregation**: Why and how (Fluentd/Fluent Bit → Elasticsearch)
1. **Metrics collection**: Prometheus scraping, exporters
1. **Dashboard components**: What metrics to monitor
1. **Alert correlation**: Why single alerts aren't enough
1. **Common security queries**: API failures, Falco alerts, secret access
1. **Integration patterns**: How components connect
1. **Compliance metrics**: What to measure for compliance

**Practice**:

- Build a simple monitoring stack
- Create security dashboards
- Write Prometheus alert rules
- Query logs with jq or Kibana
- Correlate events across sources

## Summary

**Key Takeaways**:

1. Security monitoring integrates multiple data sources
1. Log aggregation centralizes audit logs, Falco alerts, and app logs
1. Prometheus provides security-relevant metrics and alerting
1. Dashboards visualize security posture at a glance
1. Alert correlation reduces false positives and improves detection
1. Automated response speeds up incident containment
1. Compliance reporting demonstrates security controls

**Best Practices**:

- Deploy log aggregation early (before incidents)
- Create dashboards for common security scenarios
- Correlate alerts to improve confidence
- Automate evidence collection
- Document response playbooks
- Regular compliance reviews
- Test incident response procedures

**Architecture Principles**:

- Defense in depth: Multiple detection layers
- Centralization: Single pane of glass
- Retention: Keep logs long enough for forensics
- Security: Protect monitoring infrastructure itself
- Performance: Monitoring shouldn't impact workloads

**Next Steps**:

- Complete [Lab 4: Log Aggregation](../../labs/06-monitoring-logging/lab-04-log-aggregation.md)
- Complete [Lab 5: Security Monitoring Dashboard](../../labs/06-monitoring-logging/lab-05-security-monitoring.md)
- Review all Domain 6 materials
- Practice integrating multiple monitoring tools
