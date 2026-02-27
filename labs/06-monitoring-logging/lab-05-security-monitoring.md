# Lab 5: Security Monitoring Dashboard

## Objectives

- Deploy Prometheus for metrics collection
- Create security-focused Grafana dashboards
- Configure comprehensive security alert rules
- Correlate events from multiple data sources
- Simulate and detect security attacks
- Build end-to-end security monitoring solution

**Duration**: 90 minutes | **Difficulty**: Advanced

## Prerequisites

- Completed Labs 1-4
- Elasticsearch, Kibana, and Fluent Bit running
- Falco installed and operational
- Audit logging enabled
- kubectl and Helm configured

## Part 1: Deploy Prometheus (20 minutes)

### Step 1: Install Prometheus with Helm

```bash

# Add Prometheus community Helm repository

helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# Create namespace

kubectl create namespace monitoring

# Create values file

cat <<EOF > prometheus-values.yaml
server:
  persistentVolume:
    enabled: true
    size: 10Gi
  retention: "30d"
  
  global:
    scrape_interval: 15s
    evaluation_interval: 15s

alertmanager:
  enabled: true
  persistentVolume:
    enabled: true
    size: 2Gi

nodeExporter:
  enabled: true

kubeStateMetrics:
  enabled: true

pushgateway:
  enabled: false
EOF

# Install Prometheus

helm install prometheus prometheus-community/prometheus \
  -n monitoring \
  -f prometheus-values.yaml

# Watch deployment

kubectl get pods -n monitoring -w
```

```

**Wait**: Prometheus components take 2-3 minutes to start.

### Step 2: Verify Prometheus

```bash

# Check all pods are running

kubectl get pods -n monitoring

# Port-forward Prometheus

kubectl port-forward -n monitoring svc/prometheus-server 9090:80 &

# Access in browser: http://localhost:9090

# Test a query in Prometheus UI
# Query: up
# Should show all scraped targets

```

```

### Step 3: Configure Security Metrics

```bash

cat <<'EOF' > security-alerts.yaml
serverFiles:
  alerting_rules.yml:
    groups:
    - name: security
      interval: 30s
      rules:

      # High authentication failure rate

      - alert: HighAuthFailureRate
        expr: rate(apiserver_request_total{code=~"401|403"}[5m]) > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High authentication failure rate detected"
          description: "{{ $value }} auth failures per second"

      # Excessive API requests

      - alert: ExcessiveAPIRequests
        expr: rate(apiserver_request_total[5m]) > 500
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Excessive API request rate"
          description: "{{ $value }} requests per second"

      # Privileged pods running

      - alert: PrivilegedPodsDetected
        expr: count(kube_pod_container_status_running{pod=~".*",container_security_context_privileged="true"}) > 0
        labels:
          severity: warning
        annotations:
          summary: "Privileged pods are running"
          description: "{{ $value }} privileged pods detected"

      # High pod restart rate

      - alert: HighPodRestartRate
        expr: rate(kube_pod_container_status_restarts_total[15m]) > 3
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Pod restarting frequently"
          description: "Pod {{ $labels.namespace }}/{{ $labels.pod }} restart rate: {{ $value }}"

      # Node disk pressure

      - alert: NodeDiskPressure
        expr: kube_node_status_condition{condition="DiskPressure",status="true"} == 1
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Node under disk pressure"
          description: "Node {{ $labels.node }} is under disk pressure"
EOF

# Upgrade Prometheus with security alerts

helm upgrade prometheus prometheus-community/prometheus \
  -n monitoring \
  --reuse-values \
  -f security-alerts.yaml
```

```

**Verification**:

- [ ] Prometheus server running
- [ ] Can access Prometheus UI
- [ ] Targets are being scraped
- [ ] Alert rules loaded

## Part 2: Deploy Grafana (15 minutes)

### Step 4: Install Grafana

```bash

# Add Grafana Helm repository

helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

# Create values file

cat <<EOF > grafana-values.yaml
persistence:
  enabled: true
  size: 5Gi

adminPassword: admin123  # Change in production!

datasources:
  datasources.yaml:
    apiVersion: 1
    datasources:
    - name: Prometheus
      type: prometheus
      url: http://prometheus-server.monitoring.svc.cluster.local
      access: proxy
      isDefault: true
    - name: Elasticsearch
      type: elasticsearch
      url: http://elasticsearch-master.logging.svc.cluster.local:9200
      access: proxy
      database: "[kubernetes-]YYYY.MM.DD"
      jsonData:
        interval: Daily
        timeField: "@timestamp"
        esVersion: "8.0.0"

service:
  type: ClusterIP
  port: 80
EOF

# Install Grafana

helm install grafana grafana/grafana \
  -n monitoring \
  -f grafana-values.yaml

# Wait for pod

kubectl wait --for=condition=Ready pod -l app.kubernetes.io/name=grafana -n monitoring --timeout=120s
```

```

### Step 5: Access Grafana

```bash

# Port-forward Grafana

kubectl port-forward -n monitoring svc/grafana 3000:80 &

# Get admin password

kubectl get secret -n monitoring grafana -o jsonpath="{.data.admin-password}" | base64 --decode ; echo

# Access in browser: http://localhost:3000
# Login with: admin / <password-from-above>

```

```

**Verification**:

- [ ] Grafana pod running
- [ ] Can access Grafana UI
- [ ] Can login successfully
- [ ] Prometheus datasource configured

## Part 3: Create Security Dashboards (30 minutes)

### Step 6: Import Kubernetes Monitoring Dashboard

**In Grafana UI**:

1. Click **+** → **Import dashboard**
1. Enter dashboard ID: **315** (Kubernetes cluster monitoring)
1. Click **Load**
1. Select **Prometheus** datasource
1. Click **Import**

### Step 7: Create Custom Security Dashboard

**Create new dashboard**:

1. Click **+** → **Create Dashboard**
1. Click **Add visualization**
1. Select **Prometheus** datasource

**Panel 1: Authentication Failures**

```

Title: Authentication Failures (Last Hour)
Query: sum(increase(apiserver_request_total{code=~"401|403"}[1h]))
Visualization: Stat
Unit: Short

```
```

**Panel 2: API Request Rate**

```

Title: API Request Rate
Query: rate(apiserver_request_total[5m])
Visualization: Time series
Legend: {{verb}} - {{code}}
```

```

**Panel 3: Privileged Pods**

```

Title: Privileged Pods Running
Query: count(kube_pod_container_status_running{container_security_context_privileged="true"})
Visualization: Stat
Thresholds: Base=0 (green), >0 (orange), >3 (red)

```
```

**Panel 4: Pod Restart Rate**

```

Title: Pod Restarts (Last Hour)
Query: topk(10, sum(increase(kube_pod_container_status_restarts_total[1h])) by (namespace, pod))
Visualization: Bar chart
```

```

**Panel 5: Node CPU Usage**

```

Title: Node CPU Usage
Query: 100 - (avg by (instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)
Visualization: Time series
Unit: Percent (0-100)

```
```

**Panel 6: Secret Access Rate**

```

Title: Secret Access Rate (from audit logs)
Note: This would come from Elasticsearch datasource
Switch to Elasticsearch datasource
Query: Count where objectRef.resource="secrets"
Time field: requestReceivedTimestamp
Visualization: Time series
```

```

1. **Arrange panels** in grid layout
1. **Save dashboard** as "Kubernetes Security Overview"

### Step 8: Create Falco Alerts Dashboard

**Create another dashboard for Falco**:

1. Create new dashboard
1. Add visualization → Elasticsearch datasource

**Panel 1: Falco Alerts by Priority**

```

Query Type: Lucene
Query: kubernetes.namespace_name:"falco" AND priority:*
Metrics: Count
Bucket: Terms aggregation on priority.keyword
Visualization: Pie chart

```
```

**Panel 2: Falco Alerts Timeline**

```

Query: kubernetes.namespace_name:"falco"
Metrics: Count
Bucket: Date histogram on @timestamp
Visualization: Time series
```

```

**Panel 3: Top Triggered Rules**

```

Query: kubernetes.namespace_name:"falco" AND rule:*
Metrics: Count
Bucket: Terms on rule.keyword (top 10)
Visualization: Bar chart

```
```

**Panel 4: Recent Critical Alerts**

```

Query: kubernetes.namespace_name:"falco" AND priority:"Critical"
Columns: @timestamp, rule, output_fields.container.name
Visualization: Table
Sort: @timestamp descending
```

```

1. **Save dashboard** as "Falco Security Alerts"

**Verification**:

- [ ] Imported Kubernetes dashboard
- [ ] Created custom security dashboard
- [ ] Created Falco alerts dashboard
- [ ] All panels showing data

## Part 4: Configure AlertManager (15 minutes)

### Step 9: Configure Alert Routing

```bash

cat <<'EOF' > alertmanager-config.yaml
alertmanagerFiles:
  alertmanager.yml:
    global:
      resolve_timeout: 5m

    route:
      group_by: ['alertname', 'cluster', 'service']
      group_wait: 10s
      group_interval: 10s
      repeat_interval: 12h
      receiver: 'default'
      routes:
      - match:
          severity: critical
        receiver: critical-alerts
      - match:
          severity: warning
        receiver: warning-alerts

    receivers:
    - name: 'default'

      # Default receiver (logs only for lab)

    - name: 'critical-alerts'

      # In production, configure Slack, PagerDuty, etc.
      # Example Slack config:
      # slack_configs:
      # - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
      #   channel: '#security-critical'
      #   title: 'Critical Security Alert'

    - name: 'warning-alerts'

      # Warning notifications

EOF

# Upgrade Prometheus with AlertManager config

helm upgrade prometheus prometheus-community/prometheus \
  -n monitoring \
  --reuse-values \
  -f alertmanager-config.yaml
```

```

### Step 10: View Active Alerts

```bash

# Port-forward AlertManager

kubectl port-forward -n monitoring svc/prometheus-alertmanager 9093:80 &

# Access in browser: http://localhost:9093

```

```

**In AlertManager UI**:

- View active alerts
- See alert grouping
- Check alert routing

**Verification**:

- [ ] AlertManager running
- [ ] Can access AlertManager UI
- [ ] Alert routing configured
- [ ] Can see alerts (if any firing)

## Part 5: Attack Simulation and Detection (20 minutes)

### Step 11: Simulate Security Events

**Scenario 1: Unauthorized Secret Access**

```bash

# Create test secret

kubectl create secret generic sensitive-data \
  --from-literal=api-key=secret123 \
  -n default

# Access secret multiple times (should trigger audit log entry)

for i in {1..10}; do
  kubectl get secret sensitive-data -n default -o jsonpath='{.data.api-key}' | base64 -d
  sleep 2
done

# Check audit logs in Kibana
# Go to Kibana → Discover → audit-* index
# Query: objectRef.resource:"secrets" AND objectRef.name:"sensitive-data"

```

```

**Scenario 2: Privilege Escalation Attempt**

```bash

# Create privileged pod (should trigger Falco and metrics)

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: privileged-attack
spec:
  containers:
  - name: attacker
    image: nginx:1.27
    securityContext:
      privileged: true
EOF

# Check Falco alerts

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20 | grep -i privileged

# Check Grafana dashboard for privileged pods

```

```

**Scenario 3: Container Escape Attempt**

```bash

# Exec into privileged pod and attempt suspicious activity

kubectl exec privileged-attack -- bash -c "ls /var/run/docker.sock || echo 'Attempting container escape'"

# Try to access host filesystem

kubectl exec privileged-attack -- bash -c "ls /host/etc || echo 'Attempting host access'"

# Check Falco for container escape alerts

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=30 | grep -i "escape\|docker.sock"
```

```

**Scenario 4: Crypto Mining Simulation**

```bash

# Simulate crypto miner process

kubectl exec privileged-attack -- bash -c "nohup sh -c 'while true; do echo xmrig; sleep 10; done' > /tmp/miner.log 2>&1 &"

# Check Falco for crypto mining detection

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20 | grep -i crypto
```

```

**Scenario 5: Network Scanning**

```bash

# Install and use nmap (if rule exists)

kubectl exec privileged-attack -- bash -c "apt-get update && apt-get install -y nmap && nmap -p 1-100 localhost" || true

# Check Falco alerts

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20 | grep -i "network\|nmap"
```

```

### Step 12: Investigate Attacks in Dashboards

**In Grafana**:

1. Go to **Kubernetes Security Overview** dashboard
1. Check **Privileged Pods** panel (should show 1+)
1. Check **API Request Rate** for unusual spikes
1. Look at **Pod Restart Rate** for anomalies

**In Kibana**:

1. Go to **Discover** → **audit-*** index
1. Query: `verb:"create" AND objectRef.resource:"pods"`
1. Find privileged pod creation event
1. Examine user, timestamp, source IP

**In Falco Dashboard**:

1. Go to **Falco Security Alerts** dashboard
1. Check **Alerts by Priority** (should show warnings/critical)
1. View **Recent Critical Alerts** table
1. Examine alert details

**Verification**:

- [ ] Secret access visible in audit logs
- [ ] Privileged pod detected by Falco
- [ ] Container escape attempts logged
- [ ] All events visible in dashboards
- [ ] Can correlate events across sources

## Part 6: Event Correlation (Optional Challenge)

### Step 13: Create Correlation Dashboard

**Create new dashboard: "Security Incident Timeline"**

Add panels that show correlated events:

1. **Timeline Panel**: Events from all sources
   - Audit logs (Elasticsearch)
   - Falco alerts (Elasticsearch)
   - Prometheus alerts

1. **Correlation Panel**: Events for specific pod
   - Filter all sources by pod name
   - Show sequence of events

1. **User Activity Panel**: All actions by specific user
   - From audit logs
   - Grouped by namespace

**Example correlation query in Kibana**:

```

# Find all events related to privileged-attack pod

kubernetes.pod_name:"privileged-attack" OR objectRef.name:"privileged-attack"

```
```

**Verification**:

- [ ] Can see events from multiple sources
- [ ] Can filter by pod/user/namespace
- [ ] Timeline shows sequence of events
- [ ] Can investigate incidents efficiently

## Troubleshooting

### Issue 1: Prometheus Not Scraping Targets

```bash

# Check Prometheus logs

kubectl logs -n monitoring -l app.kubernetes.io/name=prometheus

# Verify ServiceMonitors

kubectl get servicemonitor -A

# Check RBAC permissions

kubectl get clusterrolebinding prometheus-server
```

```

### Issue 2: Grafana Shows No Data

```bash

# Check datasource configuration
# In Grafana: Configuration → Data Sources → Prometheus
# Click "Test" button

# Verify Prometheus is accessible

kubectl run test-curl --image=curlimages/curl -it --rm -- \
  curl http://prometheus-server.monitoring.svc.cluster.local/api/v1/query?query=up

# Check time range in Grafana panels

```

```

### Issue 3: Alerts Not Firing

```bash

# Check alert rules are loaded
# In Prometheus UI: http://localhost:9090/alerts

# Verify conditions are met
# Run queries manually in Prometheus

# Check AlertManager

kubectl logs -n monitoring -l app.kubernetes.io/name=alertmanager
```

```

## Verification Checklist

- [ ] Prometheus deployed and scraping
- [ ] Grafana deployed and accessible
- [ ] Security dashboards created
- [ ] AlertManager configured
- [ ] Can simulate security events
- [ ] Events detected by Falco
- [ ] Events logged in audit logs
- [ ] Events visible in dashboards
- [ ] Alerts firing correctly
- [ ] Can correlate events across sources
- [ ] Can investigate incidents

## Cleanup

```bash

# Remove attack simulation resources

kubectl delete pod privileged-attack
kubectl delete secret sensitive-data

# Keep monitoring stack running
# To remove everything:
# helm uninstall prometheus grafana -n monitoring
# helm uninstall elasticsearch kibana fluent-bit -n logging
# helm uninstall falco -n falco
# kubectl delete namespace monitoring logging falco

```

```

## Challenge Exercises

1. **Advanced Correlation**: Create a dashboard that automatically correlates:

   - Falco alert → Find related audit log entries → Show affected pods

1. **Custom Alerts**: Create Prometheus alert that:

   - Detects when pod restarts 3+ times in 10 minutes
   - Fires only for production namespaces
   - Includes pod logs in alert annotation

1. **Response Automation**: Create script that:

   - Listens to AlertManager webhook
   - Automatically captures pod logs on critical alert
   - Terminates malicious pods

1. **Compliance Dashboard**: Create dashboard showing:

   - All privileged pods over last 30 days
   - All secret access events
   - All RBAC changes
   - Generate PDF report

1. **Performance Optimization**: Optimize the stack for high-volume environments:

   - Tune Fluent Bit buffers
   - Optimize Elasticsearch indices
   - Configure Prometheus retention and scraping

## Key Takeaways

- Security monitoring requires multiple data sources
- Correlation improves detection accuracy
- Dashboards provide at-a-glance security posture
- Alerts enable immediate response
- Attack simulation validates detection capability
- Event correlation speeds investigation
- Automation reduces response time
- Complete monitoring = logs + metrics + runtime detection

## Summary

You've built a complete security monitoring solution:

1. **Audit Logging**: Tracks all API activity
1. **Falco**: Detects runtime threats
1. **Log Aggregation**: Centralizes all logs
1. **Metrics**: Provides resource and security metrics
1. **Visualization**: Dashboards for quick insights
1. **Alerting**: Notifies on critical events
1. **Correlation**: Connects related events

This comprehensive setup provides:

- Real-time threat detection
- Historical analysis capability
- Incident investigation tools
- Compliance reporting
- Automated alerting

## Next Steps

- Review all Domain 6 materials
- Practice investigating security incidents
- Prepare for KCSA exam with focus areas:

  - Audit policy configuration
  - Falco rule syntax
  - Log analysis techniques
  - Security monitoring best practices
- Consider advanced topics:

  - Service mesh observability
  - eBPF-based monitoring
  - ML-based anomaly detection

---

**Congratulations!** You've completed all Domain 6 labs and built a production-grade security monitoring solution for Kubernetes. You now have hands-on experience with the tools and techniques needed for the KCSA exam and real-world Kubernetes security monitoring.
