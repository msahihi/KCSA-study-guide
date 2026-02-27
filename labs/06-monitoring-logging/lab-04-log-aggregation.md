# Lab 4: Log Aggregation

## Objectives

- Deploy Elasticsearch for log storage
- Configure Fluent Bit for log collection
- Ship audit logs and Falco alerts to Elasticsearch
- Query aggregated logs with Kibana
- Create log retention policies

**Duration**: 90 minutes | **Difficulty**: Advanced

## Prerequisites

- Completed Labs 1-3
- Running Kubernetes cluster with audit logging and Falco
- Sufficient cluster resources (4GB+ RAM per node recommended)
- kubectl and Helm configured

## Part 1: Deploy Elasticsearch (25 minutes)

### Step 1: Create Logging Namespace

```bash
kubectl create namespace logging
```

```

### Step 2: Deploy Elasticsearch

```bash

# Add Elastic Helm repository

helm repo add elastic https://helm.elastic.co
helm repo update

# Create values file for Elasticsearch

cat <<EOF > elasticsearch-values.yaml
replicas: 1  # Single node for lab (use 3+ in production)
minimumMasterNodes: 1

resources:
  requests:
    cpu: "500m"
    memory: "1Gi"
  limits:
    cpu: "1000m"
    memory: "2Gi"

volumeClaimTemplate:
  accessModes: ["ReadWriteOnce"]
  resources:
    requests:
      storage: 10Gi

esConfig:
  elasticsearch.yml: |
    xpack.security.enabled: false  # Disable for lab (enable in production)
    xpack.monitoring.collection.enabled: true
EOF

# Install Elasticsearch

helm install elasticsearch elastic/elasticsearch \
  -n logging \
  -f elasticsearch-values.yaml

# Watch deployment

kubectl get pods -n logging -w
```

```

**Wait**: Elasticsearch takes 2-5 minutes to start.

### Step 3: Verify Elasticsearch

```bash

# Check pod is running

kubectl get pods -n logging

# Port-forward to access Elasticsearch

kubectl port-forward -n logging svc/elasticsearch-master 9200:9200 &

# Test Elasticsearch (in new terminal or after backgrounding)

curl http://localhost:9200

# Expected response:
# {
#   "name" : "elasticsearch-master-0",
#   "cluster_name" : "elasticsearch",
#   ...
# }

# Check cluster health

curl http://localhost:9200/_cluster/health?pretty

# Stop port-forward
# kill %1

```

```

**Verification**:

- [ ] Elasticsearch pod is running
- [ ] Can access Elasticsearch API
- [ ] Cluster status is green or yellow

## Part 2: Deploy Kibana (15 minutes)

### Step 4: Install Kibana

```bash

cat <<EOF > kibana-values.yaml
resources:
  requests:
    cpu: "100m"
    memory: "512Mi"
  limits:
    cpu: "1000m"
    memory: "1Gi"

service:
  type: ClusterIP
  port: 5601

elasticsearchHosts: "http://elasticsearch-master:9200"
EOF

# Install Kibana

helm install kibana elastic/kibana \
  -n logging \
  -f kibana-values.yaml

# Watch deployment

kubectl get pods -n logging -l app=kibana -w
```

```

### Step 5: Access Kibana

```bash

# Port-forward Kibana

kubectl port-forward -n logging svc/kibana-kibana 5601:5601

# Access in browser: http://localhost:5601

```

```

**Verification**:

- [ ] Kibana pod is running
- [ ] Can access Kibana UI
- [ ] Kibana connects to Elasticsearch

## Part 3: Deploy Fluent Bit (25 minutes)

### Step 6: Configure Fluent Bit

```bash

cat <<'EOF' > fluent-bit-values.yaml
daemonSetVolumes:
  - name: varlog
    hostPath:
      path: /var/log
  - name: varlibdockercontainers
    hostPath:
      path: /var/lib/docker/containers
  - name: etckubernetes
    hostPath:
      path: /etc/kubernetes
  - name: auditlog
    hostPath:
      path: /var/log/kubernetes

daemonSetVolumeMounts:
  - name: varlog
    mountPath: /var/log
  - name: varlibdockercontainers
    mountPath: /var/lib/docker/containers
    readOnly: true
  - name: etckubernetes
    mountPath: /etc/kubernetes
    readOnly: true
  - name: auditlog
    mountPath: /var/log/kubernetes
    readOnly: true

config:
  service: |
    [SERVICE]
        Daemon Off
        Flush 1
        Log_Level info
        Parsers_File parsers.conf
        Parsers_File custom_parsers.conf
        HTTP_Server On
        HTTP_Listen 0.0.0.0
        HTTP_Port 2020
        Health_Check On

  inputs: |
    [INPUT]
        Name tail
        Path /var/log/containers/*.log
        Parser docker
        Tag kube.*
        Mem_Buf_Limit 5MB
        Skip_Long_Lines On

    [INPUT]
        Name tail
        Path /var/log/kubernetes/audit.log
        Parser json
        Tag audit.*
        Mem_Buf_Limit 10MB

  filters: |
    [FILTER]
        Name kubernetes
        Match kube.*
        Kube_URL https://kubernetes.default.svc:443
        Kube_CA_File /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        Kube_Token_File /var/run/secrets/kubernetes.io/serviceaccount/token
        Kube_Tag_Prefix kube.var.log.containers.
        Merge_Log On
        Keep_Log Off
        K8S-Logging.Parser On
        K8S-Logging.Exclude On

    [FILTER]
        Name modify
        Match audit.*
        Add log_type audit

    [FILTER]
        Name grep
        Match kube.*
        Regex kubernetes.namespace_name ^(falco|logging|monitoring)$

  outputs: |
    [OUTPUT]
        Name es
        Match kube.*
        Host elasticsearch-master
        Port 9200
        Logstash_Format On
        Logstash_Prefix kubernetes
        Retry_Limit 5
        Suppress_Type_Name On

    [OUTPUT]
        Name es
        Match audit.*
        Host elasticsearch-master
        Port 9200
        Logstash_Format On
        Logstash_Prefix audit
        Retry_Limit 5
        Suppress_Type_Name On
EOF

# Install Fluent Bit

helm install fluent-bit fluent/fluent-bit \
  -n logging \
  -f fluent-bit-values.yaml

# Or add repo first if needed:

helm repo add fluent https://fluent.github.io/helm-charts
helm repo update
helm install fluent-bit fluent/fluent-bit -n logging -f fluent-bit-values.yaml
```

```

### Step 7: Verify Log Collection

```bash

# Check Fluent Bit pods (should be one per node)

kubectl get pods -n logging -l app.kubernetes.io/name=fluent-bit

# Check logs

kubectl logs -n logging -l app.kubernetes.io/name=fluent-bit --tail=50

# Verify Fluent Bit is sending to Elasticsearch

kubectl logs -n logging -l app.kubernetes.io/name=fluent-bit | grep "connected to"
```

```

### Step 8: Configure Falco to Send to Fluent Bit

```bash

# Update Falco to output JSON to stdout (already configured in Lab 2)
# Fluent Bit will automatically collect from container logs

# Generate some Falco events

kubectl exec test-pod -- bash -c "echo test" 2>/dev/null || \
  kubectl run test-pod --image=nginx:1.27 && sleep 5 && kubectl exec test-pod -- bash -c "echo test"

# Check if Falco logs are being collected

kubectl logs -n logging -l app.kubernetes.io/name=fluent-bit | grep -i falco
```

```

**Verification**:

- [ ] Fluent Bit pods running on all nodes
- [ ] Fluent Bit connected to Elasticsearch
- [ ] Logs being shipped successfully

## Part 4: Query and Visualize Logs (25 minutes)

### Step 9: Create Index Patterns in Kibana

```bash

# Port-forward if not already running

kubectl port-forward -n logging svc/kibana-kibana 5601:5601 &
```

```

**In Kibana UI** (http://localhost:5601):

1. Go to **Management → Stack Management → Index Patterns**
1. Click **Create index pattern**
1. Enter pattern: `kubernetes-*`
1. Click **Next step**
1. Select **@timestamp** as time field
1. Click **Create index pattern**
1. Repeat for `audit-*` index pattern

### Step 10: Explore Logs in Kibana

**In Kibana UI**:

1. Go to **Discover**
1. Select **kubernetes-*** index pattern
1. Set time range to **Last 15 minutes**
1. You should see container logs

**Search Examples**:

```

# Find Falco alerts

kubernetes.namespace_name: "falco" AND log: "priority"

# Find all logs from specific pod

kubernetes.pod_name: "test-pod"

# Find error logs

log: "error" OR log: "Error" OR log: "ERROR"

# Find audit logs (switch to audit-* index)

Select audit-* index pattern
objectRef.resource: "secrets"

```
```

### Step 11: Create Saved Searches

**Create Security Events Search**:

1. In Discover, search: `kubernetes.namespace_name: "falco"`
1. Click **Save** in top right
1. Name: "Falco Security Alerts"
1. Click **Save**

**Create Audit Events Search**:

1. Switch to `audit-*` index
1. Search: `verb: "create" OR verb: "delete"`
1. Save as: "Audit Changes"

### Step 12: Create Visualizations

**Visualization 1: Falco Alerts by Priority**

1. Go to **Visualize → Create visualization**
1. Select **Pie chart**
1. Choose **kubernetes-*** index
1. Add filter: `kubernetes.namespace_name: "falco" AND priority: *`
1. Metrics: Count
1. Buckets: Split slices
   - Aggregation: Terms
   - Field: `priority.keyword`
1. Click **Update**
1. Save as: "Falco Alerts by Priority"

**Visualization 2: API Audit Events Over Time**

1. Create visualization → Line chart
1. Choose **audit-*** index
1. Metrics: Count
1. Buckets: X-axis
   - Aggregation: Date Histogram
   - Field: @timestamp
   - Interval: Auto
1. Save as: "API Activity Timeline"

**Verification**:

- [ ] Can see logs in Kibana
- [ ] Index patterns created
- [ ] Can search and filter logs
- [ ] Visualizations created

## Part 5: Advanced Queries (Optional)

### Step 13: Complex Log Queries

**In Kibana Discover**:

```

# Secret access in audit logs (audit-* index)

objectRef.resource: "secrets" AND verb: "get"

# Failed authentication (audit-* index)

responseStatus.code: >= 400 AND objectRef.resource: "tokenreviews"

# Privileged pod creation (audit-* index)

verb: "create" AND objectRef.resource: "pods" AND requestObject.spec.containers.securityContext.privileged: true

# Critical Falco alerts (kubernetes-* index)

kubernetes.namespace_name: "falco" AND priority: "Critical"

# Pod exec events (audit-* index)

objectRef.subresource: "exec"
```

```

### Step 14: Create Dashboard

1. Go to **Dashboard → Create dashboard**
1. Click **Add** and select your visualizations:

   - Falco Alerts by Priority
   - API Activity Timeline
1. Add search panels:

   - Falco Security Alerts
   - Audit Changes
1. Arrange panels
1. Save dashboard as: "Security Monitoring Dashboard"

**Verification**:

- [ ] Dashboard created
- [ ] Shows real-time data
- [ ] Visualizations update automatically

## Part 6: Log Retention and Cleanup (Optional)

### Step 15: Configure Index Lifecycle Management

**In Kibana UI**:

1. Go to **Management → Stack Management → Index Lifecycle Policies**
1. Click **Create policy**
1. Name: "logs-lifecycle"
1. Configure phases:

   - Hot phase: Rollover after 1 day or 5GB
   - Delete phase: Delete after 30 days
1. Click **Save policy**

1. Apply to index templates:

   - Go to **Index Management → Index Templates**
   - Edit kubernetes and audit templates
   - Add lifecycle policy: "logs-lifecycle"

**Verification**:

- [ ] Lifecycle policy created
- [ ] Applied to indexes
- [ ] Old indexes will be automatically deleted

## Troubleshooting

### Issue 1: Elasticsearch Won't Start

```bash

# Check pod events

kubectl describe pod -n logging -l app=elasticsearch-master

# Common issues:
# - Insufficient memory (increase resources)
# - PVC not bound (check storage class)
# - Insufficient disk space

# Check logs

kubectl logs -n logging -l app=elasticsearch-master
```

```

### Issue 2: No Logs in Kibana

```bash

# Check Fluent Bit is running

kubectl get pods -n logging -l app.kubernetes.io/name=fluent-bit

# Check Fluent Bit logs for errors

kubectl logs -n logging -l app.kubernetes.io/name=fluent-bit

# Verify Elasticsearch has indices

curl http://localhost:9200/_cat/indices?v

# Force log generation

kubectl run test-logs --image=busybox --command -- sh -c "while true; do echo 'Test log'; sleep 5; done"
```

```

### Issue 3: Kibana Can't Connect to Elasticsearch

```bash

# Check Kibana logs

kubectl logs -n logging -l app=kibana

# Verify Elasticsearch service

kubectl get svc -n logging elasticsearch-master

# Check network connectivity

kubectl run test-curl --image=curlimages/curl -it --rm -- curl http://elasticsearch-master.logging:9200
```

```

## Verification Checklist

- [ ] Elasticsearch deployed and accessible
- [ ] Kibana deployed and accessible
- [ ] Fluent Bit collecting logs from all nodes
- [ ] Audit logs shipped to Elasticsearch
- [ ] Falco alerts shipped to Elasticsearch
- [ ] Container logs shipped to Elasticsearch
- [ ] Can query logs in Kibana
- [ ] Index patterns created
- [ ] Visualizations created
- [ ] Dashboard created

## Cleanup

```bash

# Remove test resources

kubectl delete pod test-pod test-logs --ignore-not-found

# Keep logging stack for next lab
# To completely remove:
# helm uninstall fluent-bit elasticsearch kibana -n logging
# kubectl delete namespace logging

```

```

## Challenge Exercises

1. **Custom Parser**: Create Fluent Bit parser for application-specific log format

1. **Alert Integration**: Configure Elasticsearch Watcher to send alerts on critical events

1. **Performance Tuning**: Optimize Fluent Bit buffer settings for high-volume logs

1. **Retention Policy**: Implement tiered storage (hot/warm/cold) for cost optimization

1. **Security**: Enable Elasticsearch security features (TLS, authentication)

## Key Takeaways

- Centralized logging enables comprehensive security monitoring
- Fluent Bit efficiently collects and forwards logs
- Elasticsearch provides powerful search and storage
- Kibana visualizes security data effectively
- Index patterns organize different log types
- Retention policies manage storage costs
- Log aggregation is foundation for security monitoring

## Next Steps

- Proceed to [Lab 5: Security Monitoring Dashboard](lab-05-security-monitoring.md)
- Review [Security Monitoring theory](../../domains/06-monitoring-logging/security-monitoring.md)
- Explore advanced Elasticsearch queries and aggregations

---

**Congratulations!** You've built a complete log aggregation pipeline for security monitoring.
