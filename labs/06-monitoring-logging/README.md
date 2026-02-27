# Lab Exercises: Domain 6 - Monitoring, Logging, and Runtime Security

## Overview

These hands-on labs provide practical experience with Kubernetes monitoring, logging, and runtime security. You'll configure audit logging, deploy Falco for runtime detection, create custom rules, and build a complete security monitoring solution.

**Prerequisites**:

- Completed Domain 1-5 labs
- Running Kubernetes cluster (v1.30.x)
- kubectl configured and working
- Basic understanding of YAML and JSON
- Familiarity with command-line tools

**Lab Environment**:

- Kubernetes v1.30.x
- Falco v0.37.x
- Elasticsearch/Kibana (ELK stack)
- Prometheus & Grafana
- Fluentd or Fluent Bit

## Lab Structure

Each lab includes:

- **Objectives**: What you'll learn
- **Prerequisites**: Required setup
- **Duration**: Estimated time
- **Instructions**: Step-by-step guidance
- **Verification**: How to confirm success
- **Troubleshooting**: Common issues and solutions
- **Cleanup**: Resource removal
- **Challenge**: Optional advanced exercises

## Labs

### Lab 1: Audit Logging Configuration (60 minutes)

**Focus**: Configure and analyze Kubernetes audit logging

Learn how to:

- Enable audit logging on the API server
- Write audit policies for different scenarios
- Analyze audit logs to find security events
- Query logs efficiently with jq

**Key Skills**:

- Audit policy configuration
- API server configuration
- Log analysis
- Security event identification

[Start Lab 1](lab-01-audit-logging.md)

---

### Lab 2: Falco Deployment (45 minutes)

**Focus**: Deploy and configure Falco for runtime security

Learn how to:

- Install Falco using Helm
- Verify Falco is capturing events
- Understand default Falco rules
- View and interpret Falco alerts

**Key Skills**:

- Falco installation
- Driver configuration
- Output verification
- Alert interpretation

[Start Lab 2](lab-02-falco-deployment.md)

---

### Lab 3: Custom Falco Rules (75 minutes)

**Focus**: Create and tune custom Falco detection rules

Learn how to:

- Write custom Falco rules
- Use macros and lists
- Test rule triggers
- Tune rules to reduce false positives
- Implement rule priorities

**Key Skills**:

- Falco rule syntax
- Custom rule creation
- Rule testing
- False positive reduction

[Start Lab 3](lab-03-falco-rules.md)

---

### Lab 4: Log Aggregation (90 minutes)

**Focus**: Deploy centralized log collection and storage

Learn how to:

- Deploy Elasticsearch for log storage
- Configure Fluentd/Fluent Bit for log collection
- Ship audit logs and Falco alerts to Elasticsearch
- Query aggregated logs with Kibana

**Key Skills**:

- Log aggregation architecture
- Fluentd/Fluent Bit configuration
- Elasticsearch deployment
- Log querying and search

[Start Lab 4](lab-04-log-aggregation.md)

---

### Lab 5: Security Monitoring Dashboard (90 minutes)

**Focus**: Build comprehensive security monitoring solution

Learn how to:

- Deploy Prometheus for metrics collection
- Create security-focused Grafana dashboards
- Configure security alert rules
- Correlate events from multiple sources
- Simulate and detect attacks

**Key Skills**:

- Metrics collection
- Dashboard creation
- Alert configuration
- Event correlation
- Attack simulation

[Start Lab 5](lab-05-security-monitoring.md)

---

## Lab Progression

Follow labs in order for best learning experience:

```
Lab 1: Audit Logging
    ↓
    Configure API audit logging
    Analyze security events
    ↓
Lab 2: Falco Deployment
    ↓
    Install runtime security
    Understand default detection
    ↓
Lab 3: Custom Falco Rules
    ↓
    Create custom detections
    Tune for accuracy
    ↓
Lab 4: Log Aggregation
    ↓
    Centralize all logs
    Enable search and analysis
    ↓
Lab 5: Security Monitoring
    ↓
    Complete monitoring solution
    Dashboards and alerts
```

## Environment Setup

### Quick Setup Script

```bash
#!/bin/bash
# setup-monitoring-labs.sh

echo "Setting up monitoring labs environment..."

# Create namespaces

kubectl create namespace logging
kubectl create namespace monitoring
kubectl create namespace falco

# Add Helm repositories

helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo add elastic https://helm.elastic.co
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

# Label nodes (if needed for specific labs)

kubectl label nodes --all monitoring=enabled

echo "Environment ready for labs!"
```

### Verify Setup

```bash
# Check Kubernetes version

kubectl version --short

# Check cluster nodes

kubectl get nodes

# Verify namespaces

kubectl get namespaces

# Check available storage classes

kubectl get storageclass
```

## Common Tools and Commands

### Essential Commands

```bash
# Kubernetes basics

kubectl get pods -A
kubectl logs <pod> -n <namespace>
kubectl describe pod <pod> -n <namespace>
kubectl exec -it <pod> -n <namespace> -- /bin/bash

# Helm operations

helm list -A
helm install <release> <chart> -n <namespace>
helm upgrade <release> <chart> -n <namespace>
helm uninstall <release> -n <namespace>

# Log analysis

kubectl logs <pod> -n <namespace> | grep "ERROR"
kubectl logs <pod> -n <namespace> --since=1h
kubectl logs <pod> -n <namespace> --tail=100

# Audit log analysis (if file-based)

sudo cat /var/log/kubernetes/audit.log | jq
cat audit.log | jq 'select(.objectRef.resource=="secrets")'

# Falco commands

kubectl logs -n falco -l app.kubernetes.io/name=falco -f
kubectl exec -n falco <falco-pod> -- falco --list
```

### Helpful Aliases

```bash
# Add to ~/.bashrc or ~/.zshrc

alias k='kubectl'
alias kgp='kubectl get pods'
alias kgpa='kubectl get pods -A'
alias kdp='kubectl describe pod'
alias klf='kubectl logs -f'
alias kaf='kubectl apply -f'
alias kdf='kubectl delete -f'

# Monitoring specific

alias kgf='kubectl get pods -n falco'
alias klf-falco='kubectl logs -n falco -l app.kubernetes.io/name=falco -f'
alias kgl='kubectl get pods -n logging'
alias kgm='kubectl get pods -n monitoring'
```

## Lab Completion Checklist

After completing all labs, you should be able to:

- [ ] Configure Kubernetes audit logging with custom policies
- [ ] Analyze audit logs to identify security events
- [ ] Install and configure Falco for runtime security
- [ ] Understand and interpret default Falco rules
- [ ] Create custom Falco rules for specific threats
- [ ] Tune rules to reduce false positives
- [ ] Deploy log aggregation infrastructure
- [ ] Configure log collection and shipping
- [ ] Query aggregated logs effectively
- [ ] Deploy Prometheus for metrics collection
- [ ] Create security monitoring dashboards
- [ ] Configure security alert rules
- [ ] Correlate events from multiple sources
- [ ] Respond to security alerts
- [ ] Perform incident investigation

## Tips for Success

### General Tips

1. **Read carefully**: Each lab builds on previous knowledge
1. **Verify each step**: Don't skip verification steps
1. **Take notes**: Document what you learn
1. **Experiment**: Try variations beyond the instructions
1. **Understand, don't memorize**: Focus on concepts
1. **Clean up**: Remove resources after each lab

### Troubleshooting Tips

1. **Check pod status first**: `kubectl get pods -A`
1. **Read logs**: `kubectl logs <pod> -n <namespace>`
1. **Describe resources**: `kubectl describe <resource> <name>`
1. **Verify configurations**: Check ConfigMaps and Secrets
1. **Check documentation**: Reference official docs
1. **Start fresh**: Delete and redeploy if stuck

### Time Management

- **Lab 1**: Budget 60 minutes, can be done faster with experience
- **Lab 2**: 45 minutes, mostly waiting for deployments
- **Lab 3**: 75 minutes, includes testing and tuning
- **Lab 4**: 90 minutes, most complex deployment
- **Lab 5**: 90 minutes, integrates everything

**Total time**: ~5.5 hours (spread across multiple sessions)

## Additional Resources

### Official Documentation

- [Kubernetes Auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Falco Documentation](https://falco.org/docs/)
- [Prometheus Documentation](https://prometheus.io/docs/)
- [Elasticsearch Documentation](https://www.elastic.co/guide/)

### Tools Documentation

- [kubectl Cheat Sheet](https://kubernetes.io/docs/reference/kubectl/cheatsheet/)
- [Helm Documentation](https://helm.sh/docs/)
- [jq Manual](https://stedolan.github.io/jq/manual/)

### Practice Environments

- [Killercoda Scenarios](https://killercoda.com/)
- [Falco Playground](https://play.falco.org/)
- [Falco Getting Started](https://falco.org/docs/getting-started/)

## Getting Help

### During Labs

1. **Check troubleshooting sections**: Each lab has common issues
1. **Review theory**: Refer back to domain content
1. **Search logs**: Error messages usually indicate the issue
1. **Verify prerequisites**: Ensure previous steps completed
1. **Start fresh**: Sometimes easier than debugging

### External Resources

- Kubernetes Slack: #kubernetes-users
- Falco Slack: #falco
- CNCF Community Forums
- Stack Overflow (tag: kubernetes, falco)

## Lab Environment Cleanup

After completing all labs:

```bash
# Delete lab namespaces

kubectl delete namespace logging
kubectl delete namespace monitoring
kubectl delete namespace falco

# Uninstall Helm releases (if any remain)

helm uninstall falco -n falco
helm uninstall elasticsearch -n logging
helm uninstall prometheus -n monitoring
helm uninstall grafana -n monitoring

# Remove labels

kubectl label nodes --all monitoring-

# Clean up local files

rm -rf ~/k8s-security-labs/

echo "Cleanup complete!"
```

## Next Steps

After completing these labs:

1. **Review all domain material**: Reinforce theory with practice
1. **Practice exam scenarios**: Use practice tests
1. **Build a project**: Create end-to-end security monitoring
1. **Explore advanced topics**: Service mesh, policy engines
1. **Prepare for KCSA exam**: Focus on weak areas

---

**Ready to begin?** Start with [Lab 1: Audit Logging Configuration](lab-01-audit-logging.md)

**Questions or issues?** Refer to the troubleshooting sections in each lab or review the domain theory content.
