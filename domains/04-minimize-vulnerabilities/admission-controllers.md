# Admission Controllers

## Overview

Admission controllers are powerful plugins that intercept requests to the Kubernetes API server before objects are persisted, but after the request is authenticated and authorized. They enable you to enforce policies, set defaults, validate configurations, and modify resource requests to improve security and governance in your cluster.

## Table of Contents

1. [Understanding Admission Control](#understanding-admission-control)
1. [Built-in Admission Controllers](#built-in-admission-controllers)
1. [Dynamic Admission Control](#dynamic-admission-control)
1. [OPA Gatekeeper](#opa-gatekeeper)
1. [Kyverno](#kyverno)
1. [Best Practices](#best-practices)
1. [Troubleshooting](#troubleshooting)

## Understanding Admission Control

### Admission Control Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    API Request Flow                          │
└─────────────────────────────────────────────────────────────┘
                            │
                            ↓
                   ┌────────────────┐
                   │ Authentication │
                   └────────────────┘
                            │
                            ↓
                   ┌────────────────┐
                   │ Authorization  │
                   │     (RBAC)     │
                   └────────────────┘
                            │
                            ↓
            ┌───────────────────────────────┐
            │   Mutating Admission Control  │
            │  (Modify request if needed)   │
            └───────────────────────────────┘
                            │
                            ↓
                  ┌──────────────────┐
                  │ Object Schema    │
                  │   Validation     │
                  └──────────────────┘
                            │
                            ↓
            ┌───────────────────────────────┐
            │ Validating Admission Control  │
            │  (Accept or reject request)   │
            └───────────────────────────────┘
                            │
                            ↓
                  ┌──────────────────┐
                  │ Persist to etcd  │
                  └──────────────────┘
```

### Types of Admission Controllers

#### 1. Mutating Admission Controllers

- **Modify** requests before they're persisted
- Run **before** validating admission controllers
- Can set defaults, inject sidecars, add labels, etc.
- Examples: `DefaultStorageClass`, `MutatingAdmissionWebhook`

#### 2. Validating Admission Controllers

- **Accept or reject** requests without modification
- Run **after** mutating admission controllers
- Enforce policies and compliance rules
- Examples: `PodSecurity`, `ValidatingAdmissionWebhook`

### Viewing Enabled Admission Controllers

```bash
# Check currently enabled admission controllers

kubectl exec -n kube-system kube-apiserver-<node-name> -- kube-apiserver -h | grep enable-admission-plugins

# Or check the kube-apiserver manifest

cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep admission-plugins
```

## Built-in Admission Controllers

Kubernetes includes many built-in admission controllers. Here are the most important ones for security:

### 1. PodSecurity (Replaces PodSecurityPolicy)

Enforces Pod Security Standards at the namespace level.

**Enabling PodSecurity:**

```yaml
# In kube-apiserver.yaml

- --enable-admission-plugins=NodeRestriction,PodSecurity
```

**Using PodSecurity:**

```bash
# Apply enforce level

kubectl label namespace default pod-security.kubernetes.io/enforce=baseline

# Apply warn level (warns but allows)

kubectl label namespace default pod-security.kubernetes.io/warn=restricted

# Apply audit level (logs violations)

kubectl label namespace default pod-security.kubernetes.io/audit=restricted
```

**Three Security Levels:**

- **Privileged**: Unrestricted, allows all workloads
- **Baseline**: Minimally restrictive, prevents known privilege escalations
- **Restricted**: Heavily restricted, follows hardening best practices

### 2. NodeRestriction

Limits the Node and Pod objects a kubelet can modify.

**What it prevents:**

- Kubelets modifying labels on their own Node objects
- Kubelets accessing Secrets/ConfigMaps not mounted to their pods
- Kubelets modifying pods not bound to their node

**Enabling:**

```yaml
# In kube-apiserver.yaml

- --enable-admission-plugins=NodeRestriction
```

### 3. ResourceQuota

Enforces resource consumption limits per namespace.

**Example ResourceQuota:**

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-resources
  namespace: development
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    persistentvolumeclaims: "10"
    pods: "20"
```

### 4. LimitRanger

Sets default resource limits and enforces limit constraints.

**Example LimitRange:**

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: resource-limits
  namespace: development
spec:
  limits:
  - max:
      cpu: "2"
      memory: 4Gi
    min:
      cpu: 100m
      memory: 128Mi
    default:
      cpu: 500m
      memory: 512Mi
    defaultRequest:
      cpu: 200m
      memory: 256Mi
    type: Container
  - max:
      storage: 10Gi
    min:
      storage: 1Gi
    type: PersistentVolumeClaim
```

### 5. ServiceAccount

Automatically injects ServiceAccount tokens into pods.

**Enabling:**

```yaml
# Usually enabled by default

- --enable-admission-plugins=ServiceAccount
```

**Example:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  serviceAccountName: my-service-account  # Explicitly set
  automountServiceAccountToken: false     # Disable auto-mount if not needed
  containers:
  - name: myapp
    image: nginx:1.27
```

### 6. NamespaceLifecycle

Prevents creation of objects in terminating or non-existent namespaces.

**Enabling:**

```yaml
# Usually enabled by default

- --enable-admission-plugins=NamespaceLifecycle
```

### 7. DefaultStorageClass

Assigns default StorageClass to PVCs without one specified.

### 8. DenyEscalatingExec

Denies `exec` and `attach` commands to pods with privileged containers or host access.

**Enabling:**

```yaml
- --enable-admission-plugins=DenyEscalatingExec
```

### Recommended Admission Controllers for Security

```yaml
# In /etc/kubernetes/manifests/kube-apiserver.yaml

- --enable-admission-plugins=NodeRestriction,PodSecurity,ResourceQuota,LimitRanger,ServiceAccount,NamespaceLifecycle,MutatingAdmissionWebhook,ValidatingAdmissionWebhook
```

## Dynamic Admission Control

Dynamic admission control uses webhooks to extend Kubernetes with custom logic without recompiling the API server.

### ValidatingWebhookConfiguration

Validates requests and accepts or rejects them.

**Example ValidatingWebhookConfiguration:**

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: pod-policy-webhook
webhooks:
- name: pod-policy.example.com
  clientConfig:
    service:
      name: webhook-service
      namespace: webhook-system
      path: "/validate"
    caBundle: <BASE64_ENCODED_CA_CERT>
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  admissionReviewVersions: ["v1"]
  sideEffects: None
  timeoutSeconds: 5
  failurePolicy: Fail  # Reject if webhook fails
  namespaceSelector:
    matchLabels:
      policy: enforced
```

**Webhook Server Response:**

```json
{
  "apiVersion": "admission.k8s.io/v1",
  "kind": "AdmissionReview",
  "response": {
    "uid": "<value from request>",
    "allowed": false,
    "status": {
      "code": 403,
      "message": "Container must not run as root"
    }
  }
}
```

### MutatingWebhookConfiguration

Modifies requests before they're validated and persisted.

**Example MutatingWebhookConfiguration:**

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: sidecar-injector
webhooks:
- name: sidecar-injector.example.com
  clientConfig:
    service:
      name: sidecar-injector
      namespace: webhook-system
      path: "/mutate"
    caBundle: <BASE64_ENCODED_CA_CERT>
  rules:
  - operations: ["CREATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  admissionReviewVersions: ["v1"]
  sideEffects: None
  timeoutSeconds: 5
  failurePolicy: Ignore  # Allow if webhook fails
  namespaceSelector:
    matchLabels:
      sidecar-injection: enabled
```

**Webhook Server Response (with JSON Patch):**

```json
{
  "apiVersion": "admission.k8s.io/v1",
  "kind": "AdmissionReview",
  "response": {
    "uid": "<value from request>",
    "allowed": true,
    "patchType": "JSONPatch",
    "patch": "W3sib3AiOiAiYWRkIiwgInBhdGgiOiAiL3NwZWMvY29udGFpbmVycy8tIiwgInZhbHVlIjogeyJuYW1lIjogInNpZGVjYXIiLCAiaW1hZ2UiOiAic2lkZWNhcjoxLjAifX1d"
  }
}
```

### Creating a Simple Webhook

#### 1. Webhook Server (Python Example)

```python
from flask import Flask, request, jsonify
import base64
import json

app = Flask(__name__)

@app.route('/validate', methods=['POST'])
def validate():
    admission_review = request.get_json()

    # Extract pod object

    pod = admission_review['request']['object']

    # Validation logic

    allowed = True
    message = "Pod is compliant"

    # Check if container runs as root

    for container in pod['spec'].get('containers', []):
        security_context = container.get('securityContext', {})
        if security_context.get('runAsUser') == 0:
            allowed = False
            message = f"Container {container['name']} must not run as root"
            break

    # Return response

    return jsonify({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": admission_review['request']['uid'],
            "allowed": allowed,
            "status": {
                "message": message
            }
        }
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8443, ssl_context='adhoc')
```

#### 2. Deploy Webhook Server

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webhook-server
  namespace: webhook-system
spec:
  replicas: 2
  selector:
    matchLabels:
      app: webhook-server
  template:
    metadata:
      labels:
        app: webhook-server
    spec:
      containers:
      - name: webhook
        image: webhook-server:1.0
        ports:
        - containerPort: 8443
        volumeMounts:
        - name: webhook-certs
          mountPath: /etc/webhook/certs
          readOnly: true
      volumes:
      - name: webhook-certs
        secret:
          secretName: webhook-certs

---
apiVersion: v1
kind: Service
metadata:
  name: webhook-service
  namespace: webhook-system
spec:
  selector:
    app: webhook-server
  ports:
  - port: 443
    targetPort: 8443
```

#### 3. Generate TLS Certificates

```bash
# Generate CA key and cert

openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -subj "/CN=webhook-ca" -days 10000 -out ca.crt

# Generate webhook server key

openssl genrsa -out webhook-server.key 2048

# Create CSR

cat > webhook-server.conf <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = webhook-service
DNS.2 = webhook-service.webhook-system
DNS.3 = webhook-service.webhook-system.svc
DNS.4 = webhook-service.webhook-system.svc.cluster.local
EOF

openssl req -new -key webhook-server.key -subj "/CN=webhook-service.webhook-system.svc" -out webhook-server.csr -config webhook-server.conf

# Sign certificate

openssl x509 -req -in webhook-server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out webhook-server.crt -days 10000 -extensions v3_req -extfile webhook-server.conf

# Create Kubernetes secret

kubectl create secret tls webhook-certs \
  --cert=webhook-server.crt \
  --key=webhook-server.key \
  -n webhook-system

# Get CA bundle for webhook configuration

cat ca.crt | base64 | tr -d '\n'
```

## OPA Gatekeeper

Open Policy Agent (OPA) Gatekeeper is a popular admission controller that uses the Rego policy language.

### Installation

```bash
# Install Gatekeeper

kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml

# Verify installation

kubectl get pods -n gatekeeper-system
kubectl get crd | grep gatekeeper
```

### Key Concepts

#### 1. ConstraintTemplate

Defines the schema and logic for a policy.

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
      validation:
        openAPIV3Schema:
          type: object
          properties:
            labels:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels

        violation[{"msg": msg, "details": {"missing_labels": missing}}] {
          provided := {label | input.review.object.metadata.labels[label]}
          required := {label | label := input.parameters.labels[_]}
          missing := required - provided
          count(missing) > 0
          msg := sprintf("You must provide labels: %v", [missing])
        }
```

#### 2. Constraint

Instantiates a ConstraintTemplate with specific parameters.

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: ns-must-have-owner
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Namespace"]
  parameters:
    labels: ["owner", "environment"]
```

### Common Gatekeeper Policies

#### Policy 1: Deny Privileged Containers

**ConstraintTemplate:**

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spspprivilegedcontainer
spec:
  crd:
    spec:
      names:
        kind: K8sPSPPrivilegedContainer
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8spspprivilegedcontainer

        violation[{"msg": msg}] {
          c := input.review.object.spec.containers[_]
          c.securityContext.privileged
          msg := sprintf("Privileged container is not allowed: %v", [c.name])
        }

        violation[{"msg": msg}] {
          c := input.review.object.spec.initContainers[_]
          c.securityContext.privileged
          msg := sprintf("Privileged init container is not allowed: %v", [c.name])
        }
```

**Constraint:**

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPPrivilegedContainer
metadata:
  name: deny-privileged-containers
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaceSelector:
      matchLabels:
        policy: restricted
```

#### Policy 2: Require Resource Limits

**ConstraintTemplate:**

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredresources
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredResources
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredresources

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not container.resources.limits.cpu
          msg := sprintf("Container %v must have CPU limit", [container.name])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not container.resources.limits.memory
          msg := sprintf("Container %v must have memory limit", [container.name])
        }
```

**Constraint:**

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredResources
metadata:
  name: require-resource-limits
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
```

#### Policy 3: Allowed Container Registries

**ConstraintTemplate:**

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sallowedrepos
spec:
  crd:
    spec:
      names:
        kind: K8sAllowedRepos
      validation:
        openAPIV3Schema:
          type: object
          properties:
            repos:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sallowedrepos

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not strings.any_prefix_match(container.image, input.parameters.repos)
          msg := sprintf("Container %v uses disallowed registry: %v", [container.name, container.image])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.initContainers[_]
          not strings.any_prefix_match(container.image, input.parameters.repos)
          msg := sprintf("Init container %v uses disallowed registry: %v", [container.name, container.image])
        }
```

**Constraint:**

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAllowedRepos
metadata:
  name: allowed-registries
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    repos:
      - "docker.io/library/"
      - "gcr.io/mycompany/"
      - "registry.mycompany.com/"
```

### Testing Gatekeeper Policies

```bash
# Test with compliant pod

kubectl run test-compliant \
  --image=nginx:1.27 \
  --dry-run=server

# Test with non-compliant pod

kubectl run test-noncompliant \
  --image=nginx:1.27 \
  --overrides='{"spec":{"containers":[{"name":"nginx","image":"nginx:1.27","securityContext":{"privileged":true}}]}}' \
  --dry-run=server
```

### Audit Mode

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPPrivilegedContainer
metadata:
  name: deny-privileged-containers
spec:
  enforcementAction: dryrun  # Log violations but don't block
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
```

View audit results:

```bash
kubectl get constraints
kubectl describe k8spspprivilegedcontainer deny-privileged-containers
```

## Kyverno

Kyverno is a Kubernetes-native policy engine that uses YAML instead of a new language.

### Installation

```bash
# Install Kyverno

kubectl create -f https://github.com/kyverno/kyverno/releases/download/v1.11.0/install.yaml

# Verify installation

kubectl get pods -n kyverno
```

### Kyverno Policy Structure

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-labels
spec:
  validationFailureAction: Enforce  # or Audit
  background: true
  rules:
  - name: check-for-labels
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "Label 'app' is required"
      pattern:
        metadata:
          labels:
            app: "?*"
```

### Common Kyverno Policies

#### Policy 1: Add Default Network Policy

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: add-default-network-policy
spec:
  background: false
  rules:
  - name: default-deny-ingress
    match:
      any:
      - resources:
          kinds:
          - Namespace
    generate:
      kind: NetworkPolicy
      name: default-deny-ingress
      namespace: "{{request.object.metadata.name}}"
      synchronize: true
      data:
        spec:
          podSelector: {}
          policyTypes:
          - Ingress
```

#### Policy 2: Require Non-Root Containers

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-run-as-non-root
spec:
  validationFailureAction: Enforce
  background: true
  rules:
  - name: check-containers
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "Containers must run as non-root user"
      pattern:
        spec:
          containers:
          - securityContext:
              runAsNonRoot: true
```

#### Policy 3: Mutate - Add Security Context

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: add-security-context
spec:
  background: false
  rules:
  - name: add-runasnonroot
    match:
      any:
      - resources:
          kinds:
          - Pod
    mutate:
      patchStrategicMerge:
        spec:
          securityContext:
            runAsNonRoot: true
          containers:
          - (name): "*"
            securityContext:
              allowPrivilegeEscalation: false
              capabilities:
                drop:
                - ALL
```

## Best Practices

### 1. Start with Audit Mode

Test policies in audit/dryrun mode before enforcing.

```yaml
# Gatekeeper

spec:
  enforcementAction: dryrun

# Kyverno

spec:
  validationFailureAction: Audit
```

### 2. Use Namespace Selectors

Apply policies selectively to avoid disrupting system namespaces.

```yaml
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaceSelector:
      matchExpressions:
      - key: policy-enforcement
        operator: In
        values: ["enabled"]
```

### 3. Set Appropriate Timeouts

```yaml
webhooks:
- name: my-webhook
  timeoutSeconds: 10  # Don't set too high
  failurePolicy: Ignore  # or Fail, depending on criticality
```

### 4. Monitor Webhook Performance

```bash
# Check webhook latency

kubectl get validatingwebhookconfigurations -o yaml | grep -A 5 metrics

# View admission webhook metrics

kubectl top pods -n gatekeeper-system
kubectl top pods -n kyverno
```

### 5. Implement Progressive Rollout

1. Deploy policy in audit mode
1. Monitor violations for 1-2 weeks
1. Fix existing violations
1. Switch to enforce mode
1. Monitor for unexpected impacts

### 6. Document Policies

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPPrivilegedContainer
metadata:
  name: deny-privileged-containers
  annotations:
    description: "Prevents creation of privileged containers"
    severity: "high"
    owner: "security-team@example.com"
    documentation: "https://wiki.example.com/k8s-security-policies"
```

### 7. Version Control Policies

Store all policies in Git and use GitOps for deployment.

### 8. Test Policies Before Deployment

```bash
# Gatekeeper: Use gator CLI

gator test -f constraints/ -f templates/

# Kyverno: Use kyverno CLI

kyverno apply policy.yaml --resource deployment.yaml
```

## Troubleshooting

### Webhook Not Called

```bash
# Check webhook configuration

kubectl get validatingwebhookconfigurations
kubectl describe validatingwebhookconfiguration my-webhook

# Check if webhook service is reachable

kubectl run test --image=curlimages/curl --rm -it -- curl -k https://webhook-service.webhook-system.svc:443/validate

# Check API server logs

kubectl logs -n kube-system kube-apiserver-<node> | grep webhook
```

### Certificate Issues

```bash
# Verify certificate

openssl x509 -in webhook-server.crt -text -noout

# Check SAN

openssl x509 -in webhook-server.crt -text | grep DNS

# Test TLS connection

openssl s_client -connect webhook-service.webhook-system.svc:443 -CAfile ca.crt
```

### Policy Not Enforcing

```bash
# Gatekeeper: Check constraint status

kubectl get constraints
kubectl describe k8spspprivilegedcontainer deny-privileged-containers

# Check Gatekeeper logs

kubectl logs -n gatekeeper-system -l control-plane=controller-manager

# Kyverno: Check policy status

kubectl get clusterpolicies
kubectl describe clusterpolicy require-labels

# Check Kyverno logs

kubectl logs -n kyverno -l app.kubernetes.io/name=kyverno
```

### Debugging Admission Denials

```bash
# Create resource with verbose output

kubectl create -f pod.yaml -v=8

# Check events

kubectl get events --sort-by='.lastTimestamp' | grep admission

# Review audit logs (if enabled)
# On control plane node:

sudo cat /var/log/kubernetes/audit/audit.log | grep admission
```

### Performance Issues

```bash
# Check webhook response times

kubectl get --raw /metrics | grep apiserver_admission_webhook_admission_duration_seconds

# Check webhook failures

kubectl get --raw /metrics | grep apiserver_admission_webhook_rejection_count
```

## Summary

Admission controllers are essential for enforcing security policies in Kubernetes:

1. **Built-in Controllers**: Use `PodSecurity`, `NodeRestriction`, `ResourceQuota`
1. **Dynamic Admission**: Implement custom logic with webhooks
1. **Policy Engines**: Use OPA Gatekeeper or Kyverno for declarative policies
1. **Testing**: Always test in audit mode first
1. **Monitoring**: Track webhook performance and policy violations
1. **Documentation**: Document policies and their rationale

**Key Takeaways:**

- Admission controllers provide preventive security controls
- Mutating controllers modify requests; validating controllers accept/reject
- Start with audit mode, then enforce
- Use namespace selectors to scope policies
- Monitor webhook performance and set appropriate timeouts
- Combine multiple admission controllers for defense in depth

## Additional Resources

- [Kubernetes Admission Controllers](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
- [Dynamic Admission Control](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
- [OPA Gatekeeper Documentation](https://open-policy-agent.github.io/gatekeeper/)
- [Kyverno Documentation](https://kyverno.io/docs/)
- [Rego Playground](https://play.openpolicyagent.org/)

---

[Back to Domain 4 README](./README.md) | [Previous: Secrets Management ←](./secrets-management.md) | [Next: Runtime Security Tools →](./runtime-security-tools.md)
