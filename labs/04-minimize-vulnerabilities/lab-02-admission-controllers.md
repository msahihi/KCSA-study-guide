# Lab 02 - Admission Controllers

## Objective

Learn how to create and deploy custom admission controllers using ValidatingWebhookConfiguration and MutatingWebhookConfiguration to enforce security policies at the Kubernetes API server level.

## Duration

60 minutes

## Prerequisites

- Kubernetes cluster v1.30.x
- kubectl configured with admin privileges
- Basic understanding of webhooks and TLS certificates
- Python 3.x or Go installed (for webhook server)
- openssl command-line tool

## Lab Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Kubernetes API Server                     │
│                                                              │
│  User/CI → API Request                                       │
│                ↓                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │        Mutating Admission (runs first)                │  │
│  │  - Adds labels                                        │  │
│  │  - Injects sidecars                                   │  │
│  │  - Sets defaults                                      │  │
│  └──────────────────────────────────────────────────────┘  │
│                ↓                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │        Validating Admission (runs second)             │  │
│  │  - Checks security contexts                           │  │
│  │  - Validates resource limits                          │  │
│  │  - Enforces policies                                  │  │
│  └──────────────────────────────────────────────────────┘  │
│                ↓                                             │
│         Accept or Reject                                     │
└─────────────────────────────────────────────────────────────┘
```

## Step 1: Initial Setup

### 1.1 Create Namespace

```bash
kubectl create namespace webhook-system
kubectl create namespace lab-admission

# Label namespace for policy enforcement
kubectl label namespace lab-admission policy=enforced
```

### 1.2 Verify Webhook Support

```bash
# Check if MutatingWebhookConfiguration is available
kubectl api-resources | grep MutatingWebhookConfiguration

# Check if ValidatingWebhookConfiguration is available
kubectl api-resources | grep ValidatingWebhookConfiguration
```

## Step 2: Generate TLS Certificates

Webhooks require TLS for secure communication with the API server.

### 2.1 Generate CA Certificate

```bash
# Create directory for certificates
mkdir -p webhook-certs
cd webhook-certs

# Generate CA private key
openssl genrsa -out ca.key 2048

# Generate CA certificate
openssl req -x509 -new -nodes -key ca.key \
  -subj "/CN=webhook-ca" \
  -days 3650 \
  -out ca.crt
```

### 2.2 Generate Webhook Server Certificate

```bash
# Generate webhook server private key
openssl genrsa -out webhook-server.key 2048

# Create CSR configuration
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

# Generate CSR
openssl req -new -key webhook-server.key \
  -subj "/CN=webhook-service.webhook-system.svc" \
  -out webhook-server.csr \
  -config webhook-server.conf

# Sign the certificate
openssl x509 -req -in webhook-server.csr \
  -CA ca.crt -CAkey ca.key \
  -CAcreateserial \
  -out webhook-server.crt \
  -days 3650 \
  -extensions v3_req \
  -extfile webhook-server.conf

# Verify certificate
openssl x509 -in webhook-server.crt -text -noout | grep -A 1 "Subject Alternative Name"
```

### 2.3 Create Kubernetes Secret

```bash
# Create secret with TLS certificates
kubectl create secret tls webhook-server-certs \
  --cert=webhook-server.crt \
  --key=webhook-server.key \
  -n webhook-system

# Verify secret
kubectl get secret webhook-server-certs -n webhook-system
```

### 2.4 Get CA Bundle for Webhook Configuration

```bash
# Get base64-encoded CA certificate
export CA_BUNDLE=$(cat ca.crt | base64 | tr -d '\n')
echo $CA_BUNDLE

# Save for later use
echo $CA_BUNDLE > ca-bundle.txt
```

## Step 3: Create Validating Webhook Server

### 3.1 Create Webhook Server (Python)

Create a file `webhook-server.py`:

```python
#!/usr/bin/env python3

from flask import Flask, request, jsonify
import logging
import sys

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

@app.route('/validate-pods', methods=['POST'])
def validate_pod():
    """
    Validating webhook for pods
    Checks:
    1. Containers must not run as root
    2. Containers must have resource limits
    3. Containers must not be privileged
    """
    admission_review = request.get_json()

    # Extract the pod object
    uid = admission_review['request']['uid']
    pod = admission_review['request']['object']

    logger.info(f"Validating pod: {pod['metadata'].get('name', 'unknown')}")

    # Validation logic
    allowed = True
    message = "Pod is compliant with security policies"

    # Check containers
    for container in pod['spec'].get('containers', []):
        container_name = container['name']

        # Check 1: Not running as root
        security_context = container.get('securityContext', {})
        if security_context.get('runAsUser') == 0:
            allowed = False
            message = f"Container '{container_name}' must not run as root (runAsUser: 0)"
            break

        if not security_context.get('runAsNonRoot', False):
            # If runAsNonRoot is not set, warn but allow
            logger.warning(f"Container '{container_name}' should set runAsNonRoot: true")

        # Check 2: Must have resource limits
        resources = container.get('resources', {})
        limits = resources.get('limits', {})

        if not limits.get('cpu') or not limits.get('memory'):
            allowed = False
            message = f"Container '{container_name}' must have CPU and memory limits"
            break

        # Check 3: Must not be privileged
        if security_context.get('privileged', False):
            allowed = False
            message = f"Container '{container_name}' must not be privileged"
            break

    # Build admission response
    admission_response = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": uid,
            "allowed": allowed,
            "status": {
                "message": message
            }
        }
    }

    logger.info(f"Response: allowed={allowed}, message={message}")
    return jsonify(admission_response)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy"}), 200

if __name__ == '__main__':
    # Run with TLS
    app.run(
        host='0.0.0.0',
        port=8443,
        ssl_context=('/certs/tls.crt', '/certs/tls.key')
    )
```

### 3.2 Create Dockerfile

Create `Dockerfile`:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir flask==3.0.0

# Copy webhook server
COPY webhook-server.py /app/

# Run as non-root
RUN useradd -m -u 1000 webhook && \
    chown -R webhook:webhook /app
USER webhook

EXPOSE 8443

CMD ["python", "webhook-server.py"]
```

### 3.3 Build and Push Image

```bash
# Build image
docker build -t webhook-server:1.0 .

# For Kind cluster, load image
kind load docker-image webhook-server:1.0 --name kcsa-lab

# For other clusters, push to your registry
# docker tag webhook-server:1.0 your-registry/webhook-server:1.0
# docker push your-registry/webhook-server:1.0
```

## Step 4: Deploy Webhook Server

### 4.1 Create Deployment

Create `webhook-deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webhook-server
  namespace: webhook-system
  labels:
    app: webhook-server
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
        imagePullPolicy: IfNotPresent
        ports:
        - containerPort: 8443
          name: webhook
        volumeMounts:
        - name: webhook-certs
          mountPath: /certs
          readOnly: true
        resources:
          limits:
            cpu: 200m
            memory: 256Mi
          requests:
            cpu: 100m
            memory: 128Mi
        livenessProbe:
          httpGet:
            path: /health
            port: 8443
            scheme: HTTPS
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8443
            scheme: HTTPS
          initialDelaySeconds: 5
          periodSeconds: 5
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          runAsUser: 1000
          capabilities:
            drop:
            - ALL
      volumes:
      - name: webhook-certs
        secret:
          secretName: webhook-server-certs
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
    protocol: TCP
    name: webhook
  type: ClusterIP
```

### 4.2 Deploy

```bash
cd ..  # Back to main directory
kubectl apply -f webhook-deployment.yaml

# Wait for pods to be ready
kubectl wait --for=condition=ready pod -l app=webhook-server -n webhook-system --timeout=60s

# Verify deployment
kubectl get pods -n webhook-system
kubectl get svc -n webhook-system

# Check logs
kubectl logs -n webhook-system -l app=webhook-server --tail=20
```

### 4.3 Test Webhook Service

```bash
# Test from within cluster
kubectl run test-curl --image=curlimages/curl --rm -it --restart=Never -- \
  curl -k https://webhook-service.webhook-system.svc:443/health

# Should return: {"status": "healthy"}
```

## Step 5: Create ValidatingWebhookConfiguration

### 5.1 Create Webhook Configuration

Create `validating-webhook.yaml`:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: pod-security-webhook
webhooks:
- name: validate-pods.webhook-system.svc
  admissionReviewVersions: ["v1"]
  sideEffects: None
  timeoutSeconds: 10
  failurePolicy: Fail
  clientConfig:
    service:
      name: webhook-service
      namespace: webhook-system
      path: "/validate-pods"
      port: 443
    caBundle: CA_BUNDLE_PLACEHOLDER
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
    scope: "Namespaced"
  namespaceSelector:
    matchLabels:
      policy: enforced
```

### 5.2 Replace CA Bundle and Apply

```bash
# Read CA bundle from file
CA_BUNDLE=$(cat webhook-certs/ca-bundle.txt)

# Replace placeholder with actual CA bundle
sed "s/CA_BUNDLE_PLACEHOLDER/${CA_BUNDLE}/" validating-webhook.yaml | kubectl apply -f -

# Verify webhook configuration
kubectl get validatingwebhookconfigurations
kubectl describe validatingwebhookconfiguration pod-security-webhook
```

## Step 6: Test Validating Webhook

### 6.1 Test Non-Compliant Pod (Should Fail)

```bash
# Create pod without resource limits
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-no-limits
  namespace: lab-admission
spec:
  containers:
  - name: nginx
    image: nginx:1.27
EOF

# Expected output:
# Error from server: admission webhook "validate-pods.webhook-system.svc" denied the request:
# Container 'nginx' must have CPU and memory limits
```

### 6.2 Test Privileged Pod (Should Fail)

```bash
# Create privileged pod
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-privileged
  namespace: lab-admission
spec:
  containers:
  - name: nginx
    image: nginx:1.27
    securityContext:
      privileged: true
    resources:
      limits:
        cpu: 200m
        memory: 256Mi
EOF

# Expected output:
# Error from server: admission webhook denied the request:
# Container 'nginx' must not be privileged
```

### 6.3 Test Pod Running as Root (Should Fail)

```bash
# Create pod running as root
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-root
  namespace: lab-admission
spec:
  containers:
  - name: nginx
    image: nginx:1.27
    securityContext:
      runAsUser: 0
    resources:
      limits:
        cpu: 200m
        memory: 256Mi
EOF

# Expected output:
# Error from server: admission webhook denied the request:
# Container 'nginx' must not run as root (runAsUser: 0)
```

### 6.4 Test Compliant Pod (Should Succeed)

```bash
# Create compliant pod
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-compliant
  namespace: lab-admission
spec:
  containers:
  - name: nginx
    image: nginx:1.27
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
    resources:
      limits:
        cpu: 200m
        memory: 256Mi
      requests:
        cpu: 100m
        memory: 128Mi
EOF

# Should succeed
kubectl get pod test-compliant -n lab-admission
```

### 6.5 Test in Non-Enforced Namespace

```bash
# Create namespace without policy label
kubectl create namespace no-policy

# Try creating non-compliant pod
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-no-limits
  namespace: no-policy
spec:
  containers:
  - name: nginx
    image: nginx:1.27
EOF

# Should succeed (webhook not triggered due to namespaceSelector)
kubectl get pod test-no-limits -n no-policy
```

## Step 7: Create Mutating Webhook

### 7.1 Update Webhook Server with Mutating Endpoint

Add to `webhook-server.py`:

```python
import base64
import json

@app.route('/mutate-pods', methods=['POST'])
def mutate_pod():
    """
    Mutating webhook for pods
    Mutations:
    1. Add security labels
    2. Add security context if not present
    3. Add resource limits if missing (default values)
    """
    admission_review = request.get_json()

    uid = admission_review['request']['uid']
    pod = admission_review['request']['object']

    logger.info(f"Mutating pod: {pod['metadata'].get('name', 'unknown')}")

    # Prepare JSON patches
    patches = []

    # Add security label
    if 'labels' not in pod['metadata']:
        pod['metadata']['labels'] = {}

    patches.append({
        "op": "add",
        "path": "/metadata/labels/security.admission~1mutated",
        "value": "true"
    })

    # Add securityContext if missing
    for i, container in enumerate(pod['spec'].get('containers', [])):
        if 'securityContext' not in container:
            patches.append({
                "op": "add",
                "path": f"/spec/containers/{i}/securityContext",
                "value": {
                    "runAsNonRoot": True,
                    "runAsUser": 1000,
                    "allowPrivilegeEscalation": False,
                    "capabilities": {
                        "drop": ["ALL"]
                    }
                }
            })

        # Add resource limits if missing
        if 'resources' not in container:
            patches.append({
                "op": "add",
                "path": f"/spec/containers/{i}/resources",
                "value": {
                    "limits": {
                        "cpu": "200m",
                        "memory": "256Mi"
                    },
                    "requests": {
                        "cpu": "100m",
                        "memory": "128Mi"
                    }
                }
            })

    # Encode patches
    patch_bytes = json.dumps(patches).encode('utf-8')
    patch_base64 = base64.b64encode(patch_bytes).decode('utf-8')

    # Build admission response
    admission_response = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": uid,
            "allowed": True,
            "patchType": "JSONPatch",
            "patch": patch_base64
        }
    }

    logger.info(f"Applied {len(patches)} patches")
    return jsonify(admission_response)
```

### 7.2 Rebuild and Redeploy

```bash
# Rebuild image
cd webhook-certs/..
docker build -t webhook-server:1.1 .

# Load into Kind
kind load docker-image webhook-server:1.1 --name kcsa-lab

# Update deployment
kubectl set image deployment/webhook-server \
  webhook=webhook-server:1.1 \
  -n webhook-system

# Wait for rollout
kubectl rollout status deployment/webhook-server -n webhook-system
```

### 7.3 Create MutatingWebhookConfiguration

Create `mutating-webhook.yaml`:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: pod-defaults-webhook
webhooks:
- name: mutate-pods.webhook-system.svc
  admissionReviewVersions: ["v1"]
  sideEffects: None
  timeoutSeconds: 10
  failurePolicy: Ignore
  clientConfig:
    service:
      name: webhook-service
      namespace: webhook-system
      path: "/mutate-pods"
      port: 443
    caBundle: CA_BUNDLE_PLACEHOLDER
  rules:
  - operations: ["CREATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
    scope: "Namespaced"
  namespaceSelector:
    matchLabels:
      mutation: enabled
```

### 7.4 Apply Mutating Webhook

```bash
# Replace CA bundle and apply
CA_BUNDLE=$(cat webhook-certs/ca-bundle.txt)
sed "s/CA_BUNDLE_PLACEHOLDER/${CA_BUNDLE}/" mutating-webhook.yaml | kubectl apply -f -

# Verify
kubectl get mutatingwebhookconfigurations
```

## Step 8: Test Mutating Webhook

### 8.1 Enable Mutation on Namespace

```bash
kubectl label namespace lab-admission mutation=enabled
```

### 8.2 Create Pod Without Security Context

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-mutated
  namespace: lab-admission
spec:
  containers:
  - name: nginx
    image: nginx:1.27
EOF

# Check if pod was mutated
kubectl get pod test-mutated -n lab-admission -o yaml | grep -A 10 securityContext
kubectl get pod test-mutated -n lab-admission -o yaml | grep -A 5 resources
kubectl get pod test-mutated -n lab-admission -o yaml | grep "security.admission/mutated"
```

## Challenge Exercises

### Challenge 1: Image Registry Validation

Add validation to allow only images from specific registries.

### Challenge 2: Resource Ratio Check

Validate that memory limit is at least 2x memory request.

### Challenge 3: Label Enforcement

Require specific labels (e.g., owner, team, environment) on all pods.

## Troubleshooting

### Webhook Not Called

```bash
# Check webhook configuration
kubectl describe validatingwebhookconfiguration pod-security-webhook

# Check service endpoints
kubectl get endpoints webhook-service -n webhook-system

# Test webhook directly
kubectl run test --image=curlimages/curl --rm -it -- \
  curl -k https://webhook-service.webhook-system.svc:443/health
```

### Certificate Issues

```bash
# Verify certificate SAN
openssl x509 -in webhook-certs/webhook-server.crt -text -noout | grep -A 1 "Subject Alternative Name"

# Check secret
kubectl get secret webhook-server-certs -n webhook-system -o yaml
```

### Webhook Logs

```bash
# View webhook logs
kubectl logs -n webhook-system -l app=webhook-server -f

# Check API server logs (if accessible)
# Look for webhook-related errors
```

## Lab Summary

You learned how to:
1. Generate TLS certificates for webhooks
2. Create validating webhook server
3. Deploy webhook as Kubernetes service
4. Configure ValidatingWebhookConfiguration
5. Test policy enforcement
6. Create mutating webhook
7. Test automatic mutations

## Cleanup

```bash
kubectl delete namespace webhook-system
kubectl delete namespace lab-admission
kubectl delete namespace no-policy
kubectl delete validatingwebhookconfiguration pod-security-webhook
kubectl delete mutatingwebhookconfiguration pod-defaults-webhook
rm -rf webhook-certs/
```

---

[Back to Labs](./README.md) | [Previous Lab: Secrets Encryption ←](./lab-01-secrets-encryption.md) | [Next Lab: OPA Gatekeeper →](./lab-03-opa-gatekeeper.md)
