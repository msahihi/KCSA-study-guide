# Lab 05 - Image Security

## Objective

Implement comprehensive container image security including vulnerability scanning with Trivy, image signing with Cosign, building secure images, and enforcing image policies.

## Duration

90 minutes

## Prerequisites

- Kubernetes cluster v1.30.x
- kubectl configured
- Docker or Podman installed
- Trivy installed
- Cosign installed
- Helm 3.x installed

## Step 1: Install Required Tools

### 1.1 Install Trivy

```bash
# Linux

wget https://github.com/aquasecurity/trivy/releases/download/v0.48.0/trivy_0.48.0_Linux-64bit.tar.gz
tar zxvf trivy_0.48.0_Linux-64bit.tar.gz
sudo mv trivy /usr/local/bin/

# macOS

brew install trivy

# Verify

trivy version
```

### 1.2 Install Cosign

```bash
# Linux

wget https://github.com/sigstore/cosign/releases/download/v2.2.2/cosign-linux-amd64
chmod +x cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign

# macOS

brew install cosign

# Verify

cosign version
```

## Step 2: Vulnerability Scanning with Trivy

### 2.1 Scan Public Images

```bash
# Scan nginx image

trivy image nginx:1.27

# Scan with specific severity

trivy image --severity HIGH,CRITICAL nginx:1.27

# Scan and export to JSON

trivy image --format json --output nginx-scan.json nginx:1.27

# View summary

trivy image --severity HIGH,CRITICAL --format table nginx:1.27
```

### 2.2 Compare Image Versions

```bash
# Scan older version

trivy image --severity CRITICAL nginx:1.20

# Scan current version

trivy image --severity CRITICAL nginx:1.27

# Compare vulnerability counts

echo "Old version:"
trivy image --severity CRITICAL nginx:1.20 | grep Total
echo "New version:"
trivy image --severity CRITICAL nginx:1.27 | grep Total
```

### 2.3 Scan Images in CI/CD

Create `.gitlab-ci.yml` or GitHub Actions workflow:

```yaml
# GitHub Actions example

name: Image Security Scan

on:
  push:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Run Trivy scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'

      - name: Upload results
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: 'trivy-results.sarif'
```

## Step 3: Build Secure Container Images

### 3.1 Insecure Dockerfile (Anti-pattern)

Create `Dockerfile.insecure`:

```dockerfile
# BAD: Using large base image

FROM ubuntu:22.04

# BAD: Running as root

USER root

# BAD: Installing unnecessary packages

RUN apt-get update && apt-get install -y \
    curl \
    wget \
    vim \
    python3 \
    python3-pip

# BAD: No version pinning

RUN pip3 install flask

# BAD: Copying everything

COPY . /app/

# BAD: No healthcheck

EXPOSE 8080
CMD ["python3", "/app/app.py"]
```

### 3.2 Secure Dockerfile (Best Practices)

Create `Dockerfile.secure`:

```dockerfile
# Stage 1: Builder

FROM python:3.11-slim AS builder

WORKDIR /app

# Install dependencies with pinned versions

COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Stage 2: Final image

FROM gcr.io/distroless/python3-debian11

# Copy only necessary files

COPY --from=builder /root/.local /root/.local
COPY app.py /app/
COPY static/ /app/static/

WORKDIR /app

# Set PATH for pip packages

ENV PATH=/root/.local/bin:$PATH

# Run as non-root (distroless uses nonroot user)

USER nonroot:nonroot

EXPOSE 8080

# Use exec form

ENTRYPOINT ["python3", "app.py"]

# Add health check

HEALTHCHECK --interval=30s --timeout=3s \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"
```

### 3.3 Create Application Files

Create `app.py`:

```python
from flask import Flask, jsonify
import os

app = Flask(__name__)

@app.route('/')
def hello():
    return jsonify({"message": "Hello from secure container!"})

@app.route('/health')
def health():
    return jsonify({"status": "healthy"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

Create `requirements.txt`:

```
flask==3.0.0

```

### 3.4 Build and Compare

```bash
# Build insecure image

docker build -f Dockerfile.insecure -t myapp:insecure .

# Build secure image

docker build -f Dockerfile.secure -t myapp:secure .

# Compare sizes

docker images | grep myapp

# Scan both images

echo "=== Insecure Image ==="
trivy image --severity HIGH,CRITICAL myapp:insecure | grep Total

echo "=== Secure Image ==="
trivy image --severity HIGH,CRITICAL myapp:secure | grep Total
```

## Step 4: Image Signing with Cosign

### 4.1 Generate Key Pair

```bash
# Generate signing keys

cosign generate-key-pair

# Enter password when prompted
# Creates: cosign.key (private) and cosign.pub (public)

# Store keys securely

chmod 600 cosign.key
```

### 4.2 Sign Image

```bash
# Tag image for local registry (using Kind registry)

docker tag myapp:secure localhost:5000/myapp:v1.0.0

# Push to registry (assuming local registry at localhost:5000)

docker push localhost:5000/myapp:v1.0.0

# Sign the image

cosign sign --key cosign.key localhost:5000/myapp:v1.0.0

# Enter key password when prompted

```

### 4.3 Verify Signature

```bash
# Verify with public key

cosign verify --key cosign.pub localhost:5000/myapp:v1.0.0

# Output shows verification success

```

### 4.4 Sign with Annotations

```bash
# Sign with metadata

cosign sign --key cosign.key \
  -a "git-sha=$(git rev-parse HEAD)" \
  -a "build-date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -a "builder=ci-pipeline" \
  localhost:5000/myapp:v1.0.0

# Verify with annotations

cosign verify --key cosign.pub \
  -a "builder=ci-pipeline" \
  localhost:5000/myapp:v1.0.0
```

### 4.5 Store Keys in Kubernetes

```bash
kubectl create namespace image-security

# Create secret with signing keys

kubectl create secret generic cosign-keys \
  --from-file=cosign.key \
  --from-file=cosign.pub \
  -n image-security

# Create public key only secret (for verification)

kubectl create secret generic cosign-pub \
  --from-file=cosign.pub \
  -n image-security
```

## Step 5: Image Policy Enforcement

### 5.1 Install Policy Controller (Sigstore)

```bash
# Install Policy Controller

kubectl apply -f https://github.com/sigstore/policy-controller/releases/download/v0.8.0/policy-controller.yaml

# Verify installation

kubectl get pods -n cosign-system
kubectl wait --for=condition=ready pod -l app=policy-controller -n cosign-system --timeout=120s
```

### 5.2 Create ClusterImagePolicy

Create `image-policy.yaml`:

```yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: signed-images-only
spec:
  images:
  - glob: "localhost:5000/**"
  authorities:
  - key:
      data: |
        -----BEGIN PUBLIC KEY-----
        PASTE_YOUR_PUBLIC_KEY_HERE
        -----END PUBLIC KEY-----
```

Get your public key:

```bash
cat cosign.pub
```

Apply policy:

```bash
kubectl apply -f image-policy.yaml
```

### 5.3 Test Policy Enforcement

```bash
kubectl create namespace test-policy

# Try to deploy unsigned image (should fail)

kubectl run unsigned-test \
  --image=nginx:1.27 \
  -n test-policy

# Expected: Error - image signature verification failed

# Deploy signed image (should succeed)

kubectl run signed-test \
  --image=localhost:5000/myapp:v1.0.0 \
  -n test-policy

# Should succeed

kubectl get pods -n test-policy
```

## Step 6: OPA Gatekeeper Image Policies

### 6.1 Create Image Registry Policy

Create `allowed-registries-template.yaml`:

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sallowedregistries
spec:
  crd:
    spec:
      names:
        kind: K8sAllowedRegistries
      validation:
        openAPIV3Schema:
          type: object
          properties:
            registries:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sallowedregistries

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          satisfied := [good | registry = input.parameters.registries[_] ; good = startswith(container.image, registry)]
          not any(satisfied)
          msg := sprintf("Image '%v' comes from untrusted registry. Allowed: %v", [container.image, input.parameters.registries])
        }
```

Create constraint:

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAllowedRegistries
metadata:
  name: allowed-registries-policy
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces:
      - test-policy
  parameters:
    registries:
      - "localhost:5000/"
      - "docker.io/library/"
      - "registry.k8s.io/"
```

Apply:

```bash
kubectl apply -f allowed-registries-template.yaml
kubectl apply -f allowed-registries-constraint.yaml

# Test with disallowed registry

kubectl run bad-registry \
  --image=badregistry.io/nginx:latest \
  -n test-policy

# Expected: Error - untrusted registry

```

### 6.2 Block Latest Tag

Create `deny-latest-tag-template.yaml`:

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sdenylatesttag
spec:
  crd:
    spec:
      names:
        kind: K8sDenyLatestTag
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sdenylatesttag

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          endswith(container.image, ":latest")
          msg := sprintf("Container '%v' uses :latest tag which is not allowed", [container.name])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not contains(container.image, ":")
          msg := sprintf("Container '%v' does not specify image tag (defaults to :latest)", [container.name])
        }
```

```
kubectl apply -f deny-latest-tag-template.yaml

# Create constraint

kubectl create -f - <<EOF
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sDenyLatestTag
metadata:
  name: deny-latest-tag
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces:
      - test-policy
EOF

# Test

kubectl run latest-test --image=nginx:latest -n test-policy

# Expected: Error - :latest tag not allowed

```

## Step 7: Integrate with CI/CD

### 7.1 CI/CD Pipeline Example

Create `build-and-scan.sh`:

```bash
#!/bin/bash

set -e

IMAGE_NAME="myapp"
IMAGE_TAG="v1.0.0"
REGISTRY="localhost:5000"
FULL_IMAGE="${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}"

echo "Building image..."
docker build -f Dockerfile.secure -t ${FULL_IMAGE} .

echo "Scanning for vulnerabilities..."
trivy image --exit-code 1 --severity CRITICAL ${FULL_IMAGE}

echo "Pushing image..."
docker push ${FULL_IMAGE}

echo "Signing image..."
cosign sign --key cosign.key ${FULL_IMAGE}

echo "Verifying signature..."
cosign verify --key cosign.pub ${FULL_IMAGE}

echo "Image security pipeline completed successfully!"
```

### 7.2 Create SBOM (Software Bill of Materials)

```bash
# Generate SBOM with Trivy

trivy image --format cyclonedx --output sbom.json myapp:secure

# View SBOM

cat sbom.json | jq .

# Attach SBOM to image

cosign attach sbom --sbom sbom.json localhost:5000/myapp:v1.0.0

# Verify SBOM

cosign verify-attestation --key cosign.pub localhost:5000/myapp:v1.0.0
```

## Step 8: Private Registry with Harbor

### 8.1 Install Harbor

```bash
# Install Harbor

helm repo add harbor https://helm.goharbor.io
helm install harbor harbor/harbor \
  --namespace harbor \
  --create-namespace \
  --set expose.type=nodePort \
  --set expose.tls.enabled=false \
  --set persistence.enabled=false \
  --set harborAdminPassword=Harbor12345

# Wait for Harbor to be ready

kubectl wait --for=condition=ready pod -l app=harbor -n harbor --timeout=300s

# Get Harbor URL

kubectl get svc -n harbor
```

### 8.2 Configure Image Scanning in Harbor

```bash
# Access Harbor UI
# NodePort URL: http://<node-ip>:<node-port>
# Login: admin / Harbor12345

# Via UI:
# 1. Go to Interrogation Services
# 2. Enable Trivy scanner
# 3. Set scan on push to true
# 4. Configure scan schedule

```

### 8.3 Push Image to Harbor

```bash
# Login to Harbor

docker login <harbor-url> -u admin -p Harbor12345

# Tag and push

docker tag myapp:secure <harbor-url>/library/myapp:v1.0.0
docker push <harbor-url>/library/myapp:v1.0.0

# Check scan results in Harbor UI

```

## Challenge Exercises

1. Implement image size limits in admission policy
1. Create policy requiring SHA256 image references
1. Build multi-architecture images
1. Set up automated vulnerability notifications
1. Implement image garbage collection

## Troubleshooting

### Trivy Database Issues

```bash
# Update Trivy database

trivy image --download-db-only

# Clear cache

trivy image --clear-cache
```

### Cosign Verification Failures

```bash
# Check signature exists

cosign triangulate localhost:5000/myapp:v1.0.0

# Verify with verbose output

cosign verify --key cosign.pub localhost:5000/myapp:v1.0.0 -v
```

### Policy Controller Issues

```bash
# Check logs

kubectl logs -n cosign-system -l app=policy-controller

# Verify webhook configuration

kubectl get validatingwebhookconfigurations | grep policy
```

## Lab Summary

You learned:

- Scanning images for vulnerabilities with Trivy
- Building secure container images
- Signing images with Cosign
- Verifying image signatures
- Enforcing image policies with admission controllers
- Integrating security into CI/CD pipelines
- Using private registries with Harbor
- Creating and attaching SBOMs

**Key Takeaways:**

- Always scan images before deployment
- Use minimal base images (distroless, alpine)
- Sign production images
- Enforce image policies at admission time
- Integrate security checks in CI/CD
- Use private registries for production
- Maintain image SBOMs for supply chain security

## Cleanup

```bash
kubectl delete namespace test-policy
kubectl delete namespace image-security
kubectl delete clusterimagepolicy signed-images-only
kubectl delete constrainttemplate k8sallowedregistries k8sdenylatesttag
helm uninstall harbor -n harbor
kubectl delete namespace harbor
kubectl delete namespace cosign-system
```

## Additional Resources

- [Trivy Documentation](https://trivy.dev/)
- [Cosign Documentation](https://docs.sigstore.dev/cosign/)
- [Harbor Documentation](https://goharbor.io/docs/)
- [CNCF Supply Chain Security](https://github.com/cncf/tag-security/blob/main/supply-chain-security/supply-chain-security-paper/CNCF_SSCP_v1.pdf)

---

[Back to Labs](./README.md) | [Previous Lab: Falco Runtime ←](./lab-04-falco-runtime.md) | [Domain 4 Concepts →](../../domains/04-minimize-vulnerabilities/README.md)
