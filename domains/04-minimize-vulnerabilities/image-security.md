# Image Security

## Overview

Container image security is fundamental to Kubernetes security. A compromised or vulnerable image can lead to cluster-wide security breaches. This guide covers vulnerability scanning, image signing, registry security, and best practices for building and deploying secure container images.

## Table of Contents

1. [Understanding Image Security](#understanding-image-security)
2. [Vulnerability Scanning with Trivy](#vulnerability-scanning-with-trivy)
3. [Image Signing and Verification](#image-signing-and-verification)
4. [Container Registry Security](#container-registry-security)
5. [Image Pull Secrets](#image-pull-secrets)
6. [Building Secure Images](#building-secure-images)
7. [Image Policy Enforcement](#image-policy-enforcement)
8. [Best Practices](#best-practices)

## Understanding Image Security

### Image Security Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│                    Secure Image Lifecycle                    │
└─────────────────────────────────────────────────────────────┘

1. Build Phase
   ├─ Use minimal base images
   ├─ Run as non-root user
   ├─ Scan during build (CI/CD)
   └─ Sign image

2. Registry Phase
   ├─ Store in private registry
   ├─ Enable vulnerability scanning
   ├─ Implement access control
   └─ Verify signatures

3. Deployment Phase
   ├─ Pull from trusted registries only
   ├─ Verify image signatures
   ├─ Check vulnerability scan results
   └─ Apply admission policies

4. Runtime Phase
   ├─ Monitor container behavior
   ├─ Block privilege escalation
   ├─ Apply security contexts
   └─ Scan running images periodically
```

### Common Image Vulnerabilities

1. **Known CVEs**: Publicly disclosed security vulnerabilities
2. **Outdated Dependencies**: Old libraries with known exploits
3. **Embedded Secrets**: Passwords, API keys in image layers
4. **Excessive Permissions**: Running as root, unnecessary capabilities
5. **Bloated Images**: Unnecessary packages increase attack surface
6. **Unverified Sources**: Images from untrusted registries

## Vulnerability Scanning with Trivy

Trivy is a comprehensive security scanner that detects vulnerabilities in container images, filesystems, and Kubernetes clusters.

### Installation

```bash
# Linux
wget https://github.com/aquasecurity/trivy/releases/download/v0.48.0/trivy_0.48.0_Linux-64bit.tar.gz
tar zxvf trivy_0.48.0_Linux-64bit.tar.gz
sudo mv trivy /usr/local/bin/

# macOS
brew install trivy

# Verify installation
trivy version
```

### Basic Image Scanning

```bash
# Scan an image
trivy image nginx:1.27

# Scan with specific severity
trivy image --severity HIGH,CRITICAL nginx:1.27

# Scan and exit with error if vulnerabilities found
trivy image --exit-code 1 --severity CRITICAL nginx:1.27

# Output formats
trivy image --format json nginx:1.27 > scan-results.json
trivy image --format table nginx:1.27
trivy image --format sarif nginx:1.27 > results.sarif
```

### Understanding Trivy Output

```bash
trivy image nginx:1.27

# Output:
# nginx:1.27 (alpine 3.18.4)
# ==========================
# Total: 15 (HIGH: 3, CRITICAL: 2)
#
# ┌───────────────┬────────────────┬──────────┬───────────────────┬───────────────┐
# │   Library     │ Vulnerability  │ Severity │ Installed Version │ Fixed Version │
# ├───────────────┼────────────────┼──────────┼───────────────────┼───────────────┤
# │ libssl3       │ CVE-2023-12345 │ CRITICAL │ 3.0.10-r0         │ 3.0.11-r0     │
# │ libcrypto3    │ CVE-2023-12345 │ CRITICAL │ 3.0.10-r0         │ 3.0.11-r0     │
# │ busybox       │ CVE-2023-67890 │ HIGH     │ 1.36.1-r2         │ 1.36.1-r3     │
# └───────────────┴────────────────┴──────────┴───────────────────┴───────────────┘
```

### Advanced Scanning Options

```bash
# Scan specific layers
trivy image --list-all-pkgs nginx:1.27

# Ignore unfixed vulnerabilities
trivy image --ignore-unfixed nginx:1.27

# Scan with custom security checks
trivy image --security-checks vuln,config nginx:1.27

# Skip specific files
trivy image --skip-files /usr/lib/python3.9/site-packages nginx:1.27

# Use cache server
trivy image --cache-dir /path/to/cache nginx:1.27
```

### Scanning Local Images

```bash
# Scan image from Docker daemon
docker pull nginx:1.27
trivy image nginx:1.27

# Scan image tar file
docker save nginx:1.27 -o nginx.tar
trivy image --input nginx.tar

# Scan Dockerfile
trivy config Dockerfile
```

### Scanning in CI/CD

#### GitHub Actions

```yaml
name: Container Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'

      - name: Upload Trivy results to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: 'trivy-results.sarif'
```

#### GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - build
  - scan
  - deploy

build:
  stage: build
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA

trivy-scan:
  stage: scan
  image: aquasec/trivy:latest
  script:
    - trivy image --exit-code 1 --severity CRITICAL $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  allow_failure: false
```

### Trivy Kubernetes Integration

#### Scan Running Images in Cluster

```bash
# Scan all images in cluster
trivy k8s --report summary cluster

# Scan specific namespace
trivy k8s --report summary --namespace production

# Scan and output to file
trivy k8s --report all --format json cluster > cluster-scan.json
```

#### Trivy Operator

```bash
# Install Trivy Operator
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/trivy-operator/main/deploy/static/trivy-operator.yaml

# View vulnerability reports
kubectl get vulnerabilityreports --all-namespaces

# Detailed report for specific workload
kubectl describe vulnerabilityreport <report-name> -n <namespace>
```

### Filtering and Ignoring Vulnerabilities

#### .trivyignore File

```bash
# .trivyignore
# Ignore specific CVEs with justification

# False positive - not applicable to our use case
CVE-2023-12345

# Risk accepted - mitigation in place
CVE-2023-67890

# Waiting for vendor fix
CVE-2024-00001
```

#### Policy as Code

```yaml
# .trivyignore.yaml
vulnerabilities:
  - id: CVE-2023-12345
    paths:
      - /usr/lib/python3.9/site-packages
    statement: False positive - library not used
    expired: 2024-12-31

  - id: CVE-2023-67890
    severity: MEDIUM
    statement: Risk accepted by security team
    expired: 2024-06-30
```

## Image Signing and Verification

Image signing ensures image integrity and authenticity using cryptographic signatures.

### Cosign (Sigstore)

Cosign is a tool for signing and verifying container images.

#### Installation

```bash
# Linux
wget https://github.com/sigstore/cosign/releases/download/v2.2.2/cosign-linux-amd64
chmod +x cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign

# macOS
brew install cosign

# Verify installation
cosign version
```

#### Generating Key Pair

```bash
# Generate key pair
cosign generate-key-pair

# Output:
# Enter password for private key:
# Enter password for private key again:
# Private key written to cosign.key
# Public key written to cosign.pub
```

#### Signing Images

```bash
# Sign an image
cosign sign --key cosign.key myregistry.io/myapp:v1.0.0

# Sign with keyless (OIDC-based)
cosign sign myregistry.io/myapp:v1.0.0

# Sign with annotations
cosign sign --key cosign.key \
  -a "git-sha=$(git rev-parse HEAD)" \
  -a "build-timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  myregistry.io/myapp:v1.0.0
```

#### Verifying Signatures

```bash
# Verify with public key
cosign verify --key cosign.pub myregistry.io/myapp:v1.0.0

# Verify and check annotations
cosign verify --key cosign.pub \
  -a "git-sha=abc123" \
  myregistry.io/myapp:v1.0.0

# Output on success:
# Verification for myregistry.io/myapp:v1.0.0 --
# The following checks were performed on each of these signatures:
#   - The cosign claims were validated
#   - The signatures were verified against the specified public key
```

#### Storing Keys in Kubernetes

```bash
# Create secret with signing keys
kubectl create secret generic cosign-keys \
  --from-file=cosign.key \
  --from-file=cosign.pub \
  -n security-system

# Use in admission controller
kubectl create secret generic cosign-pub \
  --from-file=cosign.pub \
  -n security-system
```

### Policy Controller (Formerly Cosigned)

Policy Controller enforces image signature verification at admission time.

#### Installation

```bash
# Install Policy Controller
kubectl apply -f https://github.com/sigstore/policy-controller/releases/download/v0.8.0/policy-controller.yaml

# Verify installation
kubectl get pods -n cosign-system
```

#### ClusterImagePolicy

```yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: signed-images-only
spec:
  images:
  - glob: "myregistry.io/**"
  authorities:
  - key:
      data: |
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
        -----END PUBLIC KEY-----
```

#### Namespace-Scoped Policy

```yaml
apiVersion: policy.sigstore.dev/v1alpha1
kind: ImagePolicy
metadata:
  name: signed-prod-images
  namespace: production
spec:
  images:
  - glob: "myregistry.io/prod/**"
  authorities:
  - keyless:
      url: https://fulcio.sigstore.dev
      identities:
      - issuer: https://token.actions.githubusercontent.com
        subject: ".*@myorg.com$"
```

### Docker Content Trust (DCT)

Docker's built-in image signing mechanism using Notary.

```bash
# Enable DCT
export DOCKER_CONTENT_TRUST=1

# Push signed image
docker push myregistry.io/myapp:v1.0.0
# Will prompt for passphrase

# Pull and verify
docker pull myregistry.io/myapp:v1.0.0
# Will only pull if signature is valid

# Disable DCT
export DOCKER_CONTENT_TRUST=0
```

## Container Registry Security

### Private Registry Setup

#### Harbor Registry

```bash
# Install Harbor using Helm
helm repo add harbor https://helm.goharbor.io
helm repo update

# Install with custom values
helm install harbor harbor/harbor \
  --namespace harbor \
  --create-namespace \
  --set expose.type=loadBalancer \
  --set externalURL=https://harbor.example.com \
  --set persistence.enabled=true \
  --set harborAdminPassword=ChangeMe123

# Enable vulnerability scanning in Harbor
# Access Harbor UI and enable Trivy scanner
```

#### Registry Authentication

```yaml
# Docker Registry with basic auth
apiVersion: v1
kind: Secret
metadata:
  name: registry-credentials
  namespace: default
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: <BASE64_ENCODED_DOCKER_CONFIG>
```

### Image Pull Policies

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pull-policy-example
spec:
  containers:
  - name: app
    image: myregistry.io/myapp:v1.0.0
    imagePullPolicy: Always  # Always, IfNotPresent, Never
  imagePullSecrets:
  - name: registry-credentials
```

**Pull Policy Options:**
- `Always`: Always pull the latest image (recommended for :latest tag)
- `IfNotPresent`: Pull only if not present locally (default for tagged images)
- `Never`: Never pull, use local image only

### Registry Access Control

#### Harbor RBAC

```yaml
# Harbor Project-level roles:
# - Project Admin: Full control
# - Developer: Push and pull
# - Guest: Pull only
# - Limited Guest: Pull specific images only
```

#### Registry Webhook

```yaml
# Harbor webhook for scan completion
webhookURL: https://your-webhook-endpoint.com/harbor
events:
  - scanningCompleted
  - scanningFailed
skipCertVerify: false
```

## Image Pull Secrets

### Creating Image Pull Secrets

#### Method 1: From Docker Config

```bash
# Login to registry
docker login myregistry.io

# Create secret from Docker config
kubectl create secret generic regcred \
  --from-file=.dockerconfigjson=$HOME/.docker/config.json \
  --type=kubernetes.io/dockerconfigjson
```

#### Method 2: From Command Line

```bash
kubectl create secret docker-registry regcred \
  --docker-server=myregistry.io \
  --docker-username=myuser \
  --docker-password=mypassword \
  --docker-email=myemail@example.com
```

#### Method 3: From YAML

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: regcred
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: eyJhdXRocyI6eyJteXJlZ2lzdHJ5LmlvIjp7InVzZXJuYW1lIjoibXl1c2VyIiwicGFzc3dvcmQiOiJteXBhc3N3b3JkIiwiZW1haWwiOiJteWVtYWlsQGV4YW1wbGUuY29tIiwiYXV0aCI6ImJYbDFjMlZ5T20xNWNHRnpjM2R2Y21RPSJ9fX0=
```

**Generating .dockerconfigjson:**
```bash
kubectl create secret docker-registry regcred \
  --docker-server=myregistry.io \
  --docker-username=myuser \
  --docker-password=mypassword \
  --dry-run=client -o yaml | grep .dockerconfigjson
```

### Using Image Pull Secrets

#### In Pod Spec

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: private-image-pod
spec:
  containers:
  - name: app
    image: myregistry.io/private/myapp:v1.0.0
  imagePullSecrets:
  - name: regcred
```

#### In ServiceAccount

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-service-account
imagePullSecrets:
- name: regcred

---
apiVersion: v1
kind: Pod
metadata:
  name: pod-with-sa
spec:
  serviceAccountName: my-service-account
  containers:
  - name: app
    image: myregistry.io/private/myapp:v1.0.0
```

### Default Image Pull Secrets

```bash
# Add to default ServiceAccount
kubectl patch serviceaccount default \
  -p '{"imagePullSecrets":[{"name":"regcred"}]}'

# Verify
kubectl get serviceaccount default -o yaml
```

## Building Secure Images

### Minimal Base Images

```dockerfile
# BAD: Large attack surface
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y python3 python3-pip
COPY app.py /app/
CMD ["python3", "/app/app.py"]

# GOOD: Minimal distroless image
FROM gcr.io/distroless/python3-debian11
COPY app.py /app/
WORKDIR /app
CMD ["app.py"]

# BETTER: Multi-stage build with distroless
FROM python:3.11-slim as builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --user -r requirements.txt

FROM gcr.io/distroless/python3-debian11
COPY --from=builder /root/.local /root/.local
COPY app.py /app/
WORKDIR /app
ENV PATH=/root/.local/bin:$PATH
CMD ["app.py"]
```

### Running as Non-Root

```dockerfile
# BAD: Running as root
FROM nginx:1.27
COPY nginx.conf /etc/nginx/nginx.conf
CMD ["nginx", "-g", "daemon off;"]

# GOOD: Running as non-root
FROM nginx:1.27
RUN chown -R nginx:nginx /var/cache/nginx && \
    chown -R nginx:nginx /var/log/nginx && \
    touch /var/run/nginx.pid && \
    chown -R nginx:nginx /var/run/nginx.pid
USER nginx
CMD ["nginx", "-g", "daemon off;"]
```

### Multi-Stage Builds

```dockerfile
# Build stage
FROM golang:1.21 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Final stage
FROM gcr.io/distroless/static-debian11
COPY --from=builder /app/main /
USER nonroot:nonroot
ENTRYPOINT ["/main"]
```

### Securing Dockerfile

```dockerfile
FROM python:3.11-slim

# Use specific versions
RUN pip install --no-cache-dir flask==3.0.0 requests==2.31.0

# Don't run as root
RUN useradd -m -u 1000 appuser

# Set secure permissions
COPY --chown=appuser:appuser app.py /app/
WORKDIR /app

# Drop privileges
USER appuser

# Use HTTPS for external resources
RUN pip install --index-url https://pypi.org/simple/ package

# Don't expose unnecessary ports
EXPOSE 8080

# Use exec form for CMD/ENTRYPOINT
CMD ["python", "app.py"]

# Add health check
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:8080/health || exit 1

# Add labels for metadata
LABEL maintainer="security@example.com" \
      version="1.0.0" \
      description="Secure Python application"
```

### .dockerignore

```bash
# .dockerignore
.git
.gitignore
.env
*.md
Dockerfile
docker-compose.yml
.dockerignore
secrets/
*.key
*.pem
node_modules/
**/*.log
.DS_Store
```

## Image Policy Enforcement

### Admission Controller Policy

Using OPA Gatekeeper to enforce image policies:

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8strustedimages
spec:
  crd:
    spec:
      names:
        kind: K8sTrustedImages
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
        package k8strustedimages

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not startswith(container.image, input.parameters.repos[_])
          msg := sprintf("Container image %v is not from trusted registry", [container.image])
        }

---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sTrustedImages
metadata:
  name: trusted-registries
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces:
      - "production"
  parameters:
    repos:
      - "myregistry.io/"
      - "gcr.io/mycompany/"
```

### Kyverno Image Policy

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: check-image-signature
spec:
  validationFailureAction: Enforce
  background: false
  webhookTimeoutSeconds: 30
  failurePolicy: Fail
  rules:
  - name: verify-signature
    match:
      any:
      - resources:
          kinds:
          - Pod
    verifyImages:
    - imageReferences:
      - "myregistry.io/*"
      attestors:
      - count: 1
        entries:
        - keys:
            publicKeys: |-
              -----BEGIN PUBLIC KEY-----
              MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
              -----END PUBLIC KEY-----
```

### ImagePolicyWebhook

```yaml
# /etc/kubernetes/admission-control/imagepolicy.yaml
imagePolicy:
  kubeConfigFile: /etc/kubernetes/admission-control/imagepolicywebhook-config.yaml
  allowTTL: 50
  denyTTL: 50
  retryBackoff: 500
  defaultAllow: false

---
# /etc/kubernetes/admission-control/imagepolicywebhook-config.yaml
apiVersion: v1
kind: Config
clusters:
- name: image-checker
  cluster:
    server: https://image-policy-webhook.security.svc:8443/check-image
    certificate-authority: /etc/kubernetes/pki/ca.crt
users:
- name: api-server
  user:
    client-certificate: /etc/kubernetes/pki/apiserver.crt
    client-key: /etc/kubernetes/pki/apiserver.key
contexts:
- name: image-checker
  context:
    cluster: image-checker
    user: api-server
current-context: image-checker
```

## Best Practices

### 1. Use Minimal Base Images

```bash
# Image size comparison
docker images
# ubuntu:22.04           ~77MB
# alpine:3.18            ~7MB
# gcr.io/distroless/base ~20MB
```

### 2. Scan Images in CI/CD

Never deploy unscanned images to production.

### 3. Implement Image Signing

Require signatures for production images.

### 4. Use Private Registry

Don't rely on public registries for production workloads.

### 5. Tag Images Properly

```bash
# BAD: Using :latest
myregistry.io/myapp:latest

# GOOD: Using specific version and SHA
myregistry.io/myapp:v1.2.3
myregistry.io/myapp@sha256:abc123...

# BETTER: Using both
myregistry.io/myapp:v1.2.3@sha256:abc123...
```

### 6. Regular Image Updates

```bash
# Set up automated image scanning
# Example: Harbor scheduled scanning
# Or use Trivy Operator for continuous scanning
```

### 7. Remove Unnecessary Tools

```dockerfile
# Don't include shells, compilers, or debug tools in production images
# Use distroless or scratch base images
FROM scratch
COPY --from=builder /app/binary /
ENTRYPOINT ["/binary"]
```

### 8. Secrets Management

```dockerfile
# BAD: Secrets in image
ENV API_KEY=abc123

# GOOD: Secrets from Kubernetes
# Mounted via Secret volume or environment variable
```

### 9. Immutable Tags

```bash
# Use image digest for immutability
kubectl set image deployment/myapp \
  app=myregistry.io/myapp@sha256:abc123...
```

### 10. Image Provenance

```bash
# Use SBOM (Software Bill of Materials)
trivy image --format cyclonedx myregistry.io/myapp:v1.0.0 > sbom.json

# Attach SBOM to image
cosign attach sbom --sbom sbom.json myregistry.io/myapp:v1.0.0
```

## Summary

Image security is a critical component of Kubernetes security:

1. **Vulnerability Scanning**: Use Trivy to scan images for CVEs
2. **Image Signing**: Use Cosign to sign and verify images
3. **Registry Security**: Use private registries with authentication
4. **Image Pull Secrets**: Securely manage registry credentials
5. **Secure Builds**: Use minimal base images and multi-stage builds
6. **Policy Enforcement**: Block untrusted or vulnerable images at admission

**Key Takeaways:**
- Scan all images before deployment
- Sign production images and verify signatures
- Use minimal, distroless base images
- Run containers as non-root users
- Store images in private, authenticated registries
- Implement admission policies to enforce image security
- Regularly update and re-scan images
- Use image digests for immutability

## Additional Resources

- [Trivy Documentation](https://trivy.dev/)
- [Cosign Documentation](https://docs.sigstore.dev/cosign/overview/)
- [Harbor Documentation](https://goharbor.io/docs/)
- [Dockerfile Best Practices](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)
- [Distroless Images](https://github.com/GoogleContainerTools/distroless)
- [CNCF Software Supply Chain Best Practices](https://github.com/cncf/tag-security/blob/main/supply-chain-security/supply-chain-security-paper/CNCF_SSCP_v1.pdf)

---

[Back to Domain 4 README](./README.md) | [Previous: Runtime Security Tools ←](./runtime-security-tools.md)
