# Registry Security

## Overview

Container registries are centralized repositories for storing, managing, and distributing container images. Securing registries is crucial because they are a prime target for attackers - compromising a registry can give access to inject malicious code into thousands of deployments.

Think of a container registry like a distribution warehouse. Just as you'd secure a warehouse with access controls, surveillance, and inventory tracking, container registries need authentication, encryption, auditing, and content verification.

## Why Registry Security Matters

1. **Central Point of Control**: Single registry serves entire organization
2. **Supply Chain Target**: Compromised registry affects all downstream deployments
3. **Credential Exposure**: Registry credentials often provide broad access
4. **Data Sensitivity**: Images may contain proprietary code or configurations
5. **Compliance**: Regulatory requirements for access control and auditing

## Container Registry Types

### Public Registries

**Docker Hub:**
- Most popular public registry
- Free and paid tiers
- Official and community images
- Rate limiting on pulls

**Advantages of buying a Docker Hub subscription:**
- Use of Docker Hub can now be subject to [rate limits](https://www.docker.com/increase-rate-limits/). Docker Hub subscriptions remove rate limits and improve build performance.

**Quay.io:**
- Red Hat operated
- Free public repositories
- Security scanning
- Robot accounts

**GitHub Container Registry (GHCR):**
- Integrated with GitHub
- Free for public repositories
- GitHub Actions integration

**Google Container Registry (GCR):**
- Google Cloud Platform
- High availability
- Vulnerability scanning
- IAM integration

### Private Registries

**Harbor:**
- CNCF graduated project
- Image scanning
- Content signing
- Replication
- RBAC

**Amazon ECR:**
- AWS managed service
- IAM integration
- Image scanning
- Lifecycle policies

**Azure Container Registry (ACR):**
- Azure managed service
- Geo-replication
- Content trust
- Azure AD integration

**Google Artifact Registry:**
- Multi-format support
- Regional replication
- Fine-grained access control

**Self-Hosted:**
- Docker Registry
- Nexus Repository
- JFrog Artifactory
- Gitlab Container Registry

## Registry Security Fundamentals

### 1. Authentication

**Registry Authentication Methods:**

- **Basic Authentication**: Username/password
- **Token Authentication**: Short-lived tokens
- **OAuth/OIDC**: Federated identity
- **mTLS**: Certificate-based authentication
- **Cloud IAM**: Cloud provider identity

### 2. Authorization (RBAC)

Role-based access control for registry operations:

| Role | Push | Pull | Delete | Admin |
|------|------|------|--------|-------|
| Guest | ❌ | ✅ | ❌ | ❌ |
| Developer | ✅ | ✅ | ❌ | ❌ |
| Maintainer | ✅ | ✅ | ✅ | ❌ |
| Admin | ✅ | ✅ | ✅ | ✅ |

### 3. Encryption

**In Transit (TLS/HTTPS):**
- All registry communications must use TLS
- Minimum TLS 1.2 (prefer TLS 1.3)
- Strong cipher suites
- Valid certificates

**At Rest:**
- Encrypt registry storage backend
- Encrypt image layers
- Secure backup encryption
- Key management

### 4. Content Trust

**Docker Content Trust (DCT):**
- Cryptographic signing of images
- Publisher verification
- Pull verification
- Notary integration

### 5. Network Security

- **Private Networks**: Host registries in private networks
- **VPN Access**: Require VPN for registry access
- **IP Whitelisting**: Restrict access by IP ranges
- **Service Mesh**: Integrate with service mesh for mTLS

## Kubernetes ImagePullSecrets

### Understanding ImagePullSecrets

ImagePullSecrets are Kubernetes secrets that store registry credentials for pulling private images.

**Secret Types:**
- `kubernetes.io/dockerconfigjson`: Docker config format
- `kubernetes.io/dockercfg`: Legacy Docker config (deprecated)

### Creating ImagePullSecrets

**Method 1: Using kubectl create**

```bash
kubectl create secret docker-registry regcred \
  --docker-server=myregistry.com \
  --docker-username=myuser \
  --docker-password=mypassword \
  --docker-email=user@example.com \
  -n default
```

**Method 2: From Docker config**

```bash
# Login with docker first
docker login myregistry.com

# Create secret from docker config
kubectl create secret generic regcred \
  --from-file=.dockerconfigjson=$HOME/.docker/config.json \
  --type=kubernetes.io/dockerconfigjson \
  -n default
```

**Method 3: From YAML manifest**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: regcred
  namespace: default
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: ewoJImF1dGhzIjogewoJCSJteXJlZ2lzdHJ5LmNvbSI6IHsKCQkJImF1dGgiOiAiYldsMWMyVnlPbTE1Y0dGemMzZHZjbVE9IgoJCX0KCX0KfQ==
```

The `data` field contains base64-encoded Docker config:
```bash
echo -n '{"auths":{"myregistry.com":{"auth":"base64(username:password)"}}}' | base64
```

### Using ImagePullSecrets

**In Pod Spec:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
  - name: myapp
    image: myregistry.com/myapp:v1.0
  imagePullSecrets:
  - name: regcred
```

**In ServiceAccount:**

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: myapp-sa
  namespace: default
imagePullSecrets:
- name: regcred
```

Then use the ServiceAccount:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  serviceAccountName: myapp-sa
  containers:
  - name: myapp
    image: myregistry.com/myapp:v1.0
```

**Add to Default ServiceAccount:**

```bash
kubectl patch serviceaccount default \
  -p '{"imagePullSecrets": [{"name": "regcred"}]}' \
  -n default
```

Now all pods in the namespace automatically use this secret.

### Managing Multiple Registry Credentials

Create a merged Docker config for multiple registries:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: multi-regcred
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: |
    {
      "auths": {
        "registry1.com": {
          "auth": "dXNlcjE6cGFzczE="
        },
        "registry2.com": {
          "auth": "dXNlcjI6cGFzczI="
        },
        "ghcr.io": {
          "auth": "Z2hwX3Rva2VuMTIzNDU2Nzg5MA=="
        }
      }
    }
```

### ImagePullSecrets Best Practices

1. **Namespace Isolation**: Create secrets per namespace
2. **Short-Lived Credentials**: Rotate credentials regularly
3. **Least Privilege**: Grant minimum required permissions
4. **External Secrets**: Use external secret management (Vault, AWS Secrets Manager)
5. **Avoid Hardcoding**: Never hardcode credentials in manifests
6. **Audit Access**: Log and monitor secret usage

## Docker Content Trust

### Enable Docker Content Trust

```bash
# Enable DCT globally
export DOCKER_CONTENT_TRUST=1

# Pull only signed images
docker pull nginx:latest
```

With DCT enabled:
- Only signed images can be pulled
- Signatures are verified automatically
- Unsigned pulls fail

### Push Signed Images with DCT

```bash
# Enable DCT
export DOCKER_CONTENT_TRUST=1

# Push image (will prompt to create signing key)
docker push myregistry.com/myapp:v1.0
```

First push creates root and repository keys:
```
You are about to create a new root signing key passphrase.
This passphrase will be used to protect the most sensitive key in your signing system.

Enter passphrase for new root key with ID abc1234:
Repeat passphrase for new root key with ID abc1234:
Enter passphrase for new repository key with ID def5678:
Repeat passphrase for new repository key with ID def5678:
```

### Verify Signed Images

```bash
# Enable DCT
export DOCKER_CONTENT_TRUST=1

# Pull will only succeed if image is signed
docker pull myregistry.com/myapp:v1.0
```

View image signatures:
```bash
docker trust inspect myregistry.com/myapp:v1.0
```

## Private Registry Setup

### Harbor Installation

Harbor is the most feature-rich open-source registry.

**Prerequisites:**
- Docker and Docker Compose
- At least 4GB RAM
- Domain name with TLS certificate

**Installation:**

```bash
# Download Harbor installer
wget https://github.com/goharbor/harbor/releases/download/v2.10.0/harbor-offline-installer-v2.10.0.tgz

# Extract
tar xvf harbor-offline-installer-v2.10.0.tgz
cd harbor

# Configure Harbor
cp harbor.yml.tmpl harbor.yml
```

Edit `harbor.yml`:
```yaml
hostname: registry.example.com

https:
  port: 443
  certificate: /path/to/cert.crt
  private_key: /path/to/cert.key

harbor_admin_password: ChangeMe123!

database:
  password: ChangeMe123!

data_volume: /data
```

Install:
```bash
sudo ./install.sh --with-trivy --with-notary
```

Harbor includes:
- Web UI
- RBAC
- Vulnerability scanning (Trivy)
- Image signing (Notary)
- Replication
- Webhook notifications

### Docker Registry with Authentication

Simple Docker registry with basic auth:

```bash
# Create htpasswd file
docker run --rm --entrypoint htpasswd httpd:2 -Bbn myuser mypassword > htpasswd

# Start registry with authentication
docker run -d \
  -p 5000:5000 \
  --name registry \
  -v $(pwd)/htpasswd:/auth/htpasswd \
  -e REGISTRY_AUTH=htpasswd \
  -e REGISTRY_AUTH_HTPASSWD_REALM="Registry Realm" \
  -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd \
  -v registry-data:/var/lib/registry \
  registry:2
```

Login:
```bash
docker login localhost:5000
```

### Registry with TLS

Generate self-signed certificate:
```bash
mkdir -p certs

openssl req -newkey rsa:4096 -nodes -sha256 \
  -keyout certs/domain.key \
  -x509 -days 365 \
  -out certs/domain.crt \
  -subj "/CN=myregistry.com"
```

Start registry with TLS:
```bash
docker run -d \
  -p 5000:5000 \
  --name registry \
  -v $(pwd)/certs:/certs \
  -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt \
  -e REGISTRY_HTTP_TLS_KEY=/certs/domain.key \
  -v registry-data:/var/lib/registry \
  registry:2
```

## Cloud Registry Security

### Amazon ECR

**Create Repository:**
```bash
aws ecr create-repository --repository-name myapp
```

**Authentication:**
```bash
# Get login password
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin \
  123456789012.dkr.ecr.us-east-1.amazonaws.com
```

**Create Kubernetes Secret:**
```bash
kubectl create secret docker-registry ecr-secret \
  --docker-server=123456789012.dkr.ecr.us-east-1.amazonaws.com \
  --docker-username=AWS \
  --docker-password=$(aws ecr get-login-password --region us-east-1)
```

**IAM Policy for ECR:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage"
      ],
      "Resource": "*"
    }
  ]
}
```

**Enable Scanning:**
```bash
aws ecr put-image-scanning-configuration \
  --repository-name myapp \
  --image-scanning-configuration scanOnPush=true
```

### Google Artifact Registry

**Create Repository:**
```bash
gcloud artifacts repositories create myapp \
  --repository-format=docker \
  --location=us-central1
```

**Authentication:**
```bash
gcloud auth configure-docker us-central1-docker.pkg.dev
```

**Create Kubernetes Secret:**
```bash
kubectl create secret docker-registry gcr-secret \
  --docker-server=us-central1-docker.pkg.dev \
  --docker-username=_json_key \
  --docker-password="$(cat keyfile.json)"
```

### Azure Container Registry

**Create Registry:**
```bash
az acr create --resource-group myResourceGroup \
  --name myregistry --sku Premium
```

**Authentication:**
```bash
az acr login --name myregistry
```

**Create Kubernetes Secret:**
```bash
kubectl create secret docker-registry acr-secret \
  --docker-server=myregistry.azurecr.io \
  --docker-username=myregistry \
  --docker-password=$(az acr credential show --name myregistry --query passwords[0].value -o tsv)
```

**Service Principal Authentication:**
```bash
# Create service principal
SP_PASSWORD=$(az ad sp create-for-rbac \
  --name myregistrysp \
  --scopes /subscriptions/<subscription-id>/resourceGroups/myResourceGroup/providers/Microsoft.ContainerRegistry/registries/myregistry \
  --role acrpull \
  --query password \
  --output tsv)

SP_APP_ID=$(az ad sp list --display-name myregistrysp --query [0].appId --output tsv)

# Create secret
kubectl create secret docker-registry acr-secret \
  --docker-server=myregistry.azurecr.io \
  --docker-username=$SP_APP_ID \
  --docker-password=$SP_PASSWORD
```

## Registry Admission Control

### OPA Gatekeeper Policy

Enforce registry restrictions:

```yaml
apiVersion: templates.gatekeeper.sh/v1beta1
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
          not starts_with_allowed_repo(container.image)
          msg := sprintf("Image '%v' comes from untrusted registry", [container.image])
        }

        starts_with_allowed_repo(image) {
          startswith(image, input.parameters.repos[_])
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAllowedRepos
metadata:
  name: repo-must-be-approved
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    repos:
      - "myregistry.com/"
      - "gcr.io/myproject/"
      - "123456789012.dkr.ecr.us-east-1.amazonaws.com/"
```

### Kyverno Policy

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-image-registries
spec:
  validationFailureAction: Enforce
  rules:
  - name: validate-registries
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "Images must come from approved registries"
      pattern:
        spec:
          containers:
          - image: "myregistry.com/* | gcr.io/myproject/* | *.azurecr.io/*"
```

## Registry Scanning

### Trivy Registry Scanning

Scan images in a registry:

```bash
# Scan specific image
trivy image myregistry.com/myapp:v1.0

# Scan all images in namespace
for IMAGE in $(kubectl get pods -n production -o jsonpath='{.items[*].spec.containers[*].image}' | tr ' ' '\n' | sort -u); do
  echo "Scanning: $IMAGE"
  trivy image --severity HIGH,CRITICAL $IMAGE
done
```

### Harbor Built-in Scanning

Harbor automatically scans images:

1. Navigate to Harbor web UI
2. Select project → repository → artifact
3. View scan results in vulnerability tab
4. Set policies to prevent vulnerable image deployment

### ECR Image Scanning

```bash
# Enable scan on push
aws ecr put-image-scanning-configuration \
  --repository-name myapp \
  --image-scanning-configuration scanOnPush=true

# Manual scan
aws ecr start-image-scan \
  --repository-name myapp \
  --image-id imageTag=v1.0

# View results
aws ecr describe-image-scan-findings \
  --repository-name myapp \
  --image-id imageTag=v1.0
```

## Best Practices

### 1. Authentication and Authorization

- Use strong authentication (OIDC, SAML, mTLS)
- Implement RBAC with least privilege
- Separate dev/staging/prod registry access
- Use service accounts for automation
- Audit authentication logs

### 2. Network Security

- Host registries in private networks
- Use TLS for all communications
- Implement IP whitelisting
- Use VPN for external access
- Deploy behind WAF/load balancer

### 3. Credential Management

- Rotate credentials every 90 days
- Use short-lived tokens
- Implement automated rotation
- Store secrets in external vaults
- Never commit credentials to Git

### 4. Content Verification

- Enable image scanning
- Require image signing
- Implement admission control
- Scan on push and periodically
- Block deployment of vulnerable images

### 5. Monitoring and Auditing

- Log all registry operations
- Monitor pull/push patterns
- Alert on suspicious activity
- Track image provenance
- Implement SBOMs

### 6. Backup and Recovery

- Regular registry backups
- Test restore procedures
- Implement replication
- Document recovery procedures
- Monitor backup integrity

### 7. Compliance

- Document access controls
- Maintain audit trails
- Implement retention policies
- Track license compliance
- Regular security assessments

## Troubleshooting

### Issue: "unauthorized: authentication required"

**Solution:**
```bash
# Check if logged in
docker login myregistry.com

# Create/update ImagePullSecret
kubectl create secret docker-registry regcred \
  --docker-server=myregistry.com \
  --docker-username=user \
  --docker-password=pass \
  --dry-run=client -o yaml | kubectl apply -f -

# Verify secret
kubectl get secret regcred -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d
```

### Issue: "x509: certificate signed by unknown authority"

**Solution:**
```bash
# For self-signed certs, add to trust store
sudo cp registry.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# Or use insecure registry (not recommended for production)
# Add to /etc/docker/daemon.json:
{
  "insecure-registries": ["myregistry.com:5000"]
}

sudo systemctl restart docker
```

### Issue: Pod stuck in "ImagePullBackOff"

**Diagnosis:**
```bash
# Check pod events
kubectl describe pod <pod-name>

# Check ImagePullSecret exists
kubectl get secret regcred -n <namespace>

# Verify secret is referenced
kubectl get pod <pod-name> -o jsonpath='{.spec.imagePullSecrets}'

# Test manual pull
docker pull <image>
```

## Key Points to Remember

1. Always use HTTPS/TLS for registry communications
2. Implement strong authentication and RBAC
3. Use ImagePullSecrets for private registries
4. Rotate credentials regularly
5. Enable scanning on push
6. Require image signing
7. Implement admission control policies
8. Monitor and audit registry access
9. Use cloud provider IAM when available
10. Keep registry software updated

## Exam Tips

1. Know how to create ImagePullSecrets (multiple methods)
2. Understand how to attach secrets to ServiceAccounts
3. Practice troubleshooting image pull failures
4. Know cloud registry authentication methods
5. Understand Docker Content Trust
6. Be able to configure admission control for registries

## Study Resources

### Official Documentation
- [Kubernetes Images](https://kubernetes.io/docs/concepts/containers/images/)
- [Pull Image from Private Registry](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/)
- [Harbor Documentation](https://goharbor.io/docs/)
- [Docker Content Trust](https://docs.docker.com/engine/security/trust/)

### Registry Providers
- [Harbor](https://goharbor.io/)
- [Amazon ECR](https://aws.amazon.com/ecr/)
- [Google Artifact Registry](https://cloud.google.com/artifact-registry)
- [Azure Container Registry](https://azure.microsoft.com/en-us/products/container-registry)

## Next Steps

1. Complete the [Registry Security Lab](../../labs/05-supply-chain-security/lab-03-registry-security.md)
2. Set up a private registry
3. Learn about [SBOM](./sbom.md) next
4. Practice with cloud registries

## Quick Reference

```bash
# Create ImagePullSecret
kubectl create secret docker-registry regcred \
  --docker-server=<server> \
  --docker-username=<user> \
  --docker-password=<pass>

# Patch ServiceAccount
kubectl patch sa default -p '{"imagePullSecrets":[{"name":"regcred"}]}'

# View secret
kubectl get secret regcred -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d

# Test registry authentication
docker login <registry>

# Enable Docker Content Trust
export DOCKER_CONTENT_TRUST=1

# ECR login
aws ecr get-login-password | docker login --username AWS --password-stdin <ecr-url>

# GCR login
gcloud auth configure-docker

# ACR login
az acr login --name <registry>
```

---

[Back to Domain 5 README](./README.md) | [Previous: Image Signing ←](./image-signing.md) | [Next: SBOM →](./sbom.md)
