# Lab 02: Image Signing with Cosign

## Objectives

By the end of this lab, you will be able to:
- Install and configure Cosign
- Generate signing key pairs
- Sign container images with key-based signing
- Verify image signatures
- Implement keyless signing with Sigstore
- Attach and verify SBOMs
- Create and verify attestations
- Integrate signing into CI/CD workflows

## Prerequisites

- Completed Lab 01 (Trivy Scanning)
- Access to a container registry (Docker Hub, GHCR, or private)
- Docker or Podman installed
- kubectl configured
- Basic understanding of public key cryptography

## Estimated Time

75 minutes

## Lab Scenario

Your organization requires all production images to be cryptographically signed to ensure authenticity and integrity. You'll implement image signing using Cosign, establish verification workflows, and integrate signing into your deployment pipeline.

## Part 1: Installation and Setup

### Step 1: Install Cosign

**Linux:**
```bash
COSIGN_VERSION=$(curl -s https://api.github.com/repos/sigstore/cosign/releases/latest | grep tag_name | cut -d '"' -f 4 | tr -d 'v')
curl -LO https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64
chmod +x cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign
```

**macOS:**
```bash
brew install cosign
```

### Step 2: Verify Installation

```bash
cosign version
```

Expected output:
```
GitVersion:    2.2.3
GitCommit:     a989b1e
Platform:      linux/amd64
```

### Step 3: Setup Lab Environment

```bash
# Create working directory
mkdir -p ~/cosign-lab
cd ~/cosign-lab

# Create namespace
kubectl create namespace cosign-lab
kubectl config set-context --current --namespace=cosign-lab
```

## Part 2: Key-Based Signing

### Exercise 1: Generate Key Pair

Generate a signing key pair:

```bash
cosign generate-key-pair
```

You'll be prompted for a password:
```
Enter password for private key:
Enter password for private key again:
Private key written to cosign.key
Public key written to cosign.pub
```

**Important:** Store the private key securely!

View the keys:
```bash
ls -l cosign.*
cat cosign.pub
```

### Exercise 2: Build and Sign an Image

Create a sample application:

```bash
cat > Dockerfile <<EOF
FROM gcr.io/distroless/static-debian12
COPY <<SCRIPT_EOF /app
#!/bin/sh
echo "Signed application v1.0"
SCRIPT_EOF
CMD ["/app"]
EOF
```

Build the image:
```bash
# Replace with your registry
REGISTRY="docker.io/yourusername"
IMAGE="${REGISTRY}/signed-app:v1.0"

docker build -t ${IMAGE} .
```

Push the image:
```bash
docker login
docker push ${IMAGE}
```

Sign the image:
```bash
cosign sign --key cosign.key ${IMAGE}
```

Enter your private key password when prompted.

Output:
```
Enter password for private key:
Pushing signature to: docker.io/yourusername/signed-app:sha256-abc123.sig
```

### Exercise 3: Verify Signed Image

Verify the signature:

```bash
cosign verify --key cosign.pub ${IMAGE}
```

Expected output (JSON):
```json
[
  {
    "critical": {
      "identity": {
        "docker-reference": "docker.io/yourusername/signed-app"
      },
      "image": {
        "docker-manifest-digest": "sha256:abc123..."
      },
      "type": "cosign container image signature"
    },
    "optional": {
      "Bundle": {
        "SignedEntryTimestamp": "...",
        "Payload": {
          "body": "...",
          "integratedTime": 1234567890,
          "logIndex": 12345
        }
      }
    }
  }
]
```

View signature location:
```bash
cosign triangulate ${IMAGE}
```

### Exercise 4: Sign with Annotations

Add metadata to signatures:

```bash
cosign sign --key cosign.key \\
  -a env=production \\
  -a team=platform \\
  -a build-id=12345 \\
  -a commit=$(git rev-parse --short HEAD 2>/dev/null || echo "local") \\
  ${IMAGE}
```

Verify with annotation checking:
```bash
cosign verify --key cosign.pub -a env=production ${IMAGE}
```

This ensures the image has the correct environment annotation.

### Exercise 5: Sign Image Digest

For immutability, sign using digest:

```bash
# Get image digest
IMAGE_DIGEST=$(docker inspect ${IMAGE} --format='{{index .RepoDigests 0}}')
echo "Digest: ${IMAGE_DIGEST}"

# Sign digest
cosign sign --key cosign.key ${IMAGE_DIGEST}
```

Verify digest signature:
```bash
cosign verify --key cosign.pub ${IMAGE_DIGEST}
```

## Part 3: Keyless Signing with Sigstore

### Exercise 6: Keyless Signing

Sign without managing keys:

```bash
# Build new version
IMAGE_V2="${REGISTRY}/signed-app:v2.0"
docker build -t ${IMAGE_V2} .
docker push ${IMAGE_V2}

# Sign keyless (will open browser)
cosign sign ${IMAGE_V2}
```

Follow the prompts:
1. Browser opens for OIDC authentication
2. Login with GitHub, Google, or Microsoft
3. Approve the signature

Expected output:
```
Generating ephemeral keys...
Retrieving signed certificate...

Note that there may be personally identifiable information associated with this signed artifact.
This may include the email address associated with the account with which you authenticate.
This information will be used for signing this artifact and will be stored in public transparency logs.

By typing 'y', you attest that you grant (or have permission to grant) permission.

Are you sure you would like to continue? [y/N] y

Your browser will now be opened to:
https://oauth2.sigstore.dev/auth/auth?...

Successfully verified SCT...
tlog entry created with index: 12345678
Pushing signature to: docker.io/yourusername/signed-app
```

### Exercise 7: Verify Keyless Signature

Verify using identity:

```bash
# Replace with your email/identity
IDENTITY="your-email@example.com"
ISSUER="https://github.com/login/oauth"  # or your OIDC provider

cosign verify \\
  --certificate-identity ${IDENTITY} \\
  --certificate-oidc-issuer ${ISSUER} \\
  ${IMAGE_V2}
```

Or use regex for identity:
```bash
cosign verify \\
  --certificate-identity-regexp ".*@example\\.com" \\
  --certificate-oidc-issuer ${ISSUER} \\
  ${IMAGE_V2}
```

## Part 4: SBOM Attestation

### Exercise 8: Generate and Attach SBOM

Generate SBOM:
```bash
trivy image --format spdx-json --output sbom.spdx.json ${IMAGE}
```

Attach SBOM to image:
```bash
cosign attach sbom --sbom sbom.spdx.json ${IMAGE}
```

Sign the SBOM:
```bash
# Get SBOM reference
SBOM_REF=$(cosign triangulate --type sbom ${IMAGE})
echo "SBOM Reference: ${SBOM_REF}"

# Sign the SBOM
cosign sign --key cosign.key ${SBOM_REF}
```

### Exercise 9: Download and Verify SBOM

Download SBOM:
```bash
cosign download sbom ${IMAGE} > downloaded-sbom.json
```

Verify SBOM signature:
```bash
cosign verify --key cosign.pub ${SBOM_REF}
```

Compare SBOMs:
```bash
diff sbom.spdx.json downloaded-sbom.json
```

## Part 5: Attestations

### Exercise 10: Create and Sign Attestations

Create a build provenance attestation:

```bash
cat > provenance.json <<EOF
{
  "buildType": "https://example.com/build-type/v1",
  "builder": {
    "id": "https://github.com/actions/runner"
  },
  "invocation": {
    "configSource": {
      "uri": "https://github.com/myorg/myrepo",
      "digest": {
        "sha256": "abc123..."
      }
    }
  },
  "metadata": {
    "buildStartedOn": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "buildFinishedOn": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  }
}
EOF
```

Attach attestation:
```bash
cosign attest --key cosign.key \\
  --predicate provenance.json \\
  --type slsaprovenance \\
  ${IMAGE}
```

### Exercise 11: Verify Attestations

Verify attestation:
```bash
cosign verify-attestation --key cosign.pub \\
  --type slsaprovenance \\
  ${IMAGE}
```

Download attestation:
```bash
cosign download attestation ${IMAGE} | jq .
```

## Part 6: Kubernetes Integration

### Exercise 12: Store Public Key in Kubernetes

Create ConfigMap with public key:

```bash
kubectl create configmap cosign-keys \\
  --from-file=cosign.pub=cosign.pub \\
  -n cosign-lab
```

Verify:
```bash
kubectl get configmap cosign-keys -o yaml
```

### Exercise 13: Verify Before Deploy

Create an init container that verifies signatures:

```bash
cat > verified-deployment.yaml <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: verified-app
  namespace: cosign-lab
spec:
  initContainers:
  - name: verify-signature
    image: gcr.io/projectsigstore/cosign:latest
    command:
    - cosign
    - verify
    - --key
    - /keys/cosign.pub
    - ${IMAGE}
    volumeMounts:
    - name: cosign-keys
      mountPath: /keys
      readOnly: true
  containers:
  - name: app
    image: ${IMAGE}
  volumes:
  - name: cosign-keys
    configMap:
      name: cosign-keys
EOF

kubectl apply -f verified-deployment.yaml
```

Check init container logs:
```bash
kubectl logs verified-app -c verify-signature
```

If verification succeeds, the pod starts. If it fails, the pod won't start.

### Exercise 14: Test with Unsigned Image

Try deploying an unsigned image:

```bash
# Build unsigned image
UNSIGNED_IMAGE="${REGISTRY}/unsigned-app:v1.0"
echo 'FROM alpine:3.19\nCMD ["echo", "unsigned"]' | docker build -t ${UNSIGNED_IMAGE} -
docker push ${UNSIGNED_IMAGE}

# Try to deploy (should fail verification)
cat > unsigned-deployment.yaml <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: unsigned-app
  namespace: cosign-lab
spec:
  initContainers:
  - name: verify-signature
    image: gcr.io/projectsigstore/cosign:latest
    command:
    - cosign
    - verify
    - --key
    - /keys/cosign.pub
    - ${UNSIGNED_IMAGE}
    volumeMounts:
    - name: cosign-keys
      mountPath: /keys
  containers:
  - name: app
    image: ${UNSIGNED_IMAGE}
  volumes:
  - name: cosign-keys
    configMap:
      name: cosign-keys
EOF

kubectl apply -f unsigned-deployment.yaml
```

Check status:
```bash
kubectl get pod unsigned-app
kubectl logs unsigned-app -c verify-signature
```

Expected: Init container fails with "no matching signatures" error.

## Part 7: CI/CD Integration

### Exercise 15: CI/CD Signing Script

Create an automated signing script:

```bash
cat > ci-sign.sh <<'EOF'
#!/bin/bash

set -e

IMAGE=$1
KEY_PATH=${2:-"cosign.key"}
KEY_PASSWORD=${3:-"${COSIGN_PASSWORD}"}

if [ -z "$IMAGE" ]; then
  echo "Usage: $0 <image> [key-path] [password]"
  exit 1
fi

echo "Signing image: $IMAGE"

# Sign with key
export COSIGN_PASSWORD=$KEY_PASSWORD
cosign sign --key $KEY_PATH \\
  -a pipeline=automated \\
  -a timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ) \\
  -a git-sha=$(git rev-parse HEAD 2>/dev/null || echo "unknown") \\
  $IMAGE

echo "✅ Image signed successfully"

# Generate and attach SBOM
echo "Generating SBOM..."
trivy image --format spdx-json --output sbom.spdx.json $IMAGE

echo "Attaching SBOM..."
cosign attach sbom --sbom sbom.spdx.json $IMAGE

# Sign SBOM
SBOM_REF=$(cosign triangulate --type sbom $IMAGE)
cosign sign --key $KEY_PATH $SBOM_REF

echo "✅ SBOM signed and attached"
EOF

chmod +x ci-sign.sh
```

Test the script:
```bash
export COSIGN_PASSWORD="your-key-password"
./ci-sign.sh ${IMAGE}
```

### Exercise 16: GitHub Actions Workflow

Create a GitHub Actions workflow:

```bash
cat > .github-workflow-example.yaml <<'EOF'
name: Build, Sign, and Push

on:
  push:
    branches: [main]

jobs:
  build-and-sign:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      id-token: write

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Login to Registry
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and Push
        uses: docker/build-push-action@v5
        with:
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.sha }}

      - name: Install Cosign
        uses: sigstore/cosign-installer@v3

      - name: Sign Image (Keyless)
        run: |
          cosign sign --yes ghcr.io/${{ github.repository }}:${{ github.sha }}
        env:
          COSIGN_EXPERIMENTAL: 1

      - name: Generate SBOM
        run: |
          trivy image --format spdx-json \\
            --output sbom.spdx.json \\
            ghcr.io/${{ github.repository }}:${{ github.sha }}

      - name: Attach and Sign SBOM
        run: |
          cosign attach sbom --sbom sbom.spdx.json ghcr.io/${{ github.repository }}:${{ github.sha }}
          cosign sign --yes $(cosign triangulate --type sbom ghcr.io/${{ github.repository }}:${{ github.sha }})
        env:
          COSIGN_EXPERIMENTAL: 1
EOF
```

## Verification and Testing

### Comprehensive Test Script

```bash
cat > test-signing.sh <<'EOF'
#!/bin/bash

echo "=== Cosign Lab Verification ==="

# Test 1: Cosign installation
echo "Test 1: Verify Cosign installation"
if command -v cosign &> /dev/null; then
  echo "✅ Cosign installed: $(cosign version --short)"
else
  echo "❌ Cosign not installed"
  exit 1
fi

# Test 2: Key pair exists
echo ""
echo "Test 2: Verify key pair"
if [ -f "cosign.key" ] && [ -f "cosign.pub" ]; then
  echo "✅ Key pair exists"
else
  echo "❌ Key pair missing"
fi

# Test 3: Signed image
echo ""
echo "Test 3: Verify signed image"
if [ -n "$IMAGE" ]; then
  cosign verify --key cosign.pub $IMAGE &> /dev/null
  if [ $? -eq 0 ]; then
    echo "✅ Image signature verified"
  else
    echo "❌ Image signature verification failed"
  fi
else
  echo "⚠️  IMAGE variable not set, skipping"
fi

# Test 4: SBOM attachment
echo ""
echo "Test 4: Verify SBOM attachment"
if [ -n "$IMAGE" ]; then
  cosign download sbom $IMAGE &> /dev/null
  if [ $? -eq 0 ]; then
    echo "✅ SBOM downloaded successfully"
  else
    echo "⚠️  No SBOM attached"
  fi
fi

echo ""
echo "=== Tests Complete ==="
EOF

chmod +x test-signing.sh
IMAGE=${IMAGE} ./test-signing.sh
```

## Challenge Questions

1. **What's the difference between key-based and keyless signing?**
   <details>
   <summary>Answer</summary>
   Key-based requires managing private/public keys. Keyless uses OIDC for identity and short-lived certificates from Fulcio, eliminating key management overhead.
   </details>

2. **Where are signatures stored?**
   <details>
   <summary>Answer</summary>
   Signatures are stored as OCI artifacts in the same registry as the image, with a reference like `registry/image:sha256-digest.sig`.
   </details>

3. **How do you rotate signing keys?**
   <details>
   <summary>Answer</summary>

   ```bash
   # Generate new key pair
   cosign generate-key-pair -new

   # Sign future images with new key
   cosign sign --key cosign-new.key image:tag

   # Keep old key for verifying old signatures
   # Update verification policies to trust both keys
   ```
   </details>

## Cleanup

```bash
# Delete namespace
kubectl delete namespace cosign-lab

# Remove images (optional)
docker rmi ${IMAGE} ${IMAGE_V2} ${UNSIGNED_IMAGE}

# Remove working directory
cd ~
rm -rf ~/cosign-lab

# Reset namespace
kubectl config set-context --current --namespace=default
```

**Important:** Keep your key pair in a secure location if you plan to continue using it!

## Key Takeaways

1. Cosign provides simple container signing and verification
2. Key-based signing requires key management
3. Keyless signing uses OIDC and transparency logs
4. Signatures are stored as OCI artifacts
5. Always sign using image digest for immutability
6. Annotations add valuable metadata to signatures
7. SBOMs can be attached and signed
8. Init containers can verify signatures before deployment
9. Integrate signing into CI/CD pipelines
10. Use admission controllers for policy enforcement

## Next Steps

1. Implement signing in your CI/CD pipeline
2. Create key rotation procedures
3. Proceed to [Lab 03: Registry Security](./lab-03-registry-security.md)

---

[← Back to Lab Overview](./README.md) | [Previous Lab: Trivy Scanning ←](./lab-01-trivy-scanning.md) | [Next Lab: Registry Security →](./lab-03-registry-security.md)
