# Image Signing and Verification

## Overview

Container image signing is a cryptographic technique used to verify the authenticity and integrity of container images. By signing images, you create a digital signature that proves the image came from a trusted source and hasn't been tampered with since signing.

Think of image signing like a wax seal on a letter - it proves who sent it and that no one has opened it along the way. In the container world, this ensures that the image you deploy is exactly what the publisher intended, with no malicious modifications.

## Why Image Signing Matters

1. **Authenticity**: Verify the image came from a trusted publisher
1. **Integrity**: Ensure the image hasn't been modified or corrupted
1. **Non-Repudiation**: Publisher cannot deny signing the image
1. **Supply Chain Security**: Prevent supply chain attacks
1. **Compliance**: Meet regulatory requirements for software provenance
1. **Trust**: Build confidence in your deployment pipeline

## Real-World Attack Scenarios

### Without Image Signing

**Scenario 1: Registry Compromise**

- Attacker gains access to registry
- Replaces legitimate image with malicious version
- You pull and deploy the malicious image
- **Result**: Compromised workload

**Scenario 2: Man-in-the-Middle Attack**

- Image pulled over insecure connection
- Attacker intercepts and modifies image
- Modified image deployed to cluster
- **Result**: Backdoor in production

**Scenario 3: Tag Mutation**

- Developer pushes nginx:latest
- Later, someone pushes different nginx:latest
- You deploy thinking it's the same image
- **Result**: Unexpected behavior or vulnerabilities

### With Image Signing

All scenarios above are prevented because:

- Signature verification fails for tampered images
- Only images signed by trusted keys are deployed
- Tag mutation is detected via digest verification
- Complete audit trail of who signed what

## Cosign: Container Signing Made Easy

Cosign is a CNCF project that provides container signing, verification, and storage in an OCI registry. It's part of the Sigstore project, which aims to improve software supply chain security.

### Cosign Features

1. **Simple CLI**: Easy-to-use command-line interface
1. **OCI Registry Storage**: Signatures stored alongside images
1. **Keyless Signing**: No key management required (using OIDC)
1. **Hardware Token Support**: YubiKey, PIV cards
1. **Policy Enforcement**: Integration with admission controllers
1. **SBOM Attestation**: Attach and verify SBOMs
1. **Multiple Signature Formats**: Support for various formats

## Installing Cosign

### Linux (Binary)

```bash

# Download latest release

COSIGN_VERSION=$(curl -s https://api.github.com/repos/sigstore/cosign/releases/latest | grep tag_name | cut -d '"' -f 4 | tr -d 'v')
curl -LO https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64
chmod +x cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign
```

```

### macOS (Homebrew)

```bash

brew install cosign
```

```

### Linux (apt)

```bash

wget -O- https://github.com/sigstore/cosign/releases/download/v2.2.3/cosign-2.2.3-1.x86_64.rpm
sudo rpm -ivh cosign-2.2.3-1.x86_64.rpm
```

```

### Verify Installation

```bash

cosign version
```

```

Expected output:

```

GitVersion:    2.2.3
GitCommit:     a989b1e67cf9913bb0e5e5cf16be0bbf4c7ae70c
GitTreeState:  clean
BuildDate:     2024-01-15T10:30:00Z
GoVersion:     go1.21.5
Compiler:      gc
Platform:      linux/amd64

```
```

## Key Pair Signing

### Generate Key Pair

Generate a new signing key pair:

```bash

cosign generate-key-pair
```

```

This creates two files:

- `cosign.key`: Private key (keep secret!)
- `cosign.pub`: Public key (distribute freely)

You'll be prompted for a password to encrypt the private key:

```

Enter password for private key:
Enter password for private key again:
Private key written to cosign.key
Public key written to cosign.pub

```
```

**Important**: Store the private key securely:

- Use a password manager
- Store in a secrets management system (Vault, AWS Secrets Manager)
- Never commit to version control
- Rotate keys regularly

### Sign an Image

Sign a container image:

```bash

cosign sign --key cosign.key myregistry.com/myapp:v1.0
```

```

You'll be prompted for the private key password:

```

Enter password for private key:
Pushing signature to: myregistry.com/myapp:sha256-abc123.sig

```
```

The signature is stored in the same registry as the image.

### Verify Image Signature

Verify the image signature using the public key:

```bash

cosign verify --key cosign.pub myregistry.com/myapp:v1.0
```

```

Successful verification output:

```json

[
  {
    "critical": {
      "identity": {
        "docker-reference": "myregistry.com/myapp"
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

```

If verification fails:

```

Error: no matching signatures

```
```

## Keyless Signing with Sigstore

Keyless signing eliminates the need to manage private keys by using OIDC (OpenID Connect) identity tokens.

### How Keyless Signing Works

1. User authenticates via OIDC provider (GitHub, Google, Microsoft)
1. Receives short-lived certificate from Fulcio (certificate authority)
1. Signs image with ephemeral key
1. Signature and certificate stored in Rekor (transparency log)
1. Short-lived key is discarded
1. Verification checks transparency log

### Sign Image (Keyless)

```bash

cosign sign myregistry.com/myapp:v1.0
```

```

This will:

1. Open browser for OIDC authentication
1. Sign image with ephemeral key
1. Store signature in registry
1. Record signature in Rekor transparency log

Example output:

```

Generating ephemeral keys...
Retrieving signed certificate...

Note that there may be personally identifiable information associated with this signed artifact.
This may include the email address associated with the account with which you authenticate.
This information will be used for signing this artifact and will be stored in public transparency logs and cannot be removed later.

By typing 'y', you attest that you grant (or have permission to grant) and agree to have this information stored permanently in transparency logs.

Are you sure you would like to continue? [y/N] y

Your browser will now be opened to:
https://oauth2.sigstore.dev/auth/auth?...

Successfully verified SCT...
tlog entry created with index: 12345678
Pushing signature to: myregistry.com/myapp

```
```

### Verify Keyless Signature

Verify without needing a public key:

```bash

cosign verify \
  --certificate-identity user@example.com \
  --certificate-oidc-issuer https://github.com/login/oauth \
  myregistry.com/myapp:v1.0
```

```

Or verify against specific OIDC claims:

```bash

cosign verify \
  --certificate-identity-regexp ".*@example\\.com" \
  --certificate-oidc-issuer https://accounts.google.com \
  myregistry.com/myapp:v1.0
```

```

## Advanced Signing Scenarios

### Sign Multiple Images

```bash

# Sign with the same key

cosign sign --key cosign.key \
  myregistry.com/myapp:v1.0 \
  myregistry.com/myapp:v1.1 \
  myregistry.com/myapp:latest
```

```

### Sign with Annotations

Add metadata to signatures:

```bash

cosign sign --key cosign.key \
  -a env=production \
  -a team=platform \
  -a build=12345 \
  myregistry.com/myapp:v1.0
```

```

Verify with annotation check:

```bash

cosign verify --key cosign.pub \
  -a env=production \
  myregistry.com/myapp:v1.0
```

```

### Sign Image Digest

Sign using image digest (recommended for immutability):

```bash

# Get image digest

IMAGE_DIGEST=$(docker inspect myregistry.com/myapp:v1.0 --format='{{.RepoDigests}}')

# Sign digest

cosign sign --key cosign.key myregistry.com/myapp@sha256:abc123...
```

```

### Attach SBOM to Image

```bash

# Generate SBOM

trivy image -f spdx-json -o sbom.json myapp:v1.0

# Attach SBOM

cosign attach sbom --sbom sbom.json myapp:v1.0

# Sign the SBOM

cosign sign --key cosign.key $(cosign triangulate myapp:v1.0)
```

```

### Attach and Sign Attestations

```bash

# Create attestation

cosign attest --key cosign.key \
  --predicate attestation.json \
  --type slsaprovenance \
  myregistry.com/myapp:v1.0

# Verify attestation

cosign verify-attestation --key cosign.pub \
  --type slsaprovenance \
  myregistry.com/myapp:v1.0
```

```

## Hardware Token Support

### YubiKey Signing

Generate key on YubiKey:

```bash

cosign generate-key-pair --kms yubikey://
```

```

Sign with YubiKey:

```bash

cosign sign --key yubikey:// myregistry.com/myapp:v1.0
```

```

### PIV/PKCS11 Support

```bash

# Sign with PIV token

cosign sign --key piv://slot-id=9c myregistry.com/myapp:v1.0

# Sign with PKCS11

cosign sign --key pkcs11:token=mytoken;object=mykey myregistry.com/myapp:v1.0
```

```

## Cloud KMS Integration

### AWS KMS

```bash

# Create key in AWS KMS

aws kms create-key --description "Cosign signing key"

# Sign with AWS KMS

cosign sign --key awskms:///arn:aws:kms:region:account:key/key-id myregistry.com/myapp:v1.0

# Verify

cosign verify --key awskms:///arn:aws:kms:region:account:key/key-id myregistry.com/myapp:v1.0
```

```

### Google Cloud KMS

```bash

# Sign with GCP KMS

cosign sign --key gcpkms://projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY myregistry.com/myapp:v1.0
```

```

### Azure Key Vault

```bash

# Sign with Azure Key Vault

cosign sign --key azurekms://vault-name.vault.azure.net/keys/key-name/key-version myregistry.com/myapp:v1.0
```

```

### HashiCorp Vault

```bash

# Sign with Vault Transit

cosign sign --key hashivault://transit/keys/my-key myregistry.com/myapp:v1.0
```

```

## Policy Enforcement with Admission Controllers

### Kubernetes Policy with Kyverno

Create a policy to require signed images:

```yaml

apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signatures
spec:
  validationFailureAction: Enforce
  rules:
  - name: verify-signature
    match:
      any:
      - resources:
          kinds:
          - Pod
    verifyImages:
    - imageReferences:
      - "myregistry.com/*"
      attestors:
      - count: 1
        entries:
        - keys:
            publicKeys: |-
              -----BEGIN PUBLIC KEY-----
              MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
              -----END PUBLIC KEY-----
```

```

Test the policy:

```bash

# This will succeed (signed image)

kubectl run nginx --image=myregistry.com/myapp:signed

# This will fail (unsigned image)

kubectl run nginx --image=myregistry.com/myapp:unsigned
```

```

### Kubernetes Policy with OPA Gatekeeper

```yaml

apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8simagesignature
spec:
  crd:
    spec:
      names:
        kind: K8sImageSignature
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8simagesignature

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not verified_signature(container.image)
          msg := sprintf("Image %v is not signed", [container.image])
        }

        verified_signature(image) {

          # Implement signature verification logic
          # This would call out to Cosign verification

        }
```

```

### Policy Controller (Sigstore)

Install Policy Controller:

```bash

kubectl apply -f https://github.com/sigstore/policy-controller/releases/latest/download/release.yaml
```

```

Create a ClusterImagePolicy:

```yaml

apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: require-signed-images
spec:
  images:
  - glob: "myregistry.com/**"
  authorities:
  - keyless:
      url: https://fulcio.sigstore.dev
      identities:
      - issuer: https://github.com/login/oauth
        subject: user@example.com
```

```

## Signature Storage and Discovery

### Where Signatures Are Stored

Cosign stores signatures in the same OCI registry as images:

```

myregistry.com/myapp:v1.0           # Original image
myregistry.com/myapp:sha256-abc.sig  # Signature

```
```

### List Signatures

```bash

# View signature tags

cosign triangulate myregistry.com/myapp:v1.0

# Get signature details

cosign verify --key cosign.pub myregistry.com/myapp:v1.0
```

```

### Copy Signed Images

When copying images, copy signatures too:

```bash

# Using crane (part of go-containerregistry)

crane copy --all-tags myregistry.com/myapp registry2.com/myapp

# Or use cosign copy

cosign copy myregistry.com/myapp:v1.0 registry2.com/myapp:v1.0
```

```

## CI/CD Integration

### GitHub Actions

```yaml

name: Build and Sign Image

on:
  push:
    branches: [main]

jobs:
  build-and-sign:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      id-token: write  # For keyless signing

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
```

```

### GitLab CI

```yaml

sign-image:
  stage: sign
  image: gcr.io/projectsigstore/cosign:latest
  script:
    - echo $COSIGN_PRIVATE_KEY | base64 -d > cosign.key
    - cosign sign --key cosign.key $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  only:
    - main
  variables:
    COSIGN_PASSWORD: $COSIGN_KEY_PASSWORD
```

```

### Jenkins Pipeline

```groovy

pipeline {
    agent any

    environment {
        COSIGN_KEY = credentials('cosign-private-key')
        COSIGN_PASSWORD = credentials('cosign-password')
    }

    stages {
        stage('Build') {
            steps {
                sh 'docker build -t myapp:${BUILD_NUMBER} .'
                sh 'docker push myapp:${BUILD_NUMBER}'
            }
        }

        stage('Sign') {
            steps {
                sh '''
                    cosign sign --key ${COSIGN_KEY} myapp:${BUILD_NUMBER}
                '''
            }
        }
    }
}
```

```

## Best Practices

### 1. Sign Immutable Tags

Always sign using digest, not mutable tags:

```bash

# Bad: Tags can be overwritten

cosign sign --key cosign.key myapp:latest

# Good: Digest is immutable

cosign sign --key cosign.key myapp@sha256:abc123...
```

```

### 2. Key Management

**Private Keys:**

- Use hardware security modules (HSMs) or cloud KMS
- Rotate keys regularly (every 90 days)
- Use strong passwords (20+ characters)
- Never commit keys to version control
- Use separate keys for different environments

**Public Keys:**

- Distribute widely
- Store in version control
- Include in admission controller policies
- Document key rotation procedures

### 3. Keyless Signing for CI/CD

Use keyless signing in automated pipelines:

- No key management overhead
- Automatic transparency logging
- Identity-based verification
- Audit trail via OIDC

### 4. Verify Before Deploy

Always verify signatures before deployment:

```yaml

apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  initContainers:
  - name: verify-signature
    image: gcr.io/projectsigstore/cosign:latest
    command:
    - cosign
    - verify
    - --key
    - /keys/cosign.pub
    - myregistry.com/myapp:v1.0
    volumeMounts:
    - name: signing-keys
      mountPath: /keys
  containers:
  - name: myapp
    image: myregistry.com/myapp:v1.0
  volumes:
  - name: signing-keys
    configMap:
      name: cosign-public-keys
```

```

### 5. Implement Defense in Depth

Combine signing with other security measures:

- Image scanning (Trivy)
- SBOM generation
- Policy enforcement
- Network policies
- RBAC
- Pod Security Standards

### 6. Maintain Audit Trails

Log all signing operations:

```bash

# Sign with logging

cosign sign --key cosign.key myapp:v1.0 2>&1 | tee sign-$(date +%Y%m%d).log

# Include metadata

cosign sign --key cosign.key \
  -a signer=$(whoami) \
  -a timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -a build-id=$BUILD_ID \
  myapp:v1.0
```

```

### 7. Automated Verification

Create verification scripts:

```bash

#!/bin/bash
# verify-deployment.sh

NAMESPACE=$1
IMAGE=$(kubectl get deploy -n $NAMESPACE -o jsonpath='{.items[0].spec.template.spec.containers[0].image}')

echo "Verifying signature for: $IMAGE"
cosign verify --key cosign.pub $IMAGE

if [ $? -eq 0 ]; then
    echo "✓ Signature verified successfully"
else
    echo "✗ Signature verification failed"
    exit 1
fi
```

```

## Troubleshooting

### Issue: "Error: signing: sign: no provider found"

**Cause**: Can't find private key

**Solution:**

```bash

# Specify key path explicitly

cosign sign --key ./cosign.key myapp:v1.0

# Or use environment variable

export COSIGN_KEY_PATH=./cosign.key
cosign sign myapp:v1.0
```

```

### Issue: "Error: image reference must be specified"

**Cause**: Missing or incorrect image reference

**Solution:**

```bash

# Include full registry path

cosign sign --key cosign.key myregistry.com/myapp:v1.0

# Not just:

cosign sign --key cosign.key myapp:v1.0
```

```

### Issue: "Error: no matching signatures"

**Cause**: Image not signed or signature mismatch

**Solution:**

```bash

# Check if image is signed

cosign triangulate myapp:v1.0

# View all signatures

cosign verify --key cosign.pub --allow-insecure-registry myapp:v1.0

# Try with specific digest

cosign verify --key cosign.pub myapp@sha256:abc123...
```

```

### Issue: Keyless signing browser doesn't open

**Cause**: Running in non-interactive environment

**Solution:**

```bash

# Use COSIGN_EXPERIMENTAL environment

COSIGN_EXPERIMENTAL=1 cosign sign myapp:v1.0

# Or for CI/CD, use OIDC token directly

cosign sign --identity-token=$OIDC_TOKEN myapp:v1.0
```

```

### Issue: "Error: registry authentication failed"

**Cause**: Not logged into registry

**Solution:**

```bash

# Login first

docker login myregistry.com

# Or use cosign login

cosign login myregistry.com

# Or pass credentials

cosign sign --key cosign.key \
  --registry-username user \
  --registry-password pass \
  myapp:v1.0
```

```

## Key Points to Remember

1. Image signing proves authenticity and integrity
1. Cosign is the standard CNCF tool for signing
1. Keyless signing eliminates key management burden
1. Signatures are stored in OCI registries
1. Always verify signatures before deployment
1. Use immutable digests, not mutable tags
1. Integrate signing into CI/CD pipelines
1. Combine signing with admission controllers
1. Rotate signing keys regularly
1. Maintain comprehensive audit trails

## Exam Tips

1. Know Cosign command syntax thoroughly
1. Understand difference between key-based and keyless signing
1. Practice signing and verifying images quickly
1. Know how to generate and manage key pairs
1. Understand signature storage in OCI registries
1. Be able to troubleshoot verification failures
1. Know how to integrate with admission controllers

## Study Resources

### Official Documentation

- [Cosign Documentation](https://edu.chainguard.dev/open-source/sigstore/cosign/an-introduction-to-cosign/)
- [Sigstore](https://www.sigstore.dev/)
- [Policy Controller](https://docs.sigstore.dev/policy-controller/overview/)
- [Rekor Transparency Log](https://docs.sigstore.dev/rekor/overview/)

### Tools

- [Cosign](https://github.com/sigstore/cosign)
- [Kyverno](https://kyverno.io/)
- [OPA Gatekeeper](https://open-policy-agent.github.io/gatekeeper/)
- [Crane](https://github.com/google/go-containerregistry/tree/main/cmd/crane)

### Learning Resources

- [Sigstore Blog](https://blog.sigstore.dev/)
- [CNCF Supply Chain Security](https://www.cncf.io/blog/tag/supply-chain-security/)

## Next Steps

1. Complete the [Cosign Signing Lab](../../labs/05-supply-chain-security/lab-02-image-signing-cosign.md)
1. Practice signing various images
1. Learn about [Registry Security](./registry-security.md) next
1. Implement admission control policies

## Quick Reference

### Essential Commands

```bash

# Generate key pair

cosign generate-key-pair

# Sign image (key-based)

cosign sign --key cosign.key myapp:v1.0

# Sign image (keyless)

cosign sign myapp:v1.0

# Verify signature

cosign verify --key cosign.pub myapp:v1.0

# List signatures

cosign triangulate myapp:v1.0

# Attach SBOM

cosign attach sbom --sbom sbom.json myapp:v1.0

# Copy with signatures

cosign copy myapp:v1.0 registry2/myapp:v1.0

# Sign with annotations

cosign sign --key cosign.key -a env=prod myapp:v1.0

# Verify with annotations

cosign verify --key cosign.pub -a env=prod myapp:v1.0
```

```

---

[Back to Domain 5 README](./README.md) | [Previous: Image Scanning ←](./image-scanning.md) | [Next: Registry Security →](./registry-security.md)
