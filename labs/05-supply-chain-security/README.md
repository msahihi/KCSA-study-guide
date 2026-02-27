# Domain 5 Labs: Supply Chain Security

## Overview

These hands-on labs provide practical experience with container supply chain security tools and techniques. You'll learn to scan images for vulnerabilities, sign and verify images, secure registries, generate SBOMs, and implement admission control for supply chain security.

## Lab Environment Requirements

### Required Tools

- Kubernetes cluster v1.30+ (kind, minikube, or cloud-based)
- kubectl v1.30+
- Docker or Podman
- Trivy v0.50.0+
- Cosign v2.0+
- Syft v0.50.0+
- curl, jq, openssl

### Optional Tools

- Grype (for SBOM scanning)
- Kyverno or OPA Gatekeeper (for admission control)
- Harbor (for private registry labs)

### Setup Script

```bash

#!/bin/bash
# setup-lab-environment.sh

echo "Installing Supply Chain Security Tools..."

# Install Trivy

echo "Installing Trivy..."
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Cosign

echo "Installing Cosign..."
COSIGN_VERSION=$(curl -s https://api.github.com/repos/sigstore/cosign/releases/latest | grep tag_name | cut -d '"' -f 4 | tr -d 'v')
curl -LO https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64
chmod +x cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign

# Install Syft

echo "Installing Syft..."
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install Grype

echo "Installing Grype..."
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Verify installations

echo ""
echo "Verifying installations..."
trivy --version
cosign version
syft version
grype version

echo ""
echo "Setup complete! Ready for labs."
```

```

## Labs

### [Lab 01: Trivy Image Scanning](./lab-01-trivy-scanning.md)

**Duration:** 60 minutes
**Difficulty:** Beginner

Learn to scan container images for vulnerabilities using Trivy. You'll scan various images, interpret results, filter by severity, and integrate scanning into workflows.

**Skills Covered:**

- Installing and configuring Trivy
- Scanning container images for vulnerabilities
- Interpreting scan results and CVEs
- Filtering by severity and fixing vulnerabilities
- Scanning Kubernetes workloads
- Integrating Trivy into CI/CD

**Prerequisites:**

- Basic Docker knowledge
- Understanding of CVEs and vulnerability scoring

---

### [Lab 02: Image Signing with Cosign](./lab-02-image-signing-cosign.md)

**Duration:** 75 minutes
**Difficulty:** Intermediate

Implement image signing and verification using Cosign. You'll generate keys, sign images, verify signatures, and explore keyless signing with Sigstore.

**Skills Covered:**

- Installing and configuring Cosign
- Generating signing key pairs
- Signing container images
- Verifying image signatures
- Keyless signing with Sigstore
- Attaching SBOMs and attestations

**Prerequisites:**

- Completed Lab 01
- Basic understanding of cryptography
- Access to container registry

---

### [Lab 03: Registry Security](./lab-03-registry-security.md)

**Duration:** 90 minutes
**Difficulty:** Intermediate

Secure container registries with authentication, encryption, and access controls. You'll create ImagePullSecrets, configure private registries, and implement registry security best practices.

**Skills Covered:**

- Creating and managing ImagePullSecrets
- Configuring private registry access
- Setting up authentication and TLS
- Implementing RBAC for registries
- Docker Content Trust
- Cloud registry integration (ECR, GCR, ACR)

**Prerequisites:**

- Completed Labs 01 and 02
- Basic Kubernetes Secrets knowledge
- Access to container registry

---

### [Lab 04: SBOM Generation and Analysis](./lab-04-sbom-generation.md)

**Duration:** 60 minutes
**Difficulty:** Beginner to Intermediate

Generate and analyze Software Bills of Materials (SBOMs) for container images. You'll create SBOMs in different formats, query them, and use SBOMs for vulnerability management.

**Skills Covered:**

- Generating SBOMs with Trivy and Syft
- Understanding SPDX and CycloneDX formats
- Analyzing SBOM contents with jq
- Scanning SBOMs for vulnerabilities
- Attaching SBOMs to images
- SBOM quality assessment

**Prerequisites:**

- Completed Lab 01
- Basic jq knowledge helpful
- Understanding of software dependencies

---

### [Lab 05: Admission Control for Supply Chain Security](./lab-05-admission-scanning.md)

**Duration:** 90 minutes
**Difficulty:** Advanced

Implement admission control to enforce supply chain security policies. You'll use Kyverno or OPA Gatekeeper to require signed images, block vulnerable images, and enforce registry restrictions.

**Skills Covered:**

- Installing admission controllers (Kyverno)
- Creating image signature verification policies
- Blocking vulnerable images
- Enforcing registry restrictions
- Testing policy enforcement
- Troubleshooting admission failures

**Prerequisites:**

- Completed Labs 01-04
- Understanding of Kubernetes admission controllers
- Advanced Kubernetes knowledge

---

## Lab Progression

We recommend completing the labs in order:

```

Lab 01: Trivy Scanning (Foundation)
    ↓
Lab 02: Image Signing (Build on scanning)
    ↓
Lab 03: Registry Security (Secure distribution)
    ↓
Lab 04: SBOM Generation (Inventory and tracking)
    ↓
Lab 05: Admission Control (Policy enforcement)

```
```

## Common Lab Environment

All labs use a consistent environment:

```bash

# Namespace for labs

kubectl create namespace supply-chain-labs

# Set as default

kubectl config set-context --current --namespace=supply-chain-labs
```

```

## Lab Cleanup

Each lab includes cleanup instructions. To clean up all labs:

```bash

# Delete lab namespace

kubectl delete namespace supply-chain-labs

# Remove local images

docker image prune -a -f

# Remove generated files

rm -rf ~/supply-chain-labs
```

```

## Troubleshooting

### Issue: Tool installation fails

**Solution:**

- Check internet connectivity
- Verify sudo/root permissions
- Review firewall rules
- Try manual installation from GitHub releases

### Issue: Kubernetes cluster not accessible

**Solution:**

```bash

# Check cluster status

kubectl cluster-info

# Verify context

kubectl config current-context

# Test connectivity

kubectl get nodes
```

```

### Issue: Registry authentication fails

**Solution:**

```bash

# Verify Docker login

docker login

# Check ImagePullSecret

kubectl get secret regcred -o yaml

# Test manual pull

docker pull <image>
```

```

### Issue: Admission controller not blocking

**Solution:**

```bash

# Check admission controller status

kubectl get pods -n kyverno

# View policy

kubectl get clusterpolicy

# Check policy violations

kubectl describe clusterpolicy <policy-name>
```

```

## Additional Resources

### Documentation

- [Trivy Documentation](https://trivy.dev/)
- [Cosign Documentation](https://edu.chainguard.dev/open-source/sigstore/cosign/an-introduction-to-cosign/)
- [Syft Documentation](https://github.com/anchore/syft)
- [Kyverno Documentation](https://kyverno.io/docs/)

### Sample Images

```bash

# Vulnerable images for testing

docker.io/vulnerables/web-dvwa
docker.io/vulnerables/cve-2017-7494
docker.io/vulnerables/metasploit-vulnerability

# Clean images

gcr.io/distroless/static-debian12
gcr.io/distroless/base-debian12
```

```

### Practice Repositories

- [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat) - Vulnerable by design
- [Example Voting App](https://github.com/dockersamples/example-voting-app) - Multi-tier app

## Lab Completion Checklist

After completing all labs, you should be able to:

- [ ] Scan container images with Trivy
- [ ] Interpret vulnerability scan results
- [ ] Generate signing keys with Cosign
- [ ] Sign and verify container images
- [ ] Implement keyless signing
- [ ] Create and manage ImagePullSecrets
- [ ] Configure private registry access
- [ ] Generate SBOMs in multiple formats
- [ ] Query and analyze SBOM contents
- [ ] Attach SBOMs to container images
- [ ] Install and configure admission controllers
- [ ] Create policies to verify image signatures
- [ ] Block deployment of vulnerable images
- [ ] Enforce registry restrictions
- [ ] Troubleshoot supply chain security issues

## Exam Preparation

These labs cover key exam topics:

| Exam Topic | Lab Coverage |
| ------------ | -------------- |
| Image Scanning | Lab 01, Lab 05 |
| Image Signing | Lab 02, Lab 05 |
| Registry Security | Lab 03 |
| SBOM | Lab 04 |
| Admission Control | Lab 05 |

## Time Estimates

| Lab | Estimated Time | Difficulty |
| ----- | ---------------- | ------------ |
| Lab 01 | 60 minutes | Beginner |
| Lab 02 | 75 minutes | Intermediate |
| Lab 03 | 90 minutes | Intermediate |
| Lab 04 | 60 minutes | Beginner-Intermediate |
| Lab 05 | 90 minutes | Advanced |
| **Total** | **6 hours** | Mixed |

## Next Steps

1. Set up your lab environment
1. Start with [Lab 01: Trivy Scanning](./lab-01-trivy-scanning.md)
1. Complete labs in sequence
1. Review [Domain 5 README](../../domains/05-supply-chain-security/README.md)
1. Practice exam scenarios

---

[Back to Domain 5 README](../../domains/05-supply-chain-security/README.md)
