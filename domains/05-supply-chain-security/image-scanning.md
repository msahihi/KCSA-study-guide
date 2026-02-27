# Image Scanning

## Overview

Container image scanning is the process of analyzing container images to identify security vulnerabilities, misconfigurations, and compliance issues before deployment. By scanning images early in the development lifecycle, you can catch security issues before they reach production environments.

Think of image scanning like a security checkpoint at an airport - just as travelers and luggage are screened before boarding, container images should be scanned for threats before deployment to Kubernetes clusters.

## Why Image Scanning Matters

1. **Early Detection**: Identify vulnerabilities during development, not in production
1. **Compliance**: Meet regulatory requirements for vulnerability management
1. **Risk Reduction**: Prevent deployment of known vulnerable components
1. **Cost Efficiency**: Fixing vulnerabilities before deployment is cheaper than post-deployment patching
1. **Attack Surface Reduction**: Understand what's in your images to minimize unnecessary components

## How Vulnerabilities Enter Container Images

Vulnerabilities can be introduced through:

1. **Base Images**: Using outdated or vulnerable base images (e.g., old Ubuntu, Alpine versions)
1. **Application Dependencies**: Vulnerable libraries and packages (npm, pip, gem, maven)
1. **System Packages**: Operating system packages with known CVEs
1. **Configuration Issues**: Misconfigurations that create security risks
1. **Secret Exposure**: Hardcoded credentials or tokens in images

## Understanding CVEs and CVSS

### Common Vulnerabilities and Exposures (CVE)

CVE is a standardized system for identifying and cataloging security vulnerabilities:

- **CVE ID**: Unique identifier (e.g., CVE-2024-1234)
- **Description**: What the vulnerability is
- **Affected Software**: Which versions are vulnerable
- **References**: Links to advisories and patches

### Common Vulnerability Scoring System (CVSS)

CVSS provides a severity score (0-10) for vulnerabilities:

| Severity | CVSS Score | Risk Level | Action Required |
| ---------- | ------------ | ------------ | ---------------- |
| CRITICAL | 9.0-10.0 | Immediate threat | Patch immediately |
| HIGH | 7.0-8.9 | Serious risk | Patch within 7 days |
| MEDIUM | 4.0-6.9 | Moderate risk | Patch within 30 days |
| LOW | 0.1-3.9 | Minimal risk | Patch when convenient |
| UNKNOWN | N/A | Not assessed | Investigate further |

## Trivy: Comprehensive Vulnerability Scanner

Trivy is an open-source, easy-to-use vulnerability scanner developed by Aqua Security. It's the recommended tool for KCSA and is widely adopted in the Kubernetes ecosystem.

### Trivy Features

1. **Comprehensive Scanning**:

   - OS packages (Alpine, RHEL, CentOS, AlmaLinux, etc.)
   - Application dependencies (npm, pip, gem, cargo, etc.)
   - Infrastructure as Code (Terraform, CloudFormation, Kubernetes)
   - Filesystem and rootfs
   - Container images
   - Kubernetes clusters

1. **Multiple Vulnerability Databases**:

   - NVD (National Vulnerability Database)
   - Distribution-specific databases
   - Language-specific advisories
   - GitHub Security Advisory Database

1. **Easy to Use**:

   - Simple CLI interface
   - No complex setup required
   - Fast scanning
   - Multiple output formats

1. **CI/CD Integration**:

   - GitHub Actions
   - GitLab CI
   - CircleCI
   - Jenkins
   - Azure Pipelines

## Installing Trivy

### Linux (apt)

```bash
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy
```

```

### macOS (Homebrew)

```bash

brew install trivy
```

```

### Linux/macOS (Binary)

```bash

VERSION=$(curl --silent "https://api.github.com/repos/aquasecurity/trivy/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
wget https://github.com/aquasecurity/trivy/releases/download/v${VERSION}/trivy_${VERSION}_Linux-64bit.tar.gz
tar zxvf trivy_${VERSION}_Linux-64bit.tar.gz
sudo mv trivy /usr/local/bin/
```

```

### Verify Installation

```bash

trivy --version
```

```

Expected output:

```

Version: 0.50.1

```
```

## Basic Image Scanning

### Scan a Public Image

```bash

trivy image nginx:1.26
```

```

This command will:

1. Download the nginx:1.26 image (if not present locally)
1. Extract all layers and analyze packages
1. Check vulnerabilities against databases
1. Display results grouped by severity

### Scan Output Example

```

nginx:1.26 (debian 12.5)

Total: 45 (UNKNOWN: 0, LOW: 20, MEDIUM: 15, HIGH: 8, CRITICAL: 2)

┌───────────────┬────────────────┬──────────┬────────┬───────────────────┬───────────────┬────────────────────────────────────┐
│   Library     │ Vulnerability  │ Severity │ Status │ Installed Version │ Fixed Version │              Title                 │
├───────────────┼────────────────┼──────────┼────────┼───────────────────┼───────────────┼────────────────────────────────────┤
│ openssl       │ CVE-2024-1234  │ CRITICAL │ fixed  │ 3.0.11-1          │ 3.0.13-1      │ OpenSSL: Memory corruption in...   │
│ libssl3       │ CVE-2024-1234  │ CRITICAL │ fixed  │ 3.0.11-1          │ 3.0.13-1      │ OpenSSL: Memory corruption in...   │
└───────────────┴────────────────┴──────────┴────────┴───────────────────┴───────────────┴────────────────────────────────────┘

```
```

## Filtering Scan Results

### Filter by Severity

Scan only for HIGH and CRITICAL vulnerabilities:

```bash

trivy image --severity HIGH,CRITICAL nginx:1.26
```

```

Scan for specific severity level:

```bash

trivy image --severity CRITICAL nginx:1.26
```

```

### Ignore Unfixed Vulnerabilities

Many vulnerabilities don't have fixes available yet. To focus on actionable items:

```bash

trivy image --ignore-unfixed nginx:1.26
```

```

This shows only vulnerabilities with available patches.

### Combine Filters

```bash

trivy image --severity HIGH,CRITICAL --ignore-unfixed nginx:1.26
```

```

This shows only HIGH/CRITICAL vulnerabilities that can be fixed.

## Advanced Scanning Options

### Scan Specific Targets

**Scan a specific layer:**

```bash

trivy image --layers nginx:1.26
```

```

**Scan filesystem:**

```bash

trivy fs /path/to/project
```

```

**Scan tarball:**

```bash

trivy image --input nginx.tar
```

```

**Scan remote repository:**

```bash

trivy repo https://github.com/aquasecurity/trivy
```

```

### Output Formats

**JSON output:**

```bash

trivy image -f json -o results.json nginx:1.26
```

```

**Table output (default):**

```bash

trivy image -f table nginx:1.26
```

```

**SARIF output (for GitHub Security):**

```bash

trivy image -f sarif -o results.sarif nginx:1.26
```

```

**Template output:**

```bash

trivy image --format template --template "@contrib/gitlab.tpl" -o gl-container-scanning.json nginx:1.26
```

```

**CycloneDX SBOM:**

```bash

trivy image --format cyclonedx nginx:1.26
```

```

**SPDX SBOM:**

```bash

trivy image --format spdx-json nginx:1.26
```

```

### Quiet Mode

Only show summary:

```bash

trivy image --quiet nginx:1.26
```

```

### Exit Code on Vulnerabilities

Fail the scan if vulnerabilities are found:

```bash

trivy image --exit-code 1 --severity HIGH,CRITICAL nginx:1.26
```

```

This returns:

- Exit code 0: No vulnerabilities found
- Exit code 1: Vulnerabilities found

Perfect for CI/CD pipelines!

## Scanning Local Images

### Build and Scan

```bash

# Build an image

docker build -t myapp:1.0 .

# Scan the local image

trivy image myapp:1.0
```

```

### Scan Without Pulling

If the image exists locally:

```bash

trivy image --no-pull myapp:1.0
```

```

## Scanning Private Registry Images

### With Authentication

```bash

# Using environment variables

export TRIVY_USERNAME=myuser
export TRIVY_PASSWORD=mypassword
trivy image registry.example.com/myapp:1.0

# Or use Docker config

trivy image --username myuser --password mypassword registry.example.com/myapp:1.0
```

```

### Using Docker Credentials

Trivy automatically uses Docker credentials from `~/.docker/config.json`:

```bash

docker login registry.example.com
trivy image registry.example.com/myapp:1.0
```

```

## Kubernetes Cluster Scanning

### Scan Entire Cluster

```bash

trivy k8s --report summary cluster
```

```

Output shows:

- Number of workloads scanned
- Total vulnerabilities by severity
- Most vulnerable workloads
- Summary by namespace

### Scan Specific Resources

**Scan a deployment:**

```bash

trivy k8s deployment/nginx -n default
```

```

**Scan a pod:**

```bash

trivy k8s pod/nginx-abc123 -n default
```

```

**Scan a namespace:**

```bash

trivy k8s --namespace production all
```

```

**Scan all resources of a type:**

```bash

trivy k8s deployments --all-namespaces
```

```

### Detailed Report

```bash

trivy k8s --report all cluster
```

```

Shows detailed vulnerability information for each workload.

### Filter Kubernetes Scans

```bash

trivy k8s --severity HIGH,CRITICAL --report summary cluster
```

```

## Vulnerability Database Management

### Update Vulnerability Database

Trivy automatically updates its database, but you can manually trigger updates:

```bash

trivy image --download-db-only
```

```

### Check Database Version

```bash

trivy image --db-repository
```

```

### Use Custom Database

```bash

trivy image --db-repository custom-db.example.com/trivy-db nginx:1.26
```

```

### Offline Scanning

For air-gapped environments:

```bash

# Download database on internet-connected machine

trivy image --download-db-only
tar -czf trivy-db.tar.gz ~/.cache/trivy

# Transfer to air-gapped machine
# Extract and scan

tar -xzf trivy-db.tar.gz -C ~/
trivy image --skip-db-update nginx:1.26
```

```

## Vulnerability Exemptions

### Using .trivyignore

Create a `.trivyignore` file to suppress specific CVEs:

```

# Ignore specific CVE

CVE-2024-1234

# Ignore CVEs for specific packages

CVE-2024-5678 openssl

# Comments are supported

# This is a known false positive

CVE-2024-9999

# Ignore until specific date

CVE-2024-7777 exp:2024-12-31

# Ignore by severity

# (Better to use --severity flag instead)

```
```

### Using Policy Files

Create a policy file `policy.rego` using OPA:

```rego

package trivy

default ignore = false

ignore_cves = [
    "CVE-2024-1234",
    "CVE-2024-5678"
]

ignore {
    input.VulnerabilityID == ignore_cves[_]
}
```

```

Scan with policy:

```bash

trivy image --policy policy.rego nginx:1.26
```

```

## CI/CD Integration

### GitHub Actions

```yaml

name: Scan Image
on:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Run Trivy scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'myapp:${{ github.sha }}'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'

      - name: Upload results to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'trivy-results.sarif'
```

```

### GitLab CI

```yaml

scan:
  stage: test
  image: aquasec/trivy:latest
  script:
    - trivy image --exit-code 1 --severity HIGH,CRITICAL $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  only:
    - main
```

```

### Jenkins Pipeline

```groovy

pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                sh 'docker build -t myapp:${BUILD_NUMBER} .'
            }
        }

        stage('Scan') {
            steps {
                sh '''
                    trivy image \
                        --exit-code 1 \
                        --severity HIGH,CRITICAL \
                        --format json \
                        --output scan-results.json \
                        myapp:${BUILD_NUMBER}
                '''
            }
        }
    }
}
```

```

## Interpreting Scan Results

### Understanding Vulnerability Details

Each vulnerability report includes:

1. **Library**: The affected package or library
1. **Vulnerability ID**: CVE identifier
1. **Severity**: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
1. **Status**: fixed, will_not_fix, affected, under_investigation
1. **Installed Version**: Current version in the image
1. **Fixed Version**: Version with the fix (if available)
1. **Title/Description**: What the vulnerability is
1. **References**: Links to CVE details, advisories, patches

### Prioritization Strategy

1. **CRITICAL vulnerabilities**: Address immediately
   - Active exploits in the wild
   - Network-exploitable
   - No authentication required

1. **HIGH vulnerabilities**: Patch within 7 days
   - Serious impact
   - May require user interaction
   - Elevated privileges

1. **MEDIUM vulnerabilities**: Patch within 30 days
   - Moderate impact
   - Requires specific conditions
   - Limited scope

1. **LOW vulnerabilities**: Patch during regular updates
   - Minimal impact
   - Difficult to exploit
   - Limited information disclosure

### Actionable vs Non-Actionable

**Actionable (fixable):**

- Fixed version available
- Update package/base image
- Apply the fix immediately

**Non-Actionable (unfixed):**

- No fix available yet
- Consider alternative packages
- Implement compensating controls
- Monitor for updates

## Best Practices

### 1. Scan Early and Often

**Development:**

- Scan during local development
- Use pre-commit hooks
- Catch issues before committing

**Build:**

- Scan in CI/CD pipelines
- Fail builds on HIGH/CRITICAL
- Generate scan reports

**Registry:**

- Scan images in registry
- Periodic rescanning
- Automated notifications

**Runtime:**

- Scan running containers
- Monitor for new CVEs
- Trigger remediation workflows

### 2. Use Minimal Base Images

Reduce attack surface by using minimal images:

```dockerfile

# Instead of full Ubuntu

FROM ubuntu:22.04

# Use distroless

FROM gcr.io/distroless/static-debian12

# Or Alpine

FROM alpine:3.19
```

```

**Comparison:**

- Ubuntu: ~70MB, 100+ packages
- Alpine: ~5MB, 15-20 packages
- Distroless: ~2MB, minimal packages

### 3. Multi-Stage Builds

Keep build tools out of final images:

```dockerfile

# Build stage

FROM golang:1.22 AS builder
WORKDIR /app
COPY . .
RUN go build -o myapp

# Runtime stage

FROM gcr.io/distroless/base-debian12
COPY --from=builder /app/myapp /
ENTRYPOINT ["/myapp"]
```

```

### 4. Keep Images Updated

```bash

# Regular base image updates

docker pull nginx:1.26
docker build --no-cache -t myapp:latest .
trivy image myapp:latest
```

```

### 5. Automate Remediation

Create automated workflows:

```bash

#!/bin/bash
# scan-and-notify.sh

IMAGE=$1
RESULTS=$(trivy image --severity HIGH,CRITICAL --format json $IMAGE)
VULN_COUNT=$(echo $RESULTS | jq '.Results[].Vulnerabilities | length')

if [ "$VULN_COUNT" -gt 0 ]; then
    echo "Found $VULN_COUNT vulnerabilities in $IMAGE"

    # Send notification (Slack, email, etc.)
    # Create Jira ticket
    # Trigger rebuild

fi
```

```

### 6. Implement Security Gates

Don't deploy vulnerable images:

```yaml

apiVersion: v1
kind: Pod
metadata:
  name: admission-controller
  annotations:
    trivy.scan.before.deploy: "true"
    trivy.severity.threshold: "HIGH"
```

```

### 7. Document Exceptions

When ignoring vulnerabilities:

```

# .trivyignore

# CVE-2024-1234 - False positive for our use case

# Package only used during build, not in runtime

# Risk assessment: LOW

# Reviewed by: security-team@example.com

# Date: 2024-01-15

# Review date: 2024-07-15

CVE-2024-1234 build-tool

```
```

## Troubleshooting

### Issue: "Failed to download vulnerability DB"

**Cause**: Network issues or proxy blocking

**Solution:**

```bash

# Use proxy

export HTTP_PROXY=http://proxy.example.com:8080
export HTTPS_PROXY=http://proxy.example.com:8080

# Or download manually

trivy image --download-db-only
```

```

### Issue: Scan takes too long

**Cause**: Large images or slow network

**Solution:**

```bash

# Use cached images

trivy image --no-pull myapp:1.0

# Scan specific severity

trivy image --severity HIGH,CRITICAL myapp:1.0

# Use timeout

trivy image --timeout 5m myapp:1.0
```

```

### Issue: Too many false positives

**Cause**: Outdated or incorrect vulnerability data

**Solution:**

```bash

# Update database

trivy image --download-db-only

# Use .trivyignore for known false positives

# Report false positives to Trivy project

```

```

### Issue: "No vulnerabilities found" but image has issues

**Cause**: Unsupported OS or package format

**Solution:**

```bash

# Check supported OS

trivy image --list-all-pkgs myapp:1.0

# Use different scanner for unsupported formats
# Consider Grype or Clair

```

```

## Key Points to Remember

1. Trivy is the CNCF standard for vulnerability scanning
1. Scan images at multiple stages: build, push, deploy, runtime
1. Focus on HIGH and CRITICAL vulnerabilities first
1. Use `--ignore-unfixed` to focus on actionable items
1. Integrate scanning into CI/CD pipelines
1. Use minimal base images to reduce attack surface
1. Keep vulnerability databases updated
1. Document exceptions and review regularly
1. Automate remediation workflows
1. Combine scanning with other security measures

## Exam Tips

1. Know Trivy command syntax by heart
1. Practice filtering results quickly
1. Understand severity levels and CVSS
1. Be able to read and interpret scan output
1. Know how to scan Kubernetes workloads
1. Understand the difference between fixed and unfixed vulnerabilities
1. Practice with various image types (distroless, Alpine, Ubuntu)

## Study Resources

### Official Documentation

- [Trivy Documentation](https://trivy.dev/)
- [Trivy GitHub Repository](https://github.com/aquasecurity/trivy)
- [CVE Database](https://cve.mitre.org/)
- [NVD](https://nvd.nist.gov/)

### Tools

- [Trivy Action](https://github.com/aquasecurity/trivy-action) - GitHub Actions integration
- [Grype](https://github.com/anchore/grype) - Alternative scanner
- [Clair](https://github.com/quay/clair) - CoreOS scanner

### Interactive Learning

- [Trivy Playground](https://play.trivy.dev/)
- [Vulnerable Container Images](https://hub.docker.com/r/vulnerables/)

## Next Steps

1. Complete the [Trivy Scanning Lab](../../labs/05-supply-chain-security/lab-01-trivy-scanning.md)
1. Practice scanning various images
1. Learn about [Image Signing](./image-signing.md) next
1. Integrate scanning into your workflows

## Quick Reference

### Essential Commands

```bash

# Basic scan

trivy image nginx:1.26

# Scan with severity filter

trivy image --severity HIGH,CRITICAL nginx:1.26

# Ignore unfixed

trivy image --ignore-unfixed nginx:1.26

# JSON output

trivy image -f json -o results.json nginx:1.26

# Scan Kubernetes

trivy k8s --report summary cluster

# Update database

trivy image --download-db-only

# CI/CD mode (exit on findings)

trivy image --exit-code 1 --severity HIGH,CRITICAL nginx:1.26
```

```

---

[Back to Domain 5 README](./README.md) | [Next: Image Signing →](./image-signing.md)
