# Software Bill of Materials (SBOM)

## Overview

A Software Bill of Materials (SBOM) is a comprehensive inventory of all components, libraries, and dependencies that make up a software application. For container images, an SBOM lists every package, library, and file included in the image, along with version information and relationships.

Think of an SBOM like an ingredients list on food packaging - it tells you exactly what's inside, where it came from, and in what quantity. This transparency is crucial for security, compliance, and supply chain management.

## Why SBOMs Matter

1. **Vulnerability Management**: Quickly identify which systems are affected by newly discovered vulnerabilities
1. **License Compliance**: Track open-source licenses and ensure compliance
1. **Supply Chain Transparency**: Understand your complete dependency tree
1. **Incident Response**: Rapidly assess impact of security incidents
1. **Regulatory Compliance**: Meet requirements like Executive Order 14028 (US)
1. **Risk Assessment**: Understand what third-party code you're running

## Real-World Impact

### Log4Shell Example (CVE-2021-44228)

When Log4Shell was discovered in December 2021:

**Without SBOM:**

- Teams manually searched codebases
- Checked every application individually
- Missed indirect dependencies
- Took weeks to assess impact

**With SBOM:**

- Query: "Which images contain log4j?"
- Instant results across all systems
- Identified indirect dependencies
- Patched within hours

### The Cost of Not Knowing

Organizations without SBOMs face:

- Slow vulnerability response
- Compliance violations and fines
- License violations and legal issues
- Inability to assess supply chain risk
- Extended incident response times

## SBOM Standards

### SPDX (Software Package Data Exchange)

**Overview:**

- ISO standard (ISO/IEC 5962:2021)
- Linux Foundation project
- Most widely adopted format
- Supports multiple serialization formats

**Format:** JSON, XML, YAML, Tag-Value

**Example (SPDX JSON):**

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "myapp-v1.0",
  "documentNamespace": "https://example.com/myapp-v1.0",
  "creationInfo": {
    "created": "2024-01-15T10:00:00Z",
    "creators": ["Tool: syft-0.50.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-nginx",
      "name": "nginx",
      "versionInfo": "1.26.0",
      "downloadLocation": "https://nginx.org",
      "filesAnalyzed": false,
      "licenseConcluded": "BSD-2-Clause",
      "copyrightText": "Copyright 2024 NGINX"
    }
  ]
}
```

```

### CycloneDX

**Overview:**

- OWASP project
- Security-focused
- Designed for software composition analysis
- Rich vulnerability metadata

**Format:** JSON, XML, Protocol Buffers

**Example (CycloneDX JSON):**

```json

{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "2024-01-15T10:00:00Z",
    "tools": [
      {
        "vendor": "Aqua Security",
        "name": "trivy",
        "version": "0.50.0"
      }
    ],
    "component": {
      "type": "container",
      "name": "myapp",
      "version": "1.0"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "openssl",
      "version": "3.0.13",
      "purl": "pkg:deb/debian/openssl@3.0.13",
      "licenses": [
        {
          "license": {
            "id": "Apache-2.0"
          }
        }
      ]
    }
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2024-1234",
      "source": {
        "name": "NVD",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
      },
      "ratings": [
        {
          "score": 9.8,
          "severity": "critical",
          "method": "CVSSv3"
        }
      ],
      "affects": [
        {
          "ref": "openssl@3.0.11"
        }
      ]
    }
  ]
}
```

```

### SWID (Software Identification Tags)

**Overview:**

- ISO/IEC 19770-2:2015
- Enterprise software management
- Hardware and software tagging

Less commonly used for containers, more for enterprise asset management.

## SBOM Generation Tools

### Trivy

**Generate SPDX SBOM:**

```bash

trivy image --format spdx-json --output sbom.spdx.json nginx:1.26
```

```

**Generate CycloneDX SBOM:**

```bash

trivy image --format cyclonedx --output sbom.cdx.json nginx:1.26
```

```

**With GitHub integration:**

```bash

trivy image --format github nginx:1.26
```

```

### Syft

Syft is a CLI tool from Anchore for generating SBOMs.

**Installation:**

```bash

# Linux/macOS

curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# macOS (Homebrew)

brew install syft

# Verify

syft version
```

```

**Generate SBOM:**

```bash

# SPDX JSON

syft nginx:1.26 -o spdx-json=sbom.spdx.json

# CycloneDX JSON

syft nginx:1.26 -o cyclonedx-json=sbom.cdx.json

# SPDX Tag-Value

syft nginx:1.26 -o spdx-tag-value=sbom.spdx

# Multiple formats

syft nginx:1.26 \
  -o spdx-json=sbom.spdx.json \
  -o cyclonedx-json=sbom.cdx.json
```

```

**Scan Sources:**

```bash

# Container image

syft nginx:1.26

# Local directory

syft dir:/path/to/project

# Archive

syft file:app.tar

# OCI layout

syft oci-dir:/path/to/oci

# Remote registry

syft registry:myregistry.com/myapp:v1.0
```

```

### Tern

**Installation:**

```bash

pip install tern
```

```

**Generate SBOM:**

```bash

tern report -i nginx:1.26 -f spdxjson -o sbom.json
```

```

### Docker SBOM (docker sbom)

Docker Desktop includes SBOM generation (experimental):

```bash

docker sbom nginx:1.26
```

```

## SBOM Components

### Essential Elements

1. **Metadata:**
   - SBOM format and version
   - Creation timestamp
   - Creator/tool information
   - Document namespace

1. **Component Information:**
   - Name
   - Version
   - Package URL (PURL)
   - License
   - Copyright
   - Supplier/originator

1. **Relationships:**
   - Dependency tree
   - Contains/depends-on relationships
   - Parent-child relationships

1. **Integrity:**
   - Checksums/hashes
   - Digital signatures
   - Verification data

### Package URL (PURL)

Standardized way to identify software packages:

```

pkg:type/namespace/name@version?qualifiers#subpath

```
```

**Examples:**

```

pkg:deb/debian/openssl@3.0.13?arch=amd64
pkg:npm/lodash@4.17.21
pkg:pypi/requests@2.31.0
pkg:golang/github.com/sirupsen/logrus@v1.9.3
pkg:docker/nginx@1.26.0
pkg:maven/org.springframework/spring-core@6.1.3
```

```

## Analyzing SBOMs

### Query SBOM with jq

**List all packages:**

```bash

# SPDX

jq '.packages[] | {name: .name, version: .versionInfo}' sbom.spdx.json

# CycloneDX

jq '.components[] | {name: .name, version: .version}' sbom.cdx.json
```

```

**Find specific package:**

```bash

# SPDX

jq '.packages[] | select(.name == "openssl")' sbom.spdx.json

# CycloneDX

jq '.components[] | select(.name == "openssl")' sbom.cdx.json
```

```

**Count packages:**

```bash

# SPDX

jq '.packages | length' sbom.spdx.json

# CycloneDX

jq '.components | length' sbom.cdx.json
```

```

**List licenses:**

```bash

# SPDX

jq '.packages[] | {name: .name, license: .licenseConcluded}' sbom.spdx.json | grep -v "NOASSERTION"

# CycloneDX

jq '.components[] | {name: .name, licenses: .licenses}' sbom.cdx.json
```

```

### SBOM Analysis Tools

**grype (Anchore):**

```bash

# Install

curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Scan SBOM for vulnerabilities

grype sbom:./sbom.spdx.json

# Filter by severity

grype sbom:./sbom.spdx.json --fail-on critical
```

```

**Trivy SBOM Scanning:**

```bash

# Scan SBOM

trivy sbom sbom.spdx.json

# Filter results

trivy sbom --severity HIGH,CRITICAL sbom.spdx.json

# JSON output

trivy sbom -f json -o results.json sbom.spdx.json
```

```

**Dependency-Track:**

Web-based SBOM analysis platform:

- Upload and track SBOMs
- Continuous vulnerability monitoring
- Policy enforcement
- License compliance tracking
- Portfolio management

## SBOM in CI/CD

### GitHub Actions

```yaml

name: Generate and Upload SBOM

on:
  push:
    branches: [main]

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Install Syft
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

      - name: Generate SBOM
        run: |
          syft myapp:${{ github.sha }} \
            -o spdx-json=sbom.spdx.json \
            -o cyclonedx-json=sbom.cdx.json

      - name: Upload SBOM as artifact
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: |
            sbom.spdx.json
            sbom.cdx.json

      - name: Scan SBOM for vulnerabilities
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
          grype sbom:./sbom.spdx.json --fail-on critical

      - name: Attach SBOM to image
        run: |

          # Using Cosign

          cosign attach sbom --sbom sbom.spdx.json myapp:${{ github.sha }}
```

```

### GitLab CI

```yaml

stages:
  - build
  - sbom
  - scan

generate-sbom:
  stage: sbom
  image: anchore/syft:latest
  script:
    - syft $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA -o spdx-json=sbom.spdx.json
    - syft $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA -o cyclonedx-json=sbom.cdx.json
  artifacts:
    paths:
      - sbom.spdx.json
      - sbom.cdx.json
    expire_in: 30 days

scan-sbom:
  stage: scan
  image: anchore/grype:latest
  script:
    - grype sbom:./sbom.spdx.json --fail-on critical
  dependencies:
    - generate-sbom
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

        stage('Generate SBOM') {
            steps {
                sh '''
                    syft myapp:${BUILD_NUMBER} \
                        -o spdx-json=sbom.spdx.json \
                        -o cyclonedx-json=sbom.cdx.json
                '''
                archiveArtifacts artifacts: 'sbom.*.json', fingerprint: true
            }
        }

        stage('Scan SBOM') {
            steps {
                sh 'grype sbom:./sbom.spdx.json --fail-on critical'
            }
        }

        stage('Upload SBOM') {
            steps {
                sh 'cosign attach sbom --sbom sbom.spdx.json myapp:${BUILD_NUMBER}'
            }
        }
    }
}
```

```

## SBOM Storage and Distribution

### 1. OCI Registry (Recommended)

Attach SBOM to image using Cosign:

```bash

# Attach SBOM

cosign attach sbom --sbom sbom.spdx.json myapp:v1.0

# Retrieve SBOM

cosign download sbom myapp:v1.0 > downloaded-sbom.json

# Verify SBOM signature

cosign verify --key cosign.pub $(cosign triangulate --type sbom myapp:v1.0)
```

```

### 2. Artifact Repository

Store SBOMs alongside images in artifact repositories:

- JFrog Artifactory
- Sonatype Nexus
- AWS S3
- Azure Blob Storage

### 3. SBOM Repository

Dedicated SBOM management:

- Dependency-Track
- SBOM Scorecard
- Custom database

### 4. Version Control

Commit SBOMs to Git:

```bash

# Generate SBOM

syft myapp:v1.0 -o spdx-json=sboms/myapp-v1.0.spdx.json

# Commit

git add sboms/myapp-v1.0.spdx.json
git commit -m "Add SBOM for myapp v1.0"
git push
```

```

## SBOM Use Cases

### 1. Vulnerability Response

When CVE-2024-1234 in OpenSSL is disclosed:

```bash

# Query all SBOMs

for sbom in sboms/*.json; do
    echo "Checking $sbom"
    jq -r 'select(.packages[]? | .name == "openssl" and (.versionInfo | test("3\\.0\\.1[0-2]"))) | .name' "$sbom"
done
```

```

### 2. License Compliance

Check for copyleft licenses:

```bash

# Find GPL licenses

jq '.packages[] | select(.licenseConcluded | contains("GPL")) | {name: .name, license: .licenseConcluded}' sbom.spdx.json
```

```

### 3. Supply Chain Audit

Track component sources:

```bash

# List all suppliers

jq '.packages[] | .supplier' sbom.spdx.json | sort -u

# Components from specific supplier

jq '.packages[] | select(.supplier == "Organization: Debian") | .name' sbom.spdx.json
```

```

### 4. Dependency Analysis

```bash

# Count dependencies by type

jq '.components | group_by(.type) | map({type: .[0].type, count: length})' sbom.cdx.json

# Find outdated packages

jq '.components[] | select(.version | test("^0\\.[0-9]")) | {name: .name, version: .version}' sbom.cdx.json
```

```

## SBOM Best Practices

### 1. Generate at Build Time

Always generate SBOMs during the build process:

- Ensures accuracy
- Captures exact build state
- Enables reproducibility

### 2. Store with Artifacts

Keep SBOMs close to the artifacts they describe:

- Same registry as images
- Signed and verified
- Version controlled

### 3. Automate SBOM Generation

Never manually create SBOMs:

- Use automated tools
- Integrate with CI/CD
- Consistent formatting

### 4. Include in Release Process

Make SBOMs part of the release:

- Publish with releases
- Customer delivery
- Compliance documentation

### 5. Regular SBOM Updates

Update SBOMs when:

- Dependencies change
- Security patches applied
- New builds created
- Periodic rescans

### 6. SBOM Verification

Sign and verify SBOMs:

```bash

# Sign SBOM with Cosign

cosign sign-blob --key cosign.key sbom.spdx.json > sbom.spdx.json.sig

# Verify signature

cosign verify-blob --key cosign.pub --signature sbom.spdx.json.sig sbom.spdx.json
```

```

### 7. SBOM Retention

Define retention policies:

- Keep SBOMs for all production releases
- Archive old development SBOMs
- Compliance retention requirements
- Disaster recovery backups

## SBOM Quality

### Minimum Elements (NTIA)

The NTIA Minimum Elements for SBOM defines baseline requirements:

1. **Supplier Name**: Who created the component
1. **Component Name**: What the component is
1. **Version**: Which version
1. **Other Unique Identifiers**: PURL, CPE
1. **Dependency Relationships**: How components relate
1. **SBOM Author**: Who created the SBOM
1. **Timestamp**: When SBOM was created

### SBOM Quality Score

Tools like sbomqs assess SBOM quality:

```bash

# Install

go install github.com/interlynk-io/sbomqs@latest

# Score SBOM

sbomqs score sbom.spdx.json
```

```

Output:

```

SBOM Quality Score: 7.2/10

Compliance:
  ✓ NTIA minimum elements
  ✓ SPDX 2.3 specification
  ⚠ Missing supplier for 5 components
  ✗ No cryptographic checksums

Recommendations:

- Add supplier information
- Include SHA256 checksums
- Add license for unlicensed components

```
```

## Troubleshooting

### Issue: SBOM Generation Fails

**Cause**: Tool can't analyze image format

**Solution:**

```bash

# Try different tool

syft nginx:1.26 -o spdx-json  # If Trivy fails
trivy image --format spdx-json nginx:1.26  # If Syft fails

# Export image and scan filesystem

docker save nginx:1.26 -o nginx.tar
tar xf nginx.tar
syft dir:. -o spdx-json
```

```

### Issue: Incomplete SBOM

**Cause**: Missing package managers or metadata

**Solution:**

```bash

# Use multiple tools and merge

syft nginx:1.26 -o spdx-json=sbom-syft.json
trivy image --format spdx-json -o sbom-trivy.json nginx:1.26

# Manually review and combine

```

```

### Issue: SBOM Too Large

**Cause**: Large images with many dependencies

**Solution:**

```bash

# Compress SBOM

gzip sbom.spdx.json

# Store summary only

jq '{metadata, summary: {packageCount: (.packages | length)}}' sbom.spdx.json
```

```

## Key Points to Remember

1. SBOM provides complete inventory of software components
1. SPDX and CycloneDX are the main standards
1. Generate SBOMs at build time
1. Store SBOMs with container images
1. Use SBOMs for vulnerability management
1. Track licenses for compliance
1. Automate SBOM generation in CI/CD
1. Sign and verify SBOMs
1. Use SBOMs for incident response
1. SBOM quality matters - follow NTIA minimum elements

## Exam Tips

1. Know how to generate SBOMs with Trivy and Syft
1. Understand SPDX and CycloneDX formats
1. Practice querying SBOMs with jq
1. Know how to attach SBOMs to images
1. Understand SBOM use cases
1. Be able to scan SBOMs for vulnerabilities
1. Know NTIA minimum elements

## Study Resources

### Official Documentation

- [NTIA SBOM](https://www.ntia.gov/sbom)
- [SPDX](https://spdx.dev/)
- [CycloneDX](https://cyclonedx.org/)
- [Syft Documentation](https://github.com/anchore/syft)
- [Package URL Specification](https://github.com/package-url/purl-spec)

### Tools

- [Syft](https://github.com/anchore/syft)
- [Grype](https://github.com/anchore/grype)
- [Dependency-Track](https://dependencytrack.org/)
- [SBOM Tool (Microsoft)](https://github.com/microsoft/sbom-tool)

### Standards

- [SPDX Specification](https://spdx.github.io/spdx-spec/)
- [CycloneDX Specification](https://cyclonedx.org/specification/overview/)
- [NTIA Minimum Elements](https://www.ntia.doc.gov/files/ntia/publications/sbom_minimum_elements_report.pdf)

## Next Steps

1. Complete the [SBOM Lab](../../labs/05-supply-chain-security/lab-04-sbom-generation.md)
1. Generate SBOMs for your images
1. Practice analyzing SBOMs
1. Integrate SBOM generation into CI/CD

## Quick Reference

```bash

# Generate SBOM with Trivy

trivy image --format spdx-json -o sbom.json nginx:1.26
trivy image --format cyclonedx -o sbom.json nginx:1.26

# Generate SBOM with Syft

syft nginx:1.26 -o spdx-json=sbom.json
syft nginx:1.26 -o cyclonedx-json=sbom.json

# Scan SBOM for vulnerabilities

trivy sbom sbom.json
grype sbom:./sbom.json

# Attach SBOM to image

cosign attach sbom --sbom sbom.json myapp:v1.0

# Download SBOM from image

cosign download sbom myapp:v1.0

# Query SBOM

jq '.packages[] | {name, version: .versionInfo}' sbom.spdx.json
jq '.components[] | {name, version}' sbom.cdx.json

# Count packages

jq '.packages | length' sbom.spdx.json

# Find package

jq '.packages[] | select(.name == "openssl")' sbom.spdx.json
```

```

---

[Back to Domain 5 README](./README.md) | [Previous: Registry Security ←](./registry-security.md)
