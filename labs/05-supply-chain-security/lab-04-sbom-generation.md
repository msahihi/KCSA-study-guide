# Lab 04: SBOM Generation and Analysis

## Objectives

By the end of this lab, you will be able to:

- Generate SBOMs using Trivy and Syft
- Understand SPDX and CycloneDX formats
- Query and analyze SBOM contents
- Scan SBOMs for vulnerabilities
- Attach SBOMs to container images
- Track dependencies and licenses
- Integrate SBOM generation into CI/CD

## Prerequisites

- Completed Labs 01-03
- Trivy installed
- Syft installed (or will install in lab)
- jq installed for JSON parsing
- Basic understanding of software dependencies

## Estimated Time

60 minutes

## Lab Scenario

Your organization needs to track all components in container images for vulnerability management and license compliance. You'll generate SBOMs, analyze them for risks, and implement SBOM workflows in your development pipeline.

## Part 1: Installation and Setup

### Step 1: Install Required Tools

**Install Syft:**

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

**Install Grype (optional, for SBOM scanning):**

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

Verify installations:

```bash
syft version
grype version
trivy --version
```

### Step 2: Create Lab Environment

```bash
mkdir -p ~/sbom-lab
cd ~/sbom-lab

# Create namespace

kubectl create namespace sbom-lab
kubectl config set-context --current --namespace=sbom-lab
```

## Part 2: SBOM Generation with Trivy

### Exercise 1: Generate SPDX SBOM

Generate SPDX format SBOM:

```bash
trivy image --format spdx-json --output nginx-sbom.spdx.json nginx:1.26
```

View SBOM structure:

```bash
cat nginx-sbom.spdx.json | jq . | head -50
```

SPDX SBOM contains:

- Document metadata
- Creation information
- Package list with versions
- License information
- Relationships

### Exercise 2: Generate CycloneDX SBOM

Generate CycloneDX format:

```bash
trivy image --format cyclonedx --output nginx-sbom.cdx.json nginx:1.26
```

Compare formats:

```bash
echo "SPDX packages:"
cat nginx-sbom.spdx.json | jq '.packages | length'

echo "CycloneDX components:"
cat nginx-sbom.cdx.json | jq '.components | length'
```

### Exercise 3: SBOM for Different Images

Generate SBOMs for various base images:

```bash
# Alpine

trivy image --format spdx-json --output alpine-sbom.json alpine:3.19

# Ubuntu

trivy image --format spdx-json --output ubuntu-sbom.json ubuntu:22.04

# Distroless

trivy image --format spdx-json --output distroless-sbom.json gcr.io/distroless/static-debian12

# Compare package counts

echo "Package counts:"
echo "Alpine: $(cat alpine-sbom.json | jq '.packages | length')"
echo "Ubuntu: $(cat ubuntu-sbom.json | jq '.packages | length')"
echo "Distroless: $(cat distroless-sbom.json | jq '.packages | length')"
```

## Part 3: SBOM Generation with Syft

### Exercise 4: Syft SBOM Generation

Generate SPDX with Syft:

```bash
syft nginx:1.26 -o spdx-json=nginx-syft.spdx.json
```

Generate CycloneDX:

```bash
syft nginx:1.26 -o cyclonedx-json=nginx-syft.cdx.json
```

Generate multiple formats:

```bash
syft nginx:1.26 \\
  -o spdx-json=nginx-multi.spdx.json \\
  -o cyclonedx-json=nginx-multi.cdx.json \\
  -o table=nginx-table.txt
```

View table output:

```bash
cat nginx-table.txt
```

### Exercise 5: Scan Different Sources

Scan local directory:

```bash
# Create sample project

mkdir sample-app
cd sample-app
cat > requirements.txt <<EOF
flask==2.3.0
requests==2.31.0
urllib3==2.0.0
EOF

# Generate SBOM

syft dir:. -o spdx-json=app-sbom.json
cd ..
```

Scan Docker archive:

```bash
docker save nginx:1.26 -o nginx.tar
syft file:nginx.tar -o spdx-json=nginx-tar-sbom.json
```

Scan remote image:

```bash
syft registry:nginx:1.26 -o spdx-json=nginx-remote-sbom.json
```

## Part 4: SBOM Analysis

### Exercise 6: Query SBOM Contents

**List all packages (SPDX):**

```bash
cat nginx-sbom.spdx.json | jq '.packages[] | {name: .name, version: .versionInfo}' | head -20
```

**List all components (CycloneDX):**

```bash
cat nginx-sbom.cdx.json | jq '.components[] | {name: .name, version: .version}' | head -20
```

**Find specific package:**

```bash
# SPDX

cat nginx-sbom.spdx.json | jq '.packages[] | select(.name == "openssl")'

# CycloneDX

cat nginx-sbom.cdx.json | jq '.components[] | select(.name == "openssl")'
```

**Count packages by type:**

```bash
# CycloneDX (has type field)

cat nginx-sbom.cdx.json | jq '.components | group_by(.type) | map({type: .[0].type, count: length})'
```

### Exercise 7: License Analysis

Extract license information:

**SPDX:**

```bash
cat nginx-sbom.spdx.json | jq '.packages[] | {name: .name, license: .licenseConcluded}' | grep -v "NOASSERTION" | head -20
```

**CycloneDX:**

```bash
cat nginx-sbom.cdx.json | jq '.components[] | select(.licenses) | {name: .name, licenses: [.licenses[].license.id]}' | head -20
```

Find packages with specific licenses:

```bash
# Find GPL licenses

cat nginx-sbom.spdx.json | jq '.packages[] | select(.licenseConcluded | contains("GPL")) | {name: .name, license: .licenseConcluded}'

# Find Apache licenses

cat nginx-sbom.spdx.json | jq '.packages[] | select(.licenseConcluded | contains("Apache")) | {name: .name, license: .licenseConcluded}'
```

Create license summary:

```bash
cat > analyze-licenses.sh <<'EOF'

#!/bin/bash

SBOM=$1

echo "License Summary for $SBOM"
echo "=========================="

# Extract and count licenses

jq -r '.packages[].licenseConcluded' $SBOM 2>/dev/null | \\
  sort | uniq -c | sort -rn | \\
  grep -v "NOASSERTION"
EOF

chmod +x analyze-licenses.sh
./analyze-licenses.sh nginx-sbom.spdx.json
```

### Exercise 8: Dependency Analysis

Extract Package URLs (PURLs):

```bash
# CycloneDX includes PURLs

cat nginx-sbom.cdx.json | jq '.components[] | select(.purl) | {name: .name, purl: .purl}' | head -10
```

Find outdated packages (version < 1.0):

```bash
cat nginx-sbom.spdx.json | jq '.packages[] | select(.versionInfo | test("^0\\.[0-9]")) | {name: .name, version: .versionInfo}'
```

## Part 5: SBOM Vulnerability Scanning

### Exercise 9: Scan SBOM with Trivy

Scan SBOM for vulnerabilities:

```bash
trivy sbom nginx-sbom.spdx.json
```

Filter by severity:

```bash
trivy sbom --severity HIGH,CRITICAL nginx-sbom.spdx.json
```

JSON output:

```bash
trivy sbom -f json -o sbom-vuln-results.json nginx-sbom.spdx.json
```

### Exercise 10: Scan SBOM with Grype

Scan with Grype:

```bash
grype sbom:./nginx-sbom.spdx.json
```

Filter results:

```bash
grype sbom:./nginx-sbom.spdx.json --fail-on critical
```

Compare Trivy vs Grype results:

```bash
echo "Trivy results:"
trivy sbom nginx-sbom.spdx.json | grep "Total:"

echo -e "\\nGrype results:"
grype sbom:./nginx-sbom.spdx.json -q | tail -5
```

### Exercise 11: Track Vulnerability Over Time

Create a vulnerability tracking script:

```bash
cat > track-vulnerabilities.sh <<'EOF'

#!/bin/bash

IMAGE=$1
OUTPUT_DIR="sbom-tracking"

mkdir -p $OUTPUT_DIR
DATE=$(date +%Y-%m-%d)

# Generate SBOM

echo "Generating SBOM for $IMAGE..."
trivy image --format spdx-json --output "${OUTPUT_DIR}/${DATE}-sbom.json" $IMAGE

# Scan for vulnerabilities

echo "Scanning for vulnerabilities..."
trivy sbom --format json --output "${OUTPUT_DIR}/${DATE}-vulns.json" "${OUTPUT_DIR}/${DATE}-sbom.json"

# Extract summary

CRITICAL=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "${OUTPUT_DIR}/${DATE}-vulns.json")
HIGH=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "${OUTPUT_DIR}/${DATE}-vulns.json")

echo "$DATE,$IMAGE,$CRITICAL,$HIGH" >> "${OUTPUT_DIR}/vulnerability-history.csv"

echo "Results:"
echo "  Date: $DATE"
echo "  CRITICAL: $CRITICAL"
echo "  HIGH: $HIGH"
EOF

chmod +x track-vulnerabilities.sh
./track-vulnerabilities.sh nginx:1.26
```

## Part 6: SBOM Attachment and Distribution

### Exercise 12: Attach SBOM to Image

Generate and attach SBOM:

```bash
# Build sample image

cat > Dockerfile <<EOF
FROM alpine:3.19
RUN apk add --no-cache curl wget
CMD ["sh"]
EOF

docker build -t myapp:sbom-demo .
docker push docker.io/youruser/myapp:sbom-demo

# Generate SBOM

trivy image --format spdx-json --output myapp-sbom.json docker.io/youruser/myapp:sbom-demo

# Attach with Cosign

cosign attach sbom --sbom myapp-sbom.json docker.io/youruser/myapp:sbom-demo
```

Verify attachment:

```bash
# Get SBOM reference

cosign triangulate --type sbom docker.io/youruser/myapp:sbom-demo

# Download SBOM

cosign download sbom docker.io/youruser/myapp:sbom-demo > downloaded-sbom.json

# Compare

diff myapp-sbom.json downloaded-sbom.json
```

### Exercise 13: Sign SBOM

Sign the attached SBOM:

```bash
# Get SBOM reference

SBOM_REF=$(cosign triangulate --type sbom docker.io/youruser/myapp:sbom-demo)

# Sign SBOM

cosign sign --key cosign.key $SBOM_REF

# Verify SBOM signature

cosign verify --key cosign.pub $SBOM_REF
```

## Part 7: CI/CD Integration

### Exercise 14: Automated SBOM Generation

Create CI/CD SBOM generation script:

```bash
cat > ci-sbom-gen.sh <<'EOF'

#!/bin/bash

set -e

IMAGE=$1
OUTPUT_PREFIX=${2:-"sbom"}

if [ -z "$IMAGE" ]; then
  echo "Usage: $0 <image> [output-prefix]"
  exit 1
fi

echo "=== SBOM Generation Pipeline ==="
echo "Image: $IMAGE"
echo ""

# Generate SPDX SBOM

echo "Generating SPDX SBOM..."
syft $IMAGE -o spdx-json="${OUTPUT_PREFIX}.spdx.json"

# Generate CycloneDX SBOM

echo "Generating CycloneDX SBOM..."
syft $IMAGE -o cyclonedx-json="${OUTPUT_PREFIX}.cdx.json"

# Scan for vulnerabilities

echo "Scanning SBOM..."
trivy sbom --severity HIGH,CRITICAL "${OUTPUT_PREFIX}.spdx.json" > "${OUTPUT_PREFIX}-vulns.txt"

# Generate summary

echo "Generating summary..."
PACKAGES=$(jq '.packages | length' "${OUTPUT_PREFIX}.spdx.json")
CRITICAL=$(grep -c "CRITICAL" "${OUTPUT_PREFIX}-vulns.txt" || echo "0")
HIGH=$(grep -c "HIGH" "${OUTPUT_PREFIX}-vulns.txt" || echo "0")

cat > "${OUTPUT_PREFIX}-summary.json" <<SUMMARY
{
  "image": "$IMAGE",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "packages": $PACKAGES,
  "vulnerabilities": {
    "critical": $CRITICAL,
    "high": $HIGH
  },
  "sbom_formats": ["SPDX", "CycloneDX"]
}
SUMMARY

echo ""
echo "=== Summary ==="
cat "${OUTPUT_PREFIX}-summary.json" | jq .

# Fail if critical vulnerabilities found

if [ $CRITICAL -gt 0 ]; then
  echo ""
  echo "❌ CRITICAL vulnerabilities found! Build should fail."
  exit 1
else
  echo ""
  echo "✅ No critical vulnerabilities found."
fi
EOF

chmod +x ci-sbom-gen.sh
./ci-sbom-gen.sh nginx:1.26
```

### Exercise 15: GitHub Actions Workflow

Create a GitHub Actions workflow example:

```bash
cat > .github-sbom-workflow.yaml <<'EOF'
name: SBOM Generation and Scanning

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 0 * * *'  # Daily

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
          syft myapp:${{ github.sha }} -o spdx-json=sbom.spdx.json
          syft myapp:${{ github.sha }} -o cyclonedx-json=sbom.cdx.json

      - name: Upload SBOM artifacts
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: |
            sbom.spdx.json
            sbom.cdx.json

      - name: Scan SBOM with Trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'sbom'
          input: 'sbom.spdx.json'
          format: 'sarif'
          output: 'trivy-results.sarif'

      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'trivy-results.sarif'

      - name: Install Cosign
        uses: sigstore/cosign-installer@v3

      - name: Attach SBOM to image
        run: |
          cosign attach sbom --sbom sbom.spdx.json myapp:${{ github.sha }}
EOF
```

## Part 8: SBOM Quality Assessment

### Exercise 16: Assess SBOM Quality

Check SBOM completeness:

```bash
cat > assess-sbom-quality.sh <<'EOF'

#!/bin/bash

SBOM=$1

echo "SBOM Quality Assessment"
echo "======================="

# Check required fields

echo "1. Document metadata"
jq -e '.spdxVersion' $SBOM > /dev/null && echo "  ✅ SPDX version present" || echo "  ❌ Missing SPDX version"
jq -e '.creationInfo' $SBOM > /dev/null && echo "  ✅ Creation info present" || echo "  ❌ Missing creation info"

# Package analysis

TOTAL_PACKAGES=$(jq '.packages | length' $SBOM)
PACKAGES_WITH_VERSION=$(jq '[.packages[] | select(.versionInfo)] | length' $SBOM)
PACKAGES_WITH_LICENSE=$(jq '[.packages[] | select(.licenseConcluded != "NOASSERTION")] | length' $SBOM)
PACKAGES_WITH_CHECKSUM=$(jq '[.packages[] | select(.checksums)] | length' $SBOM)

echo ""
echo "2. Package completeness"
echo "  Total packages: $TOTAL_PACKAGES"
echo "  With version: $PACKAGES_WITH_VERSION ($(( PACKAGES_WITH_VERSION * 100 / TOTAL_PACKAGES ))%)"
echo "  With license: $PACKAGES_WITH_LICENSE ($(( PACKAGES_WITH_LICENSE * 100 / TOTAL_PACKAGES ))%)"
echo "  With checksum: $PACKAGES_WITH_CHECKSUM ($(( PACKAGES_WITH_CHECKSUM * 100 / TOTAL_PACKAGES ))%)"

# Relationships

RELATIONSHIPS=$(jq '.relationships | length' $SBOM 2>/dev/null || echo "0")
echo ""
echo "3. Relationships"
echo "  Total relationships: $RELATIONSHIPS"

# Score calculation

SCORE=0
[ "$PACKAGES_WITH_VERSION" -eq "$TOTAL_PACKAGES" ] && SCORE=$((SCORE + 3))
[ "$PACKAGES_WITH_LICENSE" -gt "$((TOTAL_PACKAGES / 2))" ] && SCORE=$((SCORE + 2))
[ "$PACKAGES_WITH_CHECKSUM" -gt 0 ] && SCORE=$((SCORE + 2))
[ "$RELATIONSHIPS" -gt 0 ] && SCORE=$((SCORE + 3))

echo ""
echo "Quality Score: $SCORE/10"

if [ $SCORE -ge 8 ]; then
  echo "Rating: Excellent ✅"
elif [ $SCORE -ge 6 ]; then
  echo "Rating: Good ⚠️"
else
  echo "Rating: Needs Improvement ❌"
fi
EOF

chmod +x assess-sbom-quality.sh
./assess-sbom-quality.sh nginx-sbom.spdx.json
```

## Verification Script

```bash
cat > test-sbom-lab.sh <<'EOF'

#!/bin/bash

echo "=== SBOM Lab Verification ==="

# Test 1: Tools installed

echo "Test 1: Check tool installations"
command -v syft &>/dev/null && echo "✅ Syft installed" || echo "❌ Syft missing"
command -v grype &>/dev/null && echo "✅ Grype installed" || echo "❌ Grype missing"

# Test 2: SBOM files generated

echo ""
echo "Test 2: Check SBOM files"
[ -f nginx-sbom.spdx.json ] && echo "✅ SPDX SBOM exists" || echo "❌ SPDX SBOM missing"
[ -f nginx-sbom.cdx.json ] && echo "✅ CycloneDX SBOM exists" || echo "❌ CycloneDX SBOM missing"

# Test 3: SBOM content

echo ""
echo "Test 3: Validate SBOM content"
if [ -f nginx-sbom.spdx.json ]; then
  PACKAGES=$(jq '.packages | length' nginx-sbom.spdx.json)
  echo "✅ SBOM contains $PACKAGES packages"
fi

# Test 4: SBOM scanning

echo ""
echo "Test 4: SBOM vulnerability scanning"
trivy sbom --quiet nginx-sbom.spdx.json &>/dev/null
[ $? -eq 0 ] && echo "✅ SBOM scanning successful" || echo "❌ SBOM scanning failed"

echo ""
echo "=== Tests Complete ==="
EOF

chmod +x test-sbom-lab.sh
./test-sbom-lab.sh
```

## Cleanup

```bash
# Delete namespace

kubectl delete namespace sbom-lab

# Remove working directory

cd ~
rm -rf ~/sbom-lab

# Reset context

kubectl config set-context --current --namespace=default
```

## Key Takeaways

1. SBOMs provide complete inventory of software components
1. SPDX and CycloneDX are standard SBOM formats
1. Trivy and Syft are excellent SBOM generation tools
1. SBOMs enable fast vulnerability response
1. License compliance tracking via SBOMs
1. Attach SBOMs to images for distribution
1. Sign SBOMs to ensure integrity
1. Integrate SBOM generation into CI/CD
1. Scan SBOMs regularly for new vulnerabilities
1. SBOM quality affects usefulness

## Next Steps

1. Generate SBOMs for all production images
1. Establish SBOM storage and versioning
1. Proceed to [Lab 05: Admission Control](./lab-05-admission-scanning.md)

---

[← Back to Lab Overview](./README.md) | [Previous Lab: Registry Security ←](./lab-03-registry-security.md) | [Next Lab: Admission Control →](./lab-05-admission-scanning.md)
