# Lab 01: Trivy Image Scanning

## Objectives

By the end of this lab, you will be able to:

- Install and configure Trivy for vulnerability scanning
- Scan container images for vulnerabilities
- Interpret scan results and understand CVE severity levels
- Filter scan results by severity and fixability
- Scan running Kubernetes workloads
- Generate scan reports in multiple formats
- Integrate Trivy into development workflows

## Prerequisites

- Basic understanding of container images and Docker
- kubectl installed and configured
- Docker or Podman installed
- Internet access to download Trivy and pull images
- Basic command-line proficiency

## Estimated Time

60 minutes

## Lab Scenario

You are a security engineer responsible for ensuring container images deployed to your Kubernetes cluster are free from critical vulnerabilities. Your task is to implement image scanning using Trivy, identify vulnerable images, and establish a scanning workflow.

## Part 1: Installation and Setup

### Step 1: Install Trivy

**Linux (apt/deb):**

```bash
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy
```

```

**macOS (Homebrew):**

```bash

brew install trivy
```

```

**Binary Installation:**

```bash

VERSION=$(curl --silent "https://api.github.com/repos/aquasecurity/trivy/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
wget https://github.com/aquasecurity/trivy/releases/download/v${VERSION}/trivy_${VERSION}_Linux-64bit.tar.gz
tar zxvf trivy_${VERSION}_Linux-64bit.tar.gz
sudo mv trivy /usr/local/bin/
```

```

### Step 2: Verify Installation

```bash

trivy --version
```

```

Expected output:

```

Version: 0.50.1

```
```

### Step 3: Update Vulnerability Database

```bash

trivy image --download-db-only
```

```

Output:

```

2024-01-15T10:00:00.000Z  INFO  Downloading DB...
2024-01-15T10:00:05.000Z  INFO  Vulnerability DB:
  Type: Full
  UpdatedAt: 2024-01-15 09:00:00 +0000 UTC
  NextUpdate: 2024-01-15 15:00:00 +0000 UTC

```
```

## Part 2: Basic Image Scanning

### Exercise 1: Scan a Public Image

Scan the nginx image:

```bash

trivy image nginx:1.26
```

```

Observe the output structure:

1. Image metadata (OS, packages)
1. Vulnerability table with:

   - Library name
   - Vulnerability ID (CVE)
   - Severity (CRITICAL, HIGH, MEDIUM, LOW)
   - Installation version
   - Fixed version
   - Title/description

### Exercise 2: Understanding Scan Results

Scan an older, vulnerable image:

```bash

trivy image nginx:1.14.0
```

```

**Questions to answer:**

1. How many CRITICAL vulnerabilities were found?
1. How many HIGH vulnerabilities?
1. Which library has the most vulnerabilities?
1. Are there any unfixed vulnerabilities?

To count vulnerabilities:

```bash

trivy image nginx:1.14.0 | grep CRITICAL | wc -l
trivy image nginx:1.14.0 | grep HIGH | wc -l
```

```

### Exercise 3: Detailed Vulnerability Information

Scan with JSON output for detailed analysis:

```bash

trivy image -f json -o nginx-scan.json nginx:1.26
```

```

View specific vulnerability details:

```bash

cat nginx-scan.json | jq '.Results[].Vulnerabilities[] | select(.Severity == "CRITICAL") | {VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Title}'
```

```

## Part 3: Filtering and Reporting

### Exercise 4: Filter by Severity

Scan only for HIGH and CRITICAL vulnerabilities:

```bash

trivy image --severity HIGH,CRITICAL nginx:1.26
```

```

Scan only CRITICAL:

```bash

trivy image --severity CRITICAL nginx:1.26
```

```

### Exercise 5: Ignore Unfixed Vulnerabilities

Many vulnerabilities don't have patches yet. Focus on actionable items:

```bash

trivy image --ignore-unfixed nginx:1.26
```

```

Combine with severity filtering:

```bash

trivy image --severity HIGH,CRITICAL --ignore-unfixed nginx:1.26
```

```

### Exercise 6: Generate Reports

**Table format (default):**

```bash

trivy image nginx:1.26 > nginx-report.txt
```

```

**JSON format:**

```bash

trivy image -f json -o nginx-report.json nginx:1.26
```

```

**SARIF format (for GitHub Security):**

```bash

trivy image -f sarif -o nginx-report.sarif nginx:1.26
```

```

**Template format:**

```bash

trivy image --format template --template "@contrib/html.tpl" -o nginx-report.html nginx:1.26
```

```

**CycloneDX SBOM:**

```bash

trivy image --format cyclonedx -o nginx-sbom.json nginx:1.26
```

```

## Part 4: Scanning Local Images

### Exercise 7: Build and Scan a Custom Image

Create a Dockerfile:

```bash

mkdir ~/trivy-lab
cd ~/trivy-lab

cat > Dockerfile <<EOF
FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \\
    curl \\
    wget \\
    openssl

COPY app.sh /app.sh
RUN chmod +x /app.sh

CMD ["/app.sh"]
EOF
```

```

Create a simple app:

```bash

cat > app.sh <<EOF

#!/bin/bash

echo "Hello from vulnerable image"
sleep 3600
EOF
```

```

Build the image:

```bash

docker build -t myapp:vulnerable .
```

```

Scan the image:

```bash

trivy image myapp:vulnerable
```

```

**Analysis Questions:**

1. How many vulnerabilities does Ubuntu 20.04 have?
1. Which packages are vulnerable?
1. Should you use a different base image?

### Exercise 8: Compare Base Images

Scan different base images to find the most secure:

```bash

# Ubuntu

trivy image --severity HIGH,CRITICAL ubuntu:20.04 | grep "Total:"

# Ubuntu latest

trivy image --severity HIGH,CRITICAL ubuntu:22.04 | grep "Total:"

# Alpine

trivy image --severity HIGH,CRITICAL alpine:3.19 | grep "Total:"

# Distroless

trivy image --severity HIGH,CRITICAL gcr.io/distroless/static-debian12 | grep "Total:"
```

```

Create a comparison script:

```bash

cat > compare-images.sh <<'EOF'

#!/bin/bash

IMAGES=(
  "ubuntu:20.04"
  "ubuntu:22.04"
  "alpine:3.19"
  "gcr.io/distroless/static-debian12"
)

echo "Image Vulnerability Comparison"
echo "=============================="
printf "%-40s %10s %10s\\n" "Image" "HIGH" "CRITICAL"
echo "------------------------------------------------------------"

for IMAGE in "${IMAGES[@]}"; do
  RESULT=$(trivy image --severity HIGH,CRITICAL --quiet $IMAGE 2>/dev/null)
  HIGH=$(echo "$RESULT" | grep "Total:" | awk '{print $4}' | cut -d',' -f1)
  CRITICAL=$(echo "$RESULT" | grep "Total:" | awk '{print $6}' | cut -d')' -f1)
  printf "%-40s %10s %10s\\n" "$IMAGE" "${HIGH:-0}" "${CRITICAL:-0}"
done
EOF

chmod +x compare-images.sh
./compare-images.sh
```

```

## Part 5: Kubernetes Workload Scanning

### Exercise 9: Set Up Test Environment

Create a namespace with vulnerable deployments:

```bash

kubectl create namespace trivy-lab

cat > vulnerable-deployment.yaml <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
  namespace: trivy-lab
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vulnerable
  template:
    metadata:
      labels:
        app: vulnerable
    spec:
      containers:
      - name: app
        image: nginx:1.14.0
        ports:
        - containerPort: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
  namespace: trivy-lab
spec:
  replicas: 1
  selector:
    matchLabels:
      app: secure
  template:
    metadata:
      labels:
        app: secure
    spec:
      containers:
      - name: app
        image: gcr.io/distroless/static-debian12
EOF

kubectl apply -f vulnerable-deployment.yaml
```

```

Wait for pods to be ready:

```bash

kubectl wait --for=condition=ready pod -l app=vulnerable -n trivy-lab --timeout=60s
kubectl wait --for=condition=ready pod -l app=secure -n trivy-lab --timeout=60s
```

```

### Exercise 10: Scan Kubernetes Cluster

Scan the entire cluster:

```bash

trivy k8s --report summary cluster
```

```

Scan specific namespace:

```bash

trivy k8s --namespace trivy-lab --report summary all
```

```

Scan specific deployment:

```bash

trivy k8s deployment/vulnerable-app -n trivy-lab
```

```

Scan with detailed report:

```bash

trivy k8s --report all --namespace trivy-lab all
```

```

### Exercise 11: Filter Kubernetes Scans

Scan only for HIGH and CRITICAL:

```bash

trivy k8s --severity HIGH,CRITICAL --namespace trivy-lab all
```

```

Generate JSON report:

```bash

trivy k8s --format json --output k8s-scan.json --namespace trivy-lab all
```

```

Analyze results:

```bash

cat k8s-scan.json | jq '.Resources[] | {
  Namespace: .Namespace,
  Kind: .Kind,
  Name: .Name,
  Vulnerabilities: (.Results[]?.Vulnerabilities // [] | length)
}'
```

```

## Part 6: Advanced Scanning

### Exercise 12: Scan Filesystem

Extract an image and scan its filesystem:

```bash

# Create working directory

mkdir -p ~/trivy-lab/fs-scan
cd ~/trivy-lab/fs-scan

# Export image

docker save nginx:1.26 -o nginx.tar
tar xf nginx.tar

# Scan filesystem

trivy fs .
```

```

Scan a specific directory:

```bash

trivy fs /path/to/project
```

```

### Exercise 13: Scan Configuration Files

Create Kubernetes manifests with issues:

```bash

cat > insecure-pod.yaml <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: insecure-pod
spec:
  containers:
  - name: app
    image: nginx:latest
    securityContext:
      privileged: true
      runAsUser: 0
EOF

trivy config insecure-pod.yaml
```

```

### Exercise 14: Use .trivyignore

Create a .trivyignore file to suppress specific CVEs:

```bash

cat > .trivyignore <<EOF

# Ignore this CVE as it's a false positive for our use case

CVE-2023-12345

# Ignore vulnerabilities in build tools (not in runtime)

CVE-2023-67890 gcc

# Temporary ignore until patch is available - Review by 2024-02-01

CVE-2024-11111
EOF

trivy image --ignorefile .trivyignore nginx:1.26
```

```

### Exercise 15: CI/CD Integration

Create a CI/CD scan script:

```bash

cat > ci-scan.sh <<'EOF'

#!/bin/bash

IMAGE=$1
SEVERITY_THRESHOLD="HIGH,CRITICAL"
EXIT_CODE=0

echo "Scanning image: $IMAGE"
echo "================================"

# Scan image

trivy image \\
  --severity $SEVERITY_THRESHOLD \\
  --exit-code 1 \\
  --ignore-unfixed \\
  --format json \\
  --output scan-results.json \\
  $IMAGE

SCAN_EXIT_CODE=$?

if [ $SCAN_EXIT_CODE -ne 0 ]; then
  echo ""
  echo "❌ SCAN FAILED: Vulnerabilities found!"
  echo ""

  # Show summary

  cat scan-results.json | jq -r '.Results[] | select(.Vulnerabilities) |
    "\\nTarget: \\(.Target)\\n" +
    "Critical: \\([.Vulnerabilities[] | select(.Severity == "CRITICAL")] | length)\\n" +
    "High: \\([.Vulnerabilities[] | select(.Severity == "HIGH")] | length)"'

  EXIT_CODE=1
else
  echo ""
  echo "✅ SCAN PASSED: No critical vulnerabilities found!"
fi

exit $EXIT_CODE
EOF

chmod +x ci-scan.sh
```

```

Test the script:

```bash

# Should pass

./ci-scan.sh gcr.io/distroless/static-debian12

# Should fail

./ci-scan.sh nginx:1.14.0
```

```

## Part 7: Remediation

### Exercise 16: Fix Vulnerabilities

Review vulnerabilities in custom image:

```bash

trivy image --severity HIGH,CRITICAL myapp:vulnerable
```

```

Update Dockerfile to use newer base:

```bash

cat > Dockerfile.fixed <<EOF
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \\
    curl \\
    wget \\
    openssl \\
 && apt-get upgrade -y \\
 && rm -rf /var/lib/apt/lists/*

COPY app.sh /app.sh
RUN chmod +x /app.sh

CMD ["/app.sh"]
EOF
```

```

Build and scan:

```bash

docker build -f Dockerfile.fixed -t myapp:fixed .
trivy image --severity HIGH,CRITICAL myapp:fixed
```

```

Compare results:

```bash

echo "Vulnerable image:"
trivy image --severity HIGH,CRITICAL myapp:vulnerable | grep "Total:"

echo -e "\\nFixed image:"
trivy image --severity HIGH,CRITICAL myapp:fixed | grep "Total:"
```

```

### Exercise 17: Use Minimal Base Images

Create a multi-stage build with distroless:

```bash

cat > Dockerfile.minimal <<EOF

# Build stage

FROM golang:1.22 AS builder
WORKDIR /app

# Copy source

COPY <<GO_EOF main.go
package main
import "fmt"
func main() {
    fmt.Println("Hello from minimal image")
}
GO_EOF

# Build binary

RUN CGO_ENABLED=0 GOOS=linux go build -o app main.go

# Runtime stage - distroless

FROM gcr.io/distroless/static-debian12
COPY --from=builder /app/app /app
ENTRYPOINT ["/app"]
EOF

docker build -f Dockerfile.minimal -t myapp:minimal .
```

```

Scan and compare:

```bash

echo "Minimal image scan:"
trivy image myapp:minimal

echo -e "\\nImage size comparison:"
docker images | grep myapp
```

```

## Verification and Testing

### Comprehensive Test Script

```bash

cat > test-trivy.sh <<'EOF'

#!/bin/bash

echo "=== Trivy Lab Verification ==="
echo ""

# Test 1: Trivy installation

echo "Test 1: Verify Trivy installation"
if command -v trivy &> /dev/null; then
  echo "✅ Trivy is installed: $(trivy --version)"
else
  echo "❌ Trivy is not installed"
  exit 1
fi

# Test 2: Database update

echo ""
echo "Test 2: Verify vulnerability database"
trivy image --download-db-only &> /dev/null
if [ $? -eq 0 ]; then
  echo "✅ Vulnerability database is up to date"
else
  echo "❌ Failed to update vulnerability database"
fi

# Test 3: Basic scan

echo ""
echo "Test 3: Perform basic image scan"
trivy image --quiet alpine:3.19 &> /dev/null
if [ $? -eq 0 ]; then
  echo "✅ Basic image scan successful"
else
  echo "❌ Basic image scan failed"
fi

# Test 4: Kubernetes scan

echo ""
echo "Test 4: Scan Kubernetes workloads"
if kubectl get ns trivy-lab &> /dev/null; then
  trivy k8s --quiet --namespace trivy-lab deployment/vulnerable-app &> /dev/null
  if [ $? -eq 0 ]; then
    echo "✅ Kubernetes scan successful"
  else
    echo "❌ Kubernetes scan failed"
  fi
else
  echo "⚠️  trivy-lab namespace not found, skipping"
fi

# Test 5: Report generation

echo ""
echo "Test 5: Generate scan reports"
trivy image -f json -o /tmp/test-report.json alpine:3.19 &> /dev/null
if [ -f /tmp/test-report.json ]; then
  echo "✅ Report generation successful"
  rm /tmp/test-report.json
else
  echo "❌ Report generation failed"
fi

echo ""
echo "=== All Tests Complete ==="
EOF

chmod +x test-trivy.sh
./test-trivy.sh
```

```

## Challenge Questions

1. **What's the difference between installed and fixed versions?**
   <details>
   <summary>Click to see answer</summary>
   Installed version is what's currently in the image. Fixed version is the version that patches the vulnerability. If fixed version is empty, no patch is available yet.
   </details>

1. **Why might a CRITICAL vulnerability show as "unfixed"?**
   <details>
   <summary>Click to see answer</summary>
   A vulnerability is "unfixed" when:
   - Patch hasn't been released yet
   - Vendor doesn't plan to fix it
   - Package is end-of-life
   - Patch is in progress
   </details>

1. **How would you scan for license compliance?**
   <details>
   <summary>Click to see answer</summary>

   ```bash

   trivy image --scanners license nginx:1.26

   ```

   </details>

1. **How do you scan a private registry image?**
   <details>
   <summary>Click to see answer</summary>

   ```bash

   # Method 1: Use Docker credentials

   docker login myregistry.com
   trivy image myregistry.com/myapp:v1.0

   # Method 2: Explicit credentials

   trivy image --username user --password pass myregistry.com/myapp:v1.0

   # Method 3: Environment variables

   export TRIVY_USERNAME=user
   export TRIVY_PASSWORD=pass
   trivy image myregistry.com/myapp:v1.0
   ```

   ```

   </details>

## Cleanup

```bash

# Delete Kubernetes resources

kubectl delete namespace trivy-lab

# Remove local images

docker rmi myapp:vulnerable myapp:fixed myapp:minimal nginx:1.14.0

# Remove working directory

rm -rf ~/trivy-lab

# Reset namespace

kubectl config set-context --current --namespace=default
```

```

## Key Takeaways

1. Trivy is a comprehensive vulnerability scanner for containers
1. Always scan images before deployment
1. Focus on HIGH and CRITICAL vulnerabilities
1. Use --ignore-unfixed to focus on actionable items
1. Minimal base images have fewer vulnerabilities
1. Regular scanning is essential (new CVEs appear daily)
1. Integrate scanning into CI/CD pipelines
1. Document and track CVE exceptions
1. Use multi-stage builds to minimize runtime dependencies
1. Keep vulnerability databases updated

## Next Steps

1. Review scan results for your production images
1. Create a remediation plan for critical vulnerabilities
1. Integrate Trivy into your CI/CD pipeline
1. Proceed to [Lab 02: Image Signing with Cosign](./lab-02-image-signing-cosign.md)

## Additional Practice

Try scanning these images and compare results:

```bash

# Official images

trivy image redis:7.2
trivy image postgres:16
trivy image python:3.12
trivy image node:20

# Compare versions

trivy image python:3.9 vs python:3.12
trivy image node:16 vs node:20

# Different distributions

trivy image nginx:1.26-alpine
trivy image nginx:1.26-debian
```

```

---

[← Back to Lab Overview](./README.md) | [Next Lab: Image Signing →](./lab-02-image-signing-cosign.md)
