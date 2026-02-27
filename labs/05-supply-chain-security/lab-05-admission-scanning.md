# Lab 05: Admission Control for Supply Chain Security

## Objectives

By the end of this lab, you will be able to:

- Install and configure Kyverno admission controller
- Create policies to verify image signatures
- Block deployment of vulnerable images
- Enforce registry restrictions
- Require signed SBOMs
- Implement scanning admission webhooks
- Test and troubleshoot policy enforcement
- Audit policy violations

## Prerequisites

- Completed Labs 01-04
- Kubernetes cluster v1.30+ with admission control enabled
- kubectl with cluster-admin permissions
- Cosign and Trivy installed
- Understanding of Kubernetes admission controllers

## Estimated Time

90 minutes

## Lab Scenario

Your organization mandates that all container images deployed to production must be scanned, signed, and come from approved registries. You'll implement admission control policies to automatically enforce these requirements at deployment time.

## Part 1: Kyverno Installation

### Step 1: Install Kyverno

Install Kyverno:

```bash
kubectl create -f https://github.com/kyverno/kyverno/releases/download/v1.11.0/install.yaml
```

Wait for Kyverno to be ready:

```bash
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=kyverno -n kyverno --timeout=300s
```

Verify installation:

```bash
kubectl get pods -n kyverno
kubectl get svc -n kyverno
```

Check Kyverno version:

```bash
kubectl get deployment kyverno -n kyverno -o jsonpath='{.spec.template.spec.containers[0].image}'
```

### Step 2: Create Lab Namespace

```bash
kubectl create namespace admission-lab
kubectl config set-context --current --namespace=admission-lab
```

## Part 2: Basic Policy Enforcement

### Exercise 1: Require Image Tags

Create a policy that blocks deployment of images using the :latest tag:

```bash
cat > require-image-tag.yaml <<EOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-image-tag
  annotations:
    policies.kyverno.io/title: Require Image Tag
    policies.kyverno.io/severity: medium
    policies.kyverno.io/description: >-
      Using the :latest tag is not recommended as it can lead to
      unpredictable deployments. This policy requires explicit tags.
spec:
  validationFailureAction: Enforce
  background: true
  rules:
  - name: require-image-tag
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "Images must have explicit tags, not :latest"
      pattern:
        spec:
          containers:
          - image: "!*:latest"
EOF

kubectl apply -f require-image-tag.yaml
```

Test the policy:

```bash
# Should fail (using :latest)

kubectl run test-latest --image=nginx:latest

# Should succeed (explicit tag)

kubectl run test-versioned --image=nginx:1.26
```

Check policy report:

```bash
kubectl get policyreport -A
kubectl describe policyreport -n admission-lab
```

### Exercise 2: Restrict Registries

Create a policy to allow only approved registries:

```bash
cat > allowed-registries.yaml <<EOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-registries
  annotations:
    policies.kyverno.io/title: Restrict Image Registries
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      Only images from approved registries are allowed.
spec:
  validationFailureAction: Enforce
  background: true
  rules:
  - name: validate-registry
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: >-
        Images must come from approved registries:
        gcr.io/myproject, docker.io/myuser, or myregistry.com
      pattern:
        spec:
          containers:
          - image: "gcr.io/myproject/* | docker.io/myuser/* | myregistry.com/*"
EOF

kubectl apply -f allowed-registries.yaml
```

Test the policy:

```bash
# Should fail (unapproved registry)

kubectl run test-disallowed --image=nginx:1.26

# Should succeed (if using approved registry)

kubectl run test-allowed --image=docker.io/myuser/myapp:v1.0
```

## Part 3: Image Signature Verification

### Exercise 3: Verify Image Signatures

First, ensure you have signed images from Lab 02:

```bash
# Sign a test image

SIGNED_IMAGE="docker.io/youruser/signed-app:v1.0"
docker build -t $SIGNED_IMAGE .
docker push $SIGNED_IMAGE
cosign sign --key cosign.key $SIGNED_IMAGE
```

Create ConfigMap with public key:

```bash
kubectl create configmap cosign-pub-keys \\
  --from-file=cosign.pub=cosign.pub \\
  -n kyverno
```

Create signature verification policy:

```bash
cat > verify-signatures.yaml <<EOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signatures
  annotations:
    policies.kyverno.io/title: Verify Image Signatures
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      All images must be signed with our Cosign key.
spec:
  validationFailureAction: Enforce
  background: false
  webhookTimeoutSeconds: 30
  rules:
  - name: verify-signature
    match:
      any:
      - resources:
          kinds:
          - Pod
    verifyImages:
    - imageReferences:
      - "docker.io/youruser/*"
      attestors:
      - count: 1
        entries:
        - keys:
            publicKeys: |-
              $(cat cosign.pub | sed 's/^/              /')
EOF

kubectl apply -f verify-signatures.yaml
```

Test signature verification:

```bash
# Should succeed (signed image)

kubectl run signed-app --image=docker.io/youruser/signed-app:v1.0

# Should fail (unsigned image)

kubectl run unsigned-app --image=docker.io/youruser/unsigned-app:v1.0
```

Check pod events for verification details:

```bash
kubectl describe pod signed-app | grep -A 10 Events
```

### Exercise 4: Keyless Signature Verification

For keyless-signed images:

```bash
cat > verify-keyless-signatures.yaml <<EOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-keyless-signatures
spec:
  validationFailureAction: Enforce
  background: false
  webhookTimeoutSeconds: 30
  rules:
  - name: verify-keyless-signature
    match:
      any:
      - resources:
          kinds:
          - Pod
    verifyImages:
    - imageReferences:
      - "docker.io/youruser/*"
      attestors:
      - count: 1
        entries:
        - keyless:
            subject: "your-email@example.com"
            issuer: "https://github.com/login/oauth"
            rekor:
              url: https://rekor.sigstore.dev
EOF

kubectl apply -f verify-keyless-signatures.yaml
```

## Part 4: Vulnerability Scanning Admission

### Exercise 5: Install Trivy Operator

Install Trivy Operator for automated scanning:

```bash
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/trivy-operator/main/deploy/static/trivy-operator.yaml
```

Wait for operator:

```bash
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=trivy-operator -n trivy-system --timeout=300s
```

Configure operator:

```bash
cat > trivy-operator-config.yaml <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: trivy-operator
  namespace: trivy-system
data:
  scanJob.podSecurityContext: |
    runAsUser: 0
  vulnerabilityReports.scanner: Trivy
  scanJob.tolerations: |
    - operator: Exists
EOF

kubectl apply -f trivy-operator-config.yaml
```

### Exercise 6: Block Vulnerable Images

Create a policy to block images with HIGH/CRITICAL vulnerabilities:

```bash
cat > block-vulnerable-images.yaml <<EOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: block-vulnerable-images
  annotations:
    policies.kyverno.io/title: Block Vulnerable Images
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      Blocks deployment of images with HIGH or CRITICAL vulnerabilities.
spec:
  validationFailureAction: Enforce
  background: true
  rules:
  - name: check-vulnerability-reports
    match:
      any:
      - resources:
          kinds:
          - Pod
    context:
    - name: vulnReport
      apiCall:
        urlPath: "/apis/aquasecurity.github.io/v1alpha1/vulnerabilityreports"
        jmesPath: "items[?spec.artifact.repository == '{{request.object.spec.containers[0].image}}'] | [0]"
    preconditions:
      all:
      - key: "{{ vulnReport }}"
        operator: NotEquals
        value: ""
    validate:
      message: >-
        Image {{ request.object.spec.containers[0].image }} has
        {{ vulnReport.report.summary.criticalCount }} CRITICAL and
        {{ vulnReport.report.summary.highCount }} HIGH vulnerabilities.
        Deployment blocked.
      deny:
        conditions:
          any:
          - key: "{{ vulnReport.report.summary.criticalCount }}"
            operator: GreaterThan
            value: 0
          - key: "{{ vulnReport.report.summary.highCount }}"
            operator: GreaterThan
            value: 3
EOF

kubectl apply -f block-vulnerable-images.yaml
```

### Exercise 7: Scan on Deploy with Init Container

Create a policy that adds a scanning init container:

```bash
cat > scan-on-deploy.yaml <<EOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: scan-on-deploy
spec:
  background: false
  rules:
  - name: add-scan-init-container
    match:
      any:
      - resources:
          kinds:
          - Pod
    mutate:
      patchStrategicMerge:
        spec:
          initContainers:
          - name: trivy-scanner
            image: aquasec/trivy:latest
            command:
            - trivy
            - image
            - --severity
            - HIGH,CRITICAL
            - --exit-code
            - "1"
            - "{{ request.object.spec.containers[0].image }}"
EOF

kubectl apply -f scan-on-deploy.yaml
```

This adds an init container that scans the image before the pod starts.

## Part 5: SBOM Requirements

### Exercise 8: Require SBOM Attestation

Create policy requiring SBOM attestation:

```bash
cat > require-sbom.yaml <<EOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-sbom-attestation
spec:
  validationFailureAction: Enforce
  background: false
  webhookTimeoutSeconds: 30
  rules:
  - name: verify-sbom
    match:
      any:
      - resources:
          kinds:
          - Pod
    verifyImages:
    - imageReferences:
      - "docker.io/youruser/*"
      attestations:
      - predicateType: https://spdx.dev/Document
        attestors:
        - count: 1
          entries:
          - keys:
              publicKeys: |-
                $(cat cosign.pub | sed 's/^/                /')
EOF

kubectl apply -f require-sbom.yaml
```

Test with image that has SBOM:

```bash
# Attach SBOM from Lab 04

trivy image --format spdx-json -o sbom.json docker.io/youruser/myapp:v1.0
cosign attach sbom --sbom sbom.json docker.io/youruser/myapp:v1.0
cosign attest --key cosign.key --type spdx --predicate sbom.json docker.io/youruser/myapp:v1.0

# Deploy (should succeed)

kubectl run sbom-app --image=docker.io/youruser/myapp:v1.0
```

## Part 6: Policy Reporting and Audit

### Exercise 9: View Policy Reports

Check cluster-wide policy reports:

```bash
kubectl get clusterpolicyreport -A
```

View namespace policy report:

```bash
kubectl get policyreport -n admission-lab
kubectl describe policyreport -n admission-lab
```

Get policy violations:

```bash
kubectl get policyreport -n admission-lab -o json | jq '.items[].results[] | select(.result == "fail")'
```

### Exercise 10: Audit Mode vs Enforce Mode

Create an audit-only policy:

```bash
cat > audit-unsigned-images.yaml <<EOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: audit-unsigned-images
spec:
  validationFailureAction: Audit  # Audit instead of Enforce
  background: true
  rules:
  - name: check-image-signature
    match:
      any:
      - resources:
          kinds:
          - Pod
    verifyImages:
    - imageReferences:
      - "*"
      attestors:
      - count: 1
        entries:
        - keys:
            publicKeys: |-
              $(cat cosign.pub | sed 's/^/              /')
EOF

kubectl apply -f audit-unsigned-images.yaml
```

Audit mode allows deployments but records violations:

```bash
# Deploy unsigned image

kubectl run audit-test --image=nginx:1.26

# Check policy report for violations

kubectl get policyreport -n admission-lab -o yaml | grep -A 20 audit-test
```

### Exercise 11: Policy Exceptions

Create policy exceptions for specific namespaces or users:

```bash
cat > policy-exception.yaml <<EOF
apiVersion: kyverno.io/v1alpha2
kind: PolicyException
metadata:
  name: dev-namespace-exception
  namespace: kyverno
spec:
  exceptions:
  - policyName: verify-image-signatures
    ruleNames:
    - verify-signature
  match:
    any:
    - resources:
        kinds:
        - Pod
        namespaces:
        - development
        - testing
EOF

kubectl apply -f policy-exception.yaml
```

## Part 7: Custom Admission Webhook

### Exercise 12: Deploy Trivy Admission Webhook

For advanced scenarios, deploy a custom admission webhook:

```bash
# Clone repository

git clone https://github.com/aquasecurity/trivy-kubernetes-admission
cd trivy-kubernetes-admission

# Deploy webhook

kubectl apply -f deploy/
```

Configure webhook:

```bash
cat > webhook-config.yaml <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: trivy-admission-config
  namespace: trivy-admission
data:
  config.yaml: |
    severityThreshold: HIGH
    blockOnError: true
    ignoreUnfixed: true
    namespaceWhitelist:
    - kube-system
    - trivy-admission
EOF

kubectl apply -f webhook-config.yaml
```

## Part 8: Testing and Troubleshooting

### Exercise 13: Test Complete Policy Suite

Create comprehensive test script:

```bash
cat > test-admission-policies.sh <<'EOF'

#!/bin/bash

echo "=== Admission Policy Test Suite ==="
echo ""

# Test 1: Latest tag policy

echo "Test 1: Block :latest tag"
kubectl run test-latest --image=nginx:latest -n admission-lab --dry-run=server &>/dev/null
if [ $? -ne 0 ]; then
  echo "✅ :latest tag blocked"
else
  echo "❌ :latest tag allowed (should be blocked)"
fi

# Test 2: Registry restriction

echo ""
echo "Test 2: Block unapproved registry"
kubectl run test-registry --image=docker.io/nginx:1.26 -n admission-lab --dry-run=server &>/dev/null
if [ $? -ne 0 ]; then
  echo "✅ Unapproved registry blocked"
else
  echo "❌ Unapproved registry allowed (should be blocked)"
fi

# Test 3: Signature verification

echo ""
echo "Test 3: Block unsigned image"
kubectl run test-unsigned --image=docker.io/youruser/unsigned:v1.0 -n admission-lab --dry-run=server &>/dev/null
if [ $? -ne 0 ]; then
  echo "✅ Unsigned image blocked"
else
  echo "❌ Unsigned image allowed (should be blocked)"
fi

# Test 4: Policy reports

echo ""
echo "Test 4: Check policy reports"
REPORTS=$(kubectl get policyreport -n admission-lab --no-headers 2>/dev/null | wc -l)
if [ $REPORTS -gt 0 ]; then
  echo "✅ Policy reports generated ($REPORTS reports)"
else
  echo "⚠️  No policy reports found"
fi

echo ""
echo "=== Tests Complete ==="
EOF

chmod +x test-admission-policies.sh
./test-admission-policies.sh
```

### Exercise 14: Debug Policy Failures

When a policy blocks a deployment, debug with:

```bash
# View Kyverno logs

kubectl logs -n kyverno -l app.kubernetes.io/name=kyverno --tail=100

# Check webhook configuration

kubectl get validatingwebhookconfigurations
kubectl describe validatingwebhookconfigurations kyverno-resource-validating-webhook-cfg

# View policy details

kubectl get clusterpolicy verify-image-signatures -o yaml

# Test with dry-run

kubectl run test --image=nginx:1.26 --dry-run=server -v=8
```

### Exercise 15: Performance Tuning

Optimize Kyverno for large clusters:

```bash
cat > kyverno-tuning.yaml <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: kyverno
  namespace: kyverno
data:
  webhookTimeout: "30"
  generateSuccessEvents: "false"
  resourceFilters: |
    [Event,*,*]
    [*,kube-system,*]
    [*,kube-public,*]
    [*,kube-node-lease,*]
    [Node,*,*]
    [APIService,*,*]
    [TokenReview,*,*]
    [SubjectAccessReview,*,*]
    [SelfSubjectAccessReview,*,*]
    [Binding,*,*]
    [ReplicaSet,*,*]
    [PodMetrics,*,*]
EOF

kubectl apply -f kyverno-tuning.yaml
kubectl rollout restart deployment kyverno -n kyverno
```

## Verification Script

```bash
cat > verify-admission-lab.sh <<'EOF'

#!/bin/bash

echo "=== Admission Control Lab Verification ==="

# Test 1: Kyverno installed

echo "Test 1: Kyverno installation"
kubectl get deployment kyverno -n kyverno &>/dev/null
if [ $? -eq 0 ]; then
  echo "✅ Kyverno installed and running"
else
  echo "❌ Kyverno not found"
  exit 1
fi

# Test 2: Policies created

echo ""
echo "Test 2: Check policies"
POLICIES=$(kubectl get clusterpolicy --no-headers | wc -l)
echo "✅ $POLICIES ClusterPolicies found"

# Test 3: Webhook responding

echo ""
echo "Test 3: Webhook functionality"
kubectl run webhook-test --image=nginx:latest --dry-run=server &>/dev/null
if [ $? -ne 0 ]; then
  echo "✅ Webhook actively blocking requests"
else
  echo "⚠️  Webhook not blocking (may be in audit mode)"
fi

# Test 4: Policy reports

echo ""
echo "Test 4: Policy reporting"
kubectl get policyreport -A --no-headers 2>/dev/null | wc -l
REPORTS=$?
[ $REPORTS -gt 0 ] && echo "✅ Policy reports active" || echo "⚠️  No policy reports"

echo ""
echo "=== Verification Complete ==="
EOF

chmod +x verify-admission-lab.sh
./verify-admission-lab.sh
```

## Cleanup

```bash
# Delete policies

kubectl delete clusterpolicy --all

# Delete namespace

kubectl delete namespace admission-lab

# Remove Kyverno (optional)

kubectl delete -f https://github.com/kyverno/kyverno/releases/download/v1.11.0/install.yaml

# Reset context

kubectl config set-context --current --namespace=default

# Clean up files

rm -f *.yaml *.sh
```

## Key Takeaways

1. Admission controllers enforce policies at deployment time
1. Kyverno provides declarative policy management
1. Policies can verify signatures, scan for vulnerabilities, and restrict registries
1. Audit mode allows testing without blocking
1. Policy exceptions enable flexibility
1. Policy reports provide visibility into violations
1. Init containers can perform runtime scanning
1. Signature verification prevents unauthorized images
1. SBOM attestations ensure transparency
1. Performance tuning is important for large clusters

## Next Steps

1. Implement admission policies in production
1. Create policy exception workflows
1. Integrate with CI/CD for pre-deployment validation
1. Review all Domain 5 materials
1. Practice exam scenarios

## Challenge Questions

1. **What's the difference between Audit and Enforce modes?**
   <details>
   <summary>Answer</summary>
   Audit mode records policy violations but allows deployments. Enforce mode blocks deployments that violate policies. Use Audit first to test policies before enforcing.
   </details>

1. **How do you handle policy exceptions?**
   <details>
   <summary>Answer</summary>
   Use PolicyException resources to allow specific namespaces, users, or workloads to bypass policies. This is useful for system workloads or development environments.
   </details>

1. **What happens if the admission webhook is unavailable?**
   <details>
   <summary>Answer</summary>
   By default, the webhook fails closed (blocks deployments). You can configure it to fail open (allow deployments) using failurePolicy: Ignore, but this reduces security.
   </details>

---

[← Back to Lab Overview](./README.md) | [Previous Lab: SBOM Generation ←](./lab-04-sbom-generation.md) | [Back to Domain 5 README](../../domains/05-supply-chain-security/README.md)
