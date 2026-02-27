# Domain 5: Supply Chain Security (20%)

## Overview

Domain 5 of the Kubernetes Certified Security Specialist (KCSA) exam focuses on securing the container supply chain - one of the most critical aspects of Kubernetes security. This domain covers approximately 20% of the exam and emphasizes protecting container images from vulnerabilities, ensuring image authenticity, and implementing secure image distribution practices.

Supply chain security is crucial because containers package all application dependencies, and a compromised image can introduce vulnerabilities throughout your entire deployment. Understanding how to scan, sign, verify, and securely distribute container images is essential for maintaining a secure Kubernetes environment.

## Topics Covered

### 1. [Image Scanning](./image-scanning.md)
Learn how to identify vulnerabilities in container images using Trivy and other scanning tools before deploying to production.

**Key Learning Objectives:**
- Understand vulnerability scanning concepts and CVE databases
- Use Trivy to scan container images for vulnerabilities
- Interpret scan results and prioritize remediation
- Integrate scanning into CI/CD pipelines
- Scan running containers and Kubernetes clusters

**Related Lab:** [Lab 01 - Trivy Image Scanning](../../labs/05-supply-chain-security/lab-01-trivy-scanning.md)

### 2. [Image Signing and Verification](./image-signing.md)
Implement image signing with Cosign and Sigstore to ensure image authenticity and integrity throughout the supply chain.

**Key Learning Objectives:**
- Understand container image signing concepts
- Generate and manage signing keys
- Sign container images with Cosign
- Verify image signatures before deployment
- Implement keyless signing with Sigstore

**Related Lab:** [Lab 02 - Image Signing with Cosign](../../labs/05-supply-chain-security/lab-02-image-signing-cosign.md)

### 3. [Registry Security](./registry-security.md)
Secure container registries through authentication, authorization, encryption, and access controls.

**Key Learning Objectives:**
- Understand container registry architecture
- Implement registry authentication and RBAC
- Secure image pull secrets in Kubernetes
- Configure private registries
- Apply registry scanning and admission controls

**Related Lab:** [Lab 03 - Registry Security](../../labs/05-supply-chain-security/lab-03-registry-security.md)

### 4. [Software Bill of Materials (SBOM)](./sbom.md)
Generate and analyze Software Bills of Materials to track components and dependencies in container images.

**Key Learning Objectives:**
- Understand SBOM formats (SPDX, CycloneDX)
- Generate SBOMs for container images
- Analyze dependencies and licenses
- Track vulnerabilities through SBOMs
- Integrate SBOMs into compliance workflows

**Related Lab:** [Lab 04 - SBOM Generation](../../labs/05-supply-chain-security/lab-04-sbom-generation.md)

## Exam Tips

1. **Tool Proficiency**: Know how to use Trivy and Cosign from the command line. Practice common commands until they're second nature.

2. **Hands-on Practice**: Supply chain security requires practical knowledge. Complete all labs multiple times to build muscle memory.

3. **Image Scanning Priority**: Focus on HIGH and CRITICAL vulnerabilities. The exam may ask you to identify and prioritize issues.

4. **Signature Verification**: Understand the difference between signed and unsigned images, and how to enforce signature verification.

5. **Common Scenarios**: Be prepared for tasks like:
   - Scanning an image and interpreting results
   - Signing an image with Cosign
   - Verifying image signatures
   - Creating ImagePullSecrets
   - Generating and analyzing SBOMs

6. **Time Management**: Scanning large images can take time. Know how to scan specific components or use faster scan modes.

7. **Documentation Access**: Familiarize yourself with Trivy and Cosign documentation on their official sites. These may be accessible during the exam.

## Study Approach

### Week 1: Image Scanning
- Read the [Image Scanning](./image-scanning.md) guide
- Complete [Lab 01](../../labs/05-supply-chain-security/lab-01-trivy-scanning.md)
- Practice scanning various images with Trivy
- Learn to interpret and filter scan results
- Understand CVE severity levels and CVSS scores

### Week 2: Image Signing
- Study the [Image Signing](./image-signing.md) guide
- Complete [Lab 02](../../labs/05-supply-chain-security/lab-02-image-signing-cosign.md)
- Practice signing images with Cosign
- Learn signature verification workflows
- Understand keyless signing with Sigstore

### Week 3: Registry Security
- Review the [Registry Security](./registry-security.md) guide
- Complete [Lab 03](../../labs/05-supply-chain-security/lab-03-registry-security.md)
- Practice creating and managing ImagePullSecrets
- Configure private registry access
- Implement registry admission controls

### Week 4: SBOM and Integration
- Master the [SBOM](./sbom.md) guide
- Complete [Lab 04](../../labs/05-supply-chain-security/lab-04-sbom-generation.md)
- Generate and analyze SBOMs
- Complete [Lab 05](../../labs/05-supply-chain-security/lab-05-admission-scanning.md)
- Integrate scanning into admission control

## Prerequisites

Before diving into Domain 5, ensure you have:

1. **Basic Kubernetes Knowledge**
   - Understanding of Pods, Deployments, and Services
   - kubectl command-line proficiency
   - Container image concepts (registry, tag, digest)
   - Familiarity with Kubernetes admission controllers

2. **Lab Environment**
   - Kubernetes cluster v1.30.x with admission control enabled
   - kubectl installed and configured
   - Docker or containerd for building images
   - Internet access for downloading tools and images

3. **Required Tools**
   - Trivy (v0.50.0+) for vulnerability scanning
   - Cosign (v2.0+) for image signing
   - Docker or Podman for image operations
   - curl and basic command-line utilities

4. **Container Fundamentals**
   - Understanding of OCI image format
   - Knowledge of Dockerfile syntax
   - Basic understanding of container registries
   - Familiarity with image tags and digests

## Additional Resources

### Official Documentation
- [Kubernetes Image Pull Policy](https://kubernetes.io/docs/concepts/containers/images/)
- [Managing ImagePullSecrets](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/)
- [Admission Controllers](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
- [Container Image Signatures](https://kubernetes.io/docs/tasks/administer-cluster/verify-signed-images/)

### Tools and Frameworks
- [Trivy](https://trivy.dev/) - Comprehensive vulnerability scanner
- [Cosign](https://docs.sigstore.dev/cosign/overview/) - Container signing and verification
- [Sigstore](https://www.sigstore.dev/) - Keyless signing infrastructure
- [Syft](https://github.com/anchore/syft) - SBOM generation tool
- [Grype](https://github.com/anchore/grype) - Vulnerability scanner

### Security Standards
- [SLSA Framework](https://slsa.dev/) - Supply chain security levels
- [NIST SSDF](https://csrc.nist.gov/Projects/ssdf) - Secure Software Development Framework
- [CycloneDX](https://cyclonedx.org/) - SBOM standard
- [SPDX](https://spdx.dev/) - Software Package Data Exchange

### Best Practices Guides
- [CNCF Supply Chain Security Best Practices](https://www.cncf.io/blog/2021/12/14/supply-chain-security-best-practices/)
- [NSA/CISA Kubernetes Hardening Guide - Supply Chain](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/)

## Quick Reference

### Common Commands for Domain 5

```bash
# Trivy Image Scanning
trivy image <image-name>
trivy image --severity HIGH,CRITICAL <image-name>
trivy image --ignore-unfixed <image-name>
trivy image -f json -o results.json <image-name>

# Trivy Kubernetes Scanning
trivy k8s --report summary cluster
trivy k8s deployment/<name> -n <namespace>

# Cosign Image Signing
cosign generate-key-pair
cosign sign --key cosign.key <image-name>
cosign verify --key cosign.pub <image-name>
cosign sign <image-name>  # Keyless signing

# SBOM Generation
trivy image --format spdx-json -o sbom.json <image-name>
syft <image-name> -o spdx-json
trivy sbom sbom.json

# Image Pull Secrets
kubectl create secret docker-registry regcred \
  --docker-server=<registry> \
  --docker-username=<username> \
  --docker-password=<password> \
  --docker-email=<email>

# Verify ImagePullSecrets
kubectl get secret regcred -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d

# Check Image Digests
kubectl get pods -o jsonpath='{.items[*].spec.containers[*].image}'
kubectl describe pod <pod-name> | grep Image:
```

## Security Best Practices

### Image Scanning
1. **Scan Early and Often**: Scan images during build, before push, and periodically in registries
2. **Fail Fast**: Block deployment of images with HIGH/CRITICAL vulnerabilities
3. **Automate Scanning**: Integrate scanning into CI/CD pipelines
4. **Regular Updates**: Keep base images and dependencies up to date
5. **Minimal Images**: Use distroless or minimal base images to reduce attack surface

### Image Signing
1. **Always Sign**: Sign all production images
2. **Verify Before Deploy**: Enforce signature verification in admission control
3. **Rotate Keys**: Regularly rotate signing keys
4. **Keyless When Possible**: Use Sigstore for keyless signing
5. **Audit Trails**: Maintain logs of signing operations

### Registry Security
1. **Private Registries**: Use private registries for production images
2. **Strong Authentication**: Implement strong authentication and RBAC
3. **Encrypted Transit**: Use TLS for all registry communications
4. **Access Control**: Limit who can push/pull images
5. **Regular Audits**: Audit registry access logs

### SBOM Management
1. **Generate Always**: Create SBOMs for all images
2. **Version Control**: Store SBOMs with source code
3. **Track Dependencies**: Monitor dependencies for vulnerabilities
4. **License Compliance**: Use SBOMs for license auditing
5. **Automation**: Automate SBOM generation in CI/CD

## Domain 5 Statistics

- **Exam Weight**: 20% (highest weight in KCSA exam)
- **Recommended Study Time**: 4-5 weeks
- **Number of Labs**: 5 comprehensive labs
- **Key Tools**: Trivy, Cosign, Syft
- **Primary Focus**: Image scanning and signing

## Common Pitfalls

### 1. Ignoring Unfixed Vulnerabilities
Don't ignore vulnerabilities just because no fix exists. Consider:
- Using different base images
- Implementing compensating controls
- Monitoring for patches

### 2. Signing Without Verification
Signing images is useless without enforcing verification:
- Implement admission controllers
- Use policy engines (Kyverno, OPA)
- Reject unsigned images

### 3. Overly Permissive Registry Access
Secure your registries:
- Don't use default admin credentials
- Implement least privilege access
- Use short-lived credentials

### 4. Not Scanning Running Workloads
New vulnerabilities are discovered daily:
- Scan running containers periodically
- Automate patching workflows
- Monitor CVE databases

### 5. Poor Secret Management
Protect registry credentials:
- Never commit credentials to Git
- Use Kubernetes Secrets
- Implement secret rotation
- Consider external secret management

## Integration with Other Domains

Supply chain security integrates with other KCSA domains:

- **Domain 1 (Cluster Setup)**: Pod Security Standards prevent privileged containers from pulling arbitrary images
- **Domain 2 (Cluster Hardening)**: Admission controllers enforce image policies
- **Domain 3 (System Hardening)**: Runtime security monitors image execution
- **Domain 4 (Minimize Vulnerabilities)**: Image scanning identifies application vulnerabilities
- **Domain 6 (Monitoring & Logging)**: Audit logs track image pull operations

## Hands-on Practice Plan

### Week 1: Foundations
- Day 1-2: Install Trivy, scan 10+ images
- Day 3-4: Analyze scan results, understand CVEs
- Day 5: Integrate Trivy into CI/CD
- Day 6-7: Complete Lab 01, practice exercises

### Week 2: Image Signing
- Day 1-2: Install Cosign, generate keys
- Day 3-4: Sign and verify multiple images
- Day 5: Implement keyless signing
- Day 6-7: Complete Lab 02, practice exercises

### Week 3: Registry Security
- Day 1-2: Set up private registry
- Day 3-4: Configure ImagePullSecrets
- Day 5: Implement registry admission control
- Day 6-7: Complete Labs 03 and 05

### Week 4: Advanced Topics
- Day 1-2: Generate and analyze SBOMs
- Day 3-4: Complete Lab 04
- Day 5: Practice all scenarios
- Day 6-7: Mock exam scenarios

## Certification Tips

1. **Command Memorization**: Know Trivy and Cosign commands by heart
2. **Quick Scanning**: Practice fast scanning techniques
3. **Result Interpretation**: Quickly identify actionable findings
4. **Troubleshooting**: Common issues with signing and verification
5. **Time Boxing**: Allocate 20-25 minutes for supply chain questions (20% of exam)

## Next Steps

1. Start with the [Image Scanning](./image-scanning.md) guide
2. Install required tools (Trivy, Cosign)
3. Complete each lab in sequence
4. Practice with real-world images
5. Review security best practices regularly

Remember: Supply chain security is not just about tools - it's about building a culture of security that starts at the source code and extends through the entire deployment pipeline. Understanding the "why" behind each practice is just as important as knowing the "how."

---

[Back to Main README](../../README.md) | [Previous Domain: Minimize Vulnerabilities ←](../04-minimize-vulnerabilities/README.md) | [Next Domain: Monitoring & Logging →](../06-monitoring-logging/README.md)
