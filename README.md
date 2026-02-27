# KCSA - Kubernetes and Cloud Native Security Associate Study Guide

> Comprehensive study guide for the Kubernetes and Cloud Native Security Associate (KCSA) certification exam

**Version**: v1.0.0 | **Last Updated**: February 2026 | **Exam Version**: KCSA v1.30

## Overview

The **Kubernetes and Cloud Native Security Associate (KCSA)** certification demonstrates foundational knowledge and skills in securing Kubernetes clusters and cloud-native applications. This certification is designed for individuals who want to establish their expertise in Kubernetes security practices and cloud-native security fundamentals.

**Who Should Take This Exam**:

- DevOps engineers transitioning to security-focused roles
- Security professionals learning Kubernetes security
- Platform engineers responsible for cluster security
- Developers wanting to build secure cloud-native applications
- Anyone preparing for advanced security certifications (CKS)

**About This Guide**:

This comprehensive study guide provides structured learning materials, hands-on labs, practice exams, and quick reference materials aligned with the official CNCF KCSA exam blueprint. All content is designed for **beginner-level** learners who are new to Kubernetes security, with progressive complexity and practical exercises using **local Kind/Minikube clusters**.

## What's in This Directory

- [**KCSA_CHEATSHEET.md**](KCSA_CHEATSHEET.md) - Consolidated quick reference with essential commands, concepts, and exam tips
- [**domains/**](domains/) - Detailed theory and concepts for each exam domain with real-world examples
- [**labs/**](labs/) - Hands-on exercises with step-by-step instructions, expected outputs, and solutions
- [**mock-questions/**](mock-questions/) - Practice exams with detailed explanations and scoring guides

## Topics Covered

### [Domain 1: Cluster Setup (10%)](domains/01-cluster-setup/README.md)

- [Network Security Policies](domains/01-cluster-setup/network-policies.md)
- [CIS Benchmarks](domains/01-cluster-setup/cis-benchmarks.md)
- [Ingress and Service Security](domains/01-cluster-setup/ingress-service-security.md)
- [Pod Security Standards](domains/01-cluster-setup/pod-security-standards.md)

### [Domain 2: Cluster Hardening (20%)](domains/02-cluster-hardening/README.md)

- [Role-Based Access Control (RBAC)](domains/02-cluster-hardening/rbac.md)
- [Service Accounts Security](domains/02-cluster-hardening/service-accounts.md)
- [Security Contexts](domains/02-cluster-hardening/security-contexts.md)
- [Pod Security Admission](domains/02-cluster-hardening/pod-security-admission.md)

### [Domain 3: System Hardening (15%)](domains/03-system-hardening/README.md)

- [Host Operating System Security](domains/03-system-hardening/host-os-security.md)
- [Container Runtime Security](domains/03-system-hardening/runtime-security.md)
- [AppArmor and Seccomp](domains/03-system-hardening/apparmor-seccomp.md)
- [Kernel Security](domains/03-system-hardening/kernel-security.md)

### [Domain 4: Minimize Microservice Vulnerabilities (20%)](domains/04-minimize-vulnerabilities/README.md)

- [Secrets Management](domains/04-minimize-vulnerabilities/secrets-management.md)
- [Admission Controllers](domains/04-minimize-vulnerabilities/admission-controllers.md)
- [Runtime Security Tools](domains/04-minimize-vulnerabilities/runtime-security-tools.md)
- [Image Security](domains/04-minimize-vulnerabilities/image-security.md)

### [Domain 5: Supply Chain Security (20%)](domains/05-supply-chain-security/README.md)

- [Image Scanning and Vulnerability Assessment](domains/05-supply-chain-security/image-scanning.md)
- [Signed Images and Provenance](domains/05-supply-chain-security/image-signing.md)
- [Registry Security](domains/05-supply-chain-security/registry-security.md)
- [SBOM and Dependency Management](domains/05-supply-chain-security/sbom.md)

### [Domain 6: Monitoring, Logging, and Runtime Security (15%)](domains/06-monitoring-logging/README.md)

- [Audit Logging](domains/06-monitoring-logging/audit-logging.md)
- [Behavioral Analytics](domains/06-monitoring-logging/behavioral-analytics.md)
- [Runtime Detection](domains/06-monitoring-logging/runtime-detection.md)
- [Security Monitoring Tools](domains/06-monitoring-logging/security-monitoring.md)

## Exam Information

**Exam Details**:

- **Duration**: 90 minutes
- **Questions**: 60 multiple-choice questions
- **Passing Score**: 75% (45 correct answers)
- **Format**: Online proctored
- **Cost**: $250 USD (includes one free retake)
- **Validity**: 2 years

**Exam Environment Versions**:

- Kubernetes: v1.30.x
- kubectl: v1.30.x
- containerd: v1.7.x
- Kind: v0.22.x (for local practice)

**Note**: This guide covers the specific tool versions aligned with the KCSA exam. Commands and examples are tested with these versions.

## External Links

- [Official KCSA Certification Page](https://training.linuxfoundation.org/certification/kubernetes-and-cloud-native-security-associate-kcsa/)
- [CNCF KCSA Exam Curriculum](https://github.com/cncf/curriculum/blob/master/KCSA_Curriculum.pdf)
- [Kubernetes Official Documentation v1.30](https://v1-30.docs.kubernetes.io/)
- [CIS Kubernetes Benchmarks](https://www.cisecurity.org/benchmark/kubernetes)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [CNCF Cloud Native Security Whitepaper](https://github.com/cncf/tag-security/blob/main/security-whitepaper/cloud-native-security-whitepaper.md)

## Getting Started

### Prerequisites

Before starting this study guide, you should have:

- **Basic Linux command line knowledge** (file navigation, text editing, permissions)
- **Basic networking concepts** (IP addresses, ports, protocols)
- **Familiarity with containers** (Docker basics recommended but not required)
- **Basic YAML syntax** understanding
- **A computer with at least 8GB RAM** for running local Kubernetes clusters

**Optional but Helpful**:

- Completed basic Kubernetes tutorials (kubernetes.io/docs/tutorials/)
- Understanding of cloud computing concepts
- Experience with Git and version control

### Quick Start Path

1. **Set Up Your Lab Environment**
   - Install Docker Desktop or Podman
   - Install kubectl v1.30.x
   - Install Kind v0.22.x
   - Verify installation with test cluster

1. **Study by Domain**
   - Read domain theory in [domains/](domains/)
   - Complete corresponding labs in [labs/](labs/)
   - Review key concepts in [KCSA_CHEATSHEET.md](KCSA_CHEATSHEET.md)
   - Repeat for each domain in order

1. **Practice and Assess**
   - Take mock exam set 1
   - Review missed questions and study gaps
   - Retake weak domain labs
   - Take mock exam set 2
   - Review final weak areas

1. **Final Preparation**
   - Review entire cheatsheet
   - Complete all challenge exercises
   - Take final mock exam
   - Schedule your exam when scoring 90%+

### Recommended Study Approach

**Week 1-2: Foundation (Domains 1-2)**

- Study Cluster Setup concepts
- Complete all Domain 1 labs
- Study Cluster Hardening concepts
- Complete all Domain 2 labs
- Focus on RBAC, Network Policies, Security Contexts

**Week 3-4: System Security (Domain 3)**

- Study System Hardening concepts
- Complete all Domain 3 labs
- Practice AppArmor and Seccomp profiles
- Understand container runtime security
- Review CIS benchmarks

**Week 5-6: Application Security (Domains 4-5)**

- Study Minimize Vulnerabilities concepts
- Complete all Domain 4 labs
- Study Supply Chain Security concepts
- Complete all Domain 5 labs
- Practice with Trivy, OPA, and image signing

**Week 7: Monitoring & Practice (Domain 6 + Mock Exams)**

- Study Monitoring and Logging concepts
- Complete all Domain 6 labs
- Take Mock Exam Set 1
- Review weak areas
- Take Mock Exam Set 2

**Week 8: Final Review**

- Review entire KCSA_CHEATSHEET.md
- Retake challenging labs
- Take Mock Exam Set 3
- Final weak area review
- Schedule exam when ready (90%+ on mocks)

## Lab Environment Setup

### Install Docker Desktop (macOS/Windows)

Download and install from [docker.com](https://www.docker.com/products/docker-desktop/)

### Install kubectl

```bash

# macOS (using Homebrew)

brew install kubectl@1.30

# Linux

curl -LO "https://dl.k8s.io/release/v1.30.0/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Verify installation

kubectl version --client
```

### Install Kind

```bash

# macOS

brew install kind

# Linux

curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.22.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind

# Verify installation

kind version
```

### Create Your First Lab Cluster

```bash

# Create a Kind cluster for labs

cat <<EOF | kind create cluster --name kcsa-lab --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  image: kindest/node:v1.30.0
- role: worker
  image: kindest/node:v1.30.0
EOF

# Verify cluster is running

kubectl cluster-info --context kind-kcsa-lab
kubectl get nodes

# You're ready to start the labs!

```

### Optional: Install Additional Tools

```bash

# Trivy (vulnerability scanner)

brew install aquasecurity/trivy/trivy  # macOS

# or download from https://github.com/aquasecurity/trivy/releases

# kube-bench (CIS benchmark checker)

kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml

# kubesec (security risk analysis)

docker pull kubesec/kubesec:latest
```

## Study Tips

- **Hands-on practice is essential** - Don't just read, actually run the commands
- **Understand the "why"** - Know why security measures are needed, not just how to implement them
- **Break down complex topics** - Take time to understand each concept before moving on
- **Use the cheatsheet** - Reference it frequently while studying and practicing
- **Join the community** - Engage with CNCF Slack channels and study groups
- **Take breaks** - Security concepts can be dense; pace yourself
- **Document your learning** - Keep notes on tricky concepts and gotchas
- **Simulate exam conditions** - Practice under time pressure with mock exams

## Acknowledgments

- CNCF and the Kubernetes community for excellent documentation
- Contributors to open-source security tools (Trivy, Falco, OPA, etc.)
- The Kubernetes security community for sharing knowledge

---

**Ready to start?** Begin with [Domain 1: Cluster Setup](domains/01-cluster-setup/README.md) or jump to the [KCSA Cheatsheet](KCSA_CHEATSHEET.md) for a quick overview.

**Questions?** Check the [mock-questions/](mock-questions/) directory for practice exams and detailed explanations.
