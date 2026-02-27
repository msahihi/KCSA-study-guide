# KCSA Exam Cheatsheet & Study Guide

> Quick Reference for Kubernetes and Cloud Native Security Associate

**Version**: v1.0.0 | **Last Updated**: February 2026 | **Covers**: Kubernetes v1.30.x, kubectl v1.30.x, containerd v1.7.x

## Table of Contents

1. [Domain 1 - Cluster Setup (10%)](#domain-1---cluster-setup-10)
1. [Domain 2 - Cluster Hardening (20%)](#domain-2---cluster-hardening-20)
1. [Domain 3 - System Hardening (15%)](#domain-3---system-hardening-15)
1. [Domain 4 - Minimize Microservice Vulnerabilities (20%)](#domain-4---minimize-microservice-vulnerabilities-20)
1. [Domain 5 - Supply Chain Security (20%)](#domain-5---supply-chain-security-20)
1. [Domain 6 - Monitoring, Logging, and Runtime Security (15%)](#domain-6---monitoring-logging-and-runtime-security-15)
1. [Essential Commands](#essential-commands)
1. [Quick Reference Tables](#quick-reference-tables)
1. [Common Patterns & Best Practices](#common-patterns--best-practices)
1. [Exam Tips](#exam-tips)

---

## Domain 1 - Cluster Setup (10%)

<details>
<summary><strong>Key Concepts Summary</strong></summary>

### Network Security Policies

*Source: [domains/01-cluster-setup/network-policies.md](domains/01-cluster-setup/network-policies.md)*

- **NetworkPolicy** is a namespace-scoped resource that defines how pods can communicate
- By default, all traffic is allowed between pods (deny-by-default requires explicit NetworkPolicy)
- NetworkPolicy requires a CNI plugin that supports it (Calico, Cilium, Weave Net)
- Policies are additive - multiple policies combine with OR logic
- Three traffic types: **Ingress** (incoming), **Egress** (outgoing), and both
- Selectors use labels to match pods: `podSelector`, `namespaceSelector`
- Default deny all ingress: empty `podSelector: {}` with empty `ingress: []`
- Default deny all egress: empty `podSelector: {}` with empty `egress: []`
- Ports can be specified by `protocol` (TCP/UDP/SCTP) and `port` number
- IP blocks use CIDR notation with optional `except` for exclusions

### CIS Benchmarks

*Source: [domains/01-cluster-setup/cis-benchmarks.md](domains/01-cluster-setup/cis-benchmarks.md)*

- **CIS Kubernetes Benchmark** provides security configuration best practices
- Organized by component: Control Plane, Worker Nodes, Policies, Etcd
- **kube-bench** tool automates CIS benchmark checking
- Scoring levels: **PASS**, **FAIL**, **WARN**, **INFO**
- Key areas: API server flags, kubelet configuration, RBAC settings, Pod Security
- Run kube-bench as a Job in-cluster or as standalone binary
- Common checks: anonymous auth disabled, authorization mode, admission controllers
- Etcd should use TLS, encrypted data at rest, and peer authentication
- API server should disable insecure port (no `--insecure-port`)
- Kubelet should have `--anonymous-auth=false` and `--authorization-mode=Webhook`

### Ingress and Service Security

*Source: [domains/01-cluster-setup/ingress-service-security.md](domains/01-cluster-setup/ingress-service-security.md)*

- **Service types**: ClusterIP (internal), NodePort (exposes on node), LoadBalancer (cloud LB)
- **ClusterIP** is most secure - only accessible within cluster
- **NodePort** exposes on all node IPs - use NetworkPolicy to restrict
- **LoadBalancer** exposes publicly - combine with TLS and authentication
- **Ingress** provides HTTP/HTTPS routing with single entry point
- Ingress supports TLS termination with certificates stored in Secrets
- Use **Ingress Controllers** (NGINX, Traefik, Istio) for advanced features
- Restrict Ingress backend services using NetworkPolicy
- Use annotations for security headers, rate limiting, IP whitelisting
- Always use TLS for production Ingress with valid certificates

### Pod Security Standards

*Source: [domains/01-cluster-setup/pod-security-standards.md](domains/01-cluster-setup/pod-security-standards.md)*

- Three levels: **Privileged** (unrestricted), **Baseline** (minimal restrictions), **Restricted** (hardened)
- **Pod Security Admission** (PSA) enforces standards at namespace level
- Three modes: **enforce** (block), **audit** (log), **warn** (show warning)
- Labels control PSA: `pod-security.kubernetes.io/<MODE>: <LEVEL>`
- **Baseline** blocks: host namespaces, privileged containers, host path volumes, hostPort
- **Restricted** adds: must run as non-root, drop ALL capabilities, read-only root filesystem
- PSA replaces deprecated PodSecurityPolicy (removed in v1.25)
- Use `securityContext` to configure pod and container security settings
- Prefer **Restricted** for production workloads, use Baseline sparingly
- Exemptions possible by username, runtime class, or namespace

</details>

---

## Domain 2 - Cluster Hardening (20%)

<details>
<summary><strong>Key Concepts Summary</strong></summary>

### Role-Based Access Control (RBAC)

*Source: [domains/02-cluster-hardening/rbac.md](domains/02-cluster-hardening/rbac.md)*

- **RBAC** controls who can access what resources in Kubernetes
- Four resource types: **Role**, **ClusterRole**, **RoleBinding**, **ClusterRoleBinding**
- **Role** is namespace-scoped, **ClusterRole** is cluster-wide
- **RoleBinding** grants Role/ClusterRole in namespace, **ClusterRoleBinding** grants cluster-wide
- Permissions are additive - no deny rules (only allow)
- **Principle of Least Privilege** - grant minimum necessary permissions
- **Verbs**: get, list, watch, create, update, patch, delete, deletecollection
- **Resources**: pods, services, deployments, secrets, etc.
- **API groups**: core (""), apps, batch, rbac.authorization.k8s.io, etc.
- Check access: `kubectl auth can-i <verb> <resource> --as=<user>`
- Service accounts automatically bound to pods for API access
- Default service account in each namespace (limited permissions)

### Service Accounts Security

*Source: [domains/02-cluster-hardening/service-accounts.md](domains/02-cluster-hardening/service-accounts.md)*

- **Service Account** provides identity for pods to access API server
- Each namespace has `default` service account (auto-created)
- Token auto-mounted at `/var/run/secrets/kubernetes.io/serviceaccount/`
- Disable auto-mounting: `automountServiceAccountToken: false`
- Create dedicated service accounts per application (not use default)
- Bind minimal RBAC permissions to service accounts
- **TokenRequest API** creates short-lived tokens (v1.21+)
- Legacy tokens are long-lived (avoid unless necessary)
- Token projection allows mounting tokens with audience, expiry
- Use `serviceAccountName` in pod spec to specify account
- Audit service account usage regularly

### Security Contexts

*Source: [domains/02-cluster-hardening/security-contexts.md](domains/02-cluster-hardening/security-contexts.md)*

- **Security Context** defines privilege and access controls for pods/containers
- Two levels: **Pod Security Context** (pod-wide), **Container Security Context** (per-container)
- **runAsUser** / **runAsGroup**: specify UID/GID (avoid root=0)
- **runAsNonRoot**: enforce non-root user (true = block root)
- **fsGroup**: set group ownership for mounted volumes
- **readOnlyRootFilesystem**: make root filesystem read-only (true = secure)
- **allowPrivilegeEscalation**: prevent gaining more privileges (false = secure)
- **privileged**: run in privileged mode (false = secure, avoid true)
- **capabilities**: add/drop Linux capabilities (drop ALL, add specific only)
- **seccompProfile**: apply seccomp profile (RuntimeDefault or Localhost)
- **seLinuxOptions** / **appArmorProfile**: enforce mandatory access control
- Container settings override pod settings

### Pod Security Admission

*Source: [domains/02-cluster-hardening/pod-security-admission.md](domains/02-cluster-hardening/pod-security-admission.md)*

- Built-in admission controller (enabled by default v1.23+)
- Enforces Pod Security Standards at namespace level
- Three modes per namespace: **enforce**, **audit**, **warn**
- Three levels: **privileged**, **baseline**, **restricted**
- Label format: `pod-security.kubernetes.io/<mode>: <level>`
- Version pinning: `pod-security.kubernetes.io/<mode>-version: v1.30`
- **enforce** blocks non-compliant pods from creation
- **audit** logs violations in audit logs (doesn't block)
- **warn** returns warnings to user (doesn't block)
- Exemptions: usernames, runtime classes, namespaces
- Configure via admission config file or namespace labels
- Replaces deprecated PodSecurityPolicy

</details>

---

## Domain 3 - System Hardening (15%)

<details>
<summary><strong>Key Concepts Summary</strong></summary>

### Host Operating System Security

*Source: [domains/03-system-hardening/host-os-security.md](domains/03-system-hardening/host-os-security.md)*

- **Minimize host OS attack surface** - remove unnecessary packages and services
- Use **minimal OS distributions** (CoreOS, Flatcar, Bottlerocket, Talos)
- Keep OS and kernel updated with security patches
- Disable unused network services and close unnecessary ports
- Use **SSH key authentication** only (disable password auth)
- Implement **firewall rules** (iptables, nftables) to restrict traffic
- Enable **kernel security modules** (AppArmor, SELinux, seccomp)
- Disable unnecessary **kernel modules** (add to modprobe blacklist)
- Set proper **file permissions** on critical files (600 for keys)
- **Audit logs** for system access and changes (auditd)
- Separate **control plane and worker nodes** physically or logically
- Implement **node hardening** guidelines from CIS benchmarks

### Container Runtime Security

*Source: [domains/03-system-hardening/runtime-security.md](domains/03-system-hardening/runtime-security.md)*

- **Container Runtime** executes containers (containerd, CRI-O, Docker)
- Kubernetes uses **Container Runtime Interface (CRI)**
- **containerd** is default runtime in most distributions (v1.7.x)
- Runtime should run with minimal privileges (not as root)
- Use **user namespaces** to map container root to non-root host user
- **cgroups** limit resource usage (CPU, memory, I/O)
- **namespaces** isolate resources (PID, network, mount, IPC, UTS)
- Configure runtime with security options in `/etc/containerd/config.toml`
- Disable **privileged containers** in runtime configuration
- Use **RuntimeClass** to specify different runtime configs per workload
- Enable **content trust** to verify image signatures
- Monitor runtime for anomalous behavior

### AppArmor and Seccomp

*Source: [domains/03-system-hardening/apparmor-seccomp.md](domains/03-system-hardening/apparmor-seccomp.md)*

- **AppArmor** is Mandatory Access Control (MAC) system for Linux
- Profiles define per-program restrictions (file access, network, capabilities)
- Two modes: **enforce** (block violations) and **complain** (log only)
- Profiles stored in `/etc/apparmor.d/`
- Load profile: `apparmor_parser -r /path/to/profile`
- Apply to container via annotation: `container.apparmor.security.beta.kubernetes.io/<container>: localhost/<profile>`
- **Seccomp** (Secure Computing Mode) filters system calls
- Three modes: **disabled**, **strict** (allow 4 syscalls), **filter** (custom)
- Profiles are JSON files defining allowed/blocked syscalls
- Apply via security context: `seccompProfile: {type: Localhost, localhostProfile: profile.json}`
- **RuntimeDefault** profile is provided by container runtime
- Always prefer RuntimeDefault or custom profiles over Unconfined
- Test profiles in complain/audit mode before enforcing

### Kernel Security

*Source: [domains/03-system-hardening/kernel-security.md](domains/03-system-hardening/kernel-security.md)*

- Keep kernel updated with latest security patches
- Enable **kernel address space layout randomization (KASLR)**
- Use **kernel hardening options** in boot parameters
- **sysctl** settings for security: `kernel.dmesg_restrict=1`, `kernel.kptr_restrict=2`
- Disable unused kernel modules to reduce attack surface
- Use **signed kernel modules** to prevent malicious modules
- Enable **kernel lockdown mode** (integrity or confidentiality)
- **Page table isolation** (PTI) mitigates Meltdown attacks
- **SMEP/SMAP** prevent kernel from executing/accessing user memory
- Restrict access to `/proc` and `/sys` filesystems
- Monitor kernel logs for anomalies
- Use security-focused kernel distributions (grsecurity, SELinux MLS)

</details>

---

## Domain 4 - Minimize Microservice Vulnerabilities (20%)

<details>
<summary><strong>Key Concepts Summary</strong></summary>

### Secrets Management

*Source: [domains/04-minimize-vulnerabilities/secrets-management.md](domains/04-minimize-vulnerabilities/secrets-management.md)*

- **Secrets** store sensitive data (passwords, tokens, keys) base64-encoded
- Never commit secrets to version control
- Secrets are **not encrypted by default** in etcd - enable encryption at rest
- Enable with `--encryption-provider-config` on API server
- Three encryption types: **aescbc**, **aesgcm**, **secretbox**
- Mount secrets as files (volume) or environment variables (less secure)
- Use **RBAC** to restrict secret access (who can read/create)
- Prefer **volume mounts** over environment variables (not visible in ps)
- Use external secret managers (Vault, AWS Secrets Manager, Azure Key Vault)
- **External Secrets Operator** syncs external secrets to Kubernetes
- Rotate secrets regularly and after compromise
- Use **immutable secrets** to prevent accidental changes
- Scan for secrets in container images before deployment

### Admission Controllers

*Source: [domains/04-minimize-vulnerabilities/admission-controllers.md](domains/04-minimize-vulnerabilities/admission-controllers.md)*

- **Admission Controllers** intercept API requests before persistence
- Two types: **Validating** (accept/reject) and **Mutating** (modify)
- Run in sequence: mutating first, then validating
- Enable with `--enable-admission-plugins` on API server
- Key controllers: **PodSecurity**, **NamespaceLifecycle**, **ResourceQuota**, **LimitRanger**
- **NodeRestriction** limits kubelet to modify its own node/pods
- **AlwaysPullImages** forces image pull (prevents local image use)
- **EventRateLimit** prevents event flooding (DoS protection)
- **DenyEscalatingExec** prevents exec into privileged pods
- **ValidatingAdmissionWebhook** / **MutatingAdmissionWebhook** for custom logic
- Use **Open Policy Agent (OPA)** Gatekeeper for policy enforcement
- Policies written in **Rego** language with ConstraintTemplate
- Test admission policies before enforcing in production

### Runtime Security Tools

*Source: [domains/04-minimize-vulnerabilities/runtime-security-tools.md](domains/04-minimize-vulnerabilities/runtime-security-tools.md)*

- **Falco** is runtime threat detection for containers and Kubernetes
- Uses **syscall tracing** (eBPF or kernel module) to detect anomalies
- Rules define suspicious behaviors (unexpected file access, network connections)
- Outputs to stdout, syslog, HTTP, gRPC, or files
- Deploy as DaemonSet on every node
- **Falco rules** check for: privilege escalation, shell execution, sensitive file access
- **Falco Sidekick** enhances outputs (Slack, PagerDuty, etc.)
- Other tools: **Sysdig**, **Aqua**, **Twistlock** (Prisma Cloud)
- **Tracee** is eBPF-based runtime security tool
- Monitor for: unauthorized processes, network anomalies, file integrity changes
- Integrate with SIEM systems for centralized logging
- Set up alerts for critical security events

### Image Security

*Source: [domains/04-minimize-vulnerabilities/image-security.md](domains/04-minimize-vulnerabilities/image-security.md)*

- Use **minimal base images** (distroless, alpine) to reduce attack surface
- Scan images for vulnerabilities with **Trivy**, **Grype**, **Clair**, **Snyk**
- Fix or accept vulnerabilities based on risk (CVSS score)
- Use **multi-stage builds** to exclude build tools from final image
- Don't store secrets in images (use secrets management)
- Run containers as **non-root user** (USER directive in Dockerfile)
- Use **read-only root filesystem** when possible
- Set proper **file permissions** in image (avoid 777)
- Use **trusted base images** from official sources
- **Image signing** with Cosign or Notary for provenance
- Implement **image admission policies** (only signed images)
- Regularly **update base images** for security patches
- Use **private registries** with authentication and encryption

</details>

---

## Domain 5 - Supply Chain Security (20%)

<details>
<summary><strong>Key Concepts Summary</strong></summary>

### Image Scanning and Vulnerability Assessment

*Source: [domains/05-supply-chain-security/image-scanning.md](domains/05-supply-chain-security/image-scanning.md)*

- **Image scanning** detects vulnerabilities (CVEs) in container images
- Scan at multiple stages: build time, registry, admission, runtime
- **Trivy** is comprehensive scanner (vulnerabilities, secrets, misconfigurations)
- **Grype** is fast vulnerability scanner by Anchore
- **Clair** is open-source scanner with PostgreSQL database
- Scanners use CVE databases (NVD, vendor-specific feeds)
- **CVSS scores** rate severity: None (0), Low (0.1-3.9), Medium (4.0-6.9), High (7.0-8.9), Critical (9.0-10.0)
- Set **vulnerability thresholds** (block critical/high, warn medium)
- **False positives** are common - verify and create exceptions
- Scan base images and application dependencies (OS, language packages)
- Integrate scanning in CI/CD pipeline (shift-left security)
- Use **admission controllers** to block vulnerable images at deploy time
- Regular rescanning for new CVEs (daily/weekly)

### Signed Images and Provenance

*Source: [domains/05-supply-chain-security/image-signing.md](domains/05-supply-chain-security/image-signing.md)*

- **Image signing** ensures authenticity and integrity
- **Cosign** is modern signing tool (sigstore project)
- **Notary** is older CNCF signing project (Docker Content Trust)
- Signing creates **digital signature** using private key
- Verification uses **public key** to confirm signature
- Store signatures in **registry** alongside images (OCI artifacts)
- **Keyless signing** uses OIDC identity (no key management)
- **Rekor** provides transparency log for signatures
- **Policy enforcement** with admission controllers (only allow signed images)
- **Attestations** include build metadata (SLSA provenance)
- Verify: builder identity, source repo, build parameters, dependencies
- **In-toto** framework for supply chain security
- Implement signing in CI/CD (sign after build, before push)

### Registry Security

*Source: [domains/05-supply-chain-security/registry-security.md](domains/05-supply-chain-security/registry-security.md)*

- **Container registry** stores and distributes images
- Use **private registries** for sensitive images (not Docker Hub public)
- Enable **authentication** (username/password, tokens, OIDC)
- Use **RBAC** to control who can push/pull images
- Enable **TLS/HTTPS** for encrypted communication
- Implement **vulnerability scanning** in registry (Harbor, Quay, ECR)
- Use **image retention policies** to remove old images
- Enable **content trust** for signed images only
- **Harbor** provides enterprise features (scanning, signing, RBAC, replication)
- **Immutable tags** prevent overwriting (e.g., latest)
- Use **pull secrets** in Kubernetes (imagePullSecrets)
- Monitor registry access logs for suspicious activity
- Implement **webhook notifications** for push/pull events

### SBOM and Dependency Management

*Source: [domains/05-supply-chain-security/sbom.md](domains/05-supply-chain-security/sbom.md)*

- **SBOM** (Software Bill of Materials) lists all components in software
- Two formats: **SPDX** (ISO standard) and **CycloneDX** (OWASP)
- Generate SBOM: **Syft**, **Trivy**, **Tern**, **Kubernetes BOM**
- SBOM includes: packages, versions, licenses, dependencies
- Use for: vulnerability tracking, license compliance, supply chain risk
- Store SBOMs with artifacts (OCI registry, artifact repo)
- **Dependency tracking** identifies vulnerable components
- Regularly update dependencies for security patches
- Use **dependency scanners** (Dependabot, Renovate, Snyk)
- Implement **software composition analysis (SCA)**
- **Transitive dependencies** are indirect dependencies (check these too)
- **License compliance** ensures legal use of open source
- Automate SBOM generation in CI/CD pipeline

</details>

---

## Domain 6 - Monitoring, Logging, and Runtime Security (15%)

<details>
<summary><strong>Key Concepts Summary</strong></summary>

### Audit Logging

*Source: [domains/06-monitoring-logging/audit-logging.md](domains/06-monitoring-logging/audit-logging.md)*

- **Audit logs** record API server requests (who, what, when, response)
- Four stages: **RequestReceived**, **ResponseStarted**, **ResponseComplete**, **Panic**
- Four levels: **None**, **Metadata**, **Request**, **RequestResponse**
- Configure with **audit policy** file (`--audit-policy-file`)
- Policy has rules: **level**, **users**, **resources**, **omitStages**
- Backends: **log** (file), **webhook** (HTTP), **dynamic** (API)
- Enable with `--audit-log-path`, `--audit-log-maxage`, `--audit-log-maxbackup`
- Logs contain: user, verb, resource, namespace, response code, timestamp
- Use for: security investigations, compliance, anomaly detection
- Integrate with **SIEM** (Splunk, Elasticsearch, Datadog)
- **Audit2rbac** generates RBAC policies from audit logs
- Monitor for: failed authentication, privilege escalation, secret access
- Retention: balance storage cost and compliance requirements

### Behavioral Analytics

*Source: [domains/06-monitoring-logging/behavioral-analytics.md](domains/06-monitoring-logging/behavioral-analytics.md)*

- **Behavioral analytics** detects anomalies in user/application behavior
- Establishes **baseline** of normal behavior, alerts on deviations
- Use machine learning for pattern recognition
- Monitor: API access patterns, resource usage, network traffic
- Detect: credential compromise, lateral movement, privilege escalation
- **User and Entity Behavior Analytics (UEBA)** for user activity
- **Network Traffic Analysis (NTA)** for communication patterns
- Tools: **Falco**, **Sysdig**, **Datadog**, **Splunk UBA**
- Anomalies: unusual API calls, off-hours access, geographic changes
- Integrate with **threat intelligence** feeds for known bad actors
- **Alert fatigue** is common - tune thresholds carefully
- Combine with **SOAR** (Security Orchestration, Automation, Response)

### Runtime Detection

*Source: [domains/06-monitoring-logging/runtime-detection.md](domains/06-monitoring-logging/runtime-detection.md)*

- **Runtime detection** monitors container/pod behavior during execution
- Uses **syscall tracing** (eBPF, kernel modules) for visibility
- **Falco** is primary runtime security tool for Kubernetes
- Detects: shell execution in containers, unexpected network connections, file changes
- Rules match patterns: process, file, network, system call activity
- **eBPF** (extended Berkeley Packet Filter) provides kernel observability
- Advantages: low overhead, no kernel modules, safe
- **Tracee** is eBPF-based runtime security and forensics tool
- **Tetragon** provides eBPF-based security observability
- Monitor for: cryptocurrency miners, reverse shells, data exfiltration
- **File integrity monitoring (FIM)** detects unauthorized file changes
- **Process monitoring** tracks unexpected process execution
- Integrate with incident response workflows

### Security Monitoring Tools

*Source: [domains/06-monitoring-logging/security-monitoring.md](domains/06-monitoring-logging/security-monitoring.md)*

- **Prometheus** collects metrics, **Grafana** visualizes dashboards
- **Falco** for runtime security detection and alerting
- **Falco Sidekick** sends alerts to multiple destinations
- **Fluentd/Fluent Bit** for log aggregation and forwarding
- **Elasticsearch/Logstash/Kibana (ELK)** for log analysis
- **Loki** is lightweight log aggregation by Grafana Labs
- **Jaeger/Zipkin** for distributed tracing (detect security issues)
- **Sysdig** provides container security platform (runtime, scanning, compliance)
- **Aqua/Twistlock** (Prisma Cloud) are commercial security platforms
- **Kube-bench** checks CIS Kubernetes benchmarks
- **Kube-hunter** hunts for security weaknesses (penetration testing)
- **Kubescape** scans clusters for security risks (RBAC, networking, workload)
- Centralize logs in **SIEM** for correlation and compliance

</details>

---

## Essential Commands

<details>
<summary><strong>kubectl Security Commands</strong></summary>

### RBAC and Authorization

```bash

# Check if you can perform action

kubectl auth can-i create pods
kubectl auth can-i delete deployments --namespace=production
kubectl auth can-i '*' '*' --all-namespaces  # Check cluster-admin

# Check as another user

kubectl auth can-i list secrets --as=system:serviceaccount:default:my-sa

# View RBAC permissions for user

kubectl auth can-i --list --as=user@example.com

# Get roles and bindings

kubectl get roles,rolebindings -n <namespace>
kubectl get clusterroles,clusterrolebindings

# Describe role to see permissions

kubectl describe role <role-name> -n <namespace>
kubectl describe clusterrole <clusterrole-name>

# View who can access resources (requires rbac-lookup plugin)

kubectl who-can create pods
kubectl who-can delete secrets -n production
```

```

### Pod Security and Context

```bash

# Run pod with security context

kubectl run secure-pod --image=nginx \
  --dry-run=client -o yaml > pod.yaml

# Then edit pod.yaml to add securityContext

# Check pod security

kubectl get pods <pod-name> -o jsonpath='{.spec.securityContext}'
kubectl get pods <pod-name> -o jsonpath='{.spec.containers[*].securityContext}'

# View pod security admission labels

kubectl get ns <namespace> -o yaml | grep pod-security

# Label namespace for PSA

kubectl label namespace <namespace> \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
```

```

### Secrets Management

```bash

# Create secret from literal

kubectl create secret generic my-secret \
  --from-literal=username=admin \
  --from-literal=password='s3cr3t'

# Create secret from file

kubectl create secret generic tls-secret \
  --from-file=tls.crt=cert.pem \
  --from-file=tls.key=key.pem

# View secret (base64 encoded)

kubectl get secret my-secret -o yaml

# Decode secret

kubectl get secret my-secret -o jsonpath='{.data.password}' | base64 -d

# Create service account

kubectl create serviceaccount my-sa

# Get service account token

kubectl create token my-sa

# Disable auto-mount of service account token

kubectl patch serviceaccount default -p '{"automountServiceAccountToken":false}'
```

```

### Network Policies

```bash

# Get network policies

kubectl get networkpolicies -A
kubectl get netpol -n <namespace>

# Describe network policy

kubectl describe networkpolicy <policy-name> -n <namespace>

# Apply network policy from file

kubectl apply -f deny-all-ingress.yaml

# Test network connectivity (from pod)

kubectl exec -it <pod> -- wget -qO- --timeout=2 http://<service>
kubectl exec -it <pod> -- nc -zv <service> <port>
```

```

### Security Scanning and Auditing

```bash

# Run kube-bench (CIS benchmarks)

kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs -f job/kube-bench

# Scan image with Trivy

trivy image nginx:latest
trivy image --severity HIGH,CRITICAL nginx:latest
trivy image --format json -o results.json nginx:latest

# Scan Kubernetes resources

trivy k8s --report summary cluster
trivy k8s deployment/my-app

# Check pod logs

kubectl logs <pod-name> -n <namespace>
kubectl logs <pod-name> -c <container-name> --previous  # Previous crashed container
```

```

</details>

<details>
<summary><strong>Security Context Examples</strong></summary>

```bash

# Run as non-root with read-only filesystem

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
    runAsNonRoot: true
  containers:
  - name: app
    image: nginx:alpine
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
      seccompProfile:
        type: RuntimeDefault
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: cache
      mountPath: /var/cache/nginx
    - name: run
      mountPath: /var/run
  volumes:
  - name: tmp
    emptyDir: {}
  - name: cache
    emptyDir: {}
  - name: run
    emptyDir: {}
EOF
```

```

</details>

<details>
<summary><strong>Trivy Commands</strong></summary>

```bash

# Scan container image

trivy image nginx:latest
trivy image --severity HIGH,CRITICAL alpine:latest
trivy image --ignore-unfixed nginx:latest  # Only fixable vulnerabilities

# Scan filesystem

trivy fs /path/to/project
trivy fs --security-checks vuln,secret,config .

# Scan Kubernetes cluster

trivy k8s cluster
trivy k8s --report summary all

# Scan specific namespace

trivy k8s --namespace production all

# Generate SBOM

trivy image --format cyclonedx -o sbom.json nginx:latest
trivy image --format spdx -o sbom.spdx nginx:latest

# Scan with custom policy

trivy image --policy policy.rego nginx:latest

# Output formats

trivy image --format json -o results.json nginx:latest
trivy image --format table nginx:latest
trivy image --format sarif -o results.sarif nginx:latest
```

```

</details>

<details>
<summary><strong>Falco Commands</strong></summary>

```bash

# Install Falco (Helm)

helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
helm install falco falcosecurity/falco

# View Falco logs

kubectl logs -n falco daemonset/falco

# Test Falco detection (spawn shell in container)

kubectl exec -it <pod> -- /bin/sh

# Falco should alert on shell execution

# Custom Falco rules (ConfigMap)

kubectl edit configmap falco -n falco

# View Falco events

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=100 -f
```

```

</details>

<details>
<summary><strong>OPA Gatekeeper Commands</strong></summary>

```bash

# Install Gatekeeper

kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml

# View constraint templates

kubectl get constrainttemplates
kubectl describe constrainttemplate k8srequiredlabels

# View constraints

kubectl get constraints
kubectl get k8srequiredlabels

# Create constraint to require labels

cat <<EOF | kubectl apply -f -
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: ns-must-have-env
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Namespace"]
  parameters:
    labels:
    - key: "environment"
EOF

# View violations

kubectl get constraints -o yaml
```

```

</details>

---

## Quick Reference Tables

<details>
<summary><strong>Pod Security Standards Comparison</strong></summary>

| Feature | Privileged | Baseline | Restricted |
| --------- | ----------- | ---------- | ------------ |
| Host Namespaces (PID, IPC, Network) | Allowed | **Blocked** | **Blocked** |
| Privileged Containers | Allowed | **Blocked** | **Blocked** |
| Host Path Volumes | Allowed | **Blocked** | **Blocked** |
| Host Ports | Allowed | **Blocked** | **Blocked** |
| Capabilities (beyond default) | Allowed | Some allowed | **ALL dropped** |
| Run as Root | Allowed | Allowed | **Blocked** |
| Privilege Escalation | Allowed | Allowed | **Blocked** |
| Seccomp Profile | Optional | Optional | **Required (RuntimeDefault)** |
| Read-Only Root Filesystem | Optional | Optional | **Required** |
| Volume Types | All allowed | Restricted | **Highly restricted** |

**Recommendation**: Use **Restricted** for production workloads whenever possible.

</details>

<details>
<summary><strong>CVSS Severity Ratings</strong></summary>

| Rating | CVSS Score | Action |
| -------- | ----------- | -------- |
| **None** | 0.0 | No action needed |
| **Low** | 0.1 - 3.9 | Monitor, update when convenient |
| **Medium** | 4.0 - 6.9 | Update within 30 days |
| **High** | 7.0 - 8.9 | Update within 7 days, mitigate immediately |
| **Critical** | 9.0 - 10.0 | **Block deployment**, patch immediately |

**Best Practice**: Block **Critical** and **High** vulnerabilities in production deployments.

</details>

<details>
<summary><strong>Common Linux Capabilities</strong></summary>

| Capability | Description | Risk |
| ----------- | ------------- | ------ |
| **CAP_SYS_ADMIN** | Perform system administration operations | **Very High** - Avoid |
| **CAP_NET_ADMIN** | Network configuration | **High** - Rarely needed |
| **CAP_NET_BIND_SERVICE** | Bind ports < 1024 | **Low** - Often needed |
| **CAP_CHOWN** | Change file ownership | **Medium** |
| **CAP_DAC_OVERRIDE** | Bypass file permission checks | **High** - Avoid |
| **CAP_SETUID/SETGID** | Change user/group ID | **High** - Avoid |
| **CAP_SYS_PTRACE** | Trace arbitrary processes | **High** - Debugging only |
| **CAP_SYS_MODULE** | Load/unload kernel modules | **Very High** - Avoid |

**Best Practice**: Drop **ALL** capabilities, then add only specific ones needed.

```yaml

securityContext:
  capabilities:
    drop:
    - ALL
    add:
    - NET_BIND_SERVICE  # Only if needed
```

```

</details>

<details>
<summary><strong>Admission Controller Types</strong></summary>

| Type | When Runs | Purpose | Example |
| ------ | ----------- | --------- | --------- |
| **Mutating** | First | Modify requests | Set default values, inject sidecars |
| **Validating** | Second (after mutating) | Accept/reject requests | Enforce policies, check compliance |

**Built-in Admission Controllers** (key ones for security):

- **PodSecurity** - Enforce Pod Security Standards
- **NodeRestriction** - Limit kubelet permissions
- **AlwaysPullImages** - Force image pull (prevent local image use)
- **ResourceQuota** - Enforce resource limits per namespace
- **LimitRanger** - Set default resource requests/limits
- **NamespaceLifecycle** - Prevent operations in terminating namespaces
- **ServiceAccount** - Automate service account creation
- **EventRateLimit** - Prevent event flooding (DoS)

</details>

---

## Common Patterns & Best Practices

<details>
<summary><strong>Deny-All Network Policy Pattern</strong></summary>

### Default Deny All Ingress

**Use Case**: Block all incoming traffic to pods by default, then explicitly allow specific traffic.

**Implementation**:

```yaml

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-ingress
  namespace: production
spec:
  podSelector: {}  # Applies to all pods in namespace
  policyTypes:
  - Ingress

  # Empty ingress: [] means deny all

```

```

### Default Deny All Egress

```yaml

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Egress

  # Empty egress: [] means deny all

```

```

### Allow Specific Traffic

```yaml

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
```

```

**Best Practices**:

- Apply deny-all first, then add allow rules
- Test in non-production before enforcing
- Document required traffic flows
- Use labels consistently for pod selection

</details>

<details>
<summary><strong>Minimal RBAC Role Pattern</strong></summary>

**Use Case**: Grant minimum necessary permissions to service accounts.

**Implementation**:

```yaml

# Read-only access to pods in specific namespace

apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: production
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: pod-reader-binding
  namespace: production
subjects:
- kind: ServiceAccount
  name: my-app
  namespace: production
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

```

**Best Practices**:

- Start with no permissions, add as needed
- Use Roles (namespace) over ClusterRoles when possible
- Never grant `*` (wildcard) in production
- Regularly audit and remove unused permissions
- Use separate service accounts per application
- Avoid binding to `system:serviceaccounts` group

</details>

<details>
<summary><strong>Secure Pod Template Pattern</strong></summary>

**Use Case**: Deploy pods with comprehensive security settings.

**Implementation**:

```yaml

apiVersion: v1
kind: Pod
metadata:
  name: secure-app
  namespace: production
spec:

  # Pod-level security

  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault

  # Service account

  serviceAccountName: my-app-sa
  automountServiceAccountToken: false

  containers:
  - name: app
    image: myapp:v1.2.3  # Use specific tag, not :latest
    imagePullPolicy: Always

    # Container security

    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1000
      capabilities:
        drop:
        - ALL

    # Resource limits

    resources:
      requests:
        memory: "128Mi"
        cpu: "100m"
      limits:
        memory: "256Mi"
        cpu: "200m"

    # Writable directories for read-only filesystem

    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: cache
      mountPath: /app/cache

  volumes:
  - name: tmp
    emptyDir: {}
  - name: cache
    emptyDir: {}

  # Image pull secret for private registry

  imagePullSecrets:
  - name: registry-credentials
```

```

**Best Practices**:

- Apply security at both pod and container levels
- Use read-only root filesystem with emptyDir for writes
- Drop ALL capabilities, add specific ones if needed
- Never use `:latest` tag in production
- Set resource limits to prevent DoS
- Disable token auto-mount unless needed

</details>

<details>
<summary><strong>Secrets Encryption at Rest</strong></summary>

**Use Case**: Encrypt secrets in etcd to prevent plaintext exposure.

**Implementation**:

1. Create encryption configuration:

```yaml

# /etc/kubernetes/encryption-config.yaml

apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - secrets
  providers:
  - aescbc:
      keys:
      - name: key1
        secret: <base64-encoded-32-byte-key>
  - identity: {}  # Fallback for reading old unencrypted secrets
```

```

1. Generate encryption key:

```bash

head -c 32 /dev/urandom | base64
```

```

1. Configure API server flag:

```

--encryption-provider-config=/etc/kubernetes/encryption-config.yaml

```
```

1. Encrypt existing secrets:

```bash

kubectl get secrets --all-namespaces -o json | kubectl replace -f -
```

```

**Best Practices**:

- Rotate encryption keys regularly (every 90 days)
- Store encryption config securely (encrypted disk, KMS)
- Use KMS provider for external key management (AWS KMS, Azure Key Vault)
- Monitor encryption config changes
- Test decryption before key rotation

</details>

---

## Exam Tips

### General Test-Taking Strategy

- **Read questions carefully** - Keywords matter: "BEST", "MOST secure", "LEAST privilege", "NOT"
- **Eliminate wrong answers first** - Cross out obviously incorrect options
- **Time management** - 90 minutes / 60 questions = 1.5 min per question
- **Flag and return** - Don't spend > 2 minutes on any question first pass
- **No penalty for guessing** - Answer every question, even if uncertain
- **Scenario-based questions** - Understand the context and security goal
- **Command syntax** - Know exact flags and options (no autocomplete)

### Focus Areas by Domain

**Domain 1 - Cluster Setup (10%)**:

- NetworkPolicy YAML syntax (podSelector, namespaceSelector, ports)
- CIS benchmark key checks (API server flags, kubelet settings)
- Ingress TLS configuration
- Pod Security Standards levels and restrictions

**Domain 2 - Cluster Hardening (20%)**:

- RBAC verbs and resources (get, list, create, delete)
- RoleBinding vs ClusterRoleBinding (namespace vs cluster)
- Security context fields (runAsUser, capabilities, seccomp)
- Service account token management and auto-mounting
- **Most heavily weighted domain** - Study thoroughly

**Domain 3 - System Hardening (15%)**:

- AppArmor profile application (annotation syntax)
- Seccomp profile types (RuntimeDefault, Localhost, Unconfined)
- Host OS hardening best practices
- Container runtime security settings
- Kernel security modules (SELinux, AppArmor)

**Domain 4 - Minimize Vulnerabilities (20%)**:

- Secrets encryption at rest configuration
- Admission controller types and order (mutating → validating)
- OPA Gatekeeper constraint syntax
- Image security best practices (non-root, minimal base)
- **High exam weight** - Know admission controllers well

**Domain 5 - Supply Chain Security (20%)**:

- Trivy scanning commands and output interpretation
- Image signing with Cosign (keyless vs key-based)
- SBOM formats (SPDX, CycloneDX)
- CVSS severity scores and thresholds
- **High exam weight** - Practice Trivy and vulnerability assessment

**Domain 6 - Monitoring & Logging (15%)**:

- Audit policy configuration and levels
- Falco rule syntax and use cases
- Runtime detection techniques
- Audit log interpretation
- Behavioral analytics concepts

### Common Exam Traps

- **Default deny NetworkPolicy** - Empty `ingress: []` denies, missing `ingress:` allows all
- **RBAC additivity** - Multiple RoleBindings combine with OR, not override
- **Security context hierarchy** - Container settings override pod settings
- **Capabilities syntax** - Must drop ALL first, then add specific capabilities
- **Service account tokens** - Auto-mounted by default unless disabled
- **Pod Security Admission modes** - `enforce` blocks, `audit` logs, `warn` shows message
- **Image tags** - `:latest` is not recommended for production (mutable)
- **Secrets encoding** - base64 is encoding, not encryption
- **NetworkPolicy order** - Policies are additive (OR logic), not sequential
- **Read-only root filesystem** - Requires emptyDir volumes for writes

### Last-Minute Checklist

□ **NetworkPolicy syntax** - podSelector, ingress/egress, ports
□ **RBAC commands** - `kubectl auth can-i`, `kubectl create role`
□ **Security context fields** - runAsUser, capabilities, seccomp
□ **Pod Security Standards** - Privileged, Baseline, Restricted differences
□ **Trivy commands** - `trivy image`, severity filtering, output formats
□ **Admission controllers** - Order (mutating→validating), key built-in ones
□ **Secrets encryption** - EncryptionConfiguration YAML syntax
□ **Falco** - Rule syntax, common detections (shell, file access)
□ **Audit policy** - Levels (None, Metadata, Request, RequestResponse)
□ **AppArmor/Seccomp** - Annotation syntax, profile types
□ **CIS benchmarks** - kube-bench, common API server flags
□ **Image signing** - Cosign verification, keyless signing

### Quick Wins for Exam Day

**Command Aliases** (if allowed to set up environment):

```bash

alias k=kubectl
alias kg='kubectl get'
alias kd='kubectl describe'
alias ka='kubectl apply -f'
```

```

**Remember These Values**:

- Baseline PSS blocks: host namespaces, privileged, hostPath, hostPort
- Restricted PSS adds: runAsNonRoot, drop ALL capabilities, RuntimeDefault seccomp
- CVSS Critical: 9.0-10.0 (block), High: 7.0-8.9 (patch ASAP)
- Default audit levels: Metadata (most common), Request (+ request body), RequestResponse (+ response)
- Common capabilities: NET_BIND_SERVICE (ports < 1024), CHOWN, DAC_OVERRIDE, SYS_ADMIN (avoid)

**Mental Model for Security**:

1. **Least Privilege** - Minimum permissions/access necessary
1. **Defense in Depth** - Multiple layers of security
1. **Zero Trust** - Verify everything, trust nothing
1. **Shift Left** - Security early in pipeline (build, not just runtime)
1. **Immutability** - Prevent changes (read-only filesystem, immutable secrets)

**If You Get Stuck**:

- Think about "what would attackers do?" and choose option that prevents it
- More restrictive = more secure (when in doubt)
- Explicit is better than implicit (RBAC allows, NetworkPolicy blocks)
- Current tools are preferred (PSA over PSP, containerd over Docker)

---

## Additional Resources

- **Practice Labs**: [labs/](labs/) - Complete all hands-on exercises
- **Mock Exams**: [mock-questions/](mock-questions/) - Test your knowledge
- **Domain Content**: [domains/](domains/) - Deep dive into theory
- **Official Docs**: [v1-30.docs.kubernetes.io](https://v1-30.docs.kubernetes.io/)
- **CNCF Curriculum**: [github.com/cncf/curriculum](https://github.com/cncf/curriculum)

---
