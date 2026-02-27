# KCSA Mock Exam Set 1

**Duration**: 90 minutes  
**Passing Score**: 75% (45 out of 60 questions)  
**Instructions**: Choose the MOST appropriate answer for each question.

---

## Domain 1: Overview of Cloud Native Security (6 questions)

### Question 1
Your organization is adopting a cloud native architecture. Which principle is MOST important when implementing security in a cloud native environment?

A. Security should be implemented as a final step before production deployment  
B. Security should be integrated throughout the development lifecycle (shift-left approach)  
C. Security is primarily the responsibility of the infrastructure team  
D. Security policies should be manually reviewed and approved for each deployment

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
The shift-left security approach is fundamental to cloud native security. This means integrating security practices early and throughout the entire development lifecycle, not as an afterthought.

Why B is correct:
- Catches security issues early when they're cheaper to fix
- Automates security checks in CI/CD pipelines
- Makes security everyone's responsibility
- Aligns with DevSecOps principles

Why others are wrong:
- A: Security as a final step is too late and creates bottlenecks
- C: In cloud native, security is everyone's responsibility, not just one team
- D: Manual reviews don't scale in cloud native environments with frequent deployments

**Reference**: Cloud Native Security Whitepaper - Defense in Depth
</details>

---

### Question 2
Which layer of the 4C's security model represents the MOST fundamental layer that all other layers depend on?

A. Cluster  
B. Container  
C. Code  
D. Cloud/Data Center

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: D**

**Explanation:**
The 4C's of Cloud Native Security model consists of Cloud, Cluster, Container, and Code layers in that order from bottom to top. Each layer builds upon the security of the layer beneath it.

Why D is correct:
- Cloud/Data Center is the foundation layer
- If this layer is compromised, upper layers cannot be secured
- Includes physical security, network security, and infrastructure

Why others are wrong:
- A, B, C: These are higher layers that depend on the Cloud layer
- Without a secure foundation (Cloud), securing upper layers is ineffective

**Reference**: Kubernetes Documentation - 4C's of Cloud Native Security
</details>

---

### Question 3
Your company is implementing zero trust security for Kubernetes. Which statement BEST describes the zero trust principle?

A. Trust all traffic within the cluster network by default  
B. Never trust, always verify - authenticate and authorize every request  
C. Only apply security controls at the perimeter  
D. Trust service accounts by default but verify external users

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Zero trust is based on the principle of "never trust, always verify." Every request must be authenticated and authorized regardless of where it originates.

Why B is correct:
- Eliminates implicit trust based on network location
- Requires continuous verification of identity and authorization
- Applies to both east-west (internal) and north-south (external) traffic
- Implements least privilege access

Why others are wrong:
- A: Zero trust explicitly does NOT trust traffic by default
- C: Perimeter-only security is the opposite of zero trust
- D: Zero trust doesn't distinguish between internal and external - verify everything

**Reference**: NIST Zero Trust Architecture (SP 800-207)
</details>

---

### Question 4
Which component is responsible for implementing network policies in a Kubernetes cluster?

A. kube-apiserver  
B. CNI (Container Network Interface) plugin  
C. kube-proxy  
D. kubelet

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
NetworkPolicies are implemented by the CNI plugin. Not all CNI plugins support NetworkPolicy - you need one that does (e.g., Calico, Cilium, Weave Net).

Why B is correct:
- CNI plugins control network connectivity between pods
- They enforce the rules defined in NetworkPolicy objects
- Examples: Calico, Cilium, Weave Net support NetworkPolicy

Why others are wrong:
- A: API server only stores NetworkPolicy objects, doesn't enforce them
- C: kube-proxy manages service networking, not NetworkPolicy
- D: kubelet manages pods but doesn't enforce network policies

**Reference**: Kubernetes Network Policies Documentation
</details>

---

### Question 5
What is the primary purpose of admission controllers in Kubernetes security?

A. To monitor runtime behavior of containers  
B. To scan container images for vulnerabilities  
C. To intercept and validate/mutate requests to the API server before persistence  
D. To encrypt data at rest in etcd

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
Admission controllers intercept requests to the Kubernetes API server after authentication and authorization but before the object is persisted. They can validate or mutate the request.

Why C is correct:
- Admission controllers act as gatekeepers for API requests
- Can enforce security policies (Pod Security Admission)
- Can modify requests (mutating admission) or reject them (validating admission)
- Essential for policy enforcement

Why others are wrong:
- A: Runtime monitoring is done by tools like Falco, not admission controllers
- B: Image scanning is done by tools like Trivy, not admission controllers
- D: Encryption at rest is configured separately via EncryptionConfiguration

**Reference**: Kubernetes Admission Controllers Documentation
</details>

---

### Question 6
Your organization needs to comply with multiple security frameworks (PCI-DSS, HIPAA, SOC 2). Which approach is MOST effective for managing compliance in Kubernetes?

A. Manually audit each workload against each framework quarterly  
B. Implement policy-as-code with tools like OPA/Gatekeeper to enforce compliance requirements  
C. Rely on cloud provider compliance certifications only  
D. Create separate clusters for each compliance framework

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Policy-as-code automates compliance enforcement and makes it scalable, consistent, and auditable across the entire cluster.

Why B is correct:
- Automates compliance checks in real-time
- Prevents non-compliant resources from being created
- Provides audit trails
- Scales to multiple frameworks simultaneously

Why others are wrong:
- A: Manual audits don't scale and can't prevent violations in real-time
- C: Cloud provider compliance is necessary but not sufficient for workload compliance
- D: Separate clusters are expensive and don't address the compliance enforcement problem

**Reference**: OPA Gatekeeper for Kubernetes Policy Enforcement
</details>

---

## Domain 2: Kubernetes Cluster Component Security (12 questions)

### Question 7
Which kube-apiserver flag is MOST important for enabling audit logging?

A. --audit-log-path  
B. --enable-admission-plugins  
C. --authorization-mode  
D. --etcd-servers

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: A**

**Explanation:**
To enable audit logging, you must configure the audit log path where logs will be written. You also need an audit policy file (--audit-policy-file), but the path is essential.

Why A is correct:
- Specifies where audit logs are written
- Without this, audit events aren't persisted
- Part of the minimum audit configuration

Why others are wrong:
- B: Enables admission plugins, not audit logging
- C: Configures authorization modes, not audit logging
- D: Specifies etcd endpoints, not audit logging

**Reference**: Kubernetes Auditing Documentation
</details>

---

### Question 8
Your company requires that all API server communication must be encrypted. Which component certificates should you configure?

A. Only the API server certificate  
B. API server certificate and CA certificate  
C. API server certificate, CA certificate, and client certificates for all components  
D. Only the kubelet certificate

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
For complete TLS encryption in Kubernetes, you need certificates for the API server, a CA to sign them, and client certificates for all components communicating with the API server.

Why C is correct:
- API server needs a server certificate
- CA certificate is needed to establish trust
- Components (kubelet, kube-proxy, scheduler, controller-manager) need client certificates
- This enables mutual TLS (mTLS)

Why others are wrong:
- A: Only server cert doesn't enable client authentication
- B: Missing client certificates for components
- D: Only kubelet isn't sufficient; all components need certificates

**Reference**: Kubernetes PKI Certificates and Requirements
</details>

---

### Question 9
What is the PRIMARY security purpose of encrypting data at rest in etcd?

A. To improve etcd performance  
B. To protect secrets and sensitive data if etcd backup files are compromised  
C. To enable audit logging  
D. To allow etcd clustering

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Encryption at rest protects data stored in etcd (including Secrets) if someone gains unauthorized access to etcd data files or backups.

Why B is correct:
- Secrets are stored in base64 encoding by default (not encrypted)
- Encryption at rest adds actual encryption to stored data
- Protects against physical media theft or backup compromise
- Required for compliance in many frameworks

Why others are wrong:
- A: Encryption doesn't improve performance (may slightly reduce it)
- C: Audit logging is separate from encryption
- D: Clustering doesn't require encryption (though recommended)

**Reference**: Kubernetes Encryption at Rest Documentation
</details>

---

### Question 10
Which authorization mode should you use to implement fine-grained permissions in a production Kubernetes cluster?

A. AlwaysAllow  
B. ABAC (Attribute-Based Access Control)  
C. RBAC (Role-Based Access Control)  
D. Node

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
RBAC is the recommended and most widely used authorization mode for production Kubernetes clusters. It provides fine-grained access control through Roles and RoleBindings.

Why C is correct:
- Standard Kubernetes authorization mechanism
- Fine-grained permissions using Roles and RoleBindings
- Dynamic - changes don't require API server restart
- Namespace-scoped and cluster-scoped options

Why others are wrong:
- A: AlwaysAllow provides no access control (testing only)
- B: ABAC requires API server restart for changes and is deprecated
- D: Node authorization is specific to kubelet authorization, not general use

**Reference**: Kubernetes RBAC Documentation
</details>

---

### Question 11
A security scan reveals that your API server is accessible without authentication. Which flag should you verify is NOT set?

A. --anonymous-auth=false  
B. --insecure-port=0  
C. --authorization-mode=RBAC  
D. --enable-admission-plugins

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
The insecure-port (defaulted to 8080 in older versions) allows unauthenticated access to the API server. It should be disabled (set to 0) in secure configurations.

Why B is correct:
- Insecure port bypasses authentication and authorization
- Should always be disabled (--insecure-port=0)
- Default changed to 0 in newer Kubernetes versions
- Major security vulnerability if enabled

Why others are wrong:
- A: This flag disables anonymous auth (good security practice)
- C: Setting authorization mode is required for security
- D: Enabling admission plugins enhances security

**Reference**: Kubernetes API Server Security Configuration
</details>

---

### Question 12
Which component is responsible for managing TLS certificates for pods using cert-manager?

A. kube-controller-manager  
B. A custom controller (cert-manager controller)  
C. kubelet  
D. kube-apiserver

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
cert-manager is a custom Kubernetes controller that automates the management and issuance of TLS certificates from various issuing sources.

Why B is correct:
- cert-manager runs as a custom controller in the cluster
- Watches Certificate resources and automatically provisions certificates
- Integrates with various certificate authorities (Let's Encrypt, HashiCorp Vault, etc.)
- Handles certificate renewal automatically

Why others are wrong:
- A: kube-controller-manager manages built-in controllers, not cert-manager
- C: kubelet manages container lifecycle, not certificates
- D: API server stores certificate resources but doesn't manage them

**Reference**: cert-manager Documentation
</details>

---

### Question 13
What is the MOST secure way to provide credentials to the API server for accessing etcd?

A. Store credentials in a ConfigMap  
B. Use client certificates for mutual TLS authentication  
C. Pass credentials as command-line arguments  
D. Store credentials in environment variables

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Mutual TLS (mTLS) using client certificates is the most secure method for API server to etcd authentication. It provides both encryption and authentication.

Why B is correct:
- Provides mutual authentication (both sides verify identity)
- Certificates can be rotated
- No credentials stored in plaintext
- Industry best practice for component-to-component communication

Why others are wrong:
- A: ConfigMaps are not encrypted and are easily accessible
- C: Command-line arguments are visible in process lists
- D: Environment variables can be exposed and are less secure than certificates

**Reference**: Kubernetes etcd Security Documentation
</details>

---

### Question 14
Which kube-apiserver flag limits the rate of requests from a single user to prevent API server overload?

A. --max-requests-inflight  
B. --request-timeout  
C. --max-mutating-requests-inflight  
D. --client-ca-file

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: A**

**Explanation:**
The --max-requests-inflight flag limits the number of non-mutating (read) requests that can be in-flight at once, helping prevent API server overload.

Why A is correct:
- Limits concurrent non-mutating requests to the API server
- Prevents resource exhaustion from too many simultaneous requests
- Default is 400
- Works together with --max-mutating-requests-inflight

Why others are wrong:
- B: Sets timeout for requests, doesn't limit concurrency
- C: This limits mutating requests specifically, but the question asks about general rate limiting
- D: Specifies the CA certificate file, not related to rate limiting

**Reference**: Kubernetes API Server Configuration
</details>

---

### Question 15
Your audit logs show repeated failed authentication attempts to the API server. What should you investigate FIRST?

A. NetworkPolicy configurations  
B. API server logs and the source IP addresses of the attempts  
C. Pod Security Admission policies  
D. Container image vulnerabilities

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Failed authentication attempts indicate potential unauthorized access attempts. You should immediately examine API server logs and identify the source.

Why B is correct:
- Identifies the source of the attack
- Helps determine if it's malicious or misconfiguration
- API server logs contain authentication details
- Source IP helps with blocking or investigation

Why others are wrong:
- A: NetworkPolicy doesn't affect authentication
- C: PSA doesn't affect API server authentication
- D: Image vulnerabilities aren't related to authentication failures

**Reference**: Kubernetes Audit Logging Best Practices
</details>

---

### Question 16
Which component is responsible for ensuring that the desired number of pod replicas specified in a ReplicaSet are running?

A. kubelet  
B. kube-scheduler  
C. kube-controller-manager  
D. kube-proxy

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
The kube-controller-manager runs various controllers including the ReplicaSet controller, which ensures the desired number of pods are running.

Why C is correct:
- Hosts the ReplicaSet controller
- Continuously monitors and reconciles desired vs actual state
- Creates/deletes pods to match the desired replica count
- Critical for cluster reliability

Why others are wrong:
- A: kubelet manages pods on nodes, not ReplicaSets
- B: scheduler assigns pods to nodes, doesn't manage replica count
- D: kube-proxy manages network rules for services

**Reference**: Kubernetes Controllers Documentation
</details>

---

### Question 17
What is the PRIMARY security benefit of enabling kubelet certificate rotation?

A. Improves kubelet performance  
B. Reduces the risk of compromised or expired certificates  
C. Enables pod networking  
D. Allows the kubelet to access secrets

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Certificate rotation automatically renews kubelet certificates before expiration, reducing the window of opportunity for compromised certificates and preventing certificate expiration issues.

Why B is correct:
- Automatically rotates certificates before expiration
- Reduces risk from long-lived certificates
- Prevents service disruption from expired certificates
- Limits damage if a certificate is compromised

Why others are wrong:
- A: Certificate rotation doesn't affect performance
- C: Pod networking is handled by CNI, not certificate rotation
- D: Secret access is controlled by RBAC, not certificate rotation

**Reference**: Kubernetes Certificate Rotation Documentation
</details>

---

### Question 18
Which flag should you set on the kubelet to disable anonymous authentication?

A. --anonymous-auth=false  
B. --authentication-mode=none  
C. --authorization-mode=AlwaysDeny  
D. --disable-anonymous=true

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: A**

**Explanation:**
The --anonymous-auth=false flag disables anonymous requests to the kubelet API, improving security by requiring authentication for all requests.

Why A is correct:
- Explicitly disables anonymous authentication
- Standard kubelet security hardening
- Recommended in CIS Kubernetes Benchmark
- Requires all requests to be authenticated

Why others are wrong:
- B: Not a valid kubelet flag
- C: This is for authorization, not authentication
- D: Not a valid kubelet flag (correct flag is --anonymous-auth)

**Reference**: Kubernetes Kubelet Authentication/Authorization
</details>

---

## Domain 3: Kubernetes Security Fundamentals (9 questions)

### Question 19
You need to ensure that a pod runs as a non-root user. Which Security Context field should you set?

A. runAsNonRoot: true  
B. allowPrivilegeEscalation: false  
C. readOnlyRootFilesystem: true  
D. privileged: false

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: A**

**Explanation:**
The runAsNonRoot field ensures that containers run as a non-root user. If the image runs as root, the container will fail to start.

Why A is correct:
- Explicitly requires non-root user
- Kubernetes validates this at runtime
- Fails container startup if image would run as root
- Best practice for container security

Why others are wrong:
- B: Prevents privilege escalation but doesn't enforce non-root
- C: Makes filesystem read-only, doesn't affect user
- D: Disables privileged mode, doesn't enforce non-root user

**Reference**: Kubernetes Security Context Documentation
</details>

---

### Question 20
Which Security Context setting prevents a container from writing to its filesystem?

A. runAsNonRoot: true  
B. allowPrivilegeEscalation: false  
C. readOnlyRootFilesystem: true  
D. privileged: false

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
The readOnlyRootFilesystem field makes the container's root filesystem read-only, preventing any writes to the filesystem (except mounted volumes).

Why C is correct:
- Makes root filesystem immutable
- Prevents malware from writing to filesystem
- Forces use of volumes for writable storage
- Security best practice

Why others are wrong:
- A: Enforces non-root user, doesn't affect filesystem writes
- B: Prevents privilege escalation, doesn't make filesystem read-only
- D: Disables privileged mode, doesn't affect filesystem writes

**Reference**: Kubernetes Security Context - readOnlyRootFilesystem
</details>

---

### Question 21
A developer reports that their pod fails to start with "RunAsNonRoot: RunContainerError". What is the MOST likely cause?

A. The container image is configured to run as root (UID 0)  
B. The pod has insufficient CPU resources  
C. NetworkPolicy is blocking the pod  
D. The pod doesn't have a ServiceAccount

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: A**

**Explanation:**
This error occurs when runAsNonRoot is set to true, but the container image is configured to run as root (UID 0).

Why A is correct:
- Error specifically indicates RunAsNonRoot violation
- Container image USER is set to root or defaults to root
- Need to either change the image or set runAsUser to non-zero

Why others are wrong:
- B: Resource issues produce different errors
- C: NetworkPolicy doesn't prevent pod startup
- D: Missing ServiceAccount doesn't cause this specific error

**Reference**: Kubernetes Security Context Troubleshooting
</details>

---

### Question 22
Which capability should you DROP to prevent a container from changing file ownership?

A. NET_ADMIN  
B. SYS_ADMIN  
C. CHOWN  
D. DAC_OVERRIDE

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
The CHOWN capability allows changing file ownership. Dropping it prevents the container from using chown/chgrp commands.

Why C is correct:
- CHOWN capability specifically controls file ownership changes
- Dropping it prevents chown and chgrp operations
- Security best practice to drop unnecessary capabilities

Why others are wrong:
- A: NET_ADMIN is for network administration
- B: SYS_ADMIN is for system administration (very broad)
- D: DAC_OVERRIDE is for bypassing file read/write/execute permissions

**Reference**: Linux Capabilities Documentation
</details>

---

### Question 23
What is the PRIMARY difference between a Role and a ClusterRole in RBAC?

A. Role is for users, ClusterRole is for service accounts  
B. Role is namespace-scoped, ClusterRole is cluster-scoped  
C. Role is read-only, ClusterRole allows write operations  
D. Role is for developers, ClusterRole is for administrators

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Role is namespace-scoped (applies within a single namespace), while ClusterRole is cluster-scoped (applies across all namespaces or to cluster-level resources).

Why B is correct:
- Role grants access within a specific namespace
- ClusterRole can grant access to cluster-scoped resources or across all namespaces
- Fundamental RBAC concept
- ClusterRole can be bound at namespace level with RoleBinding

Why others are wrong:
- A: Both can be used for users or service accounts
- C: Both can grant any permissions (read/write)
- D: Both can be used by any identity type

**Reference**: Kubernetes RBAC Documentation
</details>

---

### Question 24
Which RBAC component binds a Role or ClusterRole to a user, group, or ServiceAccount?

A. RoleBinding or ClusterRoleBinding  
B. ServiceAccount  
C. SecurityContext  
D. PodSecurityPolicy

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: A**

**Explanation:**
RoleBinding (for namespace-scoped) and ClusterRoleBinding (for cluster-scoped) bind Roles/ClusterRoles to subjects (users, groups, or ServiceAccounts).

Why A is correct:
- RoleBinding binds Role or ClusterRole within a namespace
- ClusterRoleBinding binds ClusterRole cluster-wide
- These are the binding mechanisms in RBAC

Why others are wrong:
- B: ServiceAccount is a subject, not a binding mechanism
- C: SecurityContext is for pod/container security, not RBAC
- D: PSP is deprecated and not related to RBAC binding

**Reference**: Kubernetes RoleBinding and ClusterRoleBinding
</details>

---

### Question 25
You need to grant a developer read-only access to pods in the 'development' namespace only. What is the MOST appropriate approach?

A. Create a ClusterRole with pod read permissions and a ClusterRoleBinding  
B. Create a Role in 'development' namespace with pod read permissions and a RoleBinding  
C. Grant cluster-admin role with a RoleBinding  
D. Create a ClusterRole and bind it with a RoleBinding in 'development'

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
For namespace-specific permissions, create a Role in that namespace with the required permissions and bind it with a RoleBinding.

Why B is correct:
- Role is namespace-scoped (perfect for single namespace access)
- RoleBinding limits access to the development namespace
- Follows least privilege principle
- Simplest and most appropriate solution

Why others are wrong:
- A: ClusterRoleBinding grants access across all namespaces
- C: cluster-admin is excessive for read-only pod access
- D: While this works, creating a Role is simpler for single-namespace access

**Reference**: Kubernetes RBAC Best Practices
</details>

---

### Question 26
What is the default behavior when NO NetworkPolicy is applied to a namespace?

A. All traffic is denied  
B. All traffic is allowed  
C. Only ingress traffic is allowed  
D. Only egress traffic is allowed

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
By default, if no NetworkPolicy exists in a namespace, all ingress and egress traffic is allowed to/from pods.

Why B is correct:
- Default Kubernetes behavior is allow-all
- NetworkPolicies are opt-in security
- Once you create any NetworkPolicy selecting a pod, that pod becomes isolated
- Common misconception is that default is deny

Why others are wrong:
- A: This is what many expect, but it's incorrect
- C, D: Both ingress and egress are allowed by default

**Reference**: Kubernetes NetworkPolicy Documentation
</details>

---

### Question 27
You want to deny all ingress traffic to pods in a namespace except from pods with label 'app=frontend'. What should you create?

A. A NetworkPolicy with ingress rules selecting pods with 'app=frontend'  
B. A Service with selector 'app=frontend'  
C. An Ingress resource with 'app=frontend' annotation  
D. A PodSecurityPolicy allowing only 'app=frontend'

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: A**

**Explanation:**
NetworkPolicy with ingress rules and podSelector allows you to control which pods can send traffic to selected pods.

Why A is correct:
- NetworkPolicy is the correct mechanism for pod-to-pod traffic control
- Ingress rules define what traffic is allowed to enter
- podSelector in ingress.from specifies allowed sources
- Implicitly denies all other ingress traffic once policy is applied

Why others are wrong:
- B: Services provide discovery and load balancing, not network filtering
- C: Ingress is for external HTTP/HTTPS traffic, not pod-to-pod
- D: PSP is deprecated and doesn't control network traffic

**Reference**: Kubernetes NetworkPolicy Examples
</details>

---

## Domain 4: Kubernetes Threat Model (12 questions)

### Question 28
Which of the following is the MOST severe security risk in Kubernetes?

A. Using 'latest' tag for container images  
B. Running containers as root with privileged: true  
C. Not setting resource limits on containers  
D. Using default ServiceAccount tokens

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Running privileged containers as root provides full access to the host system, effectively negating all container isolation.

Why B is correct:
- Privileged containers bypass most security restrictions
- Can access host devices and kernel features
- Combined with root user = full host compromise
- Most dangerous configuration possible

Why others are wrong:
- A: Using 'latest' is bad practice but less severe than privileged root
- C: Missing resource limits can cause DoS but not host compromise
- D: Default tokens are a risk but less severe than privileged containers

**Reference**: Kubernetes Pod Security Standards - Privileged
</details>

---

### Question 29
An attacker has compromised a pod. Which attack vector would allow them to escalate privileges to the node?

A. Reading a ConfigMap  
B. Accessing a Secret without encryption  
C. Exploiting a hostPath volume mounted to a sensitive directory  
D. Making API calls with the pod's ServiceAccount

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
hostPath volumes mount host filesystem paths into containers. If a sensitive directory (like /etc, /var/run/docker.sock) is mounted, it can lead to node compromise.

Why C is correct:
- hostPath provides direct access to node filesystem
- Can modify node system files
- Access to /var/run/docker.sock allows container escape
- Direct path to node compromise

Why others are wrong:
- A: ConfigMaps contain non-sensitive data
- B: Secrets in the pod don't directly lead to node access
- D: ServiceAccount permissions are typically pod-scoped, not node-level

**Reference**: Kubernetes hostPath Security Considerations
</details>

---

### Question 30
What is the PRIMARY security risk of exposing the Kubernetes Dashboard without authentication?

A. Increased network bandwidth usage  
B. Unauthorized users can view and modify cluster resources  
C. Dashboard will run slowly  
D. Pods will fail to start

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
The Kubernetes Dashboard provides a web UI for cluster management. Without authentication, anyone can access it and potentially gain full cluster control.

Why B is correct:
- Dashboard can create, modify, and delete resources
- Common attack vector in exposed clusters
- Multiple real-world breaches from exposed dashboards
- Can lead to complete cluster compromise

Why others are wrong:
- A: Security risk, not a bandwidth issue
- C: Performance is not the security concern
- D: Dashboard doesn't affect pod startup

**Reference**: Kubernetes Dashboard Access Control
</details>

---

### Question 31
Which Kubernetes feature helps mitigate the risk of cryptocurrency mining attacks on compromised pods?

A. NetworkPolicy to block external connections  
B. Resource quotas and limits to restrict CPU usage  
C. RBAC to limit API access  
D. Pod Security Admission to enforce security standards

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Resource quotas and limits restrict the amount of CPU and memory a pod can consume, limiting the impact of cryptocurrency mining.

Why B is correct:
- Cryptocurrency mining is CPU-intensive
- Resource limits prevent excessive CPU usage
- Reduces financial impact of compromised pods
- Makes cryptomining attacks less profitable

Why others are wrong:
- A: While helpful, doesn't limit CPU usage
- C: RBAC doesn't limit CPU usage
- D: PSA doesn't directly limit resource consumption

**Reference**: Kubernetes Resource Quotas and Limits
</details>

---

### Question 32
What is the PRIMARY security concern with using the default ServiceAccount in pods?

A. It causes pods to fail  
B. It provides API access that pods may not need, violating least privilege  
C. It requires manual certificate rotation  
D. It prevents pods from accessing Secrets

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
The default ServiceAccount provides API access to pods. If compromised, an attacker can use this access to interact with the Kubernetes API.

Why B is correct:
- Default ServiceAccount has a token automatically mounted
- Violates principle of least privilege
- If pod doesn't need API access, it shouldn't have a token
- Common attack vector after pod compromise

Why others are wrong:
- A: Default ServiceAccount doesn't cause failures
- C: ServiceAccount tokens are automatically rotated
- D: ServiceAccount doesn't prevent Secret access (RBAC does)

**Reference**: Kubernetes ServiceAccount Security
</details>

---

### Question 33
How can you prevent a pod from automatically mounting the ServiceAccount token?

A. Delete the default ServiceAccount  
B. Set automountServiceAccountToken: false in pod spec  
C. Remove the ServiceAccount from the namespace  
D. Set serviceAccountName to empty string

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Setting automountServiceAccountToken: false prevents the automatic mounting of the ServiceAccount token into the pod.

Why B is correct:
- Explicit flag to disable token mounting
- Can be set at pod or ServiceAccount level
- Best practice for pods that don't need API access
- Reduces attack surface

Why others are wrong:
- A: Deleting default ServiceAccount causes pod creation failures
- C: Removing ServiceAccount doesn't prevent mounting
- D: Empty serviceAccountName isn't valid

**Reference**: Kubernetes ServiceAccount Token Mounting
</details>

---

### Question 34
Which tool is specifically designed for runtime threat detection in Kubernetes?

A. Trivy  
B. Falco  
C. kube-bench  
D. KubeSec

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Falco is a runtime security tool that monitors system calls and Kubernetes events to detect anomalous behavior and threats.

Why B is correct:
- Monitors runtime behavior in real-time
- Detects suspicious system calls and kernel events
- Kubernetes-aware (monitors K8s API events)
- CNCF project specifically for runtime security

Why others are wrong:
- A: Trivy is for vulnerability scanning (static analysis), not runtime detection
- C: kube-bench checks CIS benchmark compliance (static)
- D: KubeSec analyzes YAML manifests for security issues (static)

**Reference**: Falco Documentation
</details>

---

### Question 35
A Falco rule has triggered an alert: "Sensitive file opened for reading by non-trusted program". What type of threat model is this detecting?

A. Network-based attack  
B. File integrity monitoring / unauthorized file access  
C. Resource exhaustion  
D. Authentication bypass

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
This Falco rule detects unauthorized access to sensitive files, which is a file integrity monitoring and access control concern.

Why B is correct:
- Monitors access to sensitive files (like /etc/shadow)
- Detects potential data exfiltration or privilege escalation
- File integrity is a key security concern
- Indicates potential compromise or misconfiguration

Why others are wrong:
- A: This is file access, not network traffic
- C: Not related to resource consumption
- D: Not directly about authentication

**Reference**: Falco Rules Documentation
</details>

---

### Question 36
Which of the following is an example of a supply chain attack in Kubernetes?

A. DDoS attack on the API server  
B. Using a compromised container image from a public registry  
C. Weak RBAC permissions  
D. Missing NetworkPolicy

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Supply chain attacks involve compromising components before they reach the end user. Using compromised container images is a classic supply chain attack.

Why B is correct:
- Container images are part of the software supply chain
- Compromised images can contain malware or backdoors
- Affects all pods using that image
- Major concern in cloud native security

Why others are wrong:
- A: DDoS is a direct attack, not supply chain
- C: RBAC misconfiguration is not a supply chain issue
- D: Missing NetworkPolicy is a configuration issue, not supply chain

**Reference**: CNCF Supply Chain Security Best Practices
</details>

---

### Question 37
What is the purpose of image signing and verification in Kubernetes?

A. To compress images for faster download  
B. To ensure images haven't been tampered with and come from trusted sources  
C. To encrypt image layers  
D. To scan images for vulnerabilities

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Image signing (e.g., with Cosign) creates a cryptographic signature that verifies image integrity and authenticity.

Why B is correct:
- Provides cryptographic proof of image origin
- Detects tampering or unauthorized modifications
- Part of supply chain security
- Ensures you run only trusted images

Why others are wrong:
- A: Signing doesn't compress images
- C: Signing provides integrity, not encryption
- D: Signing verifies authenticity; scanning finds vulnerabilities (different purposes)

**Reference**: Sigstore Cosign Documentation
</details>

---

### Question 38
Which admission controller can you use to enforce image signature verification?

A. PodSecurity  
B. NodeRestriction  
C. An image policy webhook or Sigstore policy controller  
D. LimitRanger

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
Image signature verification requires a validating admission webhook (like Sigstore policy controller, Kyverno, or OPA Gatekeeper) that checks signatures before allowing pods.

Why C is correct:
- Validates image signatures during admission
- Rejects pods with unsigned or improperly signed images
- Integrates with signing tools like Cosign
- Enforces supply chain security policies

Why others are wrong:
- A: PodSecurity enforces Pod Security Standards, not image signatures
- B: NodeRestriction limits node permissions, not image validation
- D: LimitRanger enforces resource limits, not image policies

**Reference**: Sigstore Policy Controller Documentation
</details>

---

### Question 39
What is the MOST effective way to prevent privilege escalation within a container?

A. Set allowPrivilegeEscalation: false in Security Context  
B. Use a NetworkPolicy  
C. Set resource limits  
D. Use a private registry

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: A**

**Explanation:**
The allowPrivilegeEscalation: false setting prevents a process from gaining more privileges than its parent process.

Why A is correct:
- Directly addresses privilege escalation
- Prevents setuid binaries from granting additional privileges
- Blocks certain kernel exploits
- Recommended security practice

Why others are wrong:
- B: NetworkPolicy controls network traffic, not privilege escalation
- C: Resource limits don't prevent privilege escalation
- D: Private registries don't prevent privilege escalation

**Reference**: Kubernetes Security Context - allowPrivilegeEscalation
</details>

---

## Domain 5: Platform Security (12 questions)

### Question 40
Which tool should you use to scan container images for known vulnerabilities?

A. Falco  
B. Trivy  
C. kube-bench  
D. OPA Gatekeeper

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Trivy is a comprehensive vulnerability scanner for container images, filesystems, and Kubernetes configurations.

Why B is correct:
- Scans container images for CVEs
- Detects vulnerabilities in OS packages and application dependencies
- Can scan running containers and Kubernetes manifests
- Free and open source

Why others are wrong:
- A: Falco is for runtime threat detection, not vulnerability scanning
- C: kube-bench checks CIS benchmark compliance, not image vulnerabilities
- D: OPA Gatekeeper enforces policies, doesn't scan for vulnerabilities

**Reference**: Aqua Security Trivy Documentation
</details>

---

### Question 41
After scanning an image with Trivy, you find several HIGH and CRITICAL vulnerabilities. What should you do FIRST?

A. Deploy the image and monitor with Falco  
B. Update the base image and dependencies to patched versions  
C. Add NetworkPolicy to isolate the pod  
D. Ignore the vulnerabilities if the image is from a trusted source

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
The first step is to remediate vulnerabilities by updating to patched versions. This addresses the root cause.

Why B is correct:
- Addresses vulnerabilities at the source
- Updates to patched versions eliminate known CVEs
- Should be done before deployment
- Part of shift-left security

Why others are wrong:
- A: Don't deploy vulnerable images; fix first
- C: NetworkPolicy doesn't fix vulnerabilities
- D: Never ignore HIGH/CRITICAL vulnerabilities regardless of source

**Reference**: Container Image Security Best Practices
</details>

---

### Question 42
What is the purpose of the seccomp (Secure Computing Mode) profile in Kubernetes?

A. To encrypt pod communications  
B. To restrict system calls that containers can make  
C. To manage secrets  
D. To control network access

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Seccomp filters system calls that a process can make to the kernel, reducing the attack surface.

Why B is correct:
- Limits system calls available to containers
- Reduces kernel attack surface
- Default seccomp profile blocks ~40 dangerous system calls
- Part of container security best practices

Why others are wrong:
- A: Seccomp doesn't provide encryption
- C: Secrets management is separate
- D: Network access is controlled by NetworkPolicy

**Reference**: Kubernetes Seccomp Documentation
</details>

---

### Question 43
Which Pod Security Standard should you use for security-critical applications that require strong isolation?

A. Privileged  
B. Baseline  
C. Restricted  
D. Unrestricted

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
The Restricted standard is the most restrictive and provides strong security isolation, suitable for security-critical applications.

Why C is correct:
- Enforces strict security controls
- Requires running as non-root
- Drops all capabilities
- Enables seccomp profile
- Best for security-sensitive workloads

Why others are wrong:
- A: Privileged is the least restrictive (not secure)
- B: Baseline is moderate security, not strongest
- D: Not a valid Pod Security Standard

**Reference**: Kubernetes Pod Security Standards
</details>

---

### Question 44
What is the difference between enforce, audit, and warn modes in Pod Security Admission?

A. enforce blocks violations, audit logs violations, warn shows warnings to users  
B. All three modes block violations  
C. Only enforce mode does anything  
D. They are interchangeable

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: A**

**Explanation:**
Pod Security Admission has three modes with different behaviors for policy violations.

Why A is correct:
- enforce: Rejects pods that violate the policy
- audit: Allows pods but adds audit annotations to events
- warn: Allows pods but returns warnings to the user
- All three can be active simultaneously on a namespace

Why others are wrong:
- B: Only enforce blocks; others allow with logging/warnings
- C: All three modes have distinct purposes
- D: Each mode has a specific function

**Reference**: Kubernetes Pod Security Admission
</details>

---

### Question 45
How do you apply the Restricted Pod Security Standard with enforce mode to a namespace?

A. Create a PodSecurityPolicy  
B. Add label: pod-security.kubernetes.io/enforce=restricted to the namespace  
C. Configure the label in the pod spec  
D. Set it in the cluster's kube-apiserver flags

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Pod Security Admission is configured via namespace labels. The label pod-security.kubernetes.io/enforce=restricted applies the Restricted standard in enforce mode.

Why B is correct:
- PSA is configured through namespace labels
- pod-security.kubernetes.io/enforce specifies enforce mode
- =restricted specifies the Restricted standard
- Simple, declarative configuration

Why others are wrong:
- A: PodSecurityPolicy is deprecated (removed in K8s 1.25)
- C: PSA is namespace-scoped, not pod-scoped
- D: PSA doesn't require API server flag changes

**Reference**: Kubernetes Pod Security Admission Documentation
</details>

---

### Question 46
Which Linux security module restricts container capabilities by defining allowed operations?

A. SELinux  
B. AppArmor  
C. Both SELinux and AppArmor  
D. Neither, this is done by Kubernetes RBAC

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
Both SELinux and AppArmor are Linux Security Modules (LSMs) that can restrict container operations through mandatory access control.

Why C is correct:
- SELinux uses security contexts and labels
- AppArmor uses profiles to restrict capabilities
- Both provide mandatory access control (MAC)
- Either can be used in Kubernetes (depends on host OS)

Why others are wrong:
- A, B: Both are correct, not just one
- D: RBAC controls API access, not container operations

**Reference**: Kubernetes AppArmor and SELinux Documentation
</details>

---

### Question 47
What is the purpose of a Software Bill of Materials (SBOM) in Kubernetes security?

A. To list all pods running in the cluster  
B. To document all software components and dependencies in a container image  
C. To configure network policies  
D. To encrypt secrets

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
An SBOM provides a comprehensive inventory of all software components in a container image, essential for vulnerability management and compliance.

Why B is correct:
- Lists all software components and versions
- Helps identify vulnerable dependencies
- Required for supply chain security
- Enables vulnerability tracking and patching

Why others are wrong:
- A: SBOM is for image contents, not running pods
- C: SBOM doesn't configure network policies
- D: SBOM is for documentation, not encryption

**Reference**: CNCF SBOM Best Practices
</details>

---

### Question 48
Which tool can generate an SBOM for a container image?

A. Falco  
B. Syft  
C. kube-bench  
D. kubectl

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Syft (from Anchore) is a tool specifically designed to generate SBOMs for container images and filesystems.

Why B is correct:
- Generates SBOMs in multiple formats (SPDX, CycloneDX)
- Analyzes container images and filesystems
- Part of the Anchore/Syft/Grype toolchain
- Industry-standard SBOM generator

Why others are wrong:
- A: Falco is for runtime detection, not SBOM generation
- C: kube-bench checks CIS compliance, doesn't generate SBOMs
- D: kubectl is the Kubernetes CLI, not an SBOM tool

**Reference**: Anchore Syft Documentation
</details>

---

### Question 49
Your organization requires immutable infrastructure. What is the BEST practice for container images?

A. Use the 'latest' tag for all images  
B. Use image digests instead of tags  
C. Build images directly on production nodes  
D. Use rolling tags for each deployment

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Image digests (SHA256 hashes) are immutable and uniquely identify an image. Tags can be changed to point to different images.

Why B is correct:
- Digests are cryptographic hashes (immutable)
- Tags can be overwritten (mutable)
- Ensures exact same image is deployed
- Best practice for production and supply chain security

Why others are wrong:
- A: 'latest' tag is highly mutable and non-specific
- C: Building on production nodes is a security risk
- D: Rolling tags are mutable by definition

**Reference**: Kubernetes Best Practices - Image Tags
</details>

---

### Question 50
What is the primary security benefit of using a private container registry?

A. Faster image pulls  
B. Control over image sources and ability to scan before deployment  
C. Automatic vulnerability patching  
D. Free image hosting

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Private registries give you control over which images are available and allow you to implement security scanning and policies before images are used.

Why B is correct:
- Control over allowed images
- Can implement security scanning pipelines
- Prevents use of unknown/untrusted images
- Enforces organizational security policies

Why others are wrong:
- A: Performance is a benefit but not the primary security benefit
- C: Registries store images; they don't automatically patch them
- D: Cost is not a security benefit

**Reference**: Container Registry Security Best Practices
</details>

---

### Question 51
Which Kubernetes feature can enforce that only images from approved registries are deployed?

A. NetworkPolicy  
B. ValidatingAdmissionWebhook with policy enforcement (OPA/Kyverno)  
C. RBAC  
D. ServiceAccount

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
ValidatingAdmissionWebhooks can check image sources and reject pods that use images from unapproved registries.

Why B is correct:
- Admission webhooks intercept pod creation requests
- Can validate image registry in image reference
- Tools like OPA Gatekeeper and Kyverno provide this functionality
- Enforces registry allowlists/denylists

Why others are wrong:
- A: NetworkPolicy controls network traffic, not image sources
- C: RBAC controls API access, not image validation
- D: ServiceAccount is for pod identity, not image validation

**Reference**: OPA Gatekeeper and Kyverno Policy Examples
</details>

---

## Domain 6: Compliance and Security Frameworks (9 questions)

### Question 52
Which tool checks Kubernetes cluster configuration against CIS Kubernetes Benchmark?

A. Trivy  
B. Falco  
C. kube-bench  
D. kubelet

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
kube-bench is specifically designed to check Kubernetes clusters against the CIS Kubernetes Benchmark.

Why C is correct:
- Automated CIS benchmark compliance checking
- Tests configuration of API server, scheduler, controller manager, kubelet, etcd
- Produces detailed reports with pass/fail results
- Open source from Aqua Security

Why others are wrong:
- A: Trivy scans for vulnerabilities, not CIS compliance
- B: Falco is for runtime detection, not compliance checking
- D: kubelet is a cluster component, not a compliance tool

**Reference**: Aqua Security kube-bench
</details>

---

### Question 53
The CIS Kubernetes Benchmark recommends enabling audit logging. Which API server flag is MOST important for this?

A. --authorization-mode  
B. --audit-policy-file  
C. --enable-admission-plugins  
D. --tls-cert-file

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
The --audit-policy-file flag specifies the audit policy that defines what events should be logged and at what level.

Why B is correct:
- Defines what gets audited (which events, at what verbosity)
- Required for audit logging configuration
- Works with --audit-log-path to enable full audit logging
- CIS benchmark requirement

Why others are wrong:
- A: Authorization mode doesn't enable audit logging
- C: Admission plugins are separate from audit logging
- D: TLS cert is for secure communication, not audit logging

**Reference**: CIS Kubernetes Benchmark - Audit Logging
</details>

---

### Question 54
Which of the following is NOT typically a requirement for PCI-DSS compliance in Kubernetes?

A. Encryption of data in transit  
B. Encryption of data at rest  
C. Running all containers as privileged  
D. Access control and authentication

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
PCI-DSS requires security controls. Running containers as privileged is a security anti-pattern and would violate compliance requirements.

Why C is correct:
- Privileged containers are insecure
- PCI-DSS requires security hardening
- Privileged mode violates least privilege principle
- This would fail a PCI-DSS audit

Why others are wrong:
- A, B: Encryption in transit and at rest are PCI-DSS requirements
- D: Access control is a core PCI-DSS requirement

**Reference**: PCI-DSS Requirements for Containers
</details>

---

### Question 55
Your company must comply with GDPR. Which Kubernetes security control helps with data protection requirements?

A. Encryption of Secrets at rest in etcd  
B. Using resource quotas  
C. Enabling feature gates  
D. Using DaemonSets

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: A**

**Explanation:**
GDPR requires protecting personal data. Encrypting Secrets at rest ensures that sensitive data stored in etcd is protected.

Why A is correct:
- Protects sensitive data (potentially including personal data)
- GDPR requires appropriate technical measures for data protection
- Encryption at rest is a standard compliance requirement
- Protects against data breaches from storage compromise

Why others are wrong:
- B: Resource quotas are for resource management, not data protection
- C: Feature gates enable/disable features, not directly related to GDPR
- D: DaemonSets are a workload type, not a security control

**Reference**: GDPR Technical and Organizational Measures
</details>

---

### Question 56
What is the purpose of the NIST Cybersecurity Framework in relation to Kubernetes security?

A. It provides specific Kubernetes configuration files  
B. It provides a structured approach to managing cybersecurity risk  
C. It is a Kubernetes vulnerability scanner  
D. It replaces the need for RBAC

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
The NIST Cybersecurity Framework provides a structured methodology for managing cybersecurity risk across five functions: Identify, Protect, Detect, Respond, Recover.

Why B is correct:
- Framework for risk management (not tool-specific)
- Applies to Kubernetes as part of overall security program
- Guides security strategy and implementation
- Industry-standard framework

Why others are wrong:
- A: NIST CSF is a framework, not a config tool
- C: It's not a scanning tool
- D: It doesn't replace technical controls like RBAC

**Reference**: NIST Cybersecurity Framework
</details>

---

### Question 57
Which practice supports compliance with SOC 2 Type II requirements for Kubernetes?

A. Disabling all audit logs to improve performance  
B. Implementing comprehensive audit logging and monitoring  
C. Allowing all users cluster-admin access  
D. Using only public container registries

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
SOC 2 Type II requires demonstrating security controls over time. Comprehensive audit logging and monitoring provide the evidence needed.

Why B is correct:
- SOC 2 requires audit trails and monitoring
- Provides evidence of security controls
- Enables incident detection and response
- Required for demonstrating compliance over time

Why others are wrong:
- A: Disabling audit logs violates SOC 2 requirements
- C: Excessive permissions violate access control requirements
- D: Public registries don't support supply chain security requirements

**Reference**: SOC 2 Compliance Requirements
</details>

---

### Question 58
What is the purpose of implementing Policy-as-Code (PaC) in Kubernetes?

A. To write application code  
B. To automate and enforce security and compliance policies  
C. To manage container storage  
D. To configure networking

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Policy-as-Code treats security and compliance policies as code, enabling automation, version control, and consistent enforcement.

Why B is correct:
- Automates policy enforcement
- Ensures consistent policy application
- Enables version control and testing of policies
- Tools include OPA/Gatekeeper, Kyverno

Why others are wrong:
- A: PaC is for security policies, not application code
- C: Storage management is separate
- D: Network configuration is separate from policy enforcement

**Reference**: Open Policy Agent and Policy-as-Code
</details>

---

### Question 59
Which OPA Gatekeeper component is responsible for enforcing policies?

A. ConstraintTemplate  
B. Constraint  
C. Both ConstraintTemplate (defines policy) and Constraint (enforces it)  
D. ConfigMap

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
OPA Gatekeeper uses both ConstraintTemplates (which define reusable policy logic) and Constraints (which instantiate and enforce those policies).

Why C is correct:
- ConstraintTemplate: Defines the policy logic (reusable)
- Constraint: Creates an instance of the template and enforces it
- Both are needed for policy enforcement
- ConstraintTemplate without Constraint does nothing

Why others are wrong:
- A: ConstraintTemplate alone doesn't enforce; it's a template
- B: Constraint alone can't exist without a ConstraintTemplate
- D: ConfigMap is not part of Gatekeeper policy enforcement

**Reference**: OPA Gatekeeper Documentation
</details>

---

### Question 60
Your security team requires that all deployments be automatically scanned before admission. Which approach is MOST appropriate?

A. Manually scan images before each deployment  
B. Use a ValidatingAdmissionWebhook that triggers image scanning  
C. Rely on developers to scan locally  
D. Scan images quarterly during audits

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
A ValidatingAdmissionWebhook can integrate with scanning tools to automatically scan images during pod admission, rejecting vulnerable images.

Why B is correct:
- Automates security checks
- Enforces scanning before deployment
- Blocks vulnerable images at admission time
- Integrates with tools like Trivy, Anchore

Why others are wrong:
- A: Manual scanning doesn't scale and isn't automated
- C: Relying on developers isn't enforceable
- D: Quarterly scanning is too infrequent for continuous deployment

**Reference**: Kubernetes Admission Webhooks for Security
</details>

---

## Answer Key

| Question | Domain | Correct Answer |
|----------|--------|----------------|
| 1 | 1 | B |
| 2 | 1 | D |
| 3 | 1 | B |
| 4 | 1 | B |
| 5 | 1 | C |
| 6 | 1 | B |
| 7 | 2 | A |
| 8 | 2 | C |
| 9 | 2 | B |
| 10 | 2 | C |
| 11 | 2 | B |
| 12 | 2 | B |
| 13 | 2 | B |
| 14 | 2 | A |
| 15 | 2 | B |
| 16 | 2 | C |
| 17 | 2 | B |
| 18 | 2 | A |
| 19 | 3 | A |
| 20 | 3 | C |
| 21 | 3 | A |
| 22 | 3 | C |
| 23 | 3 | B |
| 24 | 3 | A |
| 25 | 3 | B |
| 26 | 3 | B |
| 27 | 3 | A |
| 28 | 4 | B |
| 29 | 4 | C |
| 30 | 4 | B |
| 31 | 4 | B |
| 32 | 4 | B |
| 33 | 4 | B |
| 34 | 4 | B |
| 35 | 4 | B |
| 36 | 4 | B |
| 37 | 4 | B |
| 38 | 4 | C |
| 39 | 4 | A |
| 40 | 5 | B |
| 41 | 5 | B |
| 42 | 5 | B |
| 43 | 5 | C |
| 44 | 5 | A |
| 45 | 5 | B |
| 46 | 5 | C |
| 47 | 5 | B |
| 48 | 5 | B |
| 49 | 5 | B |
| 50 | 5 | B |
| 51 | 5 | B |
| 52 | 6 | C |
| 53 | 6 | B |
| 54 | 6 | C |
| 55 | 6 | A |
| 56 | 6 | B |
| 57 | 6 | B |
| 58 | 6 | B |
| 59 | 6 | C |
| 60 | 6 | B |

---

## Scoring Guide

**Calculate your score:**
- Total correct answers: _____ / 60
- Percentage: (Correct / 60) × 100 = _____%

**Result:**
- **85-100%** (51-60 correct): Excellent! You're well-prepared for the KCSA exam.
- **75-84%** (45-50 correct): Good! You pass. Review weak areas and take another practice test.
- **60-74%** (36-44 correct): Fair. More study needed. Focus on domains with lower scores.
- **Below 60%** (0-35 correct): Additional preparation required. Review fundamentals thoroughly.

**Domain Breakdown:**
- Domain 1 (Questions 1-6): _____ / 6
- Domain 2 (Questions 7-18): _____ / 12
- Domain 3 (Questions 19-27): _____ / 9
- Domain 4 (Questions 28-39): _____ / 12
- Domain 5 (Questions 40-51): _____ / 12
- Domain 6 (Questions 52-60): _____ / 9

**Next Steps:**
1. Review detailed explanations for all incorrect answers
2. Identify your weakest domain(s)
3. Study the relevant domain materials
4. Take another mock exam after 3-5 days
5. Complete hands-on labs for weak areas

---


