# KCSA Mock Exam Set 3

**Duration**: 90 minutes  
**Passing Score**: 75% (45 out of 60 questions)  
**Instructions**: Choose the MOST appropriate answer for each question. This exam focuses on common exam traps, edge cases, and nuanced differences in Kubernetes security.

---

## Domain 1: Overview of Cloud Native Security (6 questions)

### Question 1

In the 4C's security model (Cloud, Cluster, Container, Code), which statement is TRUE?

A. Security at each layer is independent of other layers  
B. Each layer builds upon and depends on the security of the layer beneath it  
C. Only the Code layer matters for security  
D. Cloud layer security is optional if other layers are secure

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
The 4C's model emphasizes defense in depth where each layer builds on the previous one. If a lower layer is compromised, upper layers cannot be fully secured.

Why B is correct:

- Layers are interdependent
- Compromise at Cloud level affects all upper layers
- Defense in depth requires securing all layers
- Each layer provides additional protection

Why others are wrong:

- A: Layers are interdependent, not independent
- C: All layers matter, not just Code
- D: Cloud layer is foundational, not optional

**Reference**: Kubernetes 4C's Security Model
</details>

---

### Question 2

Which principle states that entities should have only the minimum permissions necessary to perform their function?

A. Defense in depth  
B. Least privilege  
C. Zero trust  
D. Separation of duties

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Least privilege means granting only the minimum permissions required, reducing potential damage from compromised accounts or misconfigurations.

Why B is correct:

- Minimizes permissions to required only
- Reduces blast radius of compromise
- Core security principle
- Applied through RBAC in Kubernetes

Why others are wrong:

- A: Defense in depth is about multiple security layers
- C: Zero trust is about verifying all requests
- D: Separation of duties is about dividing responsibilities

**Reference**: Principle of Least Privilege
</details>

---

### Question 3

Your cluster runs in multiple availability zones. Which layer of the 4C's model does this address?

A. Code  
B. Container  
C. Cluster  
D. Cloud/Infrastructure

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: D**

**Explanation:**
Availability zones are part of the Cloud/Infrastructure layer, addressing physical and infrastructure-level concerns.

Why D is correct:

- Availability zones are infrastructure-level
- Part of cloud provider setup
- Foundation layer (Cloud)
- Affects resilience and availability

Why others are wrong:

- A: Code is application-level
- B: Container is about container images and runtime
- C: Cluster is Kubernetes-specific configuration

**Reference**: 4C's Security Model - Cloud Layer
</details>

---

### Question 4

Which statement BEST describes "shift-left" security in cloud native environments?

A. Moving security teams to a different office  
B. Integrating security practices early in the development lifecycle  
C. Shifting security responsibilities to developers only  
D. Reducing security requirements

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Shift-left means integrating security earlier (to the "left" on a timeline) in the software development lifecycle.

Why B is correct:

- Security integrated in development phase
- Catches issues early when cheaper to fix
- Automates security in CI/CD
- DevSecOps principle

Why others are wrong:

- A: Not about physical location
- C: Security is everyone's responsibility, not just developers
- D: Doesn't mean reducing security

**Reference**: Shift-Left Security Practices
</details>

---

### Question 5

In a zero trust model, which statement is TRUE about network location?

A. Internal network traffic is always trusted  
B. Network location is not considered a sufficient basis for trust  
C. Only external traffic needs verification  
D. Perimeter security is sufficient

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Zero trust explicitly rejects the notion that network location determines trust. Every request must be verified regardless of origin.

Why B is correct:

- Location doesn't equal trust
- All requests must be authenticated and authorized
- Applies to internal and external traffic equally
- Core zero trust principle

Why others are wrong:

- A: Zero trust doesn't trust internal traffic by default
- C: Internal traffic also requires verification
- D: Perimeter security contradicts zero trust

**Reference**: Zero Trust Architecture Principles
</details>

---

### Question 6

Which cloud native security practice helps ensure that security policies are consistently applied?

A. Manual security reviews for each deployment  
B. Policy-as-Code with automated enforcement  
C. Security documentation  
D. Annual security training

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Policy-as-Code codifies security policies and automatically enforces them, ensuring consistency across all deployments.

Why B is correct:

- Automates policy enforcement
- Consistent application across cluster
- Version controlled and testable
- Scales with cloud native pace

Why others are wrong:

- A: Manual reviews don't scale and aren't consistent
- C: Documentation doesn't enforce policies
- D: Training is important but doesn't enforce policies

**Reference**: Policy-as-Code Best Practices
</details>

---

## Domain 2: Kubernetes Cluster Component Security (12 questions)

### Question 7

Which API server flag specifies the audit policy file that defines what events to log?

A. --audit-log-path  
B. --audit-policy-file  
C. --audit-log-maxage  
D. --enable-admission-plugins

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
The --audit-policy-file flag specifies the YAML file that defines the audit policy (what to log and at what level).

Why B is correct:

- Specifies audit policy configuration
- Defines what events to log
- Required for audit logging
- Separate from log destination (--audit-log-path)

Why others are wrong:

- A: Specifies where to write logs, not what to log
- C: Specifies log retention period
- D: Enables admission plugins, not audit logging

**Reference**: Kubernetes Audit Policy Configuration
</details>

---

### Question 8

What is the PRIMARY security risk of NOT encrypting data at rest in etcd?

A. Slower performance  
B. Secrets and sensitive data are stored in plaintext (base64) and readable if etcd is compromised  
C. etcd won't start  
D. API server communication will fail

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Without encryption at rest, Secrets are only base64-encoded (not encrypted) in etcd, making them readable if someone gains access to etcd data.

Why B is correct:

- Base64 is encoding, not encryption
- Anyone with etcd access can decode Secrets
- Major security vulnerability
- Encryption at rest required for compliance

Why others are wrong:

- A: Encryption has minimal performance impact
- C: etcd works without encryption (but insecurely)
- D: API server communication is separate (TLS in transit)

**Reference**: Kubernetes Secrets and Encryption at Rest
</details>

---

### Question 9

Which authorization mode should you AVOID in production clusters?

A. RBAC  
B. Node  
C. AlwaysAllow  
D. Webhook

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
AlwaysAllow permits all requests without any authorization checks. It should never be used in production.

Why C is correct:

- No access control whatsoever
- Major security vulnerability
- Only for testing/development
- Allows any action by any user

Why others are wrong:

- A: RBAC is the recommended production authorization mode
- B: Node authorization is appropriate for kubelet
- D: Webhook can be used for custom authorization

**Reference**: Kubernetes Authorization Modes
</details>

---

### Question 10

What is the difference between authentication and authorization in Kubernetes?

A. They are the same thing  
B. Authentication verifies identity; authorization verifies permissions  
C. Authorization verifies identity; authentication verifies permissions  
D. Neither is necessary in Kubernetes

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Authentication answers "Who are you?" while authorization answers "What are you allowed to do?"

Why B is correct:

- Authentication: Verifies identity (who)
- Authorization: Verifies permissions (what)
- Sequential process (authenticate first, then authorize)
- Both required for access control

Why others are wrong:

- A: They are distinct concepts
- C: Reversed definitions
- D: Both are essential for security

**Reference**: Kubernetes Authentication and Authorization
</details>

---

### Question 11

Which component stores all cluster state including Secrets?

A. API server  
B. etcd  
C. kubelet  
D. kube-proxy

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
etcd is the distributed key-value store that persistently stores all Kubernetes cluster data, including Secrets.

Why B is correct:

- Persistent datastore for cluster state
- Stores all API objects including Secrets
- Critical component requiring protection
- Must be secured and backed up

Why others are wrong:

- A: API server is the frontend; etcd is the backend store
- C: kubelet manages pods on nodes, doesn't store cluster state
- D: kube-proxy manages network rules, doesn't store state

**Reference**: Kubernetes etcd Overview
</details>

---

### Question 12

What does mutual TLS (mTLS) provide that regular TLS doesn't?

A. Faster performance  
B. Both client and server authenticate each other (bidirectional authentication)  
C. Lower cost  
D. Easier configuration

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
In regular TLS, only the server is authenticated. In mTLS, both client and server verify each other's identity using certificates.

Why B is correct:

- Bidirectional authentication
- Client presents certificate to server
- Server presents certificate to client
- Stronger security for component-to-component communication

Why others are wrong:

- A: mTLS doesn't improve performance
- C: Cost is not affected
- D: mTLS is more complex to configure

**Reference**: Mutual TLS in Kubernetes
</details>

---

### Question 13

Which kubelet flag disables anonymous requests to the kubelet API?

A. --authentication-mode=none  
B. --anonymous-auth=false  
C. --authorization-mode=Webhook  
D. --protect-kernel-defaults=true

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
The --anonymous-auth=false flag on kubelet disables anonymous authentication, requiring all requests to be authenticated.

Why B is correct:

- Disables anonymous kubelet API access
- Requires authentication for all requests
- CIS Benchmark recommendation
- Improves node security

Why others are wrong:

- A: Not a valid kubelet flag
- C: Authorization mode, not authentication
- D: Protects kernel parameters, not authentication

**Reference**: Kubelet Authentication Configuration
</details>

---

### Question 14

What is the purpose of the --service-cluster-ip-range flag on the API server?

A. To define the CIDR range for Service ClusterIPs  
B. To set pod IP ranges  
C. To configure node IPs  
D. To set external IPs

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: A**

**Explanation:**
This flag specifies the CIDR range from which Service ClusterIPs are allocated.

Why A is correct:

- Defines Service ClusterIP allocation range
- Virtual IPs for Services
- Must not overlap with pod or node CIDRs
- Cluster-wide configuration

Why others are wrong:

- B: Pod IPs use different configuration (CNI)
- C: Node IPs are physical/cloud-assigned
- D: External IPs are separate configuration

**Reference**: Kubernetes Service Networking
</details>

---

### Question 15

Which admission controller prevents kubelets from modifying Node and Pod objects they don't own?

A. PodSecurity  
B. NodeRestriction  
C. LimitRanger  
D. ResourceQuota

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
NodeRestriction limits each kubelet to only modify its own Node object and pods bound to that node.

Why B is correct:

- Restricts kubelet API permissions
- Prevents compromised nodes from affecting others
- Limits to own Node and bound Pods
- Essential admission controller for security

Why others are wrong:

- A: PodSecurity enforces Pod Security Standards
- C: LimitRanger enforces resource limits
- D: ResourceQuota enforces quota limits

**Reference**: NodeRestriction Admission Controller
</details>

---

### Question 16

What is the security benefit of enabling audit logging?

A. Faster API server performance  
B. Provides forensic trail of who did what and when for security investigations  
C. Reduces storage usage  
D. Improves pod startup time

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Audit logging provides a detailed record of all API requests, essential for security monitoring, compliance, and incident investigation.

Why B is correct:

- Records all API activity
- Enables forensic investigations
- Required for compliance
- Detects unauthorized access

Why others are wrong:

- A: Audit logging has minimal performance impact
- C: Audit logs use storage, not reduce it
- D: No effect on pod startup

**Reference**: Kubernetes Audit Logging
</details>

---

### Question 17

Which API server flag configures the maximum duration of audit log files?

A. --audit-log-maxage  
B. --audit-log-maxbackup  
C. --audit-log-maxsize  
D. --audit-log-path

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: A**

**Explanation:**
The --audit-log-maxage flag specifies the maximum number of days to retain audit log files.

Why A is correct:

- Specifies retention period in days
- Controls log rotation based on age
- Important for compliance requirements
- Prevents excessive disk usage

Why others are wrong:

- B: Specifies maximum number of backup files
- C: Specifies maximum size of log files in MB
- D: Specifies log file location

**Reference**: Kubernetes Audit Log Configuration
</details>

---

### Question 18

What is the PRIMARY purpose of certificate rotation?

A. To improve performance  
B. To prevent certificate expiration and reduce risk from compromised certificates  
C. To reduce storage usage  
D. To enable new features

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Certificate rotation automatically renews certificates before expiration and limits the lifetime of certificates to reduce risk.

Why B is correct:

- Prevents certificate expiration outages
- Limits window for compromised certificates
- Automated security maintenance
- Security best practice

Why others are wrong:

- A: Not a performance feature
- C: Not related to storage
- D: Not related to feature enablement

**Reference**: Kubernetes Certificate Rotation
</details>

---

## Domain 3: Kubernetes Security Fundamentals (9 questions)

### Question 19

What is the effect of setting privileged: true on a container?

A. Container runs with extra CPU priority  
B. Container runs with full access to host devices and kernel capabilities  
C. Container gets more memory  
D. Container starts faster

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Privileged containers have full access to host devices and kernel capabilities, effectively negating container isolation.

Why B is correct:

- Disables most security features
- Access to all host devices
- All kernel capabilities granted
- Extremely dangerous security risk

Why others are wrong:

- A: Not related to CPU priority
- C: Not related to memory allocation
- D: Not related to startup time

**Reference**: Kubernetes Privileged Containers
</details>

---

### Question 20

Which Security Context field prevents a process from gaining more privileges than its parent?

A. runAsNonRoot  
B. allowPrivilegeEscalation  
C. readOnlyRootFilesystem  
D. privileged

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Setting allowPrivilegeEscalation: false prevents a process from gaining additional privileges through mechanisms like setuid binaries.

Why B is correct:

- Prevents privilege escalation
- Blocks setuid/setgid exploits
- Important security control
- Should be set to false

Why others are wrong:

- A: Enforces non-root user but doesn't prevent escalation
- C: Makes filesystem read-only but doesn't prevent escalation
- D: Privileged mode enables escalation

**Reference**: Kubernetes allowPrivilegeEscalation
</details>

---

### Question 21

What happens if you set both runAsUser: 1000 and runAsNonRoot: true, but the container image defaults to user 0?

A. Container runs as user 0  
B. Container runs as user 1000 (Security Context overrides image)  
C. Container fails to start  
D. Container runs as user 65534

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
When runAsUser is explicitly set, it overrides the image's default user. The runAsNonRoot: true check passes because user 1000 is non-root.

Why B is correct:

- Security Context overrides image USER
- runAsUser: 1000 sets the user explicitly
- runAsNonRoot: true is satisfied (1000 ≠ 0)
- Both settings are compatible

Why others are wrong:

- A: Security Context overrides image default
- C: No conflict; settings are compatible
- D: Not the specified user

**Reference**: Kubernetes Security Context Override Behavior
</details>

---

### Question 22

Which Linux capability allows a container to bind to ports below 1024?

A. NET_ADMIN  
B. NET_BIND_SERVICE  
C. SYS_ADMIN  
D. CHOWN

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
NET_BIND_SERVICE capability allows binding to privileged ports (below 1024) without running as root.

Why B is correct:

- Specifically for privileged ports (<1024)
- Allows non-root binding to low ports
- Least privilege alternative to running as root
- Common requirement for web servers

Why others are wrong:

- A: NET_ADMIN is for network administration, not port binding
- C: SYS_ADMIN is broad system administration
- D: CHOWN is for file ownership changes

**Reference**: Linux Capabilities - NET_BIND_SERVICE
</details>

---

### Question 23

What is the scope difference between a Role and a ClusterRole?

A. No difference  
B. Role is namespace-scoped; ClusterRole can be cluster-scoped or namespace-scoped  
C. Role is for users; ClusterRole is for service accounts  
D. Role is read-only; ClusterRole allows writes

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Role always operates within a namespace, while ClusterRole can grant cluster-wide permissions or be bound at namespace level.

Why B is correct:

- Role: Namespace-scoped only
- ClusterRole: Can be cluster-scoped or namespace-scoped (via RoleBinding)
- ClusterRole is more flexible
- ClusterRole needed for cluster-scoped resources

Why others are wrong:

- A: Significant scope difference
- C: Both can be used for any subject type
- D: Both can grant any permissions

**Reference**: Kubernetes RBAC Role vs ClusterRole
</details>

---

### Question 24

If you create a RoleBinding that references a ClusterRole, what is the scope of access granted?

A. Cluster-wide access  
B. Access only within the RoleBinding's namespace  
C. No access (invalid configuration)  
D. Access to all namespaces

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
RoleBinding limits the scope to its namespace, even when binding a ClusterRole. This allows reusing ClusterRole definitions with namespace-scoped access.

Why B is correct:

- RoleBinding always limits to one namespace
- ClusterRole defines permissions, binding defines scope
- Common pattern for reusable permissions
- Provides namespace-level access to ClusterRole permissions

Why others are wrong:

- A: RoleBinding limits to namespace, not cluster
- C: Valid and common configuration
- D: Only ClusterRoleBinding grants cross-namespace access

**Reference**: Kubernetes RoleBinding with ClusterRole
</details>

---

### Question 25

What is the default NetworkPolicy behavior in a namespace with NO NetworkPolicy?

A. All traffic is denied  
B. All traffic is allowed  
C. Only ingress is allowed  
D. Only egress is allowed

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Without any NetworkPolicy, Kubernetes allows all ingress and egress traffic. NetworkPolicies are opt-in security.

Why B is correct:

- Default is allow-all
- NetworkPolicy is opt-in
- Once you create a NetworkPolicy selecting a pod, that pod becomes isolated
- Common misconception (many expect default-deny)

Why others are wrong:

- A: Default is allow, not deny
- C, D: Both ingress and egress are allowed by default

**Reference**: Kubernetes NetworkPolicy Default Behavior
</details>

---

### Question 26

Which NetworkPolicy field specifies the pods that the policy applies to?

A. ingress.from  
B. egress.to  
C. podSelector  
D. namespaceSelector

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
The podSelector field at the policy level selects which pods the NetworkPolicy applies to.

Why C is correct:

- Selects target pods (where policy applies)
- Required field in NetworkPolicy
- Uses label selectors
- Determines policy scope

Why others are wrong:

- A: Selects allowed ingress sources, not target pods
- B: Selects allowed egress destinations, not target pods
- D: Selects namespaces for cross-namespace rules, not target pods

**Reference**: Kubernetes NetworkPolicy Specification
</details>

---

### Question 27

What happens when you create multiple NetworkPolicies selecting the same pod?

A. Only the first policy applies  
B. Only the last policy applies  
C. Policies are combined (union of allowed traffic)  
D. Pod becomes completely isolated

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
Multiple NetworkPolicies are additive (OR logic). A connection is allowed if ANY policy allows it.

Why C is correct:

- NetworkPolicies are additive (union)
- Any policy allowing traffic permits it
- Allows modular policy design
- Cannot create conflicting deny rules

Why others are wrong:

- A, B: All policies apply, not just one
- D: Policies add allowed traffic, not isolate further

**Reference**: Kubernetes NetworkPolicy Combination
</details>

---

## Domain 4: Kubernetes Threat Model (12 questions)

### Question 28

What is the PRIMARY security risk of mounting /var/run/docker.sock into a container?

A. Increased memory usage  
B. Container can control Docker daemon and escape to host  
C. Slower performance  
D. Networking issues

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
The Docker socket provides full control over the Docker daemon. A container with this access can create privileged containers and escape to the host.

Why B is correct:

- Full Docker daemon control
- Can create privileged containers
- Direct path to host compromise
- One of the most dangerous misconfigurations

Why others are wrong:

- A: Not a memory issue
- C: Not a performance issue
- D: Not a networking issue

**Reference**: Docker Socket Security Risks
</details>

---

### Question 29

Which Security Context setting poses the GREATEST security risk?

A. runAsUser: 1000  
B. privileged: true  
C. readOnlyRootFilesystem: true  
D. allowPrivilegeEscalation: false

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
privileged: true is the most dangerous setting, granting full host access and negating container isolation.

Why B is correct:

- Bypasses all security restrictions
- Full host device access
- All capabilities granted
- Equivalent to running on host

Why others are wrong:

- A: Running as specific user is neutral/secure
- C: Read-only filesystem improves security
- D: Preventing escalation improves security

**Reference**: Kubernetes Privileged Containers
</details>

---

### Question 30

What does a Falco rule with priority "WARNING" indicate?

A. Critical security event requiring immediate action  
B. Potentially suspicious activity that may warrant investigation  
C. Normal expected behavior  
D. System error

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Falco priorities range from DEBUG to EMERGENCY. WARNING indicates potentially suspicious activity worth investigating.

Why B is correct:

- Mid-level priority
- Not critical but worth attention
- May indicate unusual but not necessarily malicious behavior
- Requires context-based investigation

Why others are wrong:

- A: CRITICAL or EMERGENCY indicates immediate action
- C: Normal behavior would be INFORMATIONAL or lower
- D: Not a system error indicator

**Reference**: Falco Rule Priorities
</details>

---

### Question 31

Which Falco rule type would detect a container modifying /etc/passwd?

A. list rule  
B. macro rule  
C. rule rule  
D. output rule

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
Falco "rules" (confusingly called "rule rules") are the actual detection rules that trigger alerts. Lists and macros are helpers.

Why C is correct:

- Rules define conditions that trigger alerts
- Would check for file writes to /etc/passwd
- Generates alerts when conditions match
- Main detection mechanism

Why others are wrong:

- A: Lists are reusable value collections
- B: Macros are reusable condition snippets
- D: Output defines alert formatting, not detection

**Reference**: Falco Rules Syntax
</details>

---

### Question 32

What is the purpose of the ServiceAccount automountServiceAccountToken field?

A. To specify the ServiceAccount name  
B. To control whether the ServiceAccount token is automatically mounted into pods  
C. To encrypt the token  
D. To rotate the token

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
automountServiceAccountToken controls whether the token is automatically mounted at /var/run/secrets/kubernetes.io/serviceaccount/token.

Why B is correct:

- Controls automatic token mounting
- Can be set at ServiceAccount or Pod level
- Should be false if pod doesn't need API access
- Reduces attack surface

Why others are wrong:

- A: serviceAccountName specifies the account
- C: Not related to token encryption
- D: Not related to token rotation

**Reference**: Kubernetes ServiceAccount Token Mounting
</details>

---

### Question 33

Which supply chain attack vector involves malicious code in third-party dependencies?

A. DDoS attack  
B. Dependency confusion or typosquatting  
C. SQL injection  
D. Cross-site scripting

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Dependency confusion and typosquatting involve attackers publishing malicious packages with names similar to legitimate dependencies.

Why B is correct:

- Attacks the software supply chain
- Exploits package management systems
- Malicious packages masquerade as legitimate
- Growing threat in cloud native ecosystem

Why others are wrong:

- A: DDoS is a direct attack, not supply chain
- C, D: Application vulnerabilities, not supply chain attacks

**Reference**: Supply Chain Security - Dependency Attacks
</details>

---

### Question 34

What is image signing primarily used for?

A. To compress images  
B. To verify image integrity and authenticity  
C. To scan for vulnerabilities  
D. To encrypt images

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Image signing uses cryptographic signatures to prove an image hasn't been tampered with and comes from a trusted source.

Why B is correct:

- Cryptographic proof of authenticity
- Detects tampering
- Verifies trusted source
- Part of supply chain security

Why others are wrong:

- A: Signing doesn't compress
- C: Scanning finds vulnerabilities (different purpose)
- D: Signing provides integrity, not encryption

**Reference**: Image Signing with Cosign
</details>

---

### Question 35

Which tool would you use to verify image signatures signed with Cosign?

A. Trivy  
B. Cosign verify  
C. Falco  
D. kubectl

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Cosign is both the signing and verification tool. "cosign verify" validates signatures on images.

Why B is correct:

- Cosign tool for signature operations
- Verifies cryptographic signatures
- Checks against public keys
- Part of Sigstore project

Why others are wrong:

- A: Trivy scans vulnerabilities, doesn't verify signatures
- C: Falco monitors runtime, doesn't verify signatures
- D: kubectl doesn't verify image signatures

**Reference**: Cosign Signature Verification
</details>

---

### Question 36

What is container drift?

A. Containers moving between nodes  
B. Runtime modifications to containers that differ from the original image  
C. Network latency  
D. Image version changes

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Container drift occurs when a running container's state differs from its image due to runtime modifications.

Why B is correct:

- Runtime changes to filesystem or processes
- Can indicate compromise or misconfiguration
- Violates immutable infrastructure principle
- Detected by tools like Falco or commercial solutions

Why others are wrong:

- A: Pod migration is normal operations
- C: Not related to network latency
- D: Version changes are normal updates

**Reference**: Container Drift Detection
</details>

---

### Question 37

Which admission webhook type would you use to automatically add security labels to pods?

A. Validating webhook  
B. Mutating webhook  
C. Audit webhook  
D. None of the above

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Mutating webhooks can modify (mutate) objects before they're persisted, allowing automatic addition of labels, annotations, or other fields.

Why B is correct:

- Can modify admission requests
- Runs before validation
- Can add labels, annotations, security settings
- Useful for enforcing defaults

Why others are wrong:

- A: Validating webhooks approve/reject, don't modify
- C: Audit webhooks log events, don't modify
- D: Mutating webhooks are the correct answer

**Reference**: Kubernetes Mutating Webhooks
</details>

---

### Question 38

What is the security benefit of using pod identity (IRSA, Workload Identity)?

A. Faster pod startup  
B. Avoids storing long-lived cloud credentials in Secrets  
C. Better networking  
D. More storage

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Pod identity mechanisms (AWS IRSA, GCP Workload Identity, Azure AD Workload Identity) provide temporary credentials without storing long-lived credentials.

Why B is correct:

- No long-lived credentials in cluster
- Temporary credentials automatically rotated
- Reduces secret management burden
- Better security through credential lifecycle management

Why others are wrong:

- A: Not primarily for performance
- C: Not related to networking
- D: Not related to storage

**Reference**: Kubernetes Pod Identity Best Practices
</details>

---

### Question 39

What type of attack can occur if a pod has excessive RBAC permissions?

A. DDoS  
B. Privilege escalation through Kubernetes API  
C. SQL injection  
D. Cross-site scripting

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Excessive RBAC permissions allow a compromised pod to use the Kubernetes API to escalate privileges, create resources, or access sensitive data.

Why B is correct:

- Compromised pod can abuse API permissions
- Can create privileged resources
- Can read secrets or modify cluster state
- Violates least privilege principle

Why others are wrong:

- A: DDoS is a direct attack, not related to RBAC
- C, D: Application vulnerabilities, not Kubernetes RBAC issues

**Reference**: Kubernetes RBAC Security Best Practices
</details>

---

## Domain 5: Platform Security (12 questions)

### Question 40

Which Trivy command scans a running Kubernetes cluster for vulnerabilities and misconfigurations?

A. trivy image  
B. trivy k8s cluster  
C. trivy config  
D. trivy fs

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
trivy k8s cluster scans all resources in a Kubernetes cluster for vulnerabilities and misconfigurations.

Why B is correct:

- Scans entire cluster
- Checks running containers and configurations
- Comprehensive cluster security assessment
- Kubernetes-specific scanner

Why others are wrong:

- A: Scans individual images, not cluster
- C: Scans config files, not running cluster
- D: Scans file systems, not Kubernetes cluster

**Reference**: Trivy Kubernetes Scanning
</details>

---

### Question 41

What does Pod Security Admission "audit" mode do?

A. Blocks pods that violate the policy  
B. Allows pods but adds audit annotations to API audit logs  
C. Deletes non-compliant pods  
D. Has no effect

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Audit mode allows pod creation but records policy violations in audit logs for monitoring and compliance.

Why B is correct:

- Allows non-compliant pods
- Records violations in audit logs
- Useful for monitoring before enforcement
- Can run alongside enforce mode

Why others are wrong:

- A: That's enforce mode
- C: PSA doesn't delete pods
- D: Audit mode records violations

**Reference**: Pod Security Admission Modes
</details>

---

### Question 42

Which Pod Security Standard is the LEAST restrictive?

A. Restricted  
B. Baseline  
C. Privileged  
D. Default

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
Privileged is the least restrictive standard, allowing all configurations including dangerous ones.

Why C is correct:

- Unrestricted (allows everything)
- No security enforcements
- Allows privileged containers, hostPath, etc.
- Should only be used for trusted workloads

Why others are wrong:

- A: Restricted is the MOST restrictive
- B: Baseline is moderately restrictive
- D: Not a standard (Privileged, Baseline, Restricted are the three)

**Reference**: Pod Security Standards
</details>

---

### Question 43

What is the purpose of an AppArmor profile in Kubernetes?

A. To improve performance  
B. To restrict container actions through mandatory access control  
C. To configure networking  
D. To manage storage

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
AppArmor is a Linux Security Module that restricts programs' capabilities through mandatory access control policies.

Why B is correct:

- Mandatory Access Control (MAC)
- Restricts file access, network, capabilities
- Applied per-container via annotations
- Defense in depth

Why others are wrong:

- A: Security feature, not performance
- C: Not for networking configuration
- D: Not for storage management

**Reference**: Kubernetes AppArmor Profiles
</details>

---

### Question 44

Which seccomp profile provides NO restriction on system calls?

A. RuntimeDefault  
B. Localhost/<profile>  
C. Unconfined  
D. Restricted

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
Unconfined seccomp profile disables seccomp filtering, allowing all system calls (insecure).

Why C is correct:

- No system call restrictions
- Equivalent to no seccomp
- Should not be used in production
- Maximum compatibility, minimum security

Why others are wrong:

- A: RuntimeDefault blocks dangerous system calls
- B: Custom profiles define specific restrictions
- D: Not a valid seccomp profile type

**Reference**: Kubernetes Seccomp Profiles
</details>

---

### Question 45

How do you apply a custom AppArmor profile to a container?

A. Via securityContext in pod spec  
B. Via annotation: container.apparmor.security.beta.kubernetes.io/<container-name>  
C. Via RBAC  
D. Via NetworkPolicy

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
AppArmor profiles are applied using a specific annotation format on the pod.

Why B is correct:

- Uses annotation (not part of Security Context yet)
- Specifies profile per container
- Format: container.apparmor.security.beta.kubernetes.io/<container-name>: <profile>
- Beta feature (annotation-based)

Why others are wrong:

- A: Not in securityContext (that's for seccomp, capabilities, etc.)
- C: RBAC is for authorization, not AppArmor
- D: NetworkPolicy is for network rules

**Reference**: Kubernetes AppArmor Configuration
</details>

---

### Question 46

What information does an SBOM provide?

A. Pod scheduling information  
B. List of all software components and dependencies in an image  
C. Network topology  
D. User permissions

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
SBOM (Software Bill of Materials) is an inventory of all software components, libraries, and dependencies in an artifact.

Why B is correct:

- Complete component inventory
- Includes versions and dependencies
- Essential for vulnerability management
- Supply chain security

Why others are wrong:

- A: Not related to scheduling
- C: Not related to networking
- D: Not related to permissions

**Reference**: SBOM Best Practices
</details>

---

### Question 47

Which tool generates SBOMs for container images?

A. Falco  
B. Syft  
C. kube-bench  
D. OPA

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Syft (from Anchore) is a specialized tool for generating SBOMs in multiple formats.

Why B is correct:

- Purpose-built for SBOM generation
- Supports multiple formats (SPDX, CycloneDX)
- Analyzes container images and filesystems
- Industry-standard tool

Why others are wrong:

- A: Falco is for runtime detection
- C: kube-bench is for compliance checking
- D: OPA is for policy enforcement

**Reference**: Syft SBOM Generator
</details>

---

### Question 48

Why should you use image digests instead of tags in production?

A. Digests are shorter  
B. Digests are immutable; tags can be changed to point to different images  
C. Digests are faster  
D. Tags don't work in production

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Image digests (SHA256 hashes) are immutable and uniquely identify an image. Tags can be moved to point to different images.

Why B is correct:

- Digests are cryptographic hashes (immutable)
- Tags are mutable pointers
- Ensures exact same image is deployed
- Prevents unexpected image changes

Why others are wrong:

- A: Digests are longer (SHA256 hash)
- C: No performance difference
- D: Tags work but are less secure

**Reference**: Kubernetes Image Digests
</details>

---

### Question 49

What does the capability DROP: ALL mean in Security Context?

A. Drop all network connections  
B. Remove all Linux capabilities from the container  
C. Delete all files  
D. Stop all processes

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
DROP: ALL removes all Linux capabilities from the container, starting from a position of zero capabilities (then add specific ones as needed).

Why B is correct:

- Removes all Linux capabilities
- Implements least privilege
- Can selectively add needed capabilities
- Security best practice

Why others are wrong:

- A: Not related to network connections
- C: Not related to file deletion
- D: Not related to process management

**Reference**: Linux Capabilities in Kubernetes
</details>

---

### Question 50

Which command scans a container image for vulnerabilities using Trivy?

A. trivy scan nginx  
B. trivy image nginx  
C. trivy inspect nginx  
D. trivy check nginx

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
The correct Trivy syntax for scanning an image is "trivy image <image-name>".

Why B is correct:

- Standard Trivy image scanning command
- Scans for OS and library vulnerabilities
- Provides CVE information and severity
- Most common Trivy use case

Why others are wrong:

- A, C, D: Not valid Trivy commands

**Reference**: Trivy Image Scanning
</details>

---

### Question 51

What is the security benefit of using a private container registry?

A. Faster downloads  
B. Control over allowed images and ability to scan before deployment  
C. Free storage  
D. Automatic updates

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Private registries provide control over which images are available and enable security scanning before images can be used.

Why B is correct:

- Curated image catalog
- Pre-deployment scanning and approval
- Prevents untrusted images
- Supply chain security

Why others are wrong:

- A: Speed is a benefit but not the primary security benefit
- C: Cost is not a security benefit
- D: Registries don't automatically update images

**Reference**: Container Registry Security
</details>

---

## Domain 6: Compliance and Security Frameworks (9 questions)

### Question 52

What does kube-bench check?

A. Application performance  
B. Kubernetes configuration against CIS Benchmark  
C. Network latency  
D. Storage capacity

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
kube-bench is an automated tool that checks Kubernetes cluster configuration against the CIS Kubernetes Benchmark.

Why B is correct:

- Automated CIS Benchmark checks
- Tests control plane and node configurations
- Provides pass/fail results and remediation
- Essential for compliance

Why others are wrong:

- A: Not for performance testing
- C: Not for network testing
- D: Not for storage testing

**Reference**: kube-bench Tool
</details>

---

### Question 53

Which CIS Benchmark recommendation is violated if the API server has --insecure-port set to a non-zero value?

A. No violation  
B. API server should not enable insecure port  
C. This is recommended  
D. Only affects performance

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
CIS Benchmark requires disabling the insecure port (--insecure-port=0) as it allows unauthenticated access.

Why B is correct:

- Insecure port bypasses authentication
- Major security vulnerability
- Should always be disabled
- CIS Benchmark critical recommendation

Why others are wrong:

- A: This is a serious violation
- C: Opposite of recommendation
- D: Security issue, not performance

**Reference**: CIS Kubernetes Benchmark - API Server
</details>

---

### Question 54

Which regulation focuses on protecting payment card data?

A. HIPAA  
B. GDPR  
C. PCI-DSS  
D. SOC 2

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
PCI-DSS (Payment Card Industry Data Security Standard) specifically regulates the handling of payment card information.

Why C is correct:

- Specific to credit/debit card data
- Mandates encryption and access controls
- Applies to payment processing systems
- Strict compliance requirements

Why others are wrong:

- A: HIPAA is for healthcare data
- B: GDPR is for personal data (EU)
- D: SOC 2 is general security compliance

**Reference**: PCI-DSS Standard
</details>

---

### Question 55

What is the primary purpose of GDPR in relation to Kubernetes?

A. Performance optimization  
B. Protecting personal data and privacy of EU residents  
C. Cost reduction  
D. Feature enablement

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
GDPR (General Data Protection Regulation) protects personal data and privacy rights of individuals in the European Union.

Why B is correct:

- EU privacy regulation
- Applies to personal data processing
- Requires technical and organizational measures
- Significant penalties for violations

Why others are wrong:

- A: Not related to performance
- C: Not related to cost
- D: Not related to features

**Reference**: GDPR Requirements
</details>

---

### Question 56

Which NIST CSF function includes activities for containment and recovery from incidents?

A. Identify  
B. Protect  
C. Detect  
D. Respond

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: D**

**Explanation:**
The Respond function includes activities for incident response, containment, eradication, and recovery.

Why D is correct:

- Incident response activities
- Containment and eradication
- Communication and coordination
- Post-incident activities

Why others are wrong:

- A: Identify is for asset and risk management
- B: Protect is for safeguards and controls
- C: Detect is for finding incidents

**Reference**: NIST Cybersecurity Framework - Respond
</details>

---

### Question 57

What type of audit is SOC 2 Type II?

A. One-time security assessment  
B. Assessment of controls operating over a period of time (typically 6-12 months)  
C. Performance audit  
D. Financial audit

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
SOC 2 Type II evaluates the effectiveness of controls over a period of time (typically 6-12 months), not just their design.

Why B is correct:

- Evaluates controls over time
- Typically 6-12 month period
- More comprehensive than Type I
- Demonstrates consistent security

Why others are wrong:

- A: That's Type I (point-in-time)
- C: Not a performance audit
- D: Not a financial audit (that's SOC 1)

**Reference**: SOC 2 Type II Requirements
</details>

---

### Question 58

Which tool implements Policy-as-Code using the Rego language?

A. Kyverno  
B. OPA/Gatekeeper  
C. Trivy  
D. Falco

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
OPA (Open Policy Agent) and Gatekeeper use the Rego policy language for defining policies as code.

Why B is correct:

- Rego is OPA's policy language
- Gatekeeper brings OPA to Kubernetes
- Flexible policy definition
- CNCF graduated project

Why others are wrong:

- A: Kyverno uses YAML, not Rego
- C: Trivy is a scanner, not policy engine
- D: Falco uses YAML rules, not Rego

**Reference**: OPA Rego Language
</details>

---

### Question 59

In OPA Gatekeeper, what is the relationship between ConstraintTemplate and Constraint?

A. No relationship  
B. ConstraintTemplate defines the policy logic; Constraint instantiates it with parameters  
C. They are the same thing  
D. Constraint defines logic; ConstraintTemplate instantiates

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
ConstraintTemplate is the reusable policy definition (Rego code). Constraint creates an instance with specific parameters.

Why B is correct:

- ConstraintTemplate: Policy logic (reusable)
- Constraint: Policy instance (specific enforcement)
- Separation of definition and enforcement
- Enables policy reuse

Why others are wrong:

- A: They are closely related
- C: Different purposes
- D: Reversed relationship

**Reference**: Gatekeeper Architecture
</details>

---

### Question 60

What is the BEST approach to enforce that all images must come from approved registries?

A. Developer training only  
B. ValidatingAdmissionWebhook with OPA/Kyverno policy  
C. Documentation  
D. Manual reviews

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Automated policy enforcement via admission webhooks ensures every pod is validated at deployment time.

Why B is correct:

- Automated enforcement
- Validates at admission time
- Blocks non-compliant pods
- Scalable and reliable

Why others are wrong:

- A: Training doesn't enforce
- C: Documentation doesn't enforce
- D: Manual reviews don't scale

**Reference**: Image Registry Policy Enforcement
</details>

---

## Answer Key

| Question | Domain | Correct Answer |
| ---------- | -------- | ---------------- |
| 1 | 1 | B |
| 2 | 1 | B |
| 3 | 1 | D |
| 4 | 1 | B |
| 5 | 1 | B |
| 6 | 1 | B |
| 7 | 2 | B |
| 8 | 2 | B |
| 9 | 2 | C |
| 10 | 2 | B |
| 11 | 2 | B |
| 12 | 2 | B |
| 13 | 2 | B |
| 14 | 2 | A |
| 15 | 2 | B |
| 16 | 2 | B |
| 17 | 2 | A |
| 18 | 2 | B |
| 19 | 3 | B |
| 20 | 3 | B |
| 21 | 3 | B |
| 22 | 3 | B |
| 23 | 3 | B |
| 24 | 3 | B |
| 25 | 3 | B |
| 26 | 3 | C |
| 27 | 3 | C |
| 28 | 4 | B |
| 29 | 4 | B |
| 30 | 4 | B |
| 31 | 4 | C |
| 32 | 4 | B |
| 33 | 4 | B |
| 34 | 4 | B |
| 35 | 4 | B |
| 36 | 4 | B |
| 37 | 4 | B |
| 38 | 4 | B |
| 39 | 4 | B |
| 40 | 5 | B |
| 41 | 5 | B |
| 42 | 5 | C |
| 43 | 5 | B |
| 44 | 5 | C |
| 45 | 5 | B |
| 46 | 5 | B |
| 47 | 5 | B |
| 48 | 5 | B |
| 49 | 5 | B |
| 50 | 5 | B |
| 51 | 5 | B |
| 52 | 6 | B |
| 53 | 6 | B |
| 54 | 6 | C |
| 55 | 6 | B |
| 56 | 6 | D |
| 57 | 6 | B |
| 58 | 6 | B |
| 59 | 6 | B |
| 60 | 6 | B |

---

## Scoring Guide

**Calculate your score:**

- Total correct answers: _____ / 60
- Percentage: (Correct / 60) × 100 = _____%

**Result:**

- **85-100%** (51-60 correct): Excellent! You're well-prepared for the KCSA exam.
- **75-84%** (45-50 correct): Good! You pass. Review weak areas and consider scheduling your exam.
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
1. Focus on common misconceptions and edge cases
1. Take Mock Exam Set 1 or 2 again after studying
1. Complete hands-on labs for weak areas
1. Schedule your KCSA exam when consistently scoring 75%+

---

## Common Exam Traps Covered in This Exam

This exam specifically focused on:

- Understanding default behaviors (NetworkPolicy default-allow)
- Distinguishing between similar concepts (authentication vs authorization)
- Scope differences (Role vs ClusterRole, RoleBinding vs ClusterRoleBinding)
- Tool purposes (Trivy vs Falco, Syft vs scanning tools)
- Configuration precedence (container vs pod Security Context)
- Policy combination (additive NetworkPolicies)
- Admission controller types (mutating vs validating)
- Security Context fields and their effects
- Image tags vs digests
- Default values and when they're insecure
