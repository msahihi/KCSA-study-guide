# KCSA Mock Exam Set 2

**Duration**: 90 minutes  
**Passing Score**: 75% (45 out of 60 questions)  
**Instructions**: Choose the MOST appropriate answer for each question. This exam features advanced scenarios and complex multi-component security configurations.

---

## Domain 1: Overview of Cloud Native Security (6 questions)

### Question 1

Your organization is migrating to a microservices architecture. Which security principle is MOST critical when designing service-to-service communication?

A. All services should trust each other within the cluster  
B. Implement mutual TLS (mTLS) for encrypted and authenticated communication  
C. Use HTTP for all internal communication to improve performance  
D. Rely solely on NetworkPolicy for service security

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Mutual TLS provides both encryption and mutual authentication for service-to-service communication, implementing zero trust principles.

Why B is correct:

- Encrypts traffic between services
- Provides mutual authentication (both sides verify identity)
- Prevents man-in-the-middle attacks
- Foundation of service mesh security (Istio, Linkerd)

Why others are wrong:

- A: Services should never implicitly trust each other (zero trust)
- C: Unencrypted HTTP is insecure for sensitive communications
- D: NetworkPolicy alone doesn't provide encryption or authentication

**Reference**: Service Mesh Security and mTLS
</details>

---

### Question 2

In the defense-in-depth security model, which layer provides the LAST line of defense if all other layers are compromised?

A. Application logging and monitoring  
B. Runtime security detection (e.g., Falco)  
C. Network segmentation  
D. Image scanning

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Runtime security detection is the last line of defense that can detect and alert on malicious behavior even when preventive controls have failed.

Why B is correct:

- Monitors actual runtime behavior
- Detects anomalies and attacks in progress
- Provides visibility when preventive controls fail
- Can trigger automated responses

Why others are wrong:

- A: Logging is important but detection is more active
- C: Network segmentation is a preventive control, not last line
- D: Image scanning is preventive (before deployment)

**Reference**: Defense in Depth Strategy
</details>

---

### Question 3

You're implementing security for a multi-tenant Kubernetes cluster. What is the STRONGEST isolation boundary?

A. Separate namespaces per tenant  
B. NetworkPolicy between tenant namespaces  
C. Separate clusters per tenant  
D. RBAC restrictions per tenant

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
Separate clusters provide the strongest isolation as tenants don't share any cluster infrastructure (control plane, nodes, network).

Why C is correct:

- Complete infrastructure isolation
- No shared control plane
- No risk of cluster-level privilege escalation affecting other tenants
- Eliminates noisy neighbor issues

Why others are wrong:

- A: Namespaces provide soft isolation but share cluster resources
- B: NetworkPolicy is network-only, doesn't isolate compute/control plane
- D: RBAC is essential but doesn't provide compute isolation

**Reference**: Kubernetes Multi-Tenancy Best Practices
</details>

---

### Question 4

Which statement BEST describes the shared responsibility model in Kubernetes security on a managed service (EKS, GKE, AKS)?

A. Cloud provider is responsible for all security  
B. Cloud provider secures the control plane; customer secures workloads and data  
C. Customer is responsible for all security  
D. Security is automatically handled by Kubernetes

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
In managed Kubernetes, the provider secures the control plane (API server, etcd, etc.), while customers secure their workloads, data, and access policies.

Why B is correct:

- Clear division of responsibility
- Provider manages control plane security and patches
- Customer handles workload security, RBAC, network policies, etc.
- Standard model for managed Kubernetes services

Why others are wrong:

- A: Customer has significant security responsibilities
- C: Provider has control plane responsibilities
- D: Security requires active configuration, not automatic

**Reference**: AWS EKS/GKE/AKS Shared Responsibility Model
</details>

---

### Question 5

Your security team implements a "shift-left" approach. At which stage should vulnerability scanning occur?

A. Only in production after deployment  
B. In CI/CD pipeline before images are pushed to registry  
C. During quarterly security audits  
D. Only when a vulnerability is publicly disclosed

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Shift-left means moving security earlier in the development lifecycle. Scanning in CI/CD catches vulnerabilities before they reach production.

Why B is correct:

- Catches issues early (cheaper to fix)
- Prevents vulnerable images from reaching registry
- Automates security in development pipeline
- Fails builds with critical vulnerabilities

Why others are wrong:

- A: Production-only scanning is too late
- C: Quarterly audits are too infrequent
- D: Reactive scanning misses many vulnerabilities

**Reference**: Shift-Left Security Practices
</details>

---

### Question 6

Which cloud native security principle emphasizes assuming breach and limiting blast radius?

A. Defense in depth  
B. Least privilege  
C. Zero trust  
D. All of the above

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: D**

**Explanation:**
All three principles contribute to assuming breach and limiting blast radius: defense in depth provides multiple layers, least privilege limits access, and zero trust verifies everything.

Why D is correct:

- Defense in depth: Multiple security layers contain breaches
- Least privilege: Limits what compromised accounts can do
- Zero trust: Continuous verification limits lateral movement
- All work together to minimize impact

Why others are wrong:

- A, B, C: Each is correct but not complete; all three together are most effective

**Reference**: Cloud Native Security Principles
</details>

---

## Domain 2: Kubernetes Cluster Component Security (12 questions)

### Question 7

You discover that anonymous requests are enabled on your API server. What is the security risk?

A. Better performance with more requests  
B. Unauthenticated users can access the API (even if limited by RBAC)  
C. Pods will fail to start  
D. etcd encryption will be disabled

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Anonymous authentication allows unauthenticated requests to reach the API server. Even if RBAC limits permissions, this increases attack surface.

Why B is correct:

- Allows requests without credentials
- Anonymous users get system:anonymous identity
- Can be used for reconnaissance
- Should be disabled unless specifically needed

Why others are wrong:

- A: Anonymous auth is a security risk, not performance benefit
- C: Anonymous auth doesn't prevent pod startup
- D: Anonymous auth doesn't affect etcd encryption

**Reference**: Kubernetes API Server Anonymous Authentication
</details>

---

### Question 8

What is the PRIMARY purpose of the --enable-admission-plugins flag on the API server?

A. To enable features in Kubernetes  
B. To activate admission controllers that validate/mutate requests  
C. To configure audit logging  
D. To set up RBAC

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
The --enable-admission-plugins flag activates specific admission controllers that can validate or mutate API requests before persistence.

Why B is correct:

- Enables specific admission controllers (NodeRestriction, PodSecurity, etc.)
- Essential for enforcing security policies
- Part of API server security configuration
- Must be explicitly enabled for security features

Why others are wrong:

- A: Feature gates enable features, not admission plugins
- C: Audit logging uses different flags
- D: RBAC is enabled via --authorization-mode

**Reference**: Kubernetes Admission Controllers Configuration
</details>

---

### Question 9

Which etcd configuration provides the STRONGEST security?

A. etcd on the same nodes as API server, no encryption  
B. etcd on dedicated nodes with client certificate authentication and encryption at rest  
C. etcd with only password authentication  
D. etcd accessible from all cluster nodes

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Dedicated etcd nodes with certificate authentication and encryption at rest provides defense in depth for the cluster's most critical datastore.

Why B is correct:

- Dedicated nodes reduce attack surface
- Client certificates provide mutual authentication
- Encryption at rest protects stored data
- Best practice for production clusters

Why others are wrong:

- A: No encryption or isolation
- C: Password auth is weaker than certificates
- D: Broad accessibility increases risk

**Reference**: etcd Security Best Practices
</details>

---

### Question 10

Your API server logs show "TooManyRequests" errors. Which configuration should you adjust?

A. --max-requests-inflight and --max-mutating-requests-inflight  
B. --authorization-mode  
C. --etcd-servers  
D. --tls-cert-file

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: A**

**Explanation:**
These flags control the maximum number of concurrent requests to the API server. TooManyRequests indicates these limits are being reached.

Why A is correct:

- Controls API server request concurrency
- Prevents overload
- Can be tuned based on cluster size
- Directly related to TooManyRequests errors

Why others are wrong:

- B: Authorization mode doesn't affect request limits
- C: etcd servers configuration doesn't control request limits
- D: TLS cert doesn't affect request limits

**Reference**: Kubernetes API Server Rate Limiting
</details>

---

### Question 11

What is the security benefit of enabling the NodeRestriction admission plugin?

A. Limits nodes to only modify their own Node object and pods bound to them  
B. Prevents all pod creation  
C. Disables all node communication  
D. Encrypts node-to-node traffic

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: A**

**Explanation:**
NodeRestriction limits what nodes (kubelets) can modify via the API, preventing compromised nodes from affecting other nodes or pods.

Why A is correct:

- Limits kubelet API permissions
- Prevents compromised node from modifying other nodes
- Restricts to own Node object and bound pods
- Essential for node security

Why others are wrong:

- B: Doesn't prevent pod creation
- C: Doesn't disable communication
- D: Doesn't handle encryption (that's CNI/service mesh)

**Reference**: Kubernetes NodeRestriction Admission Controller
</details>

---

### Question 12

Which component should you configure to automatically rotate certificates before expiration?

A. Manual certificate renewal scripts  
B. cert-manager or kubelet certificate rotation  
C. ConfigMaps with certificate data  
D. API server flags

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
cert-manager automates certificate lifecycle management, and kubelet has built-in certificate rotation capability.

Why B is correct:

- Automates certificate rotation
- Prevents certificate expiration outages
- cert-manager for workload certificates
- kubelet rotation for kubelet certificates
- Industry best practice

Why others are wrong:

- A: Manual scripts are error-prone and don't scale
- C: ConfigMaps don't provide rotation functionality
- D: API server flags don't rotate certificates

**Reference**: cert-manager and kubelet Certificate Rotation
</details>

---

### Question 13

You need to audit all requests that modify secrets. What audit log level should you use?

A. None  
B. Metadata  
C. Request  
D. RequestResponse

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: D**

**Explanation:**
RequestResponse level logs request body and response body, providing complete audit trail for secret modifications.

Why D is correct:

- Logs full request and response
- Provides complete audit trail
- Required for compliance in many frameworks
- Can see what was changed

Why others are wrong:

- A: None means no logging
- B: Metadata logs only metadata, not secret content
- C: Request logs request but not response

**Note**: Be careful with RequestResponse for secrets as it logs sensitive data. Use Request level with careful secret management.

**Reference**: Kubernetes Audit Logging Levels
</details>

---

### Question 14

What is the purpose of the --service-account-key-file flag on the API server?

A. To specify the key used to sign ServiceAccount tokens  
B. To enable RBAC  
C. To configure TLS  
D. To encrypt etcd

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: A**

**Explanation:**
This flag specifies the private key file used to sign ServiceAccount tokens. The corresponding public key is used by other components to verify tokens.

Why A is correct:

- Signs ServiceAccount tokens (JWTs)
- Part of ServiceAccount token authentication
- Critical for pod authentication to API server
- Public key used for verification

Why others are wrong:

- B: RBAC is configured via --authorization-mode
- C: TLS uses different cert files
- D: etcd encryption uses EncryptionConfiguration

**Reference**: Kubernetes ServiceAccount Token Signing
</details>

---

### Question 15

Which component should be configured with --protect-kernel-defaults=true to prevent kubelet from modifying kernel settings?

A. API server  
B. kubelet  
C. kube-proxy  
D. etcd

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
The --protect-kernel-defaults flag on kubelet prevents it from modifying kernel parameters, ensuring system hardening is maintained.

Why B is correct:

- Kubelet flag for kernel protection
- Prevents kubelet from changing sysctl settings
- Ensures security hardening isn't undone
- CIS Benchmark recommendation

Why others are wrong:

- A: API server doesn't have this flag
- C: kube-proxy doesn't manage kernel defaults
- D: etcd doesn't manage kernel defaults

**Reference**: Kubernetes Kubelet Configuration
</details>

---

### Question 16

What is the impact of enabling --encryption-provider-config on the API server?

A. Encrypts all network traffic  
B. Encrypts data at rest in etcd  
C. Enables TLS for the API server  
D. Encrypts pod logs

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
The EncryptionConfiguration file specified by this flag defines how to encrypt resources (like Secrets) at rest in etcd.

Why B is correct:

- Configures encryption for data stored in etcd
- Specifies which resources to encrypt (Secrets, ConfigMaps, etc.)
- Defines encryption providers (aescbc, aesgcm, etc.)
- Protects data at rest

Why others are wrong:

- A: Network traffic encryption uses TLS certificates
- C: TLS is configured with cert/key files
- D: Pod logs are not encrypted by this

**Reference**: Kubernetes Encryption at Rest
</details>

---

### Question 17

Which API server flag should you set to disable profiling endpoints for security?

A. --profiling=false  
B. --enable-profiling=false  
C. --disable-profiling=true  
D. --no-profiling

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: A**

**Explanation:**
The --profiling=false flag disables profiling endpoints on the API server, reducing attack surface.

Why A is correct:

- Disables /debug/pprof endpoints
- Reduces information disclosure risk
- CIS Benchmark recommendation
- Should be disabled in production

Why others are wrong:

- B, C, D: Not valid API server flags

**Reference**: Kubernetes API Server Security Configuration
</details>

---

### Question 18

What is the PRIMARY security benefit of using a separate etcd cluster instead of running etcd on master nodes?

A. Better performance  
B. Isolation and reduced attack surface for the cluster datastore  
C. Easier backups  
D. Lower cost

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Separate etcd cluster provides isolation, so compromise of a master node doesn't immediately expose etcd data.

Why B is correct:

- Physical/logical isolation from control plane
- Reduces blast radius of master node compromise
- Easier to implement network restrictions
- Best practice for production clusters

Why others are wrong:

- A: Performance is a benefit but not the primary security benefit
- C: Backups can be done in either configuration
- D: Cost is not a security benefit

**Reference**: etcd Deployment Topologies
</details>

---

## Domain 3: Kubernetes Security Fundamentals (9 questions)

### Question 19

A container needs to modify network interfaces. What is the MOST secure way to grant this capability?

A. Run the container as privileged: true  
B. Add NET_ADMIN capability and keep privileged: false  
C. Run as root with no restrictions  
D. Disable Security Context entirely

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Adding only the required capability (NET_ADMIN) follows the principle of least privilege, avoiding the broad permissions of privileged mode.

Why B is correct:

- Grants only the needed capability
- Doesn't grant full privileged access
- Maintains container isolation
- Follows least privilege principle

Why others are wrong:

- A: Privileged mode grants far more permissions than needed
- C: Running as root doesn't grant kernel capabilities
- D: Disabling Security Context removes all protections

**Reference**: Linux Capabilities in Kubernetes
</details>

---

### Question 20

You set runAsUser: 1000 at pod level and runAsUser: 2000 at container level. Which user ID will the container run as?

A. 0 (root)  
B. 1000  
C. 2000  
D. The container will fail to start

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
Container-level Security Context overrides pod-level Security Context for that specific container.

Why C is correct:

- Container settings take precedence over pod settings
- Allows different containers in a pod to have different security contexts
- Standard Kubernetes behavior
- Enables fine-grained control

Why others are wrong:

- A: Not default when runAsUser is specified
- B: Pod-level is overridden by container-level
- D: No conflict; container-level simply takes precedence

**Reference**: Kubernetes Security Context Precedence
</details>

---

### Question 21

Which combination of Security Context settings provides the STRONGEST container security?

A. runAsNonRoot: true, readOnlyRootFilesystem: true, allowPrivilegeEscalation: false, drop all capabilities  
B. privileged: true  
C. runAsUser: 0  
D. No Security Context (use defaults)

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: A**

**Explanation:**
This combination implements defense in depth: non-root user, immutable filesystem, no privilege escalation, and minimal capabilities.

Why A is correct:

- Multiple security layers
- Enforces non-root execution
- Prevents filesystem modifications
- Blocks privilege escalation
- Removes unnecessary capabilities

Why others are wrong:

- B: Privileged is the least secure option
- C: Running as root is insecure
- D: Defaults don't enforce security

**Reference**: Kubernetes Pod Security Standards - Restricted
</details>

---

### Question 22

What happens when you set fsGroup: 2000 in Security Context?

A. The container runs as user 2000  
B. Volumes mounted to the pod are owned by group 2000  
C. The pod is assigned to namespace 2000  
D. Network policies use group 2000

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
fsGroup sets the group ownership of mounted volumes, allowing non-root containers to access volume files.

Why B is correct:

- Sets supplementary group for volume access
- Changes ownership of volume files to specified GID
- Enables non-root containers to access shared volumes
- Applies to all containers in the pod

Why others are wrong:

- A: runAsUser sets the user, not fsGroup
- C: fsGroup doesn't affect namespaces
- D: NetworkPolicy doesn't use fsGroup

**Reference**: Kubernetes fsGroup Documentation
</details>

---

### Question 23

You need to create a NetworkPolicy that allows ingress from pods with label app=frontend in namespace prod to pods with label app=backend. What should the policy include?

A. podSelector: app=backend; from.podSelector: app=frontend; from.namespaceSelector: name=prod  
B. Only podSelector: app=backend  
C. Only namespaceSelector: name=prod  
D. podSelector: app=frontend

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: A**

**Explanation:**
The NetworkPolicy needs to select the backend pods and allow ingress from frontend pods in the prod namespace.

Why A is correct:

- podSelector targets backend pods (where policy applies)
- from.podSelector specifies frontend pods (source)
- from.namespaceSelector limits to prod namespace
- Both selectors are required for cross-namespace selection

Why others are wrong:

- B: Would allow from any pod (no ingress rules)
- C: Would allow all pods from prod namespace
- D: Targets wrong pods (frontend instead of backend)

**Reference**: Kubernetes NetworkPolicy Cross-Namespace
</details>

---

### Question 24

What is the effect of creating a NetworkPolicy with empty ingress: [] field?

A. Allow all ingress traffic  
B. Deny all ingress traffic  
C. No effect  
D. Allow only traffic from the same namespace

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
An empty ingress array explicitly denies all ingress traffic to selected pods.

Why B is correct:

- Empty ingress array = no allowed sources
- Explicitly denies all ingress
- Useful for creating isolated pods
- Different from omitting ingress field

Why others are wrong:

- A: Empty array denies, not allows
- C: Empty array has explicit effect (deny all)
- D: Doesn't allow any traffic, not even same namespace

**Reference**: Kubernetes NetworkPolicy Deny All Example
</details>

---

### Question 25

Which RBAC verb allows reading secrets but not creating or modifying them?

A. get, list, watch  
B. create, update  
C. * (all verbs)  
D. delete

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: A**

**Explanation:**
The get, list, and watch verbs provide read-only access to resources.

Why A is correct:

- get: Read individual secrets
- list: List all secrets
- watch: Watch for secret changes
- Read-only operations only

Why others are wrong:

- B: These are write operations
- C: Wildcard grants all permissions including write
- D: Delete is a destructive operation

**Reference**: Kubernetes RBAC Verbs
</details>

---

### Question 26

You want to grant a user access to create pods but only in the development namespace. What should you create?

A. ClusterRole with pod create permissions + ClusterRoleBinding  
B. Role in development namespace with pod create permissions + RoleBinding in development  
C. ClusterRole with pod create permissions + RoleBinding in development  
D. Role in default namespace with pod create permissions

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
A ClusterRole with RoleBinding limits the ClusterRole's permissions to a specific namespace, allowing reuse of the role definition.

Why C is correct:

- ClusterRole can be reused across namespaces
- RoleBinding in development limits scope to that namespace
- Common pattern for reusable permissions
- Follows best practices

Why others are wrong:

- A: ClusterRoleBinding grants access to all namespaces
- B: Works but less reusable (Role is namespace-specific)
- D: Wrong namespace

**Reference**: Kubernetes RBAC ClusterRole with RoleBinding
</details>

---

### Question 27

What is the security risk of granting the verb "escalate" in a Role or ClusterRole?

A. No risk, it's required for all users  
B. Allows granting permissions that the user doesn't have  
C. Improves security by allowing privilege escalation  
D. Only affects pod Security Context

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
The "escalate" verb allows binding roles with more permissions than the user has, which can lead to privilege escalation.

Why B is correct:

- Dangerous permission that breaks privilege boundaries
- Allows creating RoleBindings with higher privileges
- Can lead to privilege escalation attacks
- Should be tightly controlled

Why others are wrong:

- A: Very high risk; not required for normal users
- C: This is a security risk, not benefit
- D: Not related to pod Security Context

**Reference**: Kubernetes RBAC Privilege Escalation Prevention
</details>

---

## Domain 4: Kubernetes Threat Model (12 questions)

### Question 28

An attacker gains access to a pod with hostNetwork: true. What is the PRIMARY security risk?

A. Pod can't connect to services  
B. Pod has direct access to the host's network interfaces and can sniff traffic  
C. Pod will use more memory  
D. Pod can't use DNS

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
hostNetwork: true puts the pod in the host's network namespace, allowing access to all host network interfaces and traffic.

Why B is correct:

- Pod sees all host network traffic
- Can bind to any host port
- Bypasses NetworkPolicy
- Can perform network-based attacks on other nodes

Why others are wrong:

- A: Pod can still connect to services
- C: Network mode doesn't significantly affect memory
- D: DNS still works

**Reference**: Kubernetes hostNetwork Security Implications
</details>

---

### Question 29

Which hostPath mount is MOST dangerous from a security perspective?

A. /var/log  
B. /var/run/docker.sock  
C. /tmp  
D. /usr/share/docs

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Mounting the Docker socket gives the container full control over the Docker daemon, allowing container escape and host compromise.

Why B is correct:

- Full control over container runtime
- Can create privileged containers
- Can mount entire host filesystem
- Direct path to host root access

Why others are wrong:

- A: Log files are less sensitive
- C: /tmp is low risk
- D: Documentation directory is read-only and low risk

**Reference**: Docker Socket Security Risks
</details>

---

### Question 30

What is the security implication of hostPID: true?

A. Improved pod isolation  
B. Pod can see and interact with all processes on the host  
C. Better performance  
D. Required for running databases

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
hostPID: true puts the pod in the host's PID namespace, allowing it to see and potentially signal all host processes.

Why B is correct:

- Pod can see all host processes (ps aux shows host processes)
- Can send signals to host processes
- Information disclosure
- Can interfere with host operations

Why others are wrong:

- A: hostPID reduces isolation
- C: Not a performance feature
- D: Databases don't require hostPID

**Reference**: Kubernetes hostPID Security
</details>

---

### Question 31

A Falco alert shows: "Terminal shell in container". What type of attack might this indicate?

A. Network attack  
B. An attacker has gained interactive access to the container  
C. Normal application behavior  
D. DNS query

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Running a shell in a container is unusual for production workloads and often indicates an attacker has gained access.

Why B is correct:

- Shells shouldn't run in production containers
- Common indicator of compromise
- May indicate container breakout attempt
- Requires investigation

Why others are wrong:

- A: Not specifically a network attack
- C: Production containers shouldn't spawn shells
- D: Not related to DNS

**Reference**: Falco Container Shell Detection
</details>

---

### Question 32

Which Falco rule type would detect a process writing to /etc/passwd?

A. Network rule  
B. File system rule  
C. Process rule  
D. API audit rule

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Falco file system rules monitor file access. Writing to /etc/passwd is a classic privilege escalation indicator.

Why B is correct:

- Monitors file system operations
- Detects writes to sensitive files
- /etc/passwd is a critical system file
- Common attack technique

Why others are wrong:

- A: Not network-related
- C: While processes are involved, this is file system monitoring
- D: API audit rules monitor Kubernetes API, not file system

**Reference**: Falco File System Monitoring
</details>

---

### Question 33

An image scan reveals a critical vulnerability in a base OS package. The application doesn't use the vulnerable package. What should you do?

A. Ignore it since the application doesn't use it  
B. Remove the package or use a minimal base image  
C. Deploy anyway and monitor with Falco  
D. Add a NetworkPolicy

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Even unused packages can be exploited. Remove unnecessary packages or use minimal base images (distroless, Alpine).

Why B is correct:

- Reduces attack surface
- Unused packages can still be exploited
- Follows minimal base image principle
- Compliance requirements often mandate patching all vulnerabilities

Why others are wrong:

- A: Unused packages are still a risk
- C: Prevention is better than detection
- D: NetworkPolicy doesn't fix vulnerabilities

**Reference**: Container Image Best Practices
</details>

---

### Question 34

What is the primary security benefit of using distroless container images?

A. Larger image size  
B. Minimal attack surface with no shell or package managers  
C. Easier to debug  
D. Better performance

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Distroless images contain only the application and runtime dependencies, removing shells, package managers, and other unnecessary tools.

Why B is correct:

- No shell (prevents interactive access)
- No package managers (prevents installing tools)
- Minimal attack surface
- Reduces vulnerabilities

Why others are wrong:

- A: Distroless images are smaller, not larger
- C: Harder to debug (no shell), but more secure
- D: Security benefit, not performance

**Reference**: Google Distroless Images
</details>

---

### Question 35

Which admission controller webhook type can modify pod specs to add security defaults?

A. Validating webhook  
B. Mutating webhook  
C. Audit webhook  
D. Authorization webhook

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Mutating webhooks can modify (mutate) admission requests, allowing automatic addition of security configurations.

Why B is correct:

- Can change pod specifications
- Runs before validation
- Can add Security Context, labels, annotations
- Useful for enforcing security defaults

Why others are wrong:

- A: Validating webhooks accept or reject, don't modify
- C: Audit webhooks log, don't modify
- D: Authorization webhooks handle access control, don't modify resources

**Reference**: Kubernetes Mutating Admission Webhooks
</details>

---

### Question 36

What is container escape?

A. Normal container termination  
B. Breaking out of container isolation to access the host system  
C. Moving a container to a different node  
D. Exporting container images

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Container escape is when an attacker breaks out of container isolation to gain access to the host system.

Why B is correct:

- Exploits container runtime or kernel vulnerabilities
- Gains access to host system from container
- Critical security event
- Can lead to full cluster compromise

Why others are wrong:

- A: Normal termination is not an escape
- C: Migration is normal operations
- D: Image export is normal operations

**Reference**: Container Escape Techniques
</details>

---

### Question 37

Which technique helps prevent supply chain attacks in container images?

A. Using larger images  
B. Image signing and verification (e.g., Sigstore/Cosign)  
C. Running as root  
D. Disabling authentication

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Image signing provides cryptographic proof of image authenticity and integrity, preventing tampered or unauthorized images.

Why B is correct:

- Verifies image hasn't been tampered with
- Confirms image source
- Detects malicious modifications
- Part of supply chain security

Why others are wrong:

- A: Image size doesn't affect supply chain security
- C: Running as root is insecure
- D: Disabling authentication worsens security

**Reference**: Sigstore and Supply Chain Security
</details>

---

### Question 38

What is the security risk of using ServiceAccount tokens with no expiration?

A. No risk, tokens should never expire  
B. Long-lived tokens increase the window for compromise and misuse  
C. Better security  
D. Improved performance

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Long-lived or non-expiring tokens pose security risks if compromised, as they remain valid indefinitely.

Why B is correct:

- Longer exposure window if compromised
- Can't revoke without rotating keys
- Violates principle of least privilege (time-bound access)
- Bound tokens with expiration are recommended

Why others are wrong:

- A: Expiration improves security
- C: Non-expiring tokens are less secure
- D: Not related to performance

**Reference**: Kubernetes Bound Service Account Tokens
</details>

---

### Question 39

Which tool would you use to detect if a pod is running a cryptocurrency miner?

A. kubectl  
B. Falco with CPU usage rules  
C. NetworkPolicy  
D. RBAC

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Falco can detect anomalous behavior including high CPU usage patterns and suspicious processes characteristic of cryptocurrency mining.

Why B is correct:

- Runtime detection of suspicious processes
- Can monitor CPU usage patterns
- Detects known mining software
- Real-time alerting

Why others are wrong:

- A: kubectl shows state but doesn't detect malicious behavior
- C: NetworkPolicy doesn't detect mining
- D: RBAC is for access control, not detection

**Reference**: Falco Cryptomining Detection
</details>

---

## Domain 5: Platform Security (12 questions)

### Question 40

You run "trivy image nginx:latest" and find 50 vulnerabilities. What additional Trivy command provides more detailed information?

A. trivy image --severity HIGH,CRITICAL nginx:latest  
B. trivy config nginx:latest  
C. trivy fs nginx:latest  
D. trivy repo nginx:latest

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: A**

**Explanation:**
Filtering by severity focuses on the most important vulnerabilities (HIGH and CRITICAL) that require immediate attention.

Why A is correct:

- Filters to show only high-priority vulnerabilities
- Reduces noise from low-severity issues
- Helps prioritize remediation efforts
- Common best practice

Why others are wrong:

- B: trivy config is for Kubernetes manifest scanning
- C: trivy fs is for filesystem scanning, not container images
- D: trivy repo is for git repository scanning

**Reference**: Trivy Severity Filtering
</details>

---

### Question 41

Which Trivy scan type checks Kubernetes YAML manifests for security misconfigurations?

A. trivy image  
B. trivy config  
C. trivy repo  
D. trivy server

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
trivy config scans configuration files including Kubernetes manifests for security issues and misconfigurations.

Why B is correct:

- Scans YAML/JSON manifests
- Detects misconfigurations (privileged: true, missing Security Context, etc.)
- Checks against security best practices
- Part of shift-left security

Why others are wrong:

- A: trivy image scans container images, not configs
- C: trivy repo scans git repositories
- D: trivy server runs Trivy in server mode

**Reference**: Trivy Configuration Scanning
</details>

---

### Question 42

What does the AppArmor annotation "container.apparmor.security.beta.kubernetes.io/<container-name>: runtime/default" do?

A. Disables AppArmor  
B. Applies the default AppArmor profile to the container  
C. Creates a custom AppArmor profile  
D. Has no effect

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
This annotation applies the runtime's default AppArmor profile to the specified container, providing baseline security restrictions.

Why B is correct:

- Applies default AppArmor profile
- Provides baseline security restrictions
- Easy to apply without custom profiles
- Recommended for enhanced security

Why others are wrong:

- A: "runtime/default" enables AppArmor, not disables
- C: Custom profiles use "localhost/<profile-name>"
- D: This annotation has a definite effect

**Reference**: Kubernetes AppArmor Documentation
</details>

---

### Question 43

Which seccomp profile type should you use in production for enhanced security?

A. Unconfined  
B. RuntimeDefault  
C. Localhost/<custom-profile>  
D. None

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B (or C for custom needs)**

**Explanation:**
RuntimeDefault applies the container runtime's default seccomp profile, which blocks dangerous system calls. Custom profiles (C) can be used for specific needs.

Why B is correct:

- Blocks ~40+ dangerous system calls
- Maintained by container runtime
- Good balance of security and compatibility
- Recommended default

Why C is also acceptable:

- Custom profiles for specific security requirements
- Fine-tuned for application needs
- Maximum security when properly configured

Why others are wrong:

- A: Unconfined disables seccomp (insecure)
- D: None means no protection

**Reference**: Kubernetes Seccomp Profiles
</details>

---

### Question 44

Which Pod Security Standard allows hostPath volumes?

A. Restricted  
B. Baseline  
C. Privileged  
D. None

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
Only the Privileged standard allows hostPath volumes. Baseline and Restricted standards prohibit them due to security risks.

Why C is correct:

- Privileged standard is unrestricted
- Allows all potentially dangerous configurations
- hostPath can be used for host access/escape
- Baseline and Restricted prohibit hostPath

Why others are wrong:

- A: Restricted prohibits hostPath
- B: Baseline prohibits hostPath
- D: Privileged standard does allow it

**Reference**: Kubernetes Pod Security Standards Comparison
</details>

---

### Question 45

You want to enforce that all pods in a namespace run with readOnlyRootFilesystem: true. What's the BEST approach?

A. Manually configure each pod  
B. Use Pod Security Admission with Restricted policy  
C. Use OPA Gatekeeper or Kyverno policy  
D. Configure it in the namespace

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
OPA Gatekeeper or Kyverno can enforce custom policies like requiring readOnlyRootFilesystem. PSA Restricted doesn't enforce this field specifically.

Why C is correct:

- Policy-as-code enforcement
- Automatically validates all pods
- Can enforce specific Security Context fields
- Flexible and declarative

Why others are wrong:

- A: Manual configuration doesn't scale and can be bypassed
- B: PSA Restricted doesn't require readOnlyRootFilesystem
- D: Can't configure Security Context at namespace level directly

**Reference**: OPA Gatekeeper and Kyverno Policy Examples
</details>

---

### Question 46

What is the purpose of generating an SBOM with Syft?

A. To list all software components in an image for vulnerability tracking  
B. To encrypt images  
C. To scan for runtime threats  
D. To configure networking

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: A**

**Explanation:**
SBOM (Software Bill of Materials) lists all software components and dependencies in an image, essential for vulnerability management.

Why A is correct:

- Comprehensive inventory of components
- Enables vulnerability tracking
- Required for supply chain security
- Helps identify affected systems when new CVEs are disclosed

Why others are wrong:

- B: Syft doesn't encrypt images
- C: Runtime threat scanning is Falco's domain
- D: SBOM doesn't configure networking

**Reference**: Syft SBOM Generation
</details>

---

### Question 47

Which admission controller is REQUIRED for Pod Security Admission to work?

A. PodSecurity admission controller  
B. NodeRestriction  
C. LimitRanger  
D. ResourceQuota

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: A**

**Explanation:**
The PodSecurity admission controller must be enabled for Pod Security Admission to enforce policies.

Why A is correct:

- Implements Pod Security Standards enforcement
- Built-in admission controller (since K8s 1.23)
- Reads namespace labels and enforces policies
- Replaces PodSecurityPolicy

Why others are wrong:

- B: NodeRestriction is for node authorization, not PSA
- C: LimitRanger is for resource limits, not PSA
- D: ResourceQuota is for quota enforcement, not PSA

**Reference**: Kubernetes Pod Security Admission
</details>

---

### Question 48

You need to enforce that all images must be signed with Cosign. Which tool can enforce this at admission time?

A. Trivy  
B. Falco  
C. Sigstore Policy Controller / Kyverno / OPA Gatekeeper  
D. kube-bench

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
Policy enforcement at admission time requires an admission controller webhook like Sigstore Policy Controller, Kyverno, or OPA Gatekeeper.

Why C is correct:

- Validates signatures during admission
- Rejects unsigned images
- Enforces supply chain security policies
- Integrates with Cosign/Sigstore

Why others are wrong:

- A: Trivy scans for vulnerabilities, doesn't verify signatures at admission
- B: Falco is for runtime detection, not admission control
- D: kube-bench checks compliance, doesn't enforce admission policies

**Reference**: Sigstore Policy Controller and Kyverno
</details>

---

### Question 49

What is the security benefit of using a read-only root filesystem?

A. Better performance  
B. Prevents malware from persisting modifications to the filesystem  
C. Reduces image size  
D. Improves startup time

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Read-only root filesystem prevents attackers from modifying files, installing malware, or persisting changes in the container.

Why B is correct:

- Immutable filesystem prevents modifications
- Limits malware persistence
- Forces use of volumes for legitimate writes
- Defense in depth

Why others are wrong:

- A: Not primarily a performance feature
- C: Doesn't affect image size
- D: Doesn't affect startup time

**Reference**: Kubernetes Read-Only Root Filesystem
</details>

---

### Question 50

Which capability should you DROP to prevent a container from modifying file permissions?

A. CHOWN  
B. FOWNER  
C. DAC_OVERRIDE  
D. All of the above

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: D**

**Explanation:**
All three capabilities affect file permissions and ownership. Dropping all provides the strongest protection.

Why D is correct:

- CHOWN: Controls file ownership changes
- FOWNER: Bypasses permission checks for file ownership operations
- DAC_OVERRIDE: Bypasses read/write/execute permission checks
- Dropping all prevents file permission manipulation

Why others are wrong:

- A, B, C: Each is correct but incomplete; dropping all is strongest

**Reference**: Linux Capabilities and File Permissions
</details>

---

### Question 51

What is the primary difference between image scanning with Trivy vs runtime detection with Falco?

A. No difference  
B. Trivy finds vulnerabilities in images (static); Falco detects threats at runtime (dynamic)  
C. Trivy is for runtime; Falco is for images  
D. They do the same thing

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Trivy performs static analysis of images for vulnerabilities, while Falco monitors runtime behavior for threats.

Why B is correct:

- Trivy: Static analysis, finds CVEs in packages
- Falco: Dynamic monitoring, detects malicious behavior
- Complementary tools (both should be used)
- Different stages of security (build-time vs runtime)

Why others are wrong:

- A: Significant difference in purpose and operation
- C: Reversed - Trivy is for images, Falco for runtime
- D: Different tools with different purposes

**Reference**: Defense in Depth - Static and Dynamic Analysis
</details>

---

## Domain 6: Compliance and Security Frameworks (9 questions)

### Question 52

Which kube-bench test checks if the API server has anonymous authentication disabled?

A. Control plane component tests  
B. Worker node tests  
C. Policy tests  
D. Network tests

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: A**

**Explanation:**
kube-bench control plane component tests check API server configuration including authentication settings.

Why A is correct:

- Control plane tests cover API server configuration
- Checks flags like --anonymous-auth
- Part of CIS Benchmark section 1
- Critical for cluster security

Why others are wrong:

- B: Worker node tests focus on kubelet and node configuration
- C: Policy tests are for pod security and RBAC
- D: Network tests are for network policies

**Reference**: kube-bench Control Plane Tests
</details>

---

### Question 53

According to CIS Kubernetes Benchmark, what is the recommended setting for --anonymous-auth on the API server?

A. true  
B. false  
C. It doesn't matter  
D. Remove the flag entirely

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
CIS Benchmark recommends disabling anonymous authentication (--anonymous-auth=false) to ensure all API requests are authenticated.

Why B is correct:

- Requires authentication for all requests
- Prevents unauthenticated access
- CIS Benchmark recommendation
- Best practice for production

Why others are wrong:

- A: Enabling anonymous auth is insecure
- C: Setting matters significantly for security
- D: Flag should be explicitly set to false

**Reference**: CIS Kubernetes Benchmark - API Server
</details>

---

### Question 54

Which compliance framework specifically addresses financial data security and would apply to Kubernetes clusters processing payment card data?

A. HIPAA  
B. PCI-DSS  
C. SOC 2  
D. GDPR

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
PCI-DSS (Payment Card Industry Data Security Standard) is specifically for protecting payment card data.

Why B is correct:

- Specific to payment card data
- Requires encryption, access control, monitoring
- Applies to clusters processing credit card information
- Strict technical requirements

Why others are wrong:

- A: HIPAA is for healthcare data
- C: SOC 2 is general security compliance
- D: GDPR is for personal data privacy (EU)

**Reference**: PCI-DSS Requirements
</details>

---

### Question 55

Your cluster must comply with HIPAA for healthcare data. Which security control is MOST critical?

A. Using colorful dashboards  
B. Encryption at rest and in transit for Protected Health Information (PHI)  
C. Running all pods as root  
D. Disabling audit logs

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
HIPAA requires protecting PHI with encryption and access controls. Encryption both at rest and in transit is mandatory.

Why B is correct:

- HIPAA mandates PHI encryption
- Protects sensitive health information
- Required for compliance
- Applies to data in etcd and network traffic

Why others are wrong:

- A: Dashboards are not a compliance requirement
- C: Running as root violates security best practices
- D: Audit logs are required for HIPAA compliance

**Reference**: HIPAA Security Rule - Technical Safeguards
</details>

---

### Question 56

Which NIST Cybersecurity Framework function focuses on detecting security events?

A. Identify  
B. Protect  
C. Detect  
D. Respond

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: C**

**Explanation:**
The NIST CSF has five functions: Identify, Protect, Detect, Respond, and Recover. Detect focuses on finding security events.

Why C is correct:

- Detect function finds security incidents
- Includes monitoring, logging, anomaly detection
- Tools like Falco support this function
- Critical for incident response

Why others are wrong:

- A: Identify focuses on asset and risk management
- B: Protect focuses on safeguards and controls
- D: Respond focuses on incident response actions

**Reference**: NIST Cybersecurity Framework Core Functions
</details>

---

### Question 57

A SOC 2 audit requires demonstrating security controls over time. Which Kubernetes feature is MOST helpful?

A. Persistent audit logging  
B. Using the latest tag  
C. Disabling RBAC  
D. Running all pods as privileged

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: A**

**Explanation:**
SOC 2 Type II requires demonstrating consistent security controls over time. Audit logs provide this evidence.

Why A is correct:

- Provides evidence of security controls
- Shows who did what and when
- Required for compliance audits
- Demonstrates control effectiveness over time

Why others are wrong:

- B: Latest tag is poor practice and doesn't demonstrate controls
- C: Disabling RBAC violates security requirements
- D: Privileged pods violate security principles

**Reference**: SOC 2 Type II Requirements
</details>

---

### Question 58

Which tool implements Policy-as-Code for Kubernetes using Rego language?

A. Falco  
B. OPA (Open Policy Agent) / Gatekeeper  
C. Trivy  
D. kube-bench

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
OPA (and its Kubernetes-specific implementation Gatekeeper) uses the Rego language to define policies as code.

Why B is correct:

- OPA uses Rego policy language
- Gatekeeper is OPA for Kubernetes
- Enables Policy-as-Code
- Flexible policy enforcement

Why others are wrong:

- A: Falco uses YAML rules, not Rego
- C: Trivy is a scanner, not policy engine
- D: kube-bench checks compliance, doesn't enforce policies

**Reference**: Open Policy Agent and Rego Language
</details>

---

### Question 59

What is a ConstraintTemplate in OPA Gatekeeper?

A. A namespace configuration  
B. A reusable policy definition that can be instantiated as Constraints  
C. A pod template  
D. A network policy

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
ConstraintTemplate defines reusable policy logic in Rego. Constraints instantiate templates to enforce specific rules.

Why B is correct:

- Defines the policy logic (Rego code)
- Reusable across multiple Constraints
- Template + Constraint = policy enforcement
- Separation of policy definition from enforcement

Why others are wrong:

- A: Not related to namespace configuration
- C: Not related to pod templates
- D: Not related to NetworkPolicy

**Reference**: OPA Gatekeeper ConstraintTemplates
</details>

---

### Question 60

Your organization needs to ensure all container images come from approved registries. Which policy enforcement approach is MOST effective?

A. Manual review before deployment  
B. OPA Gatekeeper or Kyverno policy that validates image registry  
C. Documentation of approved registries  
D. Monthly audits

<details>
<summary>Answer & Explanation</summary>

**Correct Answer: B**

**Explanation:**
Automated policy enforcement with OPA Gatekeeper or Kyverno ensures every pod is checked at admission time, blocking non-compliant deployments.

Why B is correct:

- Automated enforcement (no human error)
- Validates at admission time (prevents violations)
- Scales to all deployments
- Provides audit trail

Why others are wrong:

- A: Manual review doesn't scale and can be bypassed
- C: Documentation alone isn't enforcement
- D: Monthly audits are reactive and too infrequent

**Reference**: Image Registry Policy Enforcement
</details>

---

## Answer Key

| Question | Domain | Correct Answer |
| ---------- | -------- | ---------------- |
| 1 | 1 | B |
| 2 | 1 | B |
| 3 | 1 | C |
| 4 | 1 | B |
| 5 | 1 | B |
| 6 | 1 | D |
| 7 | 2 | B |
| 8 | 2 | B |
| 9 | 2 | B |
| 10 | 2 | A |
| 11 | 2 | A |
| 12 | 2 | B |
| 13 | 2 | D |
| 14 | 2 | A |
| 15 | 2 | B |
| 16 | 2 | B |
| 17 | 2 | A |
| 18 | 2 | B |
| 19 | 3 | B |
| 20 | 3 | C |
| 21 | 3 | A |
| 22 | 3 | B |
| 23 | 3 | A |
| 24 | 3 | B |
| 25 | 3 | A |
| 26 | 3 | C |
| 27 | 3 | B |
| 28 | 4 | B |
| 29 | 4 | B |
| 30 | 4 | B |
| 31 | 4 | B |
| 32 | 4 | B |
| 33 | 4 | B |
| 34 | 4 | B |
| 35 | 4 | B |
| 36 | 4 | B |
| 37 | 4 | B |
| 38 | 4 | B |
| 39 | 4 | B |
| 40 | 5 | A |
| 41 | 5 | B |
| 42 | 5 | B |
| 43 | 5 | B |
| 44 | 5 | C |
| 45 | 5 | C |
| 46 | 5 | A |
| 47 | 5 | A |
| 48 | 5 | C |
| 49 | 5 | B |
| 50 | 5 | D |
| 51 | 5 | B |
| 52 | 6 | A |
| 53 | 6 | B |
| 54 | 6 | B |
| 55 | 6 | B |
| 56 | 6 | C |
| 57 | 6 | A |
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
1. Identify your weakest domain(s)
1. Study the relevant domain materials
1. Take Mock Exam Set 3 after 3-5 days
1. Complete hands-on labs for weak areas

---
