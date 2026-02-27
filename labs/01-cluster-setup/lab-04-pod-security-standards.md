# Lab 04: Pod Security Standards

## Objectives

By the end of this lab, you will be able to:

- Understand the three Pod Security Standards levels (Privileged, Baseline, Restricted)
- Apply Pod Security Admission labels to namespaces
- Use enforce, audit, and warn modes effectively
- Configure security contexts at pod and container levels
- Troubleshoot and fix Pod Security Standards violations
- Migrate applications from permissive to restricted standards
- Implement best practices for secure pod configurations

## Prerequisites

- Kubernetes cluster v1.30+ (PSA enabled by default since 1.25)
- kubectl configured with cluster-admin permissions
- Basic understanding of Kubernetes pods and deployments
- Familiarity with YAML syntax and security concepts

## Estimated Time

60-90 minutes

## Lab Scenario

You're tasked with implementing Pod Security Standards across your Kubernetes cluster. You need to:

1. Assess current security posture
1. Apply appropriate PSS levels to different namespaces
1. Fix applications that violate security policies
1. Gradually migrate to the restricted standard
1. Document security configurations

## Lab Environment Setup

### Step 1: Create Lab Namespaces

```bash

# Development environment (permissive)

kubectl create namespace lab-pss-dev

# Staging environment (moderate security)

kubectl create namespace lab-pss-staging

# Production environment (strict security)

kubectl create namespace lab-pss-prod

# System namespace (privileged workloads)

kubectl create namespace lab-pss-system
```

```

Verify namespaces:

```bash

kubectl get namespaces | grep lab-pss
```

```

### Step 2: Check Pod Security Admission

Verify PSA is enabled:

```bash

kubectl api-resources | grep podsecurity
```

```

Check current PSS labels on namespaces:

```bash

kubectl get namespaces -o custom-columns=\
NAME:.metadata.name,\
ENFORCE:.metadata.labels.pod-security\.kubernetes\.io/enforce,\
AUDIT:.metadata.labels.pod-security\.kubernetes\.io/audit,\
WARN:.metadata.labels.pod-security\.kubernetes\.io/warn
```

```

## Exercise 1: Understanding Default Behavior

### Step 1: Deploy Insecure Pod (Before PSS)

Create a file named `insecure-pod.yaml`:

```yaml

apiVersion: v1
kind: Pod
metadata:
  name: insecure-pod
  namespace: lab-pss-dev
spec:
  containers:
  - name: nginx
    image: nginx:1.26
    securityContext:
      privileged: true  # BAD: Privileged container
      runAsUser: 0      # BAD: Running as root
```

```

Deploy the pod:

```bash

kubectl apply -f insecure-pod.yaml
```

```

Check if it's running:

```bash

kubectl get pod insecure-pod -n lab-pss-dev
```

```

Expected: Pod runs successfully (no PSS enforcement yet).

Verify it's running as root:

```bash

kubectl exec -n lab-pss-dev insecure-pod -- whoami
```

```

Expected output: `root`

Delete the pod:

```bash

kubectl delete pod insecure-pod -n lab-pss-dev
```

```

## Exercise 2: Apply Baseline Standard

### Step 1: Apply Baseline Enforcement

```bash

kubectl label namespace lab-pss-dev \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/audit=baseline \
  pod-security.kubernetes.io/warn=baseline
```

```

Verify labels:

```bash

kubectl get namespace lab-pss-dev --show-labels
```

```

### Step 2: Try Deploying Insecure Pod Again

```bash

kubectl apply -f insecure-pod.yaml
```

```

Expected output:

```

Error from server (Forbidden): error when creating "insecure-pod.yaml":
pods "insecure-pod" is forbidden: violates PodSecurity "baseline:latest":
privileged (container "nginx" must not set securityContext.privileged=true)

```
```

The pod is rejected! Let's fix it.

### Step 3: Create Baseline-Compliant Pod

Create a file named `baseline-pod.yaml`:

```yaml

apiVersion: v1
kind: Pod
metadata:
  name: baseline-pod
  namespace: lab-pss-dev
spec:
  containers:
  - name: nginx
    image: nginx:1.26
    securityContext:

      # Required for baseline

      privileged: false
      allowPrivilegeEscalation: false

      # Still running as root (baseline allows this)

      runAsUser: 0
    ports:
    - containerPort: 80
```

```

Deploy:

```bash

kubectl apply -f baseline-pod.yaml
```

```

Verify:

```bash

kubectl get pod baseline-pod -n lab-pss-dev
kubectl describe pod baseline-pod -n lab-pss-dev | grep -A 10 "Security Context"
```

```

Expected: Pod runs successfully.

Check it's still running as root (baseline allows this):

```bash

kubectl exec -n lab-pss-dev baseline-pod -- whoami
```

```

Expected: `root`

## Exercise 3: Apply Restricted Standard

### Step 1: Apply Restricted Standard to Staging

```bash

kubectl label namespace lab-pss-staging \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
```

```

### Step 2: Try Deploying Baseline Pod to Staging

```bash

kubectl apply -f baseline-pod.yaml -n lab-pss-staging
```

```

Expected output (error):

```

Error from server (Forbidden): error when creating "baseline-pod.yaml":
pods "baseline-pod" is forbidden: violates PodSecurity "restricted:latest":
allowPrivilegeEscalation != false (container "nginx" must set
securityContext.allowPrivilegeEscalation=false), unrestricted capabilities
(container "nginx" must set securityContext.capabilities.drop=["ALL"]),
runAsNonRoot != true (pod or container "nginx" must set
securityContext.runAsNonRoot=true), seccompProfile (pod or container "nginx"
must set securityContext.seccompProfile.type to "RuntimeDefault" or "Localhost")

```
```

The restricted standard requires more security controls!

### Step 3: Create Restricted-Compliant Pod

Create a file named `restricted-pod.yaml`:

```yaml

apiVersion: v1
kind: Pod
metadata:
  name: restricted-pod
  namespace: lab-pss-staging
spec:
  securityContext:

    # Pod-level security context

    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault

  containers:
  - name: nginx
    image: nginxinc/nginx-unprivileged:1.26  # Non-root nginx image
    securityContext:

      # Container-level security context

      allowPrivilegeEscalation: false
      runAsNonRoot: true
      capabilities:
        drop:
        - ALL
      seccompProfile:
        type: RuntimeDefault

    ports:
    - containerPort: 8080

    # Read-only root filesystem (best practice)

    volumeMounts:
    - name: cache
      mountPath: /var/cache/nginx
    - name: run
      mountPath: /var/run

  volumes:
  - name: cache
    emptyDir: {}
  - name: run
    emptyDir: {}
```

```

Deploy:

```bash

kubectl apply -f restricted-pod.yaml
```

```

Verify:

```bash

kubectl get pod restricted-pod -n lab-pss-staging
kubectl describe pod restricted-pod -n lab-pss-staging | grep -A 20 "Security Context"
```

```

Check it's running as non-root:

```bash

kubectl exec -n lab-pss-staging restricted-pod -- whoami
```

```

Expected: `nginx` or user ID `1000`

## Exercise 4: Using Warn and Audit Modes

Warn and audit modes help you prepare for enforcement without breaking existing workloads.

### Step 1: Configure Staging with Warn Mode

Update staging to enforce baseline but warn about restricted violations:

```bash

kubectl label namespace lab-pss-staging \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted \
  --overwrite
```

```

### Step 2: Deploy Baseline Pod with Warnings

```bash

kubectl apply -f baseline-pod.yaml -n lab-pss-staging
```

```

Expected output:

```

Warning: would violate PodSecurity "restricted:latest": runAsNonRoot != true
(pod or container "nginx" must set securityContext.runAsNonRoot=true),
unrestricted capabilities (container "nginx" must set
securityContext.capabilities.drop=["ALL"]), seccompProfile (pod or container
"nginx" must set securityContext.seccompProfile.type to "RuntimeDefault" or
"Localhost")
pod/baseline-pod created

```
```

The pod is created (baseline enforcement passes) but you see warnings about restricted violations.

### Step 3: Check Audit Logs

Check API server audit logs for violations:

```bash

# This depends on your cluster setup
# For kubeadm clusters:

sudo cat /var/log/kubernetes/audit.log | grep -i podsecurity | tail -5

# Or check API server pod logs:

kubectl logs -n kube-system kube-apiserver-$(hostname) | grep -i podsecurity
```

```

## Exercise 5: Fixing Common Violations

Let's create and fix common PSS violations.

### Step 1: Deployment with Multiple Violations

Create a file named `violating-deployment.yaml`:

```yaml

apiVersion: apps/v1
kind: Deployment
metadata:
  name: violating-app
  namespace: lab-pss-staging
spec:
  replicas: 2
  selector:
    matchLabels:
      app: violating-app
  template:
    metadata:
      labels:
        app: violating-app
    spec:
      containers:
      - name: app
        image: nginx:1.26
        ports:
        - containerPort: 80
```

```

Try to deploy:

```bash

kubectl apply -f violating-deployment.yaml
```

```

Expected: Warnings but deployment created (baseline enforcement).

### Step 2: Fix Violations Step-by-Step

Let's fix this to meet restricted standard.

Create a file named `fixed-deployment.yaml`:

```yaml

apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
  namespace: lab-pss-staging
spec:
  replicas: 2
  selector:
    matchLabels:
      app: secure-app
  template:
    metadata:
      labels:
        app: secure-app
    spec:

      # Pod-level security context

      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
        seccompProfile:
          type: RuntimeDefault

      containers:
      - name: app
        image: nginxinc/nginx-unprivileged:1.26

        # Container-level security context

        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          runAsUser: 1000
          capabilities:
            drop:
            - ALL
          readOnlyRootFilesystem: true
          seccompProfile:
            type: RuntimeDefault

        ports:
        - containerPort: 8080

        # Provide writable directories

        volumeMounts:
        - name: cache
          mountPath: /var/cache/nginx
        - name: run
          mountPath: /var/run
        - name: tmp
          mountPath: /tmp

        # Resource limits (best practice)

        resources:
          limits:
            cpu: 500m
            memory: 256Mi
          requests:
            cpu: 250m
            memory: 128Mi

      volumes:
      - name: cache
        emptyDir: {}
      - name: run
        emptyDir: {}
      - name: tmp
        emptyDir: {}
```

```

Deploy:

```bash

kubectl apply -f fixed-deployment.yaml
```

```

Verify no warnings:

```bash

kubectl get deployment secure-app -n lab-pss-staging
kubectl get pods -n lab-pss-staging -l app=secure-app
```

```

## Exercise 6: Migration Strategy

Let's simulate migrating a namespace from permissive to restricted.

### Step 1: Initial State (No PSS)

Deploy some test applications in dev:

```bash

cat > dev-apps.yaml << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app1
  namespace: lab-pss-dev
spec:
  replicas: 1
  selector:
    matchLabels:
      app: app1
  template:
    metadata:
      labels:
        app: app1
    spec:
      containers:
      - name: nginx
        image: nginx:1.26
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app2
  namespace: lab-pss-dev
spec:
  replicas: 1
  selector:
    matchLabels:
      app: app2
  template:
    metadata:
      labels:
        app: app2
    spec:
      containers:
      - name: nginx
        image: nginx:1.26
        securityContext:
          runAsUser: 0
EOF

kubectl apply -f dev-apps.yaml
```

```

Wait for pods:

```bash

kubectl wait --for=condition=ready pod -l app=app1 -n lab-pss-dev --timeout=60s
kubectl wait --for=condition=ready pod -l app=app2 -n lab-pss-dev --timeout=60s
```

```

### Step 2: Step 1 - Add Warn Mode

```bash

kubectl label namespace lab-pss-dev \
  pod-security.kubernetes.io/warn=restricted \
  --overwrite
```

```

Recreate deployments to see warnings:

```bash

kubectl rollout restart deployment app1 -n lab-pss-dev
kubectl rollout restart deployment app2 -n lab-pss-dev
```

```

Watch for warnings:

```bash

kubectl get events -n lab-pss-dev --sort-by='.lastTimestamp' | grep -i warning
```

```

### Step 3: Step 2 - Add Audit Mode

```bash

kubectl label namespace lab-pss-dev \
  pod-security.kubernetes.io/audit=restricted \
  --overwrite
```

```

Now violations are logged in audit logs (check API server audit logs).

### Step 4: Step 3 - Fix Applications

Update deployments to be restricted-compliant:

```bash

cat > dev-apps-fixed.yaml << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app1
  namespace: lab-pss-dev
spec:
  replicas: 1
  selector:
    matchLabels:
      app: app1
  template:
    metadata:
      labels:
        app: app1
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: nginx
        image: nginxinc/nginx-unprivileged:1.26
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          capabilities:
            drop:
            - ALL
          seccompProfile:
            type: RuntimeDefault
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app2
  namespace: lab-pss-dev
spec:
  replicas: 1
  selector:
    matchLabels:
      app: app2
  template:
    metadata:
      labels:
        app: app2
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: nginx
        image: nginxinc/nginx-unprivileged:1.26
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          capabilities:
            drop:
            - ALL
          seccompProfile:
            type: RuntimeDefault
EOF

kubectl apply -f dev-apps-fixed.yaml
```

```

### Step 5: Step 4 - Enable Enforcement

Once all apps are fixed:

```bash

kubectl label namespace lab-pss-dev \
  pod-security.kubernetes.io/enforce=restricted \
  --overwrite
```

```

Verify all pods still running:

```bash

kubectl get pods -n lab-pss-dev
```

```

## Exercise 7: Special Cases

### Case 1: Init Containers

Create a file named `init-container-pod.yaml`:

```yaml

apiVersion: v1
kind: Pod
metadata:
  name: init-container-pod
  namespace: lab-pss-staging
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault

  initContainers:
  - name: init
    image: busybox:1.36
    command: ['sh', '-c', 'echo "Initializing..." > /shared/init.txt']
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      runAsUser: 1000
      capabilities:
        drop:
        - ALL
      readOnlyRootFilesystem: true
      seccompProfile:
        type: RuntimeDefault
    volumeMounts:
    - name: shared
      mountPath: /shared

  containers:
  - name: app
    image: nginxinc/nginx-unprivileged:1.26
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      capabilities:
        drop:
        - ALL
      seccompProfile:
        type: RuntimeDefault
    volumeMounts:
    - name: shared
      mountPath: /usr/share/nginx/html
      readOnly: true

  volumes:
  - name: shared
    emptyDir: {}
```

```

Deploy:

```bash

kubectl apply -f init-container-pod.yaml
```

```

Verify both init and main containers are secure:

```bash

kubectl describe pod init-container-pod -n lab-pss-staging
```

```

### Case 2: Sidecar Containers

Create a file named `sidecar-pod.yaml`:

```yaml

apiVersion: v1
kind: Pod
metadata:
  name: sidecar-pod
  namespace: lab-pss-staging
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    seccompProfile:
      type: RuntimeDefault

  containers:

  # Main application

  - name: app
    image: nginxinc/nginx-unprivileged:1.26
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      capabilities:
        drop:
        - ALL
      seccompProfile:
        type: RuntimeDefault
    ports:
    - containerPort: 8080
    volumeMounts:
    - name: logs
      mountPath: /var/log/nginx

  # Sidecar for log processing

  - name: log-processor
    image: busybox:1.36
    command: ['sh', '-c', 'tail -f /logs/access.log']
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      capabilities:
        drop:
        - ALL
      readOnlyRootFilesystem: true
      seccompProfile:
        type: RuntimeDefault
    volumeMounts:
    - name: logs
      mountPath: /logs
      readOnly: true

  volumes:
  - name: logs
    emptyDir: {}
```

```

Deploy:

```bash

kubectl apply -f sidecar-pod.yaml
```

```

Verify both containers meet restricted standard:

```bash

kubectl get pod sidecar-pod -n lab-pss-staging
kubectl logs sidecar-pod -n lab-pss-staging -c log-processor
```

```

### Case 3: Privileged System Workload

Some workloads genuinely need privileges (monitoring agents, CNI, etc.).

Apply privileged standard to system namespace:

```bash

kubectl label namespace lab-pss-system \
  pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/audit=baseline \
  pod-security.kubernetes.io/warn=baseline
```

```

Deploy a privileged pod:

```yaml

cat > privileged-system-pod.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: node-monitor
  namespace: lab-pss-system
spec:
  hostNetwork: true
  hostPID: true
  containers:
  - name: monitor
    image: nicolaka/netshoot:latest
    command: ['sleep', '3600']
    securityContext:
      privileged: true
    volumeMounts:
    - name: host-root
      mountPath: /host
      readOnly: true
  volumes:
  - name: host-root
    hostPath:
      path: /
      type: Directory
EOF

kubectl apply -f privileged-system-pod.yaml
```

```

This is allowed in the privileged namespace but document why it's necessary.

## Exercise 8: Testing and Validation

### Step 1: Create Validation Script

```bash

cat > validate-pss.sh << 'EOF'

#!/bin/bash

echo "=== Pod Security Standards Validation ==="
echo

# Test function

test_deployment() {
    local ns=$1
    local name=$2
    local expected=$3

    echo -n "Testing $name in $ns: "

    cat > /tmp/test-pod.yaml << YAML
apiVersion: v1
kind: Pod
metadata:
  name: test-$name
  namespace: $ns
spec:
  containers:
  - name: test
    image: nginx:1.26
    securityContext:
      privileged: true
YAML

    if kubectl apply -f /tmp/test-pod.yaml 2>&1 | grep -q "forbidden"; then
        if [ "$expected" = "reject" ]; then
            echo "✓ PASS (correctly rejected)"
        else
            echo "✗ FAIL (unexpectedly rejected)"
        fi
    else
        if [ "$expected" = "allow" ]; then
            echo "✓ PASS (correctly allowed)"
            kubectl delete pod test-$name -n $ns 2>/dev/null
        else
            echo "✗ FAIL (unexpectedly allowed)"
            kubectl delete pod test-$name -n $ns 2>/dev/null
        fi
    fi

    rm -f /tmp/test-pod.yaml
}

echo "Namespace PSS Configuration:"
kubectl get namespaces lab-pss-dev lab-pss-staging lab-pss-prod lab-pss-system \
    -o custom-columns=NAME:.metadata.name,ENFORCE:.metadata.labels.pod-security\.kubernetes\.io/enforce 2>/dev/null
echo

echo "Testing privileged pod deployment:"
test_deployment lab-pss-dev "dev" "reject"
test_deployment lab-pss-staging "staging" "reject"
test_deployment lab-pss-system "system" "allow"

echo
echo "=== Validation Complete ==="
EOF

chmod +x validate-pss.sh
./validate-pss.sh
```

```

### Step 2: Verify Security Contexts

```bash

# Check all pods in staging have proper security contexts

kubectl get pods -n lab-pss-staging -o json | \
    jq -r '.items[] | "\(.metadata.name): runAsNonRoot=\(.spec.securityContext.runAsNonRoot // "not set")"'

# Check capabilities are dropped

kubectl get pods -n lab-pss-staging -o json | \
    jq -r '.items[] | .metadata.name + ": " + (.spec.containers[].securityContext.capabilities.drop // [] | join(","))'
```

```

## Exercise 9: Production Configuration

### Step 1: Configure Production Namespace

```bash

kubectl label namespace lab-pss-prod \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=v1.30 \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
```

```

Version pinning prevents surprises when standards evolve.

### Step 2: Deploy Production-Ready Application

Create a file named `production-app.yaml`:

```yaml

apiVersion: apps/v1
kind: Deployment
metadata:
  name: production-app
  namespace: lab-pss-prod
  labels:
    app: production-app
    environment: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: production-app
  template:
    metadata:
      labels:
        app: production-app
    spec:

      # Pod-level security

      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
        fsGroupChangePolicy: "OnRootMismatch"
        seccompProfile:
          type: RuntimeDefault

      # Service account (least privilege)

      serviceAccountName: default
      automountServiceAccountToken: false

      containers:
      - name: app
        image: nginxinc/nginx-unprivileged:1.26

        # Container-level security

        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          runAsUser: 1000
          capabilities:
            drop:
            - ALL
            add:
            - NET_BIND_SERVICE
          readOnlyRootFilesystem: true
          seccompProfile:
            type: RuntimeDefault

        ports:
        - containerPort: 8080
          name: http

        # Resource limits

        resources:
          limits:
            cpu: 1000m
            memory: 512Mi
          requests:
            cpu: 500m
            memory: 256Mi

        # Health checks

        livenessProbe:
          httpGet:
            path: /
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 10

        readinessProbe:
          httpGet:
            path: /
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5

        # Writable volumes

        volumeMounts:
        - name: cache
          mountPath: /var/cache/nginx
        - name: run
          mountPath: /var/run
        - name: tmp
          mountPath: /tmp

      volumes:
      - name: cache
        emptyDir:
          sizeLimit: 100Mi
      - name: run
        emptyDir:
          sizeLimit: 10Mi
      - name: tmp
        emptyDir:
          sizeLimit: 50Mi

      # Anti-affinity for HA

      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - production-app
              topologyKey: kubernetes.io/hostname
```

```

Deploy:

```bash

kubectl apply -f production-app.yaml
```

```

Verify:

```bash

kubectl get deployment production-app -n lab-pss-prod
kubectl get pods -n lab-pss-prod -l app=production-app
```

```

## Challenge Questions

1. **What's the difference between `runAsUser` at pod level vs container level?**
   <details>
   <summary>Click to see answer</summary>

   - Pod level: Sets the default user for all containers in the pod
   - Container level: Overrides pod-level setting for specific container
   - Best practice: Set at pod level for consistency, override only when needed
   </details>

1. **Why do we need both `runAsNonRoot: true` and `runAsUser: 1000`?**
   <details>
   <summary>Click to see answer</summary>

   - `runAsNonRoot: true`: Tells Kubernetes to reject the pod if it tries to run as root (UID 0)
   - `runAsUser: 1000`: Explicitly sets which non-root user to use
   - Together they provide defense in depth: even if image defaults to root, it will be rejected
   </details>

1. **What does `seccompProfile.type: RuntimeDefault` do?**
   <details>
   <summary>Click to see answer</summary>

   Seccomp (Secure Computing Mode) restricts the system calls a container can make. `RuntimeDefault` uses the container runtime's default seccomp profile, which blocks dangerous system calls while allowing normal operations. This significantly reduces the attack surface.
   </details>

1. **Can you run a database with `readOnlyRootFilesystem: true`?**
   <details>
   <summary>Click to see answer</summary>

   Yes, but you need to mount writable volumes for data storage and temporary files:

   ```yaml

   volumeMounts:
   - name: data
     mountPath: /var/lib/postgresql/data
   - name: tmp
     mountPath: /tmp

   ```

   The application directory remains read-only, but data directories are writable.
   </details>

1. **When should you use the privileged standard?**
   <details>
   <summary>Click to see answer</summary>

   Only for workloads that genuinely need host-level access:

   - CNI plugins
   - CSI drivers
   - Node monitoring agents
   - System maintenance tools
   - Infrastructure components

   Always document why privileges are required and consider alternatives.
   </details>

## Troubleshooting

### Issue: "runAsNonRoot" Violation

**Error**: `runAsNonRoot != true`

**Solution**:

```yaml

spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
  - name: app
    securityContext:
      runAsNonRoot: true
```

```

### Issue: "capabilities" Violation

**Error**: `unrestricted capabilities`

**Solution**:

```yaml

securityContext:
  capabilities:
    drop:
    - ALL
```

```

### Issue: "seccompProfile" Violation

**Error**: `seccompProfile`

**Solution**:

```yaml

securityContext:
  seccompProfile:
    type: RuntimeDefault
```

```

### Issue: Pod Fails with Read-Only Filesystem

**Error**: Application crashes writing to filesystem

**Solution**: Mount writable emptyDir volumes:

```yaml

volumeMounts:
- name: tmp
  mountPath: /tmp
- name: cache
  mountPath: /var/cache
volumes:
- name: tmp
  emptyDir: {}
- name: cache
  emptyDir: {}
```

```

### Issue: Image Runs as Root

**Error**: Image tries to run as UID 0

**Solution**:

1. Use non-root image (e.g., `nginx-unprivileged`)
1. Or modify Dockerfile:

   ```dockerfile

   USER 1000

   ```

1. Or override in pod spec:

   ```yaml

   securityContext:
     runAsUser: 1000

   ```

## Cleanup

```bash

# Delete all lab namespaces

kubectl delete namespace lab-pss-dev
kubectl delete namespace lab-pss-staging
kubectl delete namespace lab-pss-prod
kubectl delete namespace lab-pss-system

# Remove local files

rm -f *.yaml
rm -f validate-pss.sh
```

```

## Key Takeaways

1. Three PSS levels: Privileged (unrestricted), Baseline (minimal restrictions), Restricted (hardened)
1. Three modes: Enforce (reject), Audit (log), Warn (notify)
1. Use warn/audit modes to prepare for enforcement
1. Restricted requires: runAsNonRoot, drop ALL capabilities, seccompProfile
1. `readOnlyRootFilesystem: true` is a best practice
1. Pod-level security context applies to all containers
1. Container-level overrides pod-level settings
1. Use non-root container images when possible
1. Provide writable volumes for applications that need them
1. Document any privileged workloads and why they need privileges

## Best Practices Summary

```yaml

# Complete Security Context Template

spec:

  # Pod level

  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault

  containers:
  - name: app

    # Container level

    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      runAsUser: 1000
      capabilities:
        drop:
        - ALL
      readOnlyRootFilesystem: true
      seccompProfile:
        type: RuntimeDefault
```

```

## Next Steps

1. Review [Pod Security Standards concept documentation](../../../domains/01-cluster-setup/pod-security-standards.md)
1. Apply PSS to your actual workloads (start with warn mode)
1. Create organization-specific security policies
1. Move to [Domain 2: Cluster Hardening](../../../domains/02-cluster-hardening/README.md)

---

[← Previous Lab: Ingress Security](./lab-03-ingress-security.md) | [Back to Lab Overview](./README.md) | [Back to Domain 1](../../../domains/01-cluster-setup/README.md)
