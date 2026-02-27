# Lab 01: Network Policies

## Objectives

By the end of this lab, you will be able to:

- Create and apply default deny network policies
- Configure ingress network policies to allow specific traffic
- Configure egress network policies to control outbound traffic
- Use pod selectors and namespace selectors in network policies
- Test and verify network policy effectiveness
- Troubleshoot network policy issues

## Prerequisites

- Kubernetes cluster v1.30+ with NetworkPolicy support (Calico, Cilium, or Weave Net CNI)
- kubectl configured to access the cluster
- Basic understanding of Kubernetes pods and services
- Familiarity with YAML syntax

## Estimated Time

60-90 minutes

## Lab Scenario

You are securing a three-tier web application consisting of:

- **Frontend**: Web server that needs to accept external traffic and communicate with backend
- **Backend**: API server that receives requests from frontend and queries the database
- **Database**: PostgreSQL database that only the backend should access

Your task is to implement network policies that enforce this security model.

## Lab Environment Setup

### Step 1: Create Lab Namespace

```bash
kubectl create namespace lab-netpol
kubectl config set-context --current --namespace=lab-netpol
```

Verify namespace creation:

```bash
kubectl get namespace lab-netpol
```

Expected output:

```
NAME         STATUS   AGE
lab-netpol   Active   5s

```

### Step 2: Deploy the Three-Tier Application

Create a file named `app-deployment.yaml`:

```yaml
---

# Frontend Deployment

apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
  namespace: lab-netpol
spec:
  replicas: 2
  selector:
    matchLabels:
      app: frontend
      tier: web
  template:
    metadata:
      labels:
        app: frontend
        tier: web
    spec:
      containers:
      - name: nginx
        image: nginx:1.26
        ports:
        - containerPort: 80
---

# Frontend Service

apiVersion: v1
kind: Service
metadata:
  name: frontend
  namespace: lab-netpol
spec:
  selector:
    app: frontend
    tier: web
  ports:
  - port: 80
    targetPort: 80
  type: ClusterIP
---

# Backend Deployment

apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
  namespace: lab-netpol
spec:
  replicas: 2
  selector:
    matchLabels:
      app: backend
      tier: api
  template:
    metadata:
      labels:
        app: backend
        tier: api
    spec:
      containers:
      - name: api
        image: hashicorp/http-echo:1.0
        args:
        - "-text=Backend API Response"
        ports:
        - containerPort: 5678
---

# Backend Service

apiVersion: v1
kind: Service
metadata:
  name: backend
  namespace: lab-netpol
spec:
  selector:
    app: backend
    tier: api
  ports:
  - port: 8080
    targetPort: 5678
  type: ClusterIP
---

# Database Deployment

apiVersion: apps/v1
kind: Deployment
metadata:
  name: database
  namespace: lab-netpol
spec:
  replicas: 1
  selector:
    matchLabels:
      app: database
      tier: data
  template:
    metadata:
      labels:
        app: database
        tier: data
    spec:
      containers:
      - name: postgres
        image: postgres:16
        env:
        - name: POSTGRES_PASSWORD
          value: secretpassword
        ports:
        - containerPort: 5432
---

# Database Service

apiVersion: v1
kind: Service
metadata:
  name: database
  namespace: lab-netpol
spec:
  selector:
    app: database
    tier: data
  ports:
  - port: 5432
    targetPort: 5432
  type: ClusterIP
```

Apply the deployment:

```bash
kubectl apply -f app-deployment.yaml
```

Verify all pods are running:

```bash
kubectl get pods -n lab-netpol
```

Expected output:

```
NAME                        READY   STATUS    RESTARTS   AGE
frontend-xxxxx-yyyyy        1/1     Running   0          30s
frontend-xxxxx-zzzzz        1/1     Running   0          30s
backend-xxxxx-yyyyy         1/1     Running   0          30s
backend-xxxxx-zzzzz         1/1     Running   0          30s
database-xxxxx-yyyyy        1/1     Running   0          30s

```

## Exercise 1: Test Default Behavior (No Network Policies)

Before implementing network policies, let's verify that all pods can communicate freely.

### Step 1: Deploy a Test Pod

```bash
kubectl run test-pod --image=busybox:1.36 -n lab-netpol -- sleep 3600
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/test-pod -n lab-netpol --timeout=60s
```

### Step 2: Test Connectivity to All Services

Test frontend access:

```bash
kubectl exec -n lab-netpol test-pod -- wget -O- --timeout=2 http://frontend
```

Expected output: HTML content from nginx

Test backend access:

```bash
kubectl exec -n lab-netpol test-pod -- wget -O- --timeout=2 http://backend:8080
```

Expected output: "Backend API Response"

Test database access:

```bash
kubectl exec -n lab-netpol test-pod -- nc -zv database 5432
```

Expected output: "database (10.x.x.x:5432) open"

### Step 3: Test Inter-Pod Communication

Get a frontend pod name:

```bash
FRONTEND_POD=$(kubectl get pod -n lab-netpol -l app=frontend -o jsonpath='{.items[0].metadata.name}')
echo $FRONTEND_POD
```

Test frontend → backend:

```bash
kubectl exec -n lab-netpol $FRONTEND_POD -- wget -O- --timeout=2 http://backend:8080
```

Expected output: "Backend API Response"

Get a backend pod name:

```bash
BACKEND_POD=$(kubectl get pod -n lab-netpol -l app=backend -o jsonpath='{.items[0].metadata.name}')
echo $BACKEND_POD
```

Test backend → database:

```bash
kubectl exec -n lab-netpol $BACKEND_POD -- nc -zv database 5432
```

Expected output: "database (10.x.x.x:5432) open"

**Observation**: All pods can communicate with each other without restriction. This is Kubernetes' default behavior.

## Exercise 2: Implement Default Deny Policy

Now let's implement a default deny policy that blocks all ingress traffic.

### Step 1: Create Default Deny Ingress Policy

Create a file named `default-deny-ingress.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: lab-netpol
spec:
  podSelector: {}  # Empty selector = applies to all pods
  policyTypes:
  - Ingress
```

Apply the policy:

```bash
kubectl apply -f default-deny-ingress.yaml
```

Verify the policy:

```bash
kubectl get networkpolicy -n lab-netpol
kubectl describe networkpolicy default-deny-ingress -n lab-netpol
```

Expected output:

```
Name:         default-deny-ingress
Namespace:    lab-netpol
Created on:   2024-01-15 10:00:00 +0000 UTC
Labels:       <none>
Annotations:  <none>
Spec:
  PodSelector:     <none> (Allowing the specific traffic to all pods in this namespace)
  Allowing ingress traffic:
    <none> (Selected pods are isolated for ingress connectivity)
  Not affecting egress traffic
  Policy Types: Ingress

```

### Step 2: Test Connectivity After Default Deny

Try accessing frontend (should timeout):

```bash
kubectl exec -n lab-netpol test-pod -- wget -O- --timeout=2 http://frontend
```

Expected output:

```
wget: download timed out
command terminated with exit code 1

```

Try accessing backend (should timeout):

```bash
kubectl exec -n lab-netpol test-pod -- wget -O- --timeout=2 http://backend:8080
```

Expected output:

```
wget: download timed out
command terminated with exit code 1

```

**Important**: Egress traffic from test-pod still works (DNS queries, outbound connections), but ingress to all pods is now blocked.

### Step 3: Verify Frontend Cannot Reach Backend

```bash
kubectl exec -n lab-netpol $FRONTEND_POD -- wget -O- --timeout=2 http://backend:8080
```

Expected output:

```
wget: download timed out
command terminated with exit code 1

```

**Observation**: The default deny policy has isolated all pods. Now we'll selectively allow required traffic.

## Exercise 3: Allow Frontend Access

Let's allow external traffic to reach the frontend.

### Step 1: Create Frontend Ingress Policy

Create a file named `frontend-allow-ingress.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-allow-ingress
  namespace: lab-netpol
spec:
  podSelector:
    matchLabels:
      app: frontend
      tier: web
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector: {}  # Allow from all pods in same namespace
    ports:
    - protocol: TCP
      port: 80
```

Apply the policy:

```bash
kubectl apply -f frontend-allow-ingress.yaml
```

### Step 2: Verify Frontend Access

Test from test-pod:

```bash
kubectl exec -n lab-netpol test-pod -- wget -O- --timeout=2 http://frontend
```

Expected output: HTML content from nginx (success!)

Test from backend pod:

```bash
kubectl exec -n lab-netpol $BACKEND_POD -- wget -O- --timeout=2 http://frontend
```

Expected output: HTML content from nginx

**Observation**: Frontend is now accessible, but backend and database are still blocked.

## Exercise 4: Allow Frontend → Backend Communication

### Step 1: Create Backend Ingress Policy

Create a file named `backend-allow-from-frontend.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-allow-from-frontend
  namespace: lab-netpol
spec:
  podSelector:
    matchLabels:
      app: backend
      tier: api
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
          tier: web
    ports:
    - protocol: TCP
      port: 5678
```

Apply the policy:

```bash
kubectl apply -f backend-allow-from-frontend.yaml
```

### Step 2: Verify Backend Access

Test from frontend (should work):

```bash
kubectl exec -n lab-netpol $FRONTEND_POD -- wget -O- --timeout=2 http://backend:8080
```

Expected output: "Backend API Response"

Test from test-pod (should fail):

```bash
kubectl exec -n lab-netpol test-pod -- wget -O- --timeout=2 http://backend:8080
```

Expected output: Timeout (blocked because test-pod doesn't have the required labels)

**Observation**: Only frontend pods can access backend now.

## Exercise 5: Allow Backend → Database Communication

### Step 1: Create Database Ingress Policy

Create a file named `database-allow-from-backend.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: database-allow-from-backend
  namespace: lab-netpol
spec:
  podSelector:
    matchLabels:
      app: database
      tier: data
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: backend
          tier: api
    ports:
    - protocol: TCP
      port: 5432
```

Apply the policy:

```bash
kubectl apply -f database-allow-from-backend.yaml
```

### Step 2: Verify Database Access

Test from backend (should work):

```bash
kubectl exec -n lab-netpol $BACKEND_POD -- nc -zv database 5432
```

Expected output: "database (10.x.x.x:5432) open"

Test from frontend (should fail):

```bash
kubectl exec -n lab-netpol $FRONTEND_POD -- nc -zv database 5432 2>&1 | head -1
```

Expected output: Connection timeout or "nc: bad address 'database'" (blocked)

Test from test-pod (should fail):

```bash
kubectl exec -n lab-netpol test-pod -- nc -zv database 5432
```

Expected output: Timeout

**Observation**: Only backend pods can access the database.

## Exercise 6: Implement Egress Policies

Now let's control outbound traffic using egress policies.

### Step 1: Add Default Deny Egress

Create a file named `default-deny-egress.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: lab-netpol
spec:
  podSelector: {}
  policyTypes:
  - Egress
```

Apply the policy:

```bash
kubectl apply -f default-deny-egress.yaml
```

### Step 2: Test Egress Block

Try DNS resolution from test-pod (should fail):

```bash
kubectl exec -n lab-netpol test-pod -- nslookup kubernetes.default
```

Expected output: Timeout (DNS is blocked)

**Important**: When you implement egress policies, you must explicitly allow DNS!

### Step 3: Allow DNS Egress

Create a file named `allow-dns-egress.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: lab-netpol
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
```

Apply the policy:

```bash
kubectl apply -f allow-dns-egress.yaml
```

### Step 4: Verify DNS Works

```bash
kubectl exec -n lab-netpol test-pod -- nslookup kubernetes.default
```

Expected output: DNS resolution succeeds

### Step 5: Create Specific Egress Policies

Frontend egress policy (allow to backend):

Create a file named `frontend-egress.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-egress
  namespace: lab-netpol
spec:
  podSelector:
    matchLabels:
      app: frontend
      tier: web
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: backend
          tier: api
    ports:
    - protocol: TCP
      port: 5678
  - to:  # DNS
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
```

Backend egress policy (allow to database):

Create a file named `backend-egress.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-egress
  namespace: lab-netpol
spec:
  podSelector:
    matchLabels:
      app: backend
      tier: api
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database
          tier: data
    ports:
    - protocol: TCP
      port: 5432
  - to:  # DNS
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
```

Apply both policies:

```bash
kubectl apply -f frontend-egress.yaml
kubectl apply -f backend-egress.yaml
```

### Step 6: Verify Complete Policy

Test the full chain:

```bash
# Frontend can reach backend

kubectl exec -n lab-netpol $FRONTEND_POD -- wget -O- --timeout=2 http://backend:8080

# Backend can reach database

kubectl exec -n lab-netpol $BACKEND_POD -- nc -zv database 5432

# Frontend cannot reach database

kubectl exec -n lab-netpol $FRONTEND_POD -- nc -zv database 5432 -w 2
```

Expected: First two succeed, third fails.

## Exercise 7: Cross-Namespace Communication

Let's create a monitoring namespace that needs access to our application.

### Step 1: Create Monitoring Namespace

```bash
kubectl create namespace monitoring
kubectl label namespace monitoring name=monitoring
```

### Step 2: Deploy Monitoring Pod

```bash
kubectl run prometheus -n monitoring --image=prom/prometheus:v2.45.0 -- sleep 3600
kubectl wait --for=condition=ready pod/prometheus -n monitoring --timeout=60s
```

### Step 3: Test Cross-Namespace Access (Currently Blocked)

```bash
kubectl exec -n monitoring prometheus -- wget -O- --timeout=2 http://backend.lab-netpol.svc.cluster.local:8080
```

Expected output: Timeout (blocked by default deny)

### Step 4: Allow Monitoring Access

Create a file named `backend-allow-monitoring.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-allow-monitoring
  namespace: lab-netpol
spec:
  podSelector:
    matchLabels:
      app: backend
      tier: api
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - protocol: TCP
      port: 5678
```

Apply the policy:

```bash
kubectl apply -f backend-allow-monitoring.yaml
```

### Step 5: Verify Monitoring Access

```bash
kubectl exec -n monitoring prometheus -- wget -O- --timeout=2 http://backend.lab-netpol.svc.cluster.local:8080
```

Expected output: "Backend API Response"

**Note**: This works because NetworkPolicies are additive. The backend now allows traffic from both frontend pods (same namespace) and monitoring namespace.

## Exercise 8: IP Block Rules (Egress to External Services)

Let's allow the frontend to access an external API.

### Step 1: Update Frontend Egress for External Access

Create a file named `frontend-egress-external.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-egress-external
  namespace: lab-netpol
spec:
  podSelector:
    matchLabels:
      app: frontend
      tier: web
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: backend
    ports:
    - protocol: TCP
      port: 5678
  - to:  # Allow access to Google DNS
    - ipBlock:
        cidr: 8.8.8.8/32
    ports:
    - protocol: TCP
      port: 443
  - to:  # DNS
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
```

Apply the policy:

```bash
kubectl apply -f frontend-egress-external.yaml
```

### Step 2: Test External Access

```bash
# This should work (allowed IP)

kubectl exec -n lab-netpol $FRONTEND_POD -- nc -zv 8.8.8.8 443 -w 2

# This should fail (not allowed)

kubectl exec -n lab-netpol $FRONTEND_POD -- nc -zv 1.1.1.1 443 -w 2
```

## Verification and Testing

### View All Network Policies

```bash
kubectl get networkpolicies -n lab-netpol
```

Expected output:

```
NAME                          POD-SELECTOR       AGE
default-deny-ingress          <none>             10m
default-deny-egress           <none>             5m
frontend-allow-ingress        app=frontend       8m
backend-allow-from-frontend   app=backend        6m
database-allow-from-backend   app=database       4m
frontend-egress               app=frontend       3m
backend-egress                app=backend        3m
allow-dns-egress              <none>             4m
backend-allow-monitoring      app=backend        2m
frontend-egress-external      app=frontend       1m

```

### Describe a Network Policy

```bash
kubectl describe networkpolicy backend-allow-from-frontend -n lab-netpol
```

### Test Complete Traffic Flow

Create a comprehensive test script:

```bash
cat > test-netpol.sh << 'EOF'

#!/bin/bash

echo "=== Network Policy Test Suite ==="
echo

FRONTEND_POD=$(kubectl get pod -n lab-netpol -l app=frontend -o jsonpath='{.items[0].metadata.name}')
BACKEND_POD=$(kubectl get pod -n lab-netpol -l app=backend -o jsonpath='{.items[0].metadata.name}')

echo "1. Frontend can reach Backend: "
if kubectl exec -n lab-netpol $FRONTEND_POD -- wget -O- --timeout=2 http://backend:8080 > /dev/null 2>&1; then
    echo "   ✓ PASS"
else
    echo "   ✗ FAIL"
fi

echo "2. Backend can reach Database: "
if kubectl exec -n lab-netpol $BACKEND_POD -- nc -zv database 5432 -w 2 > /dev/null 2>&1; then
    echo "   ✓ PASS"
else
    echo "   ✗ FAIL"
fi

echo "3. Frontend CANNOT reach Database: "
if kubectl exec -n lab-netpol $FRONTEND_POD -- nc -zv database 5432 -w 2 > /dev/null 2>&1; then
    echo "   ✗ FAIL (should be blocked)"
else
    echo "   ✓ PASS (correctly blocked)"
fi

echo "4. Test-pod CANNOT reach Backend: "
if kubectl exec -n lab-netpol test-pod -- wget -O- --timeout=2 http://backend:8080 > /dev/null 2>&1; then
    echo "   ✗ FAIL (should be blocked)"
else
    echo "   ✓ PASS (correctly blocked)"
fi

echo "5. Monitoring can reach Backend: "
if kubectl exec -n monitoring prometheus -- wget -O- --timeout=2 http://backend.lab-netpol.svc.cluster.local:8080 > /dev/null 2>&1; then
    echo "   ✓ PASS"
else
    echo "   ✗ FAIL"
fi

echo
echo "=== Test Complete ==="
EOF

chmod +x test-netpol.sh
./test-netpol.sh
```

Expected output: All tests pass.

## Challenge Questions

Test your understanding:

1. **What would happen if you removed the default-deny-ingress policy?**
   <details>
   <summary>Click to see answer</summary>
   All pods would be able to receive traffic from anywhere, as Kubernetes allows all traffic by default. However, the specific allow policies would still work (they would just be redundant).
   </details>

1. **Why is DNS access required in egress policies?**
   <details>
   <summary>Click to see answer</summary>
   Pods use DNS to resolve service names (like "backend") to IP addresses. Without DNS egress, pods cannot resolve names and communication fails even if the IP is allowed.
   </details>

1. **How would you allow frontend to access an external HTTPS API at api.example.com?**
   <details>
   <summary>Click to see answer</summary>

   ```yaml
   egress:
   - to:

     - ipBlock:
         cidr: 0.0.0.0/0  # Or specific IP of api.example.com
     ports:
     - protocol: TCP
       port: 443
   - to:  # Don't forget DNS
     - namespaceSelector:
         matchLabels:
           kubernetes.io/metadata.name: kube-system
       podSelector:
         matchLabels:
           k8s-app: kube-dns
     ports:
     - protocol: UDP
       port: 53

   ```

   </details>

1. **What's the difference between these two policies?**

   ```yaml
   # Policy A

   - from:

     - namespaceSelector:
         matchLabels:
           env: prod
       podSelector:
         matchLabels:
           app: frontend

   # Policy B

   - from:

     - namespaceSelector:
         matchLabels:
           env: prod
     - podSelector:
         matchLabels:
           app: frontend

   ```

   <details>
   <summary>Click to see answer</summary>

   Policy A uses AND logic: Traffic must come from pods labeled app=frontend in namespaces labeled env=prod.

   Policy B uses OR logic: Traffic can come from either (1) any pod in namespaces labeled env=prod, OR (2) pods labeled app=frontend in the same namespace.
   </details>

1. **How can you temporarily disable a NetworkPolicy without deleting it?**
   <details>
   <summary>Click to see answer</summary>
   You cannot disable a NetworkPolicy without deleting it. However, you can modify the podSelector to match no pods:

   ```yaml
   spec:
     podSelector:
       matchLabels:
         nonexistent: label
   ```

   Or simply delete and keep the YAML file for later reapplication.
   </details>

## Troubleshooting

### Issue: NetworkPolicy Not Taking Effect

**Symptoms**: Pods can still communicate after applying deny policy

**Solutions**:

1. Check if CNI supports NetworkPolicy:

   ```bash
   kubectl get pods -n kube-system | grep -E "calico|cilium|weave"

   ```

1. Verify NetworkPolicy exists:

   ```bash
   kubectl get networkpolicy -n lab-netpol

   ```

1. Check pod labels match selectors:

   ```bash
   kubectl get pods -n lab-netpol --show-labels

   ```

### Issue: DNS Resolution Failing

**Symptoms**: Connection timeouts, "bad address" errors

**Solutions**:

1. Ensure DNS egress is allowed:

   ```bash
   kubectl get networkpolicy allow-dns-egress -n lab-netpol -o yaml

   ```

1. Verify kube-dns labels:

   ```bash
   kubectl get pods -n kube-system -l k8s-app=kube-dns --show-labels

   ```

1. Test DNS directly:

   ```bash
   kubectl exec -n lab-netpol test-pod -- nslookup kubernetes.default

   ```

### Issue: Cross-Namespace Policy Not Working

**Symptoms**: Cannot access services from other namespaces

**Solutions**:

1. Verify namespace has required labels:

   ```bash
   kubectl get namespace monitoring --show-labels

   ```

1. Add labels if missing:

   ```bash
   kubectl label namespace monitoring name=monitoring

   ```

1. Check NetworkPolicy includes namespaceSelector:

   ```bash
   kubectl describe networkpolicy backend-allow-monitoring -n lab-netpol

   ```

## Cleanup

Remove all lab resources:

```bash
# Delete monitoring namespace

kubectl delete namespace monitoring

# Delete lab namespace (includes all resources)

kubectl delete namespace lab-netpol

# Remove test script

rm -f test-netpol.sh

# Reset default namespace

kubectl config set-context --current --namespace=default
```

Verify cleanup:

```bash
kubectl get namespaces | grep -E "lab-netpol|monitoring"
```

Expected output: No results

## Additional Challenges

### Challenge 1: Multi-Tier with Multiple Frontends

Deploy two frontend applications (web and mobile-api) that both need to access the backend, but shouldn't communicate with each other.

<details>
<summary>Click for solution</summary>

```yaml
# Both frontends can access backend

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-allow-frontends
spec:
  podSelector:
    matchLabels:
      tier: api
  ingress:
  - from:
    - podSelector:
        matchLabels:
          tier: frontend
---

# Prevent frontend-to-frontend

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-deny-other-frontends
spec:
  podSelector:
    matchLabels:
      tier: frontend
  ingress:
  - from:
    - podSelector:
        matchLabels:
          tier: external  # Only external traffic, not other frontends
```

</details>

### Challenge 2: Implement Zero-Trust Namespace

Create policies where every service must explicitly allow traffic - no default allows.

<details>
<summary>Click for solution</summary>

```yaml
# Start with deny all

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---

# Then add specific allows for each service
# (Use policies from earlier exercises)

```

</details>

## Key Takeaways

1. Default Kubernetes behavior allows all pod-to-pod communication
1. NetworkPolicies are additive - multiple policies combine
1. Empty podSelector ({}) applies to all pods in namespace
1. Must allow DNS in egress policies
1. Use labels for flexible, maintainable policies
1. Start with default deny, then allow specific traffic
1. Test policies thoroughly before production deployment
1. NetworkPolicies are namespace-scoped resources
1. Both ingress and egress should be controlled
1. Regular audits ensure policies remain effective

## Next Steps

1. Review [Network Policies concept documentation](../../../domains/01-cluster-setup/network-policies.md)
1. Practice creating policies from scratch
1. Proceed to [Lab 02: CIS Benchmarks](./lab-02-cis-benchmarks.md)

---

[← Back to Lab Overview](./README.md) | [Next Lab: CIS Benchmarks →](./lab-02-cis-benchmarks.md)
