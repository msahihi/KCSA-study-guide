# Lab 03: Ingress and TLS Security

## Objectives

By the end of this lab, you will be able to:

- Deploy and configure an Ingress controller
- Generate TLS certificates for HTTPS
- Create Kubernetes TLS secrets
- Configure Ingress resources with TLS termination
- Implement basic authentication on Ingress
- Configure rate limiting and IP whitelisting
- Add security headers to HTTP responses
- Test and troubleshoot Ingress configurations

## Prerequisites

- Kubernetes cluster v1.30+
- kubectl configured to access the cluster
- NGINX Ingress Controller installed (or ability to install it)
- openssl command-line tool
- curl or similar tool for testing
- Basic understanding of HTTP/HTTPS and TLS

## Estimated Time

60-90 minutes

## Lab Scenario

You're deploying a web application that needs to be accessible from the internet. Your requirements are:

1. Secure all traffic with HTTPS
1. Implement basic authentication for admin endpoints
1. Rate limit API requests to prevent abuse
1. Add security headers to protect against common web vulnerabilities
1. Restrict admin access to specific IP addresses

## Lab Environment Setup

### Step 1: Create Lab Namespace

```bash
kubectl create namespace lab-ingress
kubectl config set-context --current --namespace=lab-ingress
```

### Step 2: Install NGINX Ingress Controller (if not already installed)

Check if already installed:

```bash
kubectl get pods -n ingress-nginx
```

If not installed, install it:

**For cloud providers**:

```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.9.0/deploy/static/provider/cloud/deploy.yaml
```

**For kind or local clusters**:

```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.9.0/deploy/static/provider/kind/deploy.yaml
```

Wait for the controller to be ready:

```bash
kubectl wait --namespace ingress-nginx \
  --for=condition=ready pod \
  --selector=app.kubernetes.io/component=controller \
  --timeout=90s
```

Verify installation:

```bash
kubectl get pods -n ingress-nginx
kubectl get svc -n ingress-nginx
```

Expected output: Ingress controller pod running and service created.

### Step 3: Deploy Sample Applications

Create a file named `apps-deployment.yaml`:

```yaml
---

# Frontend Application

apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
  namespace: lab-ingress
spec:
  replicas: 2
  selector:
    matchLabels:
      app: frontend
  template:
    metadata:
      labels:
        app: frontend
    spec:
      containers:
      - name: nginx
        image: nginx:1.26
        ports:
        - containerPort: 80
        volumeMounts:
        - name: html
          mountPath: /usr/share/nginx/html
      volumes:
      - name: html
        configMap:
          name: frontend-html
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: frontend-html
  namespace: lab-ingress
data:
  index.html: |
    <!DOCTYPE html>
    <html>
    <head><title>Frontend</title></head>
    <body>
      <h1>Welcome to the Frontend!</h1>
      <p>This is a secure HTTPS application.</p>
    </body>
    </html>
---
apiVersion: v1
kind: Service
metadata:
  name: frontend
  namespace: lab-ingress
spec:
  selector:
    app: frontend
  ports:
  - port: 80
    targetPort: 80
---

# API Application

apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: lab-ingress
spec:
  replicas: 2
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
      - name: api
        image: hashicorp/http-echo:1.0
        args:
        - "-text=API Response: Hello from the API!"
        ports:
        - containerPort: 5678
---
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: lab-ingress
spec:
  selector:
    app: api
  ports:
  - port: 8080
    targetPort: 5678
---

# Admin Application

apiVersion: apps/v1
kind: Deployment
metadata:
  name: admin
  namespace: lab-ingress
spec:
  replicas: 1
  selector:
    matchLabels:
      app: admin
  template:
    metadata:
      labels:
        app: admin
    spec:
      containers:
      - name: admin
        image: hashicorp/http-echo:1.0
        args:
        - "-text=Admin Panel - Restricted Access"
        ports:
        - containerPort: 5678
---
apiVersion: v1
kind: Service
metadata:
  name: admin
  namespace: lab-ingress
spec:
  selector:
    app: admin
  ports:
  - port: 8080
    targetPort: 5678
```

Apply the deployment:

```bash
kubectl apply -f apps-deployment.yaml
```

Verify pods are running:

```bash
kubectl get pods -n lab-ingress
```

Expected output:

```
NAME                        READY   STATUS    RESTARTS   AGE
frontend-xxxxx-yyyyy        1/1     Running   0          30s
frontend-xxxxx-zzzzz        1/1     Running   0          30s
api-xxxxx-yyyyy             1/1     Running   0          30s
api-xxxxx-zzzzz             1/1     Running   0          30s
admin-xxxxx-yyyyy           1/1     Running   0          30s

```

## Exercise 1: Basic HTTP Ingress (Unsecured)

First, let's create a basic HTTP Ingress to understand the structure.

### Step 1: Create Basic Ingress

Create a file named `basic-ingress.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: basic-ingress
  namespace: lab-ingress
spec:
  ingressClassName: nginx
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend
            port:
              number: 80
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: api
            port:
              number: 8080
```

Apply the Ingress:

```bash
kubectl apply -f basic-ingress.yaml
```

Verify Ingress:

```bash
kubectl get ingress -n lab-ingress
kubectl describe ingress basic-ingress -n lab-ingress
```

### Step 2: Test HTTP Access

Get the Ingress IP/hostname:

```bash
kubectl get ingress basic-ingress -n lab-ingress
```

Test access (using curl with Host header):

**For LoadBalancer**:

```bash
INGRESS_IP=$(kubectl get ingress basic-ingress -n lab-ingress -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
echo $INGRESS_IP

# Test frontend

curl -H "Host: app.example.com" http://$INGRESS_IP/

# Test API

curl -H "Host: app.example.com" http://$INGRESS_IP/api
```

**For NodePort (kind/minikube)**:

```bash
# For kind

INGRESS_IP="localhost"

# For minikube

INGRESS_IP=$(minikube ip)

# Test

curl -H "Host: app.example.com" http://$INGRESS_IP/
curl -H "Host: app.example.com" http://$INGRESS_IP/api
```

Expected: Frontend HTML and API response visible.

**Problem**: Traffic is unencrypted! Let's fix that.

## Exercise 2: Generate TLS Certificates

### Step 1: Generate Self-Signed Certificate

For production, use Let's Encrypt or a trusted CA. For this lab, we'll create self-signed certificates.

```bash
# Generate private key

openssl genrsa -out tls.key 2048

# Generate certificate signing request

openssl req -new -key tls.key -out tls.csr -subj "/CN=app.example.com/O=MyOrg"

# Generate self-signed certificate (valid for 365 days)

openssl x509 -req -days 365 -in tls.csr -signkey tls.key -out tls.crt

# View certificate details

openssl x509 -in tls.crt -text -noout | head -20
```

### Step 2: Create Kubernetes TLS Secret

```bash
kubectl create secret tls app-tls \
  --cert=tls.crt \
  --key=tls.key \
  -n lab-ingress
```

Verify secret:

```bash
kubectl get secret app-tls -n lab-ingress
kubectl describe secret app-tls -n lab-ingress
```

View secret contents (base64 encoded):

```bash
kubectl get secret app-tls -n lab-ingress -o yaml
```

Decode certificate from secret:

```bash
kubectl get secret app-tls -n lab-ingress -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -text -noout | head -20
```

## Exercise 3: Configure HTTPS Ingress

### Step 1: Create TLS-Enabled Ingress

Create a file named `tls-ingress.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: tls-ingress
  namespace: lab-ingress
  annotations:

    # Force HTTPS redirect

    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"

    # Use strong TLS protocols

    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - app.example.com
    secretName: app-tls
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend
            port:
              number: 80
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: api
            port:
              number: 8080
```

Delete the old HTTP-only Ingress and apply TLS version:

```bash
kubectl delete ingress basic-ingress -n lab-ingress
kubectl apply -f tls-ingress.yaml
```

### Step 2: Test HTTPS Access

```bash
# Test HTTPS (using -k to ignore self-signed certificate warning)

curl -k -H "Host: app.example.com" https://$INGRESS_IP/

# Test frontend

curl -k -H "Host: app.example.com" https://$INGRESS_IP/

# Test API

curl -k -H "Host: app.example.com" https://$INGRESS_IP/api

# Verify HTTP redirects to HTTPS

curl -v -H "Host: app.example.com" http://$INGRESS_IP/
```

Expected:

- HTTPS requests succeed
- HTTP requests get 308 redirect to HTTPS

### Step 3: Verify TLS Configuration

```bash
# Check certificate details

echo | openssl s_client -connect ${INGRESS_IP}:443 -servername app.example.com 2>/dev/null | openssl x509 -noout -text | head -20

# Check TLS protocols

nmap --script ssl-enum-ciphers -p 443 $INGRESS_IP
```

## Exercise 4: Add Security Headers

Security headers protect against common web vulnerabilities.

### Step 1: Create Ingress with Security Headers

Create a file named `secure-ingress.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: secure-ingress
  namespace: lab-ingress
  annotations:

    # TLS settings

    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"

    # Security headers

    nginx.ingress.kubernetes.io/configuration-snippet: |
      more_set_headers "X-Frame-Options: DENY";
      more_set_headers "X-Content-Type-Options: nosniff";
      more_set_headers "X-XSS-Protection: 1; mode=block";
      more_set_headers "Strict-Transport-Security: max-age=31536000; includeSubDomains";
      more_set_headers "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'";
      more_set_headers "Referrer-Policy: strict-origin-when-cross-origin";
      more_set_headers "Permissions-Policy: geolocation=(), microphone=(), camera=()";
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - app.example.com
    secretName: app-tls
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend
            port:
              number: 80
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: api
            port:
              number: 8080
```

Apply the updated Ingress:

```bash
kubectl delete ingress tls-ingress -n lab-ingress
kubectl apply -f secure-ingress.yaml
```

### Step 2: Verify Security Headers

```bash
curl -k -I -H "Host: app.example.com" https://$INGRESS_IP/
```

Expected output includes:

```
HTTP/1.1 200 OK
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'
Referrer-Policy: strict-origin-when-cross-origin

```

## Exercise 5: Implement Basic Authentication

Protect admin endpoints with username/password authentication.

### Step 1: Create Basic Auth Credentials

```bash
# Install htpasswd (if not available)
# For Ubuntu/Debian: sudo apt-get install apache2-utils
# For Mac: brew install httpd
# For RHEL/CentOS: sudo yum install httpd-tools

# Create auth file with user "admin"

htpasswd -c auth admin

# Enter password when prompted (use: admin123)

# View the file

cat auth
```

Expected output: `admin:$apr1$...` (encrypted password)

### Step 2: Create Kubernetes Secret for Auth

```bash
kubectl create secret generic admin-auth \
  --from-file=auth \
  -n lab-ingress
```

Verify:

```bash
kubectl get secret admin-auth -n lab-ingress
kubectl describe secret admin-auth -n lab-ingress
```

### Step 3: Create Ingress with Authentication for Admin Path

Create a file named `auth-ingress.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: public-ingress
  namespace: lab-ingress
  annotations:
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - app.example.com
    secretName: app-tls
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend
            port:
              number: 80
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: api
            port:
              number: 8080
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: admin-ingress
  namespace: lab-ingress
  annotations:
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"

    # Basic Authentication

    nginx.ingress.kubernetes.io/auth-type: basic
    nginx.ingress.kubernetes.io/auth-secret: admin-auth
    nginx.ingress.kubernetes.io/auth-realm: 'Authentication Required - Admin Area'
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - app.example.com
    secretName: app-tls
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /admin
        pathType: Prefix
        backend:
          service:
            name: admin
            port:
              number: 8080
```

Apply the configuration:

```bash
kubectl delete ingress secure-ingress -n lab-ingress
kubectl apply -f auth-ingress.yaml
```

### Step 4: Test Authentication

```bash
# Try accessing admin without credentials (should fail with 401)

curl -k -H "Host: app.example.com" https://$INGRESS_IP/admin

# Access with credentials (should succeed)

curl -k -u admin:admin123 -H "Host: app.example.com" https://$INGRESS_IP/admin

# Public paths should work without authentication

curl -k -H "Host: app.example.com" https://$INGRESS_IP/
curl -k -H "Host: app.example.com" https://$INGRESS_IP/api
```

Expected:

- `/admin` without credentials: 401 Unauthorized
- `/admin` with credentials: "Admin Panel - Restricted Access"
- `/` and `/api`: Accessible without authentication

## Exercise 6: Implement Rate Limiting

Protect your API from abuse with rate limiting.

### Step 1: Create Ingress with Rate Limiting

Create a file named `ratelimit-ingress.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-ratelimit-ingress
  namespace: lab-ingress
  annotations:
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"

    # Rate limiting (10 requests per second per IP)

    nginx.ingress.kubernetes.io/limit-rps: "10"

    # Connection limit (5 concurrent connections per IP)

    nginx.ingress.kubernetes.io/limit-connections: "5"

    # Burst size (allow burst of 20 requests)

    nginx.ingress.kubernetes.io/limit-burst-multiplier: "2"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - app.example.com
    secretName: app-tls
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: api
            port:
              number: 8080
```

Apply:

```bash
kubectl apply -f ratelimit-ingress.yaml
```

### Step 2: Test Rate Limiting

```bash
# Make rapid requests (should eventually get 503)

for i in {1..30}; do
  curl -k -H "Host: app.example.com" -w "\nStatus: %{http_code}\n" https://$INGRESS_IP/api
  sleep 0.05
done
```

Expected: First ~10-20 requests succeed (200), then you'll see 503 Service Temporarily Unavailable.

## Exercise 7: IP Whitelisting

Restrict admin access to specific IP addresses.

### Step 1: Get Your Current IP

```bash
# Get your current public IP

MY_IP=$(curl -s ifconfig.me)
echo "My IP: $MY_IP"
```

### Step 2: Create Ingress with IP Whitelist

Update `auth-ingress.yaml` to add IP whitelisting:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: admin-ingress
  namespace: lab-ingress
  annotations:
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"
    nginx.ingress.kubernetes.io/auth-type: basic
    nginx.ingress.kubernetes.io/auth-secret: admin-auth
    nginx.ingress.kubernetes.io/auth-realm: 'Authentication Required - Admin Area'

    # IP Whitelist (replace with your IP or use 0.0.0.0/0 for testing)

    nginx.ingress.kubernetes.io/whitelist-source-range: "10.0.0.0/8,192.168.0.0/16"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - app.example.com
    secretName: app-tls
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /admin
        pathType: Prefix
        backend:
          service:
            name: admin
            port:
              number: 8080
```

Apply:

```bash
kubectl apply -f auth-ingress.yaml
```

### Step 3: Test IP Restriction

If your IP is not in the whitelist:

```bash
curl -k -u admin:admin123 -H "Host: app.example.com" https://$INGRESS_IP/admin
```

Expected: 403 Forbidden (if your IP is not whitelisted)

To test, temporarily allow all IPs:

```yaml
nginx.ingress.kubernetes.io/whitelist-source-range: "0.0.0.0/0"
```

## Exercise 8: Complete Production-Ready Configuration

Let's combine everything into a production-ready configuration.

### Step 1: Create Complete Ingress Configuration

Create a file named `production-ingress.yaml`:

```yaml
---

# Public Frontend and API

apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: public-ingress
  namespace: lab-ingress
  annotations:

    # TLS

    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"
    nginx.ingress.kubernetes.io/ssl-ciphers: "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384"

    # Rate limiting for API

    nginx.ingress.kubernetes.io/limit-rps: "100"
    nginx.ingress.kubernetes.io/limit-connections: "50"

    # Request size limits

    nginx.ingress.kubernetes.io/proxy-body-size: "10m"

    # Security headers

    nginx.ingress.kubernetes.io/configuration-snippet: |
      more_set_headers "X-Frame-Options: DENY";
      more_set_headers "X-Content-Type-Options: nosniff";
      more_set_headers "X-XSS-Protection: 1; mode=block";
      more_set_headers "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload";
      more_set_headers "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; frame-ancestors 'none'";
      more_set_headers "Referrer-Policy: strict-origin-when-cross-origin";
      more_set_headers "Permissions-Policy: geolocation=(), microphone=(), camera=()";
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - app.example.com
    secretName: app-tls
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend
            port:
              number: 80
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: api
            port:
              number: 8080
---

# Protected Admin Area

apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: admin-ingress
  namespace: lab-ingress
  annotations:

    # TLS

    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"

    # Authentication

    nginx.ingress.kubernetes.io/auth-type: basic
    nginx.ingress.kubernetes.io/auth-secret: admin-auth
    nginx.ingress.kubernetes.io/auth-realm: 'Admin Access Required'

    # IP Whitelist (for production, use specific IPs)

    nginx.ingress.kubernetes.io/whitelist-source-range: "0.0.0.0/0"

    # Stricter rate limiting

    nginx.ingress.kubernetes.io/limit-rps: "10"
    nginx.ingress.kubernetes.io/limit-connections: "5"

    # Security headers

    nginx.ingress.kubernetes.io/configuration-snippet: |
      more_set_headers "X-Frame-Options: DENY";
      more_set_headers "X-Content-Type-Options: nosniff";
      more_set_headers "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload";
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - app.example.com
    secretName: app-tls
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /admin
        pathType: Prefix
        backend:
          service:
            name: admin
            port:
              number: 8080
```

Apply the complete configuration:

```bash
kubectl delete ingress --all -n lab-ingress
kubectl apply -f production-ingress.yaml
```

### Step 2: Comprehensive Testing

Create a test script:

```bash
cat > test-ingress.sh << 'EOF'

#!/bin/bash

INGRESS_IP=${1:-localhost}
HOST="app.example.com"

echo "=== Ingress Security Test Suite ==="
echo "Testing against: $INGRESS_IP"
echo

echo "1. HTTP to HTTPS Redirect:"
REDIRECT=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST" http://$INGRESS_IP/)
if [ "$REDIRECT" = "308" ] || [ "$REDIRECT" = "301" ]; then
    echo "   ✓ PASS - HTTP redirects to HTTPS (${REDIRECT})"
else
    echo "   ✗ FAIL - Expected redirect, got ${REDIRECT}"
fi

echo "2. HTTPS Frontend Access:"
STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" -H "Host: $HOST" https://$INGRESS_IP/)
if [ "$STATUS" = "200" ]; then
    echo "   ✓ PASS - Frontend accessible via HTTPS"
else
    echo "   ✗ FAIL - Expected 200, got ${STATUS}"
fi

echo "3. API Access:"
STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" -H "Host: $HOST" https://$INGRESS_IP/api)
if [ "$STATUS" = "200" ]; then
    echo "   ✓ PASS - API accessible"
else
    echo "   ✗ FAIL - Expected 200, got ${STATUS}"
fi

echo "4. Admin Without Auth:"
STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" -H "Host: $HOST" https://$INGRESS_IP/admin)
if [ "$STATUS" = "401" ]; then
    echo "   ✓ PASS - Admin requires authentication (401)"
else
    echo "   ✗ FAIL - Expected 401, got ${STATUS}"
fi

echo "5. Admin With Auth:"
STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" -u admin:admin123 -H "Host: $HOST" https://$INGRESS_IP/admin)
if [ "$STATUS" = "200" ]; then
    echo "   ✓ PASS - Admin accessible with credentials"
else
    echo "   ✗ FAIL - Expected 200, got ${STATUS}"
fi

echo "6. Security Headers:"
HEADERS=$(curl -k -s -I -H "Host: $HOST" https://$INGRESS_IP/ | grep -i "x-frame-options\|x-content-type-options\|strict-transport-security" | wc -l)
if [ "$HEADERS" -ge 3 ]; then
    echo "   ✓ PASS - Security headers present"
else
    echo "   ✗ FAIL - Missing security headers"
fi

echo "7. Rate Limiting (Making 30 rapid requests):"
RATE_LIMITED=0
for i in {1..30}; do
    STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" -H "Host: $HOST" https://$INGRESS_IP/api)
    if [ "$STATUS" = "503" ]; then
        RATE_LIMITED=1
        break
    fi
    sleep 0.05
done
if [ "$RATE_LIMITED" = "1" ]; then
    echo "   ✓ PASS - Rate limiting is active"
else
    echo "   ⚠ WARNING - Rate limiting may not be configured or limit not reached"
fi

echo
echo "=== Test Complete ==="
EOF

chmod +x test-ingress.sh
./test-ingress.sh $INGRESS_IP
```

## Verification and Troubleshooting

### View Ingress Configuration

```bash
# List all Ingress resources

kubectl get ingress -n lab-ingress

# Describe Ingress

kubectl describe ingress public-ingress -n lab-ingress
kubectl describe ingress admin-ingress -n lab-ingress

# View Ingress YAML

kubectl get ingress public-ingress -n lab-ingress -o yaml
```

### Check Ingress Controller Logs

```bash
# Get controller pod name

CONTROLLER_POD=$(kubectl get pods -n ingress-nginx -l app.kubernetes.io/component=controller -o jsonpath='{.items[0].metadata.name}')

# View logs

kubectl logs -n ingress-nginx $CONTROLLER_POD --tail=50

# Follow logs

kubectl logs -n ingress-nginx $CONTROLLER_POD -f
```

### Test TLS Certificate

```bash
# View certificate details

echo | openssl s_client -connect ${INGRESS_IP}:443 -servername app.example.com 2>/dev/null | openssl x509 -noout -dates -subject -issuer

# Test TLS handshake

openssl s_client -connect ${INGRESS_IP}:443 -servername app.example.com < /dev/null
```

## Challenge Questions

1. **What's the difference between `pathType: Prefix` and `pathType: Exact`?**
   <details>
   <summary>Click to see answer</summary>

   - `Prefix`: Matches URL paths based on prefix splitting by `/`. For example, `/api` matches `/api`, `/api/users`, `/api/users/123`
   - `Exact`: Matches the exact path only. `/api` matches only `/api`, not `/api/users`
   </details>

1. **Why is it important to use `force-ssl-redirect`?**
   <details>
   <summary>Click to see answer</summary>

   Without it, users might access your site over HTTP, sending data unencrypted. The redirect ensures all traffic uses HTTPS, protecting sensitive information in transit. It also helps prevent SSL stripping attacks.
   </details>

1. **Can you have multiple TLS certificates for different hosts in one Ingress?**
   <details>
   <summary>Click to see answer</summary>

   Yes! You can specify multiple entries in the `tls` section:

   ```yaml
   tls:
   - hosts:

     - app1.example.com
     secretName: app1-tls
   - hosts:

     - app2.example.com
     secretName: app2-tls

   ```

   </details>

1. **What happens if you don't specify `ingressClassName`?**
   <details>
   <summary>Click to see answer</summary>

   In Kubernetes 1.18+, if you don't specify `ingressClassName` and have multiple Ingress controllers, the behavior depends on whether there's a default IngressClass. It's best practice to always specify it explicitly.
   </details>

1. **How does rate limiting work at the Ingress level vs application level?**
   <details>
   <summary>Click to see answer</summary>

   - **Ingress-level**: Protects infrastructure from DDoS, reduces load on backend services, works across all applications
   - **Application-level**: More granular control (per user, per API key), can implement business logic, but doesn't protect infrastructure from traffic spikes

   Best practice: Implement both layers.
   </details>

## Troubleshooting Common Issues

### Issue: 404 Not Found

**Symptoms**: Ingress exists but returns 404

**Solutions**:

1. Check service exists and has endpoints:

   ```bash
   kubectl get svc -n lab-ingress
   kubectl get endpoints -n lab-ingress

   ```

1. Verify Ingress path matches your request:

   ```bash
   kubectl get ingress -n lab-ingress -o yaml | grep path

   ```

1. Check Ingress controller logs for errors

### Issue: Certificate Not Trusted

**Symptoms**: Browser shows certificate error

**Solutions**:

1. Expected for self-signed certificates (use `-k` with curl)
1. For production, use Let's Encrypt or a trusted CA
1. Verify secret contains valid cert/key:

   ```bash
   kubectl get secret app-tls -n lab-ingress -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -text

   ```

### Issue: Authentication Not Working

**Symptoms**: Can access protected paths without credentials

**Solutions**:

1. Verify secret exists:

   ```bash
   kubectl get secret admin-auth -n lab-ingress

   ```

1. Check Ingress annotations:

   ```bash
   kubectl get ingress admin-ingress -n lab-ingress -o yaml | grep auth

   ```

1. Test with verbose curl:

   ```bash
   curl -v -k -H "Host: app.example.com" https://$INGRESS_IP/admin

   ```

## Cleanup

```bash
# Delete all Ingress resources

kubectl delete ingress --all -n lab-ingress

# Delete secrets

kubectl delete secret app-tls admin-auth -n lab-ingress

# Delete applications

kubectl delete -f apps-deployment.yaml

# Delete namespace

kubectl delete namespace lab-ingress

# Remove local files

rm -f *.yaml
rm -f tls.key tls.crt tls.csr auth
rm -f test-ingress.sh

# Reset context

kubectl config set-context --current --namespace=default
```

## Key Takeaways

1. Always use TLS for production applications
1. Use strong TLS protocols (TLSv1.2, TLSv1.3 only)
1. Security headers protect against common web vulnerabilities
1. Rate limiting prevents abuse and DDoS attacks
1. Basic authentication is simple but should be combined with other security measures
1. IP whitelisting adds an extra layer for sensitive endpoints
1. Multiple Ingress resources can reference the same host with different paths
1. Test thoroughly after configuration changes
1. Monitor Ingress controller logs for issues
1. Use cert-manager for automated certificate management in production

## Next Steps

1. Review [Ingress Security concept documentation](../../../domains/01-cluster-setup/ingress-service-security.md)
1. Learn about [cert-manager](https://cert-manager.io/) for automated certificate management
1. Proceed to [Lab 04: Pod Security Standards](./lab-04-pod-security-standards.md)

---

[← Previous Lab: CIS Benchmarks](./lab-02-cis-benchmarks.md) | [Back to Lab Overview](./README.md) | [Next Lab: Pod Security Standards →](./lab-04-pod-security-standards.md)
