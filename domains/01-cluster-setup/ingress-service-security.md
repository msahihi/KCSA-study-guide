# Ingress and Service Security

## Overview

Ingress and Services are the primary ways external traffic enters your Kubernetes cluster. Securing these entry points is critical because they represent your cluster's attack surface. Properly configured Ingress and Service resources ensure that only legitimate traffic reaches your applications while maintaining encryption, authentication, and proper access controls.

Think of Ingress as the front door to your cluster and Services as the hallways connecting different rooms (pods). Just as you would secure a building's entrance with locks, cameras, and guards, you need to secure Ingress with TLS, authentication, and access controls.

## Understanding Services

Services provide network connectivity to a set of pods. There are several Service types, each with different security implications.

### Service Types

#### 1. ClusterIP (Default)
**Description**: Exposes the service on an internal IP within the cluster.

**Security Profile**: Most secure - only accessible within cluster.

**Use Case**: Backend services, databases, internal APIs.

**Example**:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: backend-service
  namespace: production
spec:
  type: ClusterIP
  selector:
    app: backend
  ports:
  - port: 8080
    targetPort: 8080
    protocol: TCP
```

**Security Best Practices**:
- Use for all internal communication
- Combine with NetworkPolicies for additional isolation
- No external exposure risk

#### 2. NodePort
**Description**: Exposes the service on each node's IP at a static port (30000-32767).

**Security Profile**: Medium risk - exposed on all nodes.

**Use Case**: Development, testing, or when LoadBalancer isn't available.

**Example**:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: frontend-nodeport
  namespace: production
spec:
  type: NodePort
  selector:
    app: frontend
  ports:
  - port: 80
    targetPort: 8080
    nodePort: 30080
    protocol: TCP
```

**Security Concerns**:
- Opens port on all nodes (even if pod isn't running there)
- Node IP addresses must be protected
- Bypasses Ingress security controls
- No built-in TLS termination

**Security Best Practices**:
- Restrict access with firewall rules
- Use only for non-production environments
- Prefer LoadBalancer or Ingress for production
- Implement NetworkPolicies to limit pod access

#### 3. LoadBalancer
**Description**: Exposes the service externally using a cloud provider's load balancer.

**Security Profile**: Medium-to-High risk - publicly exposed.

**Use Case**: Production external services, especially in cloud environments.

**Example**:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: frontend-lb
  namespace: production
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
    service.beta.kubernetes.io/aws-load-balancer-internal: "false"
spec:
  type: LoadBalancer
  selector:
    app: frontend
  ports:
  - port: 443
    targetPort: 8080
    protocol: TCP
```

**Security Best Practices**:
- Use annotations to configure cloud provider security features
- Enable TLS at the load balancer level
- Restrict source IP ranges when possible
- Use internal load balancers for private services
- Implement health checks
- Configure connection limits

**Cloud Provider Security Annotations**:

**AWS**:
```yaml
metadata:
  annotations:
    # Use Network Load Balancer (more secure than Classic)
    service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
    # Internal LB (not internet-facing)
    service.beta.kubernetes.io/aws-load-balancer-internal: "true"
    # Restrict to specific CIDR
    service.beta.kubernetes.io/load-balancer-source-ranges: "10.0.0.0/8"
    # Enable access logs
    service.beta.kubernetes.io/aws-load-balancer-access-log-enabled: "true"
```

**GCP**:
```yaml
metadata:
  annotations:
    # Internal LB
    cloud.google.com/load-balancer-type: "Internal"
    # Custom health check
    cloud.google.com/app-protocols: '{"https":"HTTPS"}'
```

**Azure**:
```yaml
metadata:
  annotations:
    # Internal LB
    service.beta.kubernetes.io/azure-load-balancer-internal: "true"
    # Restrict source IPs
    service.beta.kubernetes.io/load-balancer-source-ranges: "10.0.0.0/8"
```

#### 4. ExternalName
**Description**: Maps a service to a DNS name.

**Security Profile**: Low direct risk, but can be misused.

**Example**:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: external-api
  namespace: production
spec:
  type: ExternalName
  externalName: api.external-service.com
```

**Security Concerns**:
- Can bypass network policies
- No control over external endpoint security
- DNS spoofing risks
- No traffic encryption guarantee

**Security Best Practices**:
- Validate external endpoints
- Use only for trusted external services
- Document all ExternalName services
- Consider using egress gateways instead

### Service Source IP Preservation

**Problem**: By default, service traffic may lose source IP information.

**Solution**: Configure source IP preservation:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: frontend
spec:
  type: LoadBalancer
  externalTrafficPolicy: Local  # Preserves source IP
  selector:
    app: frontend
  ports:
  - port: 80
```

**Trade-offs**:
- `externalTrafficPolicy: Cluster` (default): Even load distribution, but loses source IP
- `externalTrafficPolicy: Local`: Preserves source IP, but uneven load distribution

## Understanding Ingress

Ingress provides HTTP/HTTPS routing to services based on rules. It's an abstraction layer that requires an Ingress Controller to function.

### Ingress Controllers

Popular Ingress Controllers include:
- **NGINX Ingress Controller**: Most widely used, feature-rich
- **Traefik**: Easy to use, automatic service discovery
- **HAProxy**: High performance, enterprise features
- **Contour**: Envoy-based, modern architecture
- **Cloud Provider Ingress**: AWS ALB, GCP Ingress, Azure Application Gateway

### Basic Ingress Resource

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: basic-ingress
  namespace: production
spec:
  ingressClassName: nginx
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend
            port:
              number: 80
```

### TLS Configuration

TLS (Transport Layer Security) encrypts traffic between clients and your cluster.

#### Creating TLS Certificates

**Option 1: Self-Signed Certificate (Development)**:
```bash
# Generate private key
openssl genrsa -out tls.key 2048

# Generate certificate
openssl req -new -x509 -key tls.key -out tls.crt -days 365 \
  -subj "/CN=example.com"

# Create Kubernetes secret
kubectl create secret tls example-tls \
  --cert=tls.crt \
  --key=tls.key \
  -n production
```

**Option 2: Let's Encrypt with cert-manager (Production)**:

1. **Install cert-manager**:
```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml
```

2. **Create ClusterIssuer**:
```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
```

3. **Use in Ingress**:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: secure-ingress
  namespace: production
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - example.com
    secretName: example-tls  # cert-manager creates this automatically
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend
            port:
              number: 80
```

#### TLS Best Practices

**1. Manual TLS Secret Creation**:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: example-tls
  namespace: production
type: kubernetes.io/tls
data:
  tls.crt: <base64-encoded-cert>
  tls.key: <base64-encoded-key>
```

**2. TLS Ingress Configuration**:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: tls-ingress
  namespace: production
  annotations:
    # Force HTTPS redirect
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    # TLS protocol version
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"
    # Strong cipher suites
    nginx.ingress.kubernetes.io/ssl-ciphers: "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - example.com
    - www.example.com
    secretName: example-tls
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend
            port:
              number: 80
```

**3. Multiple TLS Certificates**:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: multi-tls-ingress
  namespace: production
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - app1.example.com
    secretName: app1-tls
  - hosts:
    - app2.example.com
    secretName: app2-tls
  rules:
  - host: app1.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: app1
            port:
              number: 80
  - host: app2.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: app2
            port:
              number: 80
```

## Advanced Ingress Security

### 1. Basic Authentication

Protect applications with username/password authentication:

```bash
# Create auth file
htpasswd -c auth admin
# Enter password when prompted

# Create secret
kubectl create secret generic basic-auth \
  --from-file=auth \
  -n production
```

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: auth-ingress
  namespace: production
  annotations:
    nginx.ingress.kubernetes.io/auth-type: basic
    nginx.ingress.kubernetes.io/auth-secret: basic-auth
    nginx.ingress.kubernetes.io/auth-realm: 'Authentication Required'
spec:
  ingressClassName: nginx
  rules:
  - host: admin.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: admin-panel
            port:
              number: 80
```

### 2. IP Whitelisting

Restrict access to specific IP addresses or ranges:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: whitelist-ingress
  namespace: production
  annotations:
    nginx.ingress.kubernetes.io/whitelist-source-range: "10.0.0.0/8,192.168.1.0/24"
spec:
  ingressClassName: nginx
  rules:
  - host: internal.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: internal-app
            port:
              number: 80
```

### 3. Rate Limiting

Protect against DDoS and brute-force attacks:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ratelimit-ingress
  namespace: production
  annotations:
    # Limit to 10 requests per second per IP
    nginx.ingress.kubernetes.io/limit-rps: "10"
    # Limit to 100 connections per IP
    nginx.ingress.kubernetes.io/limit-connections: "100"
    # Burst size
    nginx.ingress.kubernetes.io/limit-burst-multiplier: "5"
spec:
  ingressClassName: nginx
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api
            port:
              number: 80
```

### 4. CORS Configuration

Control cross-origin resource sharing:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cors-ingress
  namespace: production
  annotations:
    nginx.ingress.kubernetes.io/enable-cors: "true"
    nginx.ingress.kubernetes.io/cors-allow-methods: "GET, POST, OPTIONS"
    nginx.ingress.kubernetes.io/cors-allow-origin: "https://trusted-site.com"
    nginx.ingress.kubernetes.io/cors-allow-credentials: "true"
spec:
  ingressClassName: nginx
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: api
            port:
              number: 80
```

### 5. OAuth/OIDC Authentication

Implement OAuth2 authentication using oauth2-proxy:

**Deploy oauth2-proxy**:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oauth2-proxy
  namespace: production
spec:
  replicas: 2
  selector:
    matchLabels:
      app: oauth2-proxy
  template:
    metadata:
      labels:
        app: oauth2-proxy
    spec:
      containers:
      - name: oauth2-proxy
        image: quay.io/oauth2-proxy/oauth2-proxy:v7.5.0
        args:
        - --provider=oidc
        - --email-domain=*
        - --upstream=file:///dev/null
        - --http-address=0.0.0.0:4180
        - --oidc-issuer-url=https://accounts.google.com
        env:
        - name: OAUTH2_PROXY_CLIENT_ID
          valueFrom:
            secretKeyRef:
              name: oauth2-proxy
              key: client-id
        - name: OAUTH2_PROXY_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: oauth2-proxy
              key: client-secret
        - name: OAUTH2_PROXY_COOKIE_SECRET
          valueFrom:
            secretKeyRef:
              name: oauth2-proxy
              key: cookie-secret
        ports:
        - containerPort: 4180
---
apiVersion: v1
kind: Service
metadata:
  name: oauth2-proxy
  namespace: production
spec:
  selector:
    app: oauth2-proxy
  ports:
  - port: 4180
    targetPort: 4180
```

**Configure Ingress with oauth2-proxy**:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: oauth-protected-ingress
  namespace: production
  annotations:
    nginx.ingress.kubernetes.io/auth-url: "https://oauth2-proxy.example.com/oauth2/auth"
    nginx.ingress.kubernetes.io/auth-signin: "https://oauth2-proxy.example.com/oauth2/start?rd=$scheme://$host$request_uri"
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
            name: protected-app
            port:
              number: 80
```

### 6. Request Size Limits

Protect against large payload attacks:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: size-limit-ingress
  namespace: production
  annotations:
    # Limit request body to 10MB
    nginx.ingress.kubernetes.io/proxy-body-size: "10m"
    # Client buffer size
    nginx.ingress.kubernetes.io/client-body-buffer-size: "1m"
spec:
  ingressClassName: nginx
  rules:
  - host: upload.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: upload-service
            port:
              number: 80
```

### 7. Custom Error Pages

Prevent information disclosure:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: custom-error-ingress
  namespace: production
  annotations:
    nginx.ingress.kubernetes.io/custom-http-errors: "404,503"
    nginx.ingress.kubernetes.io/default-backend: custom-error-pages
spec:
  ingressClassName: nginx
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend
            port:
              number: 80
```

### 8. Security Headers

Add security headers to responses:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: security-headers-ingress
  namespace: production
  annotations:
    nginx.ingress.kubernetes.io/configuration-snippet: |
      more_set_headers "X-Frame-Options: DENY";
      more_set_headers "X-Content-Type-Options: nosniff";
      more_set_headers "X-XSS-Protection: 1; mode=block";
      more_set_headers "Strict-Transport-Security: max-age=31536000; includeSubDomains";
      more_set_headers "Content-Security-Policy: default-src 'self'";
      more_set_headers "Referrer-Policy: strict-origin-when-cross-origin";
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - example.com
    secretName: example-tls
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend
            port:
              number: 80
```

## Backend Protocol Configuration

Secure communication between Ingress and backend services:

### HTTPS Backend

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: https-backend-ingress
  namespace: production
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
    # For self-signed certificates
    nginx.ingress.kubernetes.io/proxy-ssl-verify: "off"
    # For proper certificates
    # nginx.ingress.kubernetes.io/proxy-ssl-verify: "on"
    # nginx.ingress.kubernetes.io/proxy-ssl-secret: "production/backend-ca"
spec:
  ingressClassName: nginx
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: secure-backend
            port:
              number: 443
```

### gRPC Backend

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: grpc-ingress
  namespace: production
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: "GRPC"
spec:
  ingressClassName: nginx
  rules:
  - host: grpc.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: grpc-service
            port:
              number: 50051
```

## Path-Based Security

Apply different security policies to different paths:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: multi-path-ingress
  namespace: production
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - example.com
    secretName: example-tls
  rules:
  - host: example.com
    http:
      paths:
      # Public API - rate limited
      - path: /api/public
        pathType: Prefix
        backend:
          service:
            name: public-api
            port:
              number: 80
      # Admin API - IP restricted
      - path: /api/admin
        pathType: Prefix
        backend:
          service:
            name: admin-api
            port:
              number: 80
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: admin-path-security
  namespace: production
  annotations:
    nginx.ingress.kubernetes.io/whitelist-source-range: "10.0.0.0/8"
    nginx.ingress.kubernetes.io/auth-type: basic
    nginx.ingress.kubernetes.io/auth-secret: admin-auth
spec:
  ingressClassName: nginx
  rules:
  - host: example.com
    http:
      paths:
      - path: /api/admin
        pathType: Prefix
        backend:
          service:
            name: admin-api
            port:
              number: 80
```

## Service Mesh Integration

Service meshes provide advanced traffic management and security:

### Istio Example

**Enable mutual TLS**:
```yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: production
spec:
  mtls:
    mode: STRICT
```

**Authorization Policy**:
```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: frontend-policy
  namespace: production
spec:
  selector:
    matchLabels:
      app: frontend
  action: ALLOW
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/production/sa/backend"]
    to:
    - operation:
        methods: ["GET", "POST"]
```

## Monitoring and Logging

### Ingress Access Logs

Configure detailed access logging:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: nginx-configuration
  namespace: ingress-nginx
data:
  log-format-upstream: '{"time": "$time_iso8601", "remote_addr": "$remote_addr",
    "x_forwarded_for": "$proxy_add_x_forwarded_for", "request": "$request",
    "status": $status, "body_bytes_sent": $body_bytes_sent,
    "request_time": $request_time, "http_referrer": "$http_referer",
    "http_user_agent": "$http_user_agent"}'
```

### Monitoring Metrics

Key metrics to monitor:
- Request rate by status code
- Request latency
- Error rates (4xx, 5xx)
- Certificate expiration
- Rate limit violations
- Authentication failures

**Prometheus Integration**:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx-ingress-metrics
  namespace: ingress-nginx
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "10254"
spec:
  selector:
    app.kubernetes.io/name: ingress-nginx
  ports:
  - name: metrics
    port: 10254
```

## Common Security Patterns

### 1. Complete Production Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: production-ingress
  namespace: production
  annotations:
    # TLS
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"

    # Rate limiting
    nginx.ingress.kubernetes.io/limit-rps: "10"
    nginx.ingress.kubernetes.io/limit-connections: "100"

    # Security headers
    nginx.ingress.kubernetes.io/configuration-snippet: |
      more_set_headers "X-Frame-Options: DENY";
      more_set_headers "X-Content-Type-Options: nosniff";
      more_set_headers "X-XSS-Protection: 1; mode=block";
      more_set_headers "Strict-Transport-Security: max-age=31536000";

    # Request limits
    nginx.ingress.kubernetes.io/proxy-body-size: "10m"

    # CORS
    nginx.ingress.kubernetes.io/enable-cors: "true"
    nginx.ingress.kubernetes.io/cors-allow-origin: "https://app.example.com"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - api.example.com
    secretName: api-tls
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api
            port:
              number: 80
```

### 2. Internal Service (No External Access)

```yaml
apiVersion: v1
kind: Service
metadata:
  name: internal-database
  namespace: production
  annotations:
    # Ensure no external exposure
    service.kubernetes.io/topology-aware-hints: "auto"
spec:
  type: ClusterIP
  clusterIP: None  # Headless service
  selector:
    app: database
  ports:
  - port: 5432
    targetPort: 5432
```

### 3. Defense in Depth

Combine multiple security layers:

```yaml
# NetworkPolicy - Layer 1
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: frontend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
---
# Service - Layer 2
apiVersion: v1
kind: Service
metadata:
  name: frontend
  namespace: production
spec:
  type: ClusterIP
  selector:
    app: frontend
  ports:
  - port: 80
    targetPort: 8080
---
# Ingress - Layer 3
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: frontend-ingress
  namespace: production
  annotations:
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/limit-rps: "100"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - example.com
    secretName: example-tls
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend
            port:
              number: 80
```

## Best Practices

1. **Always Use TLS**: Never expose services without TLS in production.

2. **Automate Certificate Management**: Use cert-manager for automatic certificate renewal.

3. **Implement Rate Limiting**: Protect against DDoS and abuse.

4. **Add Security Headers**: Protect against common web vulnerabilities.

5. **Use ClusterIP by Default**: Only expose services externally when necessary.

6. **Restrict IP Ranges**: Use whitelisting for administrative interfaces.

7. **Enable Access Logging**: Monitor all incoming requests.

8. **Implement Authentication**: Don't rely solely on network controls.

9. **Regular Security Audits**: Review Ingress and Service configurations regularly.

10. **Use Service Mesh for Advanced Scenarios**: Consider Istio or Linkerd for complex security requirements.

## Common Pitfalls

### 1. Exposing Services Unnecessarily

**Problem**: Using LoadBalancer or NodePort when ClusterIP would suffice.

**Solution**: Default to ClusterIP and use Ingress for HTTP/HTTPS traffic.

### 2. Missing TLS Configuration

**Problem**: Services exposed without encryption.

**Solution**: Always configure TLS for external services.

### 3. Weak TLS Configuration

**Problem**: Allowing old TLS versions or weak ciphers.

**Solution**: Explicitly configure strong TLS:
```yaml
nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"
```

### 4. No Rate Limiting

**Problem**: Services vulnerable to DDoS.

**Solution**: Always implement rate limiting on public endpoints.

### 5. Exposing Internal Ports

**Problem**: Exposing debug/metrics ports externally.

**Solution**: Use separate services for internal and external access.

## Key Points to Remember

1. Services provide network access to pods; Ingress provides HTTP(S) routing.
2. ClusterIP is the most secure service type (internal only).
3. Always use TLS for external services.
4. Automate certificate management with cert-manager.
5. Implement rate limiting on all public endpoints.
6. Add security headers to protect against web vulnerabilities.
7. Use IP whitelisting for administrative interfaces.
8. Combine Ingress security with NetworkPolicies for defense in depth.
9. Monitor and log all incoming traffic.
10. Service meshes provide advanced security features for complex environments.

## Study Resources

### Official Documentation
- [Kubernetes Services](https://kubernetes.io/docs/concepts/services-networking/service/)
- [Kubernetes Ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/)
- [NGINX Ingress Controller](https://kubernetes.github.io/ingress-nginx/)
- [cert-manager](https://cert-manager.io/)

### Tools
- [cert-manager](https://cert-manager.io/)
- [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/)
- [NGINX Ingress Controller](https://kubernetes.github.io/ingress-nginx/)

### Additional Reading
- [TLS Best Practices](https://wiki.mozilla.org/Security/Server_Side_TLS)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)

## Next Steps

1. Complete the [Ingress Security Lab](../../labs/01-cluster-setup/lab-03-ingress-security.md)
2. Practice configuring TLS certificates
3. Experiment with different Ingress annotations
4. Learn about [Pod Security Standards](./pod-security-standards.md) next

## Quick Reference

### Common Commands

```bash
# Services
kubectl get services -n <namespace>
kubectl describe service <name> -n <namespace>
kubectl expose deployment <name> --port=80 --type=ClusterIP

# Ingress
kubectl get ingress -n <namespace>
kubectl describe ingress <name> -n <namespace>

# TLS Secrets
kubectl create secret tls <name> --cert=cert.crt --key=cert.key -n <namespace>
kubectl get secret <name> -n <namespace> -o yaml

# Testing
curl -v https://example.com
curl -H "Host: example.com" http://<ingress-ip>
```

### Common Annotations (NGINX Ingress)

```yaml
# TLS
nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"

# Rate Limiting
nginx.ingress.kubernetes.io/limit-rps: "10"
nginx.ingress.kubernetes.io/limit-connections: "100"

# Authentication
nginx.ingress.kubernetes.io/auth-type: basic
nginx.ingress.kubernetes.io/auth-secret: auth-secret

# IP Whitelisting
nginx.ingress.kubernetes.io/whitelist-source-range: "10.0.0.0/8"

# CORS
nginx.ingress.kubernetes.io/enable-cors: "true"
nginx.ingress.kubernetes.io/cors-allow-origin: "https://example.com"

# Body Size
nginx.ingress.kubernetes.io/proxy-body-size: "10m"

# Backend Protocol
nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
```

---

[← Previous: CIS Benchmarks](./cis-benchmarks.md) | [Back to Domain 1 README](./README.md) | [Next: Pod Security Standards →](./pod-security-standards.md)
