# Secrets Management

## Overview

Secrets management in Kubernetes is critical for protecting sensitive information such as passwords, API keys, tokens, certificates, and other confidential data. This guide covers Kubernetes native Secrets, encryption at rest, external secrets management, and best practices for securing sensitive data in your cluster.

## Table of Contents

1. [Understanding Kubernetes Secrets](#understanding-kubernetes-secrets)
2. [Encryption at Rest](#encryption-at-rest)
3. [External Secrets Management](#external-secrets-management)
4. [Secrets Store CSI Driver](#secrets-store-csi-driver)
5. [RBAC for Secrets](#rbac-for-secrets)
6. [Best Practices](#best-practices)
7. [Common Pitfalls](#common-pitfalls)

## Understanding Kubernetes Secrets

### What are Kubernetes Secrets?

Kubernetes Secrets are objects that store sensitive information separately from Pod definitions or container images. Secrets reduce the risk of exposing confidential data in your application code.

### Types of Secrets

```yaml
# Opaque (generic) Secret - most common type
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
type: Opaque
data:
  username: YWRtaW4=        # base64 encoded
  password: cGFzc3dvcmQxMjM= # base64 encoded
```

**Secret Types:**
- `Opaque`: Default type for arbitrary user-defined data
- `kubernetes.io/service-account-token`: Service account token
- `kubernetes.io/dockercfg`: Serialized `~/.dockercfg` file
- `kubernetes.io/dockerconfigjson`: Serialized `~/.docker/config.json`
- `kubernetes.io/basic-auth`: Credentials for basic authentication
- `kubernetes.io/ssh-auth`: Credentials for SSH authentication
- `kubernetes.io/tls`: TLS certificate and key
- `bootstrap.kubernetes.io/token`: Bootstrap token data

### Creating Secrets

#### Method 1: From Literal Values

```bash
kubectl create secret generic my-app-secret \
  --from-literal=db-username=admin \
  --from-literal=db-password=supersecret123
```

#### Method 2: From Files

```bash
# Create files with secret data
echo -n 'admin' > ./username.txt
echo -n 'supersecret123' > ./password.txt

# Create Secret from files
kubectl create secret generic my-app-secret \
  --from-file=username=./username.txt \
  --from-file=password=./password.txt

# Clean up files
rm ./username.txt ./password.txt
```

#### Method 3: From YAML Manifest

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-app-secret
  namespace: default
type: Opaque
data:
  # Base64 encoded values
  username: YWRtaW4=
  password: c3VwZXJzZWNyZXQxMjM=
```

**Encoding values:**
```bash
echo -n 'admin' | base64
# Output: YWRtaW4=

echo -n 'supersecret123' | base64
# Output: c3VwZXJzZWNyZXQxMjM=
```

#### Method 4: Using stringData (No Base64 Required)

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-app-secret
type: Opaque
stringData:
  # Plain text - Kubernetes will base64 encode automatically
  username: admin
  password: supersecret123
```

### Using Secrets in Pods

#### As Environment Variables

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secret-env-pod
spec:
  containers:
  - name: myapp
    image: nginx:1.27
    env:
    - name: DB_USERNAME
      valueFrom:
        secretKeyRef:
          name: my-app-secret
          key: username
    - name: DB_PASSWORD
      valueFrom:
        secretKeyRef:
          name: my-app-secret
          key: password
```

#### As Volume Mounts (Recommended)

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secret-volume-pod
spec:
  containers:
  - name: myapp
    image: nginx:1.27
    volumeMounts:
    - name: secret-volume
      mountPath: /etc/secrets
      readOnly: true
  volumes:
  - name: secret-volume
    secret:
      secretName: my-app-secret
```

**Accessing mounted secrets:**
```bash
# Inside the container
cat /etc/secrets/username
# Output: admin

cat /etc/secrets/password
# Output: supersecret123
```

#### Mounting Specific Keys

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secret-specific-keys
spec:
  containers:
  - name: myapp
    image: nginx:1.27
    volumeMounts:
    - name: secret-volume
      mountPath: /etc/secrets
      readOnly: true
  volumes:
  - name: secret-volume
    secret:
      secretName: my-app-secret
      items:
      - key: username
        path: db-username
      - key: password
        path: db-password
        mode: 0400  # Set file permissions
```

### Viewing and Decoding Secrets

```bash
# List secrets
kubectl get secrets

# View secret details (data is still encoded)
kubectl get secret my-app-secret -o yaml

# Decode a specific key
kubectl get secret my-app-secret -o jsonpath='{.data.username}' | base64 -d
# Output: admin

# Decode all keys
kubectl get secret my-app-secret -o json | jq -r '.data | map_values(@base64d)'
```

## Encryption at Rest

By default, Kubernetes Secrets are stored in etcd as **base64-encoded** (NOT encrypted). Base64 is encoding, not encryption. Anyone with access to etcd can read all Secrets.

### Why Encryption at Rest?

- Protects against etcd database theft
- Prevents unauthorized access to backup data
- Meets compliance requirements (PCI-DSS, HIPAA, etc.)
- Defense in depth security practice

### Encryption Configuration

#### Step 1: Create Encryption Configuration File

```yaml
# /etc/kubernetes/enc/encryption-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <BASE64_ENCODED_32_BYTE_KEY>
      - identity: {}  # Fallback to plaintext (for reading old data)
```

#### Step 2: Generate Encryption Key

```bash
# Generate a random 32-byte key and base64 encode it
head -c 32 /dev/urandom | base64
# Example output: 8dRbG7xK2QmN5vP9wT3hU6eL1fJ4oS7aZ0kX8cY2bW9=
```

#### Step 3: Create Directory and File

```bash
# On the control plane node
sudo mkdir -p /etc/kubernetes/enc

# Create the configuration file with the generated key
sudo cat > /etc/kubernetes/enc/encryption-config.yaml <<EOF
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: 8dRbG7xK2QmN5vP9wT3hU6eL1fJ4oS7aZ0kX8cY2bW9=
      - identity: {}
EOF

# Secure the file
sudo chmod 600 /etc/kubernetes/enc/encryption-config.yaml
sudo chown root:root /etc/kubernetes/enc/encryption-config.yaml
```

#### Step 4: Configure kube-apiserver

Edit the kube-apiserver manifest:

```bash
sudo vi /etc/kubernetes/manifests/kube-apiserver.yaml
```

Add the following to the `kube-apiserver` container spec:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - command:
    - kube-apiserver
    # Add this flag
    - --encryption-provider-config=/etc/kubernetes/enc/encryption-config.yaml
    # ... other flags ...
    volumeMounts:
    # Add this volume mount
    - name: encryption-config
      mountPath: /etc/kubernetes/enc
      readOnly: true
    # ... other volume mounts ...
  volumes:
  # Add this volume
  - name: encryption-config
    hostPath:
      path: /etc/kubernetes/enc
      type: DirectoryOrCreate
  # ... other volumes ...
```

#### Step 5: Wait for kube-apiserver to Restart

```bash
# Watch for the kube-apiserver pod to restart
kubectl get pods -n kube-system -w | grep kube-apiserver

# Verify encryption is configured
kubectl get pod kube-apiserver-<node-name> -n kube-system -o yaml | grep encryption
```

#### Step 6: Encrypt Existing Secrets

```bash
# Re-encrypt all existing secrets
kubectl get secrets --all-namespaces -o json | kubectl replace -f -

# Verify a secret is encrypted in etcd
# (Requires access to etcd)
sudo ETCDCTL_API=3 etcdctl \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/default/my-app-secret

# Encrypted output will start with: k8s:enc:aescbc:v1:key1:...
```

### Encryption Providers

Kubernetes supports multiple encryption providers:

#### 1. AES-CBC (aescbc)
```yaml
providers:
  - aescbc:
      keys:
        - name: key1
          secret: <BASE64_32_BYTE_KEY>
```
- Symmetric encryption using AES in CBC mode
- Requires 32-byte key
- Good performance
- **Recommended for most use cases**

#### 2. AES-GCM (aesgcm)
```yaml
providers:
  - aesgcm:
      keys:
        - name: key1
          secret: <BASE64_32_BYTE_KEY>
```
- AES in GCM mode (authenticated encryption)
- Better security than CBC
- Slightly more CPU intensive
- Supported in Kubernetes 1.13+

#### 3. Secretbox
```yaml
providers:
  - secretbox:
      keys:
        - name: key1
          secret: <BASE64_32_BYTE_KEY>
```
- Uses XSalsa20 and Poly1305
- Fast and secure
- Requires 32-byte key

#### 4. KMS (Key Management Service)
```yaml
providers:
  - kms:
      name: myKmsPlugin
      endpoint: unix:///var/run/kmsplugin/socket.sock
      cachesize: 100
      timeout: 3s
```
- Integrates with external KMS (AWS KMS, Azure Key Vault, GCP KMS, HashiCorp Vault)
- Keys managed externally
- Better key rotation and audit capabilities
- **Recommended for production environments**

#### 5. Identity (No Encryption)
```yaml
providers:
  - identity: {}
```
- No encryption (plaintext)
- Used as fallback for reading old data during migration

### Key Rotation

#### Step 1: Add New Key at the Beginning

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key2  # New key first
              secret: <NEW_BASE64_32_BYTE_KEY>
            - name: key1  # Old key second
              secret: <OLD_BASE64_32_BYTE_KEY>
      - identity: {}
```

#### Step 2: Restart kube-apiserver

```bash
# Update the encryption config file
sudo vi /etc/kubernetes/enc/encryption-config.yaml

# kube-apiserver will automatically restart (static pod)
# Wait for restart
kubectl get pods -n kube-system -w | grep kube-apiserver
```

#### Step 3: Re-encrypt All Secrets with New Key

```bash
kubectl get secrets --all-namespaces -o json | kubectl replace -f -
```

#### Step 4: Remove Old Key (After Verification)

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key2  # Only new key
              secret: <NEW_BASE64_32_BYTE_KEY>
      - identity: {}
```

## External Secrets Management

### Why External Secrets?

- Centralized secrets management across multiple clusters
- Better audit logging and access control
- Automatic secrets rotation
- Integration with existing enterprise tools
- Compliance and governance requirements

### Popular External Secrets Solutions

1. **HashiCorp Vault**
2. **AWS Secrets Manager**
3. **Azure Key Vault**
4. **Google Secret Manager**
5. **External Secrets Operator** (bridges Kubernetes with external systems)

### External Secrets Operator

The External Secrets Operator extends Kubernetes with Custom Resources for syncing secrets from external sources.

#### Installation

```bash
# Add Helm repository
helm repo add external-secrets https://charts.external-secrets.io
helm repo update

# Install External Secrets Operator
helm install external-secrets \
  external-secrets/external-secrets \
  -n external-secrets-system \
  --create-namespace
```

#### AWS Secrets Manager Example

```yaml
# SecretStore - Defines connection to AWS Secrets Manager
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: aws-secret-store
  namespace: default
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-west-2
      auth:
        jwt:
          serviceAccountRef:
            name: external-secrets-sa

---
# ExternalSecret - Syncs specific secret from AWS
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: my-app-external-secret
  namespace: default
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secret-store
    kind: SecretStore
  target:
    name: my-app-secret  # Kubernetes Secret name
    creationPolicy: Owner
  data:
  - secretKey: username
    remoteRef:
      key: prod/myapp/db-credentials
      property: username
  - secretKey: password
    remoteRef:
      key: prod/myapp/db-credentials
      property: password
```

#### HashiCorp Vault Example

```yaml
# SecretStore for Vault
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-secret-store
  namespace: default
spec:
  provider:
    vault:
      server: "https://vault.example.com:8200"
      path: "secret"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "my-app-role"
          serviceAccountRef:
            name: my-app-sa

---
# ExternalSecret for Vault
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: vault-external-secret
  namespace: default
spec:
  refreshInterval: 30m
  secretStoreRef:
    name: vault-secret-store
    kind: SecretStore
  target:
    name: app-credentials
  data:
  - secretKey: db-password
    remoteRef:
      key: secret/data/myapp/database
      property: password
```

## Secrets Store CSI Driver

The Secrets Store CSI Driver allows Kubernetes to mount secrets stored in external secret stores as volumes into pods.

### Architecture

```
Pod → CSI Driver → External Secret Store (Vault, AWS, Azure, GCP)
                ↓
            tmpfs Volume (in-memory)
```

### Installation

```bash
# Install Secrets Store CSI Driver
helm repo add secrets-store-csi-driver https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts
helm install csi-secrets-store \
  secrets-store-csi-driver/secrets-store-csi-driver \
  --namespace kube-system

# Install provider (example: AWS)
kubectl apply -f https://raw.githubusercontent.com/aws/secrets-store-csi-driver-provider-aws/main/deployment/aws-provider-installer.yaml
```

### Usage Example

```yaml
# SecretProviderClass - Defines how to fetch secrets
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: aws-secrets
  namespace: default
spec:
  provider: aws
  parameters:
    objects: |
      - objectName: "MySecret"
        objectType: "secretsmanager"
        jmesPath:
          - path: username
            objectAlias: dbUsername
          - path: password
            objectAlias: dbPassword

---
# Pod using CSI Driver
apiVersion: v1
kind: Pod
metadata:
  name: app-with-secrets
spec:
  serviceAccountName: my-app-sa
  containers:
  - name: myapp
    image: nginx:1.27
    volumeMounts:
    - name: secrets-store
      mountPath: "/mnt/secrets"
      readOnly: true
  volumes:
  - name: secrets-store
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: "aws-secrets"
```

### Syncing to Kubernetes Secrets

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: aws-secrets-sync
spec:
  provider: aws
  secretObjects:
  - secretName: my-k8s-secret
    type: Opaque
    data:
    - objectName: dbUsername
      key: username
    - objectName: dbPassword
      key: password
  parameters:
    objects: |
      - objectName: "MySecret"
        objectType: "secretsmanager"
        jmesPath:
          - path: username
            objectAlias: dbUsername
          - path: password
            objectAlias: dbPassword
```

## RBAC for Secrets

### Principle of Least Privilege

Grant minimum required permissions for accessing Secrets.

### Read-Only Access

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: default
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
  resourceNames: ["my-app-secret"]  # Specific secrets only

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-secrets
  namespace: default
subjects:
- kind: ServiceAccount
  name: my-app-sa
  namespace: default
roleRef:
  kind: Role
  name: secret-reader
  apiGroup: rbac.authorization.k8s.io
```

### Full Access (Use Sparingly)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-admin
  namespace: default
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: secret-admin-binding
  namespace: default
subjects:
- kind: User
  name: admin-user
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: secret-admin
  apiGroup: rbac.authorization.k8s.io
```

### Deny Secrets Access

```yaml
# Use ClusterRole with no permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: no-secret-access
rules: []  # No rules = no permissions

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: deny-secrets
  namespace: default
subjects:
- kind: ServiceAccount
  name: untrusted-app
roleRef:
  kind: ClusterRole
  name: no-secret-access
  apiGroup: rbac.authorization.k8s.io
```

### Audit Secrets Access

```bash
# View who accessed secrets (requires audit logging)
kubectl get events --sort-by='.lastTimestamp' | grep -i secret

# Check RBAC permissions
kubectl auth can-i get secrets --as=system:serviceaccount:default:my-app-sa
kubectl auth can-i list secrets --as=system:serviceaccount:default:my-app-sa -n default
```

## Best Practices

### 1. Enable Encryption at Rest
Always encrypt Secrets in etcd, especially in production environments.

### 2. Use Volume Mounts Over Environment Variables
- Environment variables can be logged or exposed in process listings
- Volume mounts provide better isolation
- Environment variables are visible in Pod spec

### 3. Implement RBAC
- Grant minimum required permissions
- Use specific resourceNames when possible
- Regularly audit RBAC policies

### 4. Use External Secrets Management
- For production workloads, use external systems (Vault, AWS Secrets Manager)
- Enables centralized management and rotation
- Better audit logging

### 5. Rotate Secrets Regularly
- Implement automatic rotation policies
- Test rotation procedures
- Update encryption keys periodically

### 6. Never Commit Secrets to Git
```bash
# Use .gitignore
echo "secrets/" >> .gitignore
echo "*.key" >> .gitignore
echo "*.pem" >> .gitignore

# Use git-secrets tool to prevent commits
git secrets --install
git secrets --register-aws
```

### 7. Use Separate Secrets per Application
Don't create one large Secret for multiple applications.

### 8. Set Resource Quotas
```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: secret-quota
  namespace: default
spec:
  hard:
    secrets: "10"
```

### 9. Monitor Secret Access
Enable audit logging to track Secret access patterns.

### 10. Use Immutable Secrets (Kubernetes 1.21+)
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: immutable-secret
immutable: true
data:
  password: c3VwZXJzZWNyZXQ=
```

## Common Pitfalls

### 1. Base64 is Not Encryption
```bash
# Easily decoded
kubectl get secret my-secret -o jsonpath='{.data.password}' | base64 -d
```
**Solution:** Enable encryption at rest.

### 2. Secrets Visible in Pod Spec
```bash
# Environment variables are visible
kubectl get pod my-pod -o yaml
```
**Solution:** Use volume mounts and restrict RBAC.

### 3. Secrets in Container Images
Never bake secrets into container images.
**Solution:** Mount secrets at runtime.

### 4. Overly Permissive RBAC
```yaml
# BAD: Grants access to all secrets
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["*"]
```
**Solution:** Use specific resourceNames and verbs.

### 5. Forgotten Secrets
Old, unused secrets remain in the cluster.
**Solution:** Regular audits and cleanup.

### 6. Plain Text in Logs
```bash
# BAD: Logging secret values
echo "Password is: $DB_PASSWORD"
```
**Solution:** Never log secret values.

### 7. Shared Secrets Across Environments
Using same secrets for dev, staging, and production.
**Solution:** Separate secrets per environment.

## Verification and Testing

### Verify Encryption at Rest

```bash
# Create a test secret
kubectl create secret generic encryption-test --from-literal=key=value

# Check etcd (requires etcd access)
sudo ETCDCTL_API=3 etcdctl \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/default/encryption-test

# Encrypted output starts with: k8s:enc:aescbc:v1:key1:
# Unencrypted output starts with: k8s:\x00
```

### Test Secret Access

```bash
# Create test ServiceAccount
kubectl create serviceaccount test-sa

# Test access
kubectl auth can-i get secrets --as=system:serviceaccount:default:test-sa
# Output: no

# Grant access
kubectl create role secret-reader --verb=get --resource=secrets --resource-name=my-secret
kubectl create rolebinding test-binding --role=secret-reader --serviceaccount=default:test-sa

# Test again
kubectl auth can-i get secrets --as=system:serviceaccount:default:test-sa --resource-name=my-secret
# Output: yes
```

### Test Secret Mounting

```bash
# Create pod with secret
kubectl run test-pod --image=nginx:1.27 \
  --overrides='
{
  "spec": {
    "containers": [{
      "name": "nginx",
      "image": "nginx:1.27",
      "volumeMounts": [{
        "name": "secret-volume",
        "mountPath": "/etc/secrets"
      }]
    }],
    "volumes": [{
      "name": "secret-volume",
      "secret": {"secretName": "my-secret"}
    }]
  }
}'

# Verify mounting
kubectl exec test-pod -- ls /etc/secrets
kubectl exec test-pod -- cat /etc/secrets/username
```

## Summary

Secrets management in Kubernetes requires multiple layers of security:

1. **Encryption at Rest**: Protect secrets stored in etcd
2. **RBAC**: Control who can access secrets
3. **External Management**: Use dedicated secrets management tools for production
4. **Volume Mounts**: Prefer volumes over environment variables
5. **Rotation**: Regularly rotate secrets and encryption keys
6. **Audit**: Monitor and log secret access
7. **Best Practices**: Follow security guidelines and avoid common pitfalls

**Key Takeaways:**
- Kubernetes Secrets are base64-encoded by default, not encrypted
- Always enable encryption at rest in production
- Use external secrets management for enterprise workloads
- Implement strict RBAC for secret access
- Rotate secrets and keys regularly
- Never commit secrets to source control
- Prefer volume mounts over environment variables

## Additional Resources

- [Kubernetes Secrets Documentation](https://kubernetes.io/docs/concepts/configuration/secret/)
- [Encrypting Secret Data at Rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
- [External Secrets Operator](https://external-secrets.io/)
- [Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/)
- [HashiCorp Vault](https://www.vaultproject.io/)

---

[Back to Domain 4 README](./README.md) | [Next: Admission Controllers →](./admission-controllers.md)
