# Lab 01 - Secrets Encryption at Rest

## Objective

Learn how to enable and configure encryption at rest for Kubernetes Secrets to protect sensitive data stored in etcd. This lab covers encryption configuration, key management, verification, and key rotation.

## Duration

45 minutes

## Prerequisites

- Kubernetes cluster v1.30.x with control plane access
- kubectl configured with admin privileges
- Access to control plane node(s) to modify kube-apiserver configuration
- Basic understanding of Kubernetes Secrets

**Note**: This lab requires control plane access. Use Kind, Minikube, or kubeadm-based clusters. Managed services (EKS, GKE, AKS) typically handle encryption automatically and don't expose control plane configuration.

## Lab Architecture

```
┌─────────────────────────────────────────────────────────┐
│                 kube-apiserver                          │
│                                                         │
│  ┌─────────────────────────────────────────────────┐  │
│  │   Encryption Provider Config                    │  │
│  │   - aescbc (key1)                               │  │
│  │   - identity (fallback)                         │  │
│  └─────────────────────────────────────────────────┘  │
│                        ↓                                │
│  ┌─────────────────────────────────────────────────┐  │
│  │         etcd (encrypted storage)                │  │
│  │   k8s:enc:aescbc:v1:key1:<encrypted-data>      │  │
│  └─────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Step 1: Initial Setup

### 1.1 Create Test Namespace

```bash
kubectl create namespace lab-secrets

# Verify
kubectl get namespace lab-secrets
```

### 1.2 Create Unencrypted Secret (for comparison)

```bash
# Create a secret before enabling encryption
kubectl create secret generic unencrypted-secret \
  --from-literal=username=admin \
  --from-literal=password=secretpassword123 \
  -n lab-secrets

# Verify secret creation
kubectl get secret unencrypted-secret -n lab-secrets
kubectl describe secret unencrypted-secret -n lab-secrets
```

### 1.3 Verify Secret is Not Encrypted

If you have access to etcd, verify the secret is stored in plaintext (base64 encoded):

```bash
# Access control plane node
# For Kind cluster:
docker exec -it kcsa-lab-control-plane bash

# Check etcd
ETCDCTL_API=3 etcdctl \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/lab-secrets/unencrypted-secret | hexdump -C

# Output should show readable text (not encrypted)
# Look for plaintext like "admin", "secretpassword123"
```

## Step 2: Generate Encryption Key

### 2.1 Generate Random Encryption Key

```bash
# Generate a 32-byte random key and base64 encode it
head -c 32 /dev/urandom | base64

# Example output (yours will be different):
# 8dRbG7xK2QmN5vP9wT3hU6eL1fJ4oS7aZ0kX8cY2bW9=
```

**Save this key securely!** You'll need it for the encryption configuration.

### 2.2 Store Key Securely

```bash
# In production, store this in a secure key management system
# For this lab, we'll store it in a variable
export ENCRYPTION_KEY="8dRbG7xK2QmN5vP9wT3hU6eL1fJ4oS7aZ0kX8cY2bW9="

# Verify
echo $ENCRYPTION_KEY
```

## Step 3: Create Encryption Configuration

### 3.1 Access Control Plane Node

```bash
# For Kind cluster
docker exec -it kcsa-lab-control-plane bash

# For Minikube
minikube ssh

# For kubeadm cluster
ssh user@control-plane-node
```

### 3.2 Create Encryption Config Directory

```bash
# On control plane node
sudo mkdir -p /etc/kubernetes/enc
```

### 3.3 Create Encryption Configuration File

```bash
# Create encryption configuration
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
              secret: ${ENCRYPTION_KEY}
      - identity: {}
EOF

# Verify file contents
sudo cat /etc/kubernetes/enc/encryption-config.yaml
```

**Configuration Explanation:**
- `resources: [secrets]`: Apply encryption to Secret objects
- `aescbc`: AES-CBC encryption provider
- `key1`: Key identifier for rotation
- `identity: {}`: Fallback for reading unencrypted data

### 3.4 Secure the Configuration File

```bash
# Set restrictive permissions
sudo chmod 600 /etc/kubernetes/enc/encryption-config.yaml
sudo chown root:root /etc/kubernetes/enc/encryption-config.yaml

# Verify permissions
ls -la /etc/kubernetes/enc/encryption-config.yaml
# Should show: -rw------- 1 root root
```

## Step 4: Configure kube-apiserver

### 4.1 Backup kube-apiserver Manifest

```bash
# Backup original manifest
sudo cp /etc/kubernetes/manifests/kube-apiserver.yaml \
     /etc/kubernetes/manifests/kube-apiserver.yaml.backup

# Verify backup
ls -la /etc/kubernetes/manifests/kube-apiserver.yaml.backup
```

### 4.2 Modify kube-apiserver Configuration

```bash
# Edit kube-apiserver manifest
sudo vi /etc/kubernetes/manifests/kube-apiserver.yaml
```

Add the following to the `kube-apiserver` container spec:

**Add to command array:**
```yaml
spec:
  containers:
  - command:
    - kube-apiserver
    # ... existing flags ...
    - --encryption-provider-config=/etc/kubernetes/enc/encryption-config.yaml
```

**Add to volumeMounts array:**
```yaml
    volumeMounts:
    # ... existing mounts ...
    - name: encryption-config
      mountPath: /etc/kubernetes/enc
      readOnly: true
```

**Add to volumes array:**
```yaml
  volumes:
  # ... existing volumes ...
  - name: encryption-config
    hostPath:
      path: /etc/kubernetes/enc
      type: DirectoryOrCreate
```

### 4.3 Complete Modified Manifest Example

Here's a complete example of the relevant sections:

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
    - --advertise-address=192.168.1.10
    - --allow-privileged=true
    # ... other existing flags ...
    - --encryption-provider-config=/etc/kubernetes/enc/encryption-config.yaml
    image: registry.k8s.io/kube-apiserver:v1.30.0
    name: kube-apiserver
    volumeMounts:
    - mountPath: /etc/kubernetes/pki
      name: k8s-certs
      readOnly: true
    - mountPath: /etc/ssl/certs
      name: ca-certs
      readOnly: true
    - mountPath: /etc/kubernetes/enc
      name: encryption-config
      readOnly: true
  volumes:
  - hostPath:
      path: /etc/kubernetes/pki
      type: DirectoryOrCreate
    name: k8s-certs
  - hostPath:
      path: /etc/ssl/certs
      type: DirectoryOrCreate
    name: ca-certs
  - hostPath:
      path: /etc/kubernetes/enc
      type: DirectoryOrCreate
    name: encryption-config
```

## Step 5: Wait for kube-apiserver to Restart

### 5.1 Monitor kube-apiserver Pod

```bash
# Exit from control plane node (if inside)
exit

# Watch for kube-apiserver pod restart
kubectl get pods -n kube-system -w | grep kube-apiserver

# Wait until STATUS is Running
```

### 5.2 Verify Encryption Flag

```bash
# Check if encryption flag is present
kubectl get pod kube-apiserver-<node-name> -n kube-system -o yaml | grep encryption-provider-config

# Output should show:
# - --encryption-provider-config=/etc/kubernetes/enc/encryption-config.yaml
```

### 5.3 Test API Server Connectivity

```bash
# Verify API server is responding
kubectl cluster-info
kubectl get nodes
kubectl get namespaces
```

## Step 6: Encrypt Existing Secrets

### 6.1 Re-encrypt All Existing Secrets

```bash
# Re-write all secrets to encrypt them with the new configuration
kubectl get secrets --all-namespaces -o json | kubectl replace -f -

# This command:
# 1. Gets all secrets from all namespaces
# 2. Pipes them to kubectl replace
# 3. Triggers re-encryption with the new provider
```

### 6.2 Verify Specific Secret Re-encryption

```bash
# Check if our test secret was re-encrypted
kubectl get secret unencrypted-secret -n lab-secrets -o yaml
```

## Step 7: Verify Encryption is Working

### 7.1 Create New Encrypted Secret

```bash
# Create a new secret (should be encrypted automatically)
kubectl create secret generic encrypted-secret \
  --from-literal=api-key=super-secret-key-456 \
  --from-literal=token=abc123xyz789 \
  -n lab-secrets

# Verify creation
kubectl get secret encrypted-secret -n lab-secrets
```

### 7.2 Verify in etcd (Direct Verification)

```bash
# Access control plane node
docker exec -it kcsa-lab-control-plane bash

# Check encrypted secret in etcd
ETCDCTL_API=3 etcdctl \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/lab-secrets/encrypted-secret | hexdump -C

# Encrypted output should start with:
# k8s:enc:aescbc:v1:key1:
# Followed by encrypted binary data (not readable)
```

### 7.3 Compare Encrypted vs Unencrypted

```bash
# Get both secrets from etcd
ETCDCTL_API=3 etcdctl \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/lab-secrets/ --prefix --keys-only

# Compare output:
# - encrypted-secret should show: k8s:enc:aescbc:v1:key1:...
# - unencrypted-secret (if not re-encrypted) should show readable data
```

## Step 8: Key Rotation

### 8.1 Generate New Encryption Key

```bash
# Generate a new key
NEW_KEY=$(head -c 32 /dev/urandom | base64)
echo "New Key: $NEW_KEY"

# Save for later use
export NEW_ENCRYPTION_KEY=$NEW_KEY
```

### 8.2 Update Encryption Configuration with New Key

```bash
# Access control plane node
docker exec -it kcsa-lab-control-plane bash

# Update encryption config with new key FIRST
sudo cat > /etc/kubernetes/enc/encryption-config.yaml <<EOF
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key2
              secret: ${NEW_ENCRYPTION_KEY}
            - name: key1
              secret: ${ENCRYPTION_KEY}
      - identity: {}
EOF

# Note: key2 is listed FIRST (used for new encryptions)
#       key1 is listed SECOND (used for decrypting old secrets)
```

### 8.3 Wait for kube-apiserver to Pick Up Changes

```bash
# Exit control plane node
exit

# Watch for config reload (may take a minute)
# API server watches the config file and reloads automatically
sleep 60

# Verify API server is still healthy
kubectl get nodes
```

### 8.4 Re-encrypt All Secrets with New Key

```bash
# Re-encrypt all secrets with key2
kubectl get secrets --all-namespaces -o json | kubectl replace -f -

# This rewrites all secrets using key2
```

### 8.5 Verify New Key is Used

```bash
# Create a test secret
kubectl create secret generic rotated-secret \
  --from-literal=test=rotated-value \
  -n lab-secrets

# Check in etcd
docker exec -it kcsa-lab-control-plane bash

ETCDCTL_API=3 etcdctl \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/lab-secrets/rotated-secret | hexdump -C

# Output should show: k8s:enc:aescbc:v1:key2:
# (note "key2" instead of "key1")
```

### 8.6 Remove Old Key (After Verification)

After confirming all secrets are encrypted with key2:

```bash
# Update encryption config to remove old key
sudo cat > /etc/kubernetes/enc/encryption-config.yaml <<EOF
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key2
              secret: ${NEW_ENCRYPTION_KEY}
      - identity: {}
EOF

# Exit and verify
exit
sleep 30
kubectl get secrets -n lab-secrets
```

## Step 9: Testing and Validation

### 9.1 Test Secret Creation

```bash
# Create multiple test secrets
for i in {1..5}; do
  kubectl create secret generic test-secret-$i \
    --from-literal=value=$i \
    -n lab-secrets
done

# Verify all created
kubectl get secrets -n lab-secrets
```

### 9.2 Test Secret Retrieval

```bash
# Retrieve and decode a secret
kubectl get secret encrypted-secret -n lab-secrets -o jsonpath='{.data.api-key}' | base64 -d
# Output: super-secret-key-456

# Verify decryption works correctly
kubectl get secret encrypted-secret -n lab-secrets -o yaml
```

### 9.3 Test RBAC with Encrypted Secrets

```bash
# Create ServiceAccount
kubectl create serviceaccount secret-reader -n lab-secrets

# Create Role (read-only access to secrets)
kubectl create role secret-reader \
  --verb=get,list \
  --resource=secrets \
  -n lab-secrets

# Create RoleBinding
kubectl create rolebinding secret-reader-binding \
  --role=secret-reader \
  --serviceaccount=lab-secrets:secret-reader \
  -n lab-secrets

# Test access as ServiceAccount
kubectl auth can-i get secrets \
  --as=system:serviceaccount:lab-secrets:secret-reader \
  -n lab-secrets
# Output: yes
```

## Step 10: Troubleshooting

### 10.1 API Server Won't Start

```bash
# Check API server logs
docker logs kcsa-lab-control-plane | grep apiserver

# Check for encryption config errors
docker exec -it kcsa-lab-control-plane bash
journalctl -u kubelet -n 100 | grep encryption

# Common issues:
# - Invalid base64 key (must be exactly 32 bytes base64-encoded)
# - Incorrect file path
# - File permissions too open
```

### 10.2 Verify Encryption Provider Configuration

```bash
# Check if file exists and is readable
docker exec -it kcsa-lab-control-plane ls -la /etc/kubernetes/enc/

# Validate YAML syntax
docker exec -it kcsa-lab-control-plane cat /etc/kubernetes/enc/encryption-config.yaml
```

### 10.3 Test Encryption Manually

```bash
# Create a test secret
kubectl create secret generic test-enc \
  --from-literal=test=value \
  -n lab-secrets

# Immediately check etcd
docker exec -it kcsa-lab-control-plane bash
ETCDCTL_API=3 etcdctl \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/lab-secrets/test-enc

# Should see: k8s:enc:aescbc:v1:key2:...
```

## Challenge Exercises

### Challenge 1: Multiple Resource Types

Extend encryption to ConfigMaps:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
      - configmaps
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <KEY>
      - identity: {}
```

### Challenge 2: KMS Provider

Research and configure a KMS provider (AWS KMS, Azure Key Vault, GCP KMS) instead of local keys.

### Challenge 3: Audit Logging

Enable audit logging to track Secret access:

```yaml
# kube-apiserver flag
- --audit-policy-file=/etc/kubernetes/audit-policy.yaml
- --audit-log-path=/var/log/kubernetes/audit.log
```

Create audit policy:
```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: RequestResponse
  verbs: ["get", "list", "watch"]
  resources:
  - group: ""
    resources: ["secrets"]
```

## Lab Summary

In this lab, you:
1. Created unencrypted Secrets and verified their storage format
2. Generated encryption keys
3. Configured encryption at rest for Secrets
4. Modified kube-apiserver to enable encryption
5. Encrypted existing Secrets
6. Verified encryption in etcd
7. Performed key rotation
8. Tested and validated the encryption setup

**Key Concepts:**
- Encryption at rest protects secrets stored in etcd
- AES-CBC is a common encryption provider
- Key rotation is essential for security
- Multiple keys can coexist during rotation
- Identity provider allows reading unencrypted data during migration

## Cleanup

### Remove Lab Resources

```bash
# Delete lab namespace
kubectl delete namespace lab-secrets

# (Optional) Restore original kube-apiserver config
docker exec -it kcsa-lab-control-plane bash
sudo mv /etc/kubernetes/manifests/kube-apiserver.yaml.backup \
     /etc/kubernetes/manifests/kube-apiserver.yaml
exit

# Wait for API server to restart
kubectl get pods -n kube-system -w | grep kube-apiserver
```

## Additional Resources

- [Kubernetes Encrypting Secret Data at Rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
- [Encryption Configuration API](https://kubernetes.io/docs/reference/config-api/apiserver-encryption.v1/)
- [KMS Encryption Provider](https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/)

---

[Back to Labs](./README.md) | [Next Lab: Admission Controllers →](./lab-02-admission-controllers.md)
