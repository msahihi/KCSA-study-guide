# Lab 03: Registry Security

## Objectives

By the end of this lab, you will be able to:

- Create and manage Kubernetes ImagePullSecrets
- Configure private registry authentication
- Attach secrets to ServiceAccounts
- Implement Docker Content Trust
- Configure cloud registry access (ECR, GCR, ACR)
- Troubleshoot image pull failures
- Implement registry admission policies

## Prerequisites

- Completed Labs 01 and 02
- kubectl configured
- Docker or Podman installed
- Access to at least one container registry
- Basic understanding of Kubernetes Secrets

## Estimated Time

90 minutes

## Lab Scenario

Your organization uses private container registries to store proprietary application images. You need to configure Kubernetes to authenticate with these registries, implement secure credential management, and enforce registry policies.

## Part 1: ImagePullSecrets Basics

### Exercise 1: Create ImagePullSecret from Credentials

Create a secret for Docker Hub:

```bash

# Create namespace

kubectl create namespace registry-lab
kubectl config set-context --current --namespace=registry-lab

# Create secret

kubectl create secret docker-registry dockerhub-secret \\
  --docker-server=https://index.docker.io/v1/ \\
  --docker-username=your-username \\
  --docker-password=your-password \\
  --docker-email=your-email@example.com
```

```

Verify the secret:

```bash

kubectl get secret dockerhub-secret
kubectl describe secret dockerhub-secret
```

```

View secret data:

```bash

kubectl get secret dockerhub-secret -o jsonpath='{.data.\\.dockerconfigjson}' | base64 -d | jq .
```

```

### Exercise 2: Create Secret from Docker Config

Login to registries first:

```bash

docker login

# Or specific registry

docker login myregistry.com
```

```

Create secret from existing Docker config:

```bash

kubectl create secret generic docker-config-secret \\
  --from-file=.dockerconfigjson=$HOME/.docker/config.json \\
  --type=kubernetes.io/dockerconfigjson
```

```

### Exercise 3: Create Secret from YAML

Create a manual secret:

```bash

# Encode credentials

AUTH=$(echo -n 'username:password' | base64)

cat > registry-secret.yaml <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: manual-registry-secret
  namespace: registry-lab
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: $(echo -n "{\"auths\":{\"myregistry.com\":{\"auth\":\"${AUTH}\"}}}" | base64 -w0)
EOF

kubectl apply -f registry-secret.yaml
```

```

## Part 2: Using ImagePullSecrets

### Exercise 4: Use Secret in Pod Spec

Create a deployment with ImagePullSecret:

```bash

cat > private-image-deployment.yaml <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: private-app
  namespace: registry-lab
spec:
  replicas: 1
  selector:
    matchLabels:
      app: private-app
  template:
    metadata:
      labels:
        app: private-app
    spec:
      containers:
      - name: app
        image: docker.io/yourusername/private-app:v1.0
        ports:
        - containerPort: 8080
      imagePullSecrets:
      - name: dockerhub-secret
EOF

kubectl apply -f private-image-deployment.yaml
```

```

Check pod status:

```bash

kubectl get pods -l app=private-app
kubectl describe pod -l app=private-app
```

```

### Exercise 5: Attach Secret to ServiceAccount

Create ServiceAccount with ImagePullSecret:

```bash

cat > serviceaccount-with-secret.yaml <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: registry-sa
  namespace: registry-lab
imagePullSecrets:
- name: dockerhub-secret
EOF

kubectl apply -f serviceaccount-with-secret.yaml
```

```

Use ServiceAccount in Pod:

```bash

cat > pod-with-sa.yaml <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: app-with-sa
  namespace: registry-lab
spec:
  serviceAccountName: registry-sa
  containers:
  - name: app
    image: docker.io/yourusername/private-app:v1.0
EOF

kubectl apply -f pod-with-sa.yaml
```

```

### Exercise 6: Patch Default ServiceAccount

Add ImagePullSecret to default ServiceAccount:

```bash

kubectl patch serviceaccount default \\
  -p '{"imagePullSecrets": [{"name": "dockerhub-secret"}]}' \\
  -n registry-lab
```

```

Verify:

```bash

kubectl get serviceaccount default -o yaml | grep -A 2 imagePullSecrets
```

```

Now all pods without explicit ServiceAccount will use this secret.

## Part 3: Multiple Registry Authentication

### Exercise 7: Multi-Registry Secret

Create a secret for multiple registries:

```bash

# Create combined auth

cat > docker-config.json <<EOF
{
  "auths": {
    "docker.io": {
      "auth": "$(echo -n 'user1:pass1' | base64)"
    },
    "ghcr.io": {
      "auth": "$(echo -n 'user2:token2' | base64)"
    },
    "myregistry.com": {
      "auth": "$(echo -n 'user3:pass3' | base64)"
    }
  }
}
EOF

kubectl create secret generic multi-registry-secret \\
  --from-file=.dockerconfigjson=docker-config.json \\
  --type=kubernetes.io/dockerconfigjson \\
  -n registry-lab
```

```

Use in deployment:

```bash

cat > multi-registry-deployment.yaml <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: multi-registry-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: multi-app
  template:
    metadata:
      labels:
        app: multi-app
    spec:
      containers:
      - name: app1
        image: docker.io/youruser/app1:v1.0
      - name: app2
        image: ghcr.io/youruser/app2:v1.0
      - name: app3
        image: myregistry.com/app3:v1.0
      imagePullSecrets:
      - name: multi-registry-secret
EOF

kubectl apply -f multi-registry-deployment.yaml
```

```

## Part 4: Cloud Registry Integration

### Exercise 8: Amazon ECR Authentication

Setup ECR authentication:

```bash

# Install AWS CLI if needed
# curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
# unzip awscliv2.zip
# sudo ./aws/install

# Get ECR login token

AWS_ACCOUNT_ID="123456789012"
AWS_REGION="us-east-1"
ECR_URL="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

# Login to ECR

aws ecr get-login-password --region ${AWS_REGION} | \\
  docker login --username AWS --password-stdin ${ECR_URL}

# Create Kubernetes secret

kubectl create secret docker-registry ecr-secret \\
  --docker-server=${ECR_URL} \\
  --docker-username=AWS \\
  --docker-password=$(aws ecr get-login-password --region ${AWS_REGION}) \\
  -n registry-lab
```

```

Note: ECR tokens expire after 12 hours. Consider using a CronJob for rotation:

```bash

cat > ecr-credential-refresher.yaml <<EOF
apiVersion: batch/v1
kind: CronJob
metadata:
  name: ecr-cred-refresher
  namespace: registry-lab
spec:
  schedule: "0 */8 * * *"  # Every 8 hours
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: ecr-refresher-sa
          containers:
          - name: refresher
            image: amazon/aws-cli:latest
            command:
            - /bin/bash
            - -c
            - |
              kubectl delete secret ecr-secret --ignore-not-found
              kubectl create secret docker-registry ecr-secret \\
                --docker-server=${ECR_URL} \\
                --docker-username=AWS \\
                --docker-password=$(aws ecr get-login-password --region ${AWS_REGION})
          restartPolicy: OnFailure
EOF
```

```

### Exercise 9: Google Container Registry (GCR)

Setup GCR authentication:

```bash

# Service account key file (download from GCP)

GCR_KEY_FILE="path/to/keyfile.json"
GCR_URL="gcr.io"

# Create secret

kubectl create secret docker-registry gcr-secret \\
  --docker-server=${GCR_URL} \\
  --docker-username=_json_key \\
  --docker-password="$(cat ${GCR_KEY_FILE})" \\
  --docker-email=user@example.com \\
  -n registry-lab
```

```

For Google Artifact Registry:

```bash

GAR_URL="us-central1-docker.pkg.dev"

kubectl create secret docker-registry gar-secret \\
  --docker-server=${GAR_URL} \\
  --docker-username=_json_key \\
  --docker-password="$(cat ${GCR_KEY_FILE})" \\
  -n registry-lab
```

```

### Exercise 10: Azure Container Registry (ACR)

Setup ACR authentication:

```bash

ACR_NAME="myregistry"
ACR_URL="${ACR_NAME}.azurecr.io"

# Login with Azure CLI

az acr login --name ${ACR_NAME}

# Create secret with admin credentials

ACR_USERNAME=${ACR_NAME}
ACR_PASSWORD=$(az acr credential show --name ${ACR_NAME} --query passwords[0].value -o tsv)

kubectl create secret docker-registry acr-secret \\
  --docker-server=${ACR_URL} \\
  --docker-username=${ACR_USERNAME} \\
  --docker-password=${ACR_PASSWORD} \\
  -n registry-lab
```

```

Better: Use service principal:

```bash

# Create service principal

SP_PASSWORD=$(az ad sp create-for-rbac \\
  --name ${ACR_NAME}-pull-sp \\
  --scopes /subscriptions/<subscription-id>/resourceGroups/<rg>/providers/Microsoft.ContainerRegistry/registries/${ACR_NAME} \\
  --role acrpull \\
  --query password \\
  --output tsv)

SP_APP_ID=$(az ad sp list --display-name ${ACR_NAME}-pull-sp --query [0].appId --output tsv)

kubectl create secret docker-registry acr-sp-secret \\
  --docker-server=${ACR_URL} \\
  --docker-username=${SP_APP_ID} \\
  --docker-password=${SP_PASSWORD} \\
  -n registry-lab
```

```

## Part 5: Docker Content Trust

### Exercise 11: Enable Docker Content Trust

Enable DCT globally:

```bash

export DOCKER_CONTENT_TRUST=1
```

```

Sign and push an image:

```bash

# Build image

docker build -t docker.io/youruser/trusted-app:v1.0 .

# Push (will create signing keys)

docker push docker.io/youruser/trusted-app:v1.0
```

```

You'll be prompted to create keys:

```

You are about to create a new root signing key passphrase.
This passphrase will be used to protect the most sensitive key in your signing system.

Enter passphrase for new root key with ID abc1234:
Repeat passphrase for new root key with ID abc1234:
Enter passphrase for new repository key with ID def5678:
Repeat passphrase for new repository key with ID def5678:

```
```

Pull with DCT (only signed images allowed):

```bash

docker pull docker.io/youruser/trusted-app:v1.0
```

```

Try pulling unsigned image (will fail):

```bash

docker pull docker.io/youruser/unsigned-app:v1.0

# Error: remote trust data does not exist

```

```

View trust data:

```bash

docker trust inspect docker.io/youruser/trusted-app:v1.0
```

```

## Part 6: Admission Control for Registries

### Exercise 12: Install Kyverno

Install Kyverno for policy enforcement:

```bash

kubectl create -f https://github.com/kyverno/kyverno/releases/download/v1.11.0/install.yaml
```

```

Wait for Kyverno to be ready:

```bash

kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=kyverno -n kyverno --timeout=300s
```

```

### Exercise 13: Restrict Allowed Registries

Create policy to allow only specific registries:

```bash

cat > allowed-registries-policy.yaml <<EOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-registries
spec:
  validationFailureAction: Enforce
  background: true
  rules:
  - name: validate-registry
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "Images must come from approved registries: docker.io/youruser, gcr.io/yourproject, or myregistry.com"
      pattern:
        spec:
          containers:
          - image: "docker.io/youruser/* | gcr.io/yourproject/* | myregistry.com/*"
EOF

kubectl apply -f allowed-registries-policy.yaml
```

```

Test the policy:

```bash

# Should succeed (allowed registry)

kubectl run allowed-app --image=docker.io/youruser/app:v1.0 -n registry-lab

# Should fail (disallowed registry)

kubectl run disallowed-app --image=docker.io/nginx:latest -n registry-lab
```

```

### Exercise 14: Require Signed Images

Policy to require image signatures:

```bash

cat > require-signatures-policy.yaml <<EOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signatures
spec:
  validationFailureAction: Enforce
  background: false
  webhookTimeoutSeconds: 30
  rules:
  - name: verify-signature
    match:
      any:
      - resources:
          kinds:
          - Pod
    verifyImages:
    - imageReferences:
      - "docker.io/youruser/*"
      attestors:
      - count: 1
        entries:
        - keys:
            publicKeys: |-
              -----BEGIN PUBLIC KEY-----
              $(cat cosign.pub | tail -n +2 | head -n -1)
              -----END PUBLIC KEY-----
EOF

kubectl apply -f require-signatures-policy.yaml
```

```

Test with signed and unsigned images:

```bash

# Signed image (should succeed)

kubectl run signed-app --image=docker.io/youruser/signed-app:v1.0 -n registry-lab

# Unsigned image (should fail)

kubectl run unsigned-app --image=docker.io/youruser/unsigned-app:v1.0 -n registry-lab
```

```

## Part 7: Troubleshooting

### Exercise 15: Debug ImagePullBackOff

Create a pod with invalid credentials:

```bash

cat > broken-pod.yaml <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: broken-pod
spec:
  containers:
  - name: app
    image: docker.io/private/image:v1.0
  imagePullSecrets:
  - name: wrong-secret
EOF

kubectl apply -f broken-pod.yaml
```

```

Debug:

```bash

# Check pod status

kubectl get pod broken-pod

# Describe pod (look for events)

kubectl describe pod broken-pod

# Check if secret exists

kubectl get secret wrong-secret

# Check secret content

kubectl get secret dockerhub-secret -o jsonpath='{.data.\\.dockerconfigjson}' | base64 -d

# Test manual pull

docker pull docker.io/private/image:v1.0
```

```

Common issues:

1. Secret doesn't exist
1. Wrong registry URL
1. Expired credentials
1. Wrong secret format
1. Secret in different namespace

### Exercise 16: Verify Registry Connectivity

Create debug pod to test registry access:

```bash

kubectl run registry-debug \\
  --image=curlimages/curl:latest \\
  --rm -it --restart=Never \\
  -- sh

# Inside the pod:
# Test registry connectivity

curl -v https://index.docker.io/v2/

# Test authentication

curl -u username:password https://index.docker.io/v2/
```

```

## Verification Script

```bash

cat > test-registry-security.sh <<'EOF'

#!/bin/bash

echo "=== Registry Security Lab Verification ==="

# Test 1: ImagePullSecret exists

echo "Test 1: Check ImagePullSecret"
kubectl get secret dockerhub-secret -n registry-lab &>/dev/null
echo $?  == 0 ]] && echo "✅ ImagePullSecret exists" || echo "❌ ImagePullSecret missing"

# Test 2: ServiceAccount has imagePullSecrets

echo ""
echo "Test 2: Check ServiceAccount"
kubectl get sa registry-sa -n registry-lab -o jsonpath='{.imagePullSecrets}' | grep -q "dockerhub-secret"
if [ $? -eq 0 ]; then
  echo "✅ ServiceAccount configured"
else
  echo "❌ ServiceAccount not configured"
fi

# Test 3: Multi-registry secret

echo ""
echo "Test 3: Check multi-registry secret"
kubectl get secret multi-registry-secret -n registry-lab &>/dev/null
if [ $? -eq 0 ]; then
  NUM_REGISTRIES=$(kubectl get secret multi-registry-secret -o jsonpath='{.data.\\.dockerconfigjson}' | base64 -d | jq '.auths | length')
  echo "✅ Multi-registry secret exists with $NUM_REGISTRIES registries"
else
  echo "❌ Multi-registry secret missing"
fi

# Test 4: Kyverno installed

echo ""
echo "Test 4: Check Kyverno"
kubectl get deployment -n kyverno kyverno &>/dev/null
if [ $? -eq 0 ]; then
  echo "✅ Kyverno installed"
else
  echo "⚠️  Kyverno not installed"
fi

echo ""
echo "=== Tests Complete ==="
EOF

chmod +x test-registry-security.sh
./test-registry-security.sh
```

```

## Cleanup

```bash

# Delete namespace

kubectl delete namespace registry-lab

# Delete Kyverno (optional)

kubectl delete -f https://github.com/kyverno/kyverno/releases/download/v1.11.0/install.yaml

# Reset context

kubectl config set-context --current --namespace=default

# Remove working files

rm -f *.yaml *.json *.sh
```

```

## Key Takeaways

1. ImagePullSecrets enable private registry authentication
1. Attach secrets to ServiceAccounts for automatic usage
1. Support multiple registries in a single secret
1. Cloud registries have specific authentication methods
1. ECR tokens expire and need rotation
1. Docker Content Trust enforces image signing
1. Admission policies can restrict allowed registries
1. Always verify signature policies before enforcement
1. Troubleshoot with kubectl describe and manual pulls
1. Test policies in audit mode before enforce mode

## Next Steps

1. Implement registry policies in your cluster
1. Set up automated credential rotation
1. Proceed to [Lab 04: SBOM Generation](./lab-04-sbom-generation.md)

---

[← Back to Lab Overview](./README.md) | [Previous Lab: Image Signing ←](./lab-02-image-signing-cosign.md) | [Next Lab: SBOM Generation →](./lab-04-sbom-generation.md)
