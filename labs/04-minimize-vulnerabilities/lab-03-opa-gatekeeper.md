# Lab 03 - OPA Gatekeeper

## Objective

Deploy OPA Gatekeeper and implement security policies using ConstraintTemplates and Constraints to enforce organizational security standards.

## Duration

75 minutes

## Prerequisites

- Kubernetes cluster v1.30.x
- kubectl configured
- Helm 3.x installed
- Understanding of YAML and basic policy concepts

## Step 1: Install OPA Gatekeeper

```bash
# Add Gatekeeper Helm repository
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm repo update

# Install Gatekeeper
helm install gatekeeper gatekeeper/gatekeeper \
  --namespace gatekeeper-system \
  --create-namespace \
  --set auditInterval=60 \
  --set replicas=2

# Verify installation
kubectl get pods -n gatekeeper-system
kubectl get crd | grep gatekeeper

# Wait for Gatekeeper to be ready
kubectl wait --for=condition=ready pod \
  -l control-plane=controller-manager \
  -n gatekeeper-system \
  --timeout=120s
```

## Step 2: Create Test Namespace

```bash
kubectl create namespace lab-gatekeeper
kubectl label namespace lab-gatekeeper policy=restricted
```

## Step 3: Require Labels Policy

### 3.1 Create ConstraintTemplate

Create `k8srequiredlabels-template.yaml`:

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
  annotations:
    description: "Requires resources to contain specified labels"
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
      validation:
        openAPIV3Schema:
          type: object
          properties:
            message:
              type: string
            labels:
              type: array
              description: "A list of labels required"
              items:
                type: object
                properties:
                  key:
                    type: string
                  allowedRegex:
                    type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels

        get_message(parameters, _default) = msg {
          not parameters.message
          msg := _default
        }

        get_message(parameters, _default) = msg {
          msg := parameters.message
        }

        violation[{"msg": msg, "details": {"missing_labels": missing}}] {
          provided := {label | input.review.object.metadata.labels[label]}
          required := {label | label := input.parameters.labels[_].key}
          missing := required - provided
          count(missing) > 0
          def_msg := sprintf("You must provide labels: %v", [missing])
          msg := get_message(input.parameters, def_msg)
        }

        violation[{"msg": msg}] {
          value := input.review.object.metadata.labels[key]
          expected := input.parameters.labels[_]
          expected.key == key
          expected.allowedRegex != ""
          not re_match(expected.allowedRegex, value)
          def_msg := sprintf("Label <%v: %v> does not satisfy allowed regex: %v", [key, value, expected.allowedRegex])
          msg := get_message(input.parameters, def_msg)
        }
```

```bash
kubectl apply -f k8srequiredlabels-template.yaml

# Verify template
kubectl get constrainttemplates
kubectl describe constrainttemplate k8srequiredlabels
```

### 3.2 Create Constraint

Create `require-labels-constraint.yaml`:

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: pods-must-have-owner
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces:
      - lab-gatekeeper
  parameters:
    message: "All pods must have 'owner' and 'environment' labels"
    labels:
      - key: "owner"
        allowedRegex: "^[a-zA-Z]+$"
      - key: "environment"
        allowedRegex: "^(dev|staging|prod)$"
```

```bash
kubectl apply -f require-labels-constraint.yaml

# Check constraint status
kubectl get k8srequiredlabels
kubectl describe k8srequiredlabels pods-must-have-owner
```

### 3.3 Test the Policy

```bash
# Test: Pod without required labels (should fail)
kubectl run test-no-labels --image=nginx:1.27 -n lab-gatekeeper
# Expected: Error - missing labels

# Test: Pod with labels (should succeed)
kubectl run test-with-labels \
  --image=nginx:1.27 \
  --labels="owner=alice,environment=dev" \
  -n lab-gatekeeper

# Test: Invalid label value (should fail)
kubectl run test-invalid-env \
  --image=nginx:1.27 \
  --labels="owner=alice,environment=test" \
  -n lab-gatekeeper
# Expected: Error - environment must be dev, staging, or prod
```

## Step 4: Deny Privileged Containers

### 4.1 Create ConstraintTemplate

Create `k8spspprivileged-template.yaml`:

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spspprivilegedcontainer
spec:
  crd:
    spec:
      names:
        kind: K8sPSPPrivilegedContainer
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8spspprivileged

        violation[{"msg": msg, "details": {}}] {
          c := input_containers[_]
          c.securityContext.privileged
          msg := sprintf("Privileged container is not allowed: %v, securityContext: %v", [c.name, c.securityContext])
        }

        input_containers[c] {
          c := input.review.object.spec.containers[_]
        }

        input_containers[c] {
          c := input.review.object.spec.initContainers[_]
        }

        input_containers[c] {
          c := input.review.object.spec.ephemeralContainers[_]
        }
```

```bash
kubectl apply -f k8spspprivileged-template.yaml
```

### 4.2 Create Constraint

Create `deny-privileged-constraint.yaml`:

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPPrivilegedContainer
metadata:
  name: deny-privileged-containers
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces:
      - lab-gatekeeper
```

```bash
kubectl apply -f deny-privileged-constraint.yaml

# Test privileged container
kubectl run test-privileged \
  --image=nginx:1.27 \
  --labels="owner=alice,environment=dev" \
  --overrides='{"spec":{"containers":[{"name":"nginx","image":"nginx:1.27","securityContext":{"privileged":true}}]}}' \
  -n lab-gatekeeper
# Expected: Error - privileged containers not allowed
```

## Step 5: Require Resource Limits

### 5.1 Create ConstraintTemplate

Create `k8srequiredresources-template.yaml`:

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredresources
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredResources
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredresources

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not container.resources.limits.cpu
          msg := sprintf("Container %v must have CPU limit", [container.name])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not container.resources.limits.memory
          msg := sprintf("Container %v must have memory limit", [container.name])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not container.resources.requests.cpu
          msg := sprintf("Container %v must have CPU request", [container.name])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not container.resources.requests.memory
          msg := sprintf("Container %v must have memory request", [container.name])
        }
```

```bash
kubectl apply -f k8srequiredresources-template.yaml
```

### 5.2 Create Constraint

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredResources
metadata:
  name: require-resource-limits
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces:
      - lab-gatekeeper
```

Save as `require-resources-constraint.yaml` and apply:

```bash
kubectl apply -f require-resources-constraint.yaml

# Test without resources
kubectl run test-no-resources \
  --image=nginx:1.27 \
  --labels="owner=alice,environment=dev" \
  -n lab-gatekeeper
# Expected: Error - must have CPU and memory limits
```

## Step 6: Allowed Container Registries

### 6.1 Create ConstraintTemplate

Create `k8sallowedrepos-template.yaml`:

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sallowedrepos
spec:
  crd:
    spec:
      names:
        kind: K8sAllowedRepos
      validation:
        openAPIV3Schema:
          type: object
          properties:
            repos:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sallowedrepos

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          satisfied := [good | repo = input.parameters.repos[_] ; good = startswith(container.image, repo)]
          not any(satisfied)
          msg := sprintf("Container %v has invalid image repo %v, allowed repos are %v", [container.name, container.image, input.parameters.repos])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.initContainers[_]
          satisfied := [good | repo = input.parameters.repos[_] ; good = startswith(container.image, repo)]
          not any(satisfied)
          msg := sprintf("InitContainer %v has invalid image repo %v, allowed repos are %v", [container.name, container.image, input.parameters.repos])
        }
```

```bash
kubectl apply -f k8sallowedrepos-template.yaml
```

### 6.2 Create Constraint

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAllowedRepos
metadata:
  name: allowed-registries
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces:
      - lab-gatekeeper
  parameters:
    repos:
      - "docker.io/"
      - "gcr.io/"
      - "registry.k8s.io/"
```

Save as `allowed-repos-constraint.yaml` and apply:

```bash
kubectl apply -f allowed-repos-constraint.yaml

# Test with disallowed registry
kubectl run test-bad-registry \
  --image=badregistry.com/nginx:1.27 \
  --labels="owner=alice,environment=dev" \
  --dry-run=server -n lab-gatekeeper
# Expected: Error - registry not allowed
```

## Step 7: Audit Existing Resources

```bash
# Check constraint status (shows violations)
kubectl get constraints

# Detailed view
kubectl get k8srequiredlabels pods-must-have-owner -o yaml

# View audit results
kubectl describe k8srequiredlabels pods-must-have-owner | grep -A 10 "Total Violations"
```

## Step 8: Dry-Run Mode (Audit Only)

```bash
# Change enforcement action to dryrun
kubectl patch k8srequiredlabels pods-must-have-owner \
  --type='json' \
  -p='[{"op": "replace", "path": "/spec/enforcementAction", "value": "dryrun"}]'

# Now violations are logged but not blocked
kubectl run test-violation \
  --image=nginx:1.27 \
  -n lab-gatekeeper
# Should succeed but violation is logged

# Check audit
kubectl describe k8srequiredlabels pods-must-have-owner
```

## Challenge Exercises

1. Create policy to require `readOnlyRootFilesystem: true`
2. Implement policy to deny `hostNetwork: true`
3. Create ratio check: memory limit >= 2x memory request
4. Block images with `:latest` tag

## Troubleshooting

```bash
# Check Gatekeeper logs
kubectl logs -n gatekeeper-system -l control-plane=controller-manager

# Check constraint status
kubectl get constraints
kubectl describe <constraint-type> <constraint-name>

# Test policy with dry-run
kubectl apply --dry-run=server -f pod.yaml
```

## Lab Summary

You learned:
- Installing OPA Gatekeeper
- Creating ConstraintTemplates with Rego
- Implementing Constraints
- Testing policies
- Audit mode vs enforce mode
- Common security policies

## Cleanup

```bash
kubectl delete namespace lab-gatekeeper
kubectl delete constrainttemplates --all
helm uninstall gatekeeper -n gatekeeper-system
kubectl delete namespace gatekeeper-system
```

---

[Back to Labs](./README.md) | [Previous Lab: Admission Controllers ←](./lab-02-admission-controllers.md) | [Next Lab: Falco Runtime →](./lab-04-falco-runtime.md)
