# Installation

## Quick Deploy

Deploy directly to your cluster with a single command (no clone required):

```bash
kubectl apply -f https://raw.githubusercontent.com/sebrandon1/imagecertinfo-operator/main/dist/install.yaml
```

To uninstall:

```bash
kubectl delete -f https://raw.githubusercontent.com/sebrandon1/imagecertinfo-operator/main/dist/install.yaml
```

## Build and Deploy from Source

```bash
# Build and push to your registry
make docker-build docker-push IMG=quay.io/bapalm/imagecertinfo-operator:latest

# Install CRDs and deploy
make install
make deploy IMG=quay.io/bapalm/imagecertinfo-operator:latest
```

## OpenShift

### Using oc CLI

```bash
# Apply the installation manifest
oc apply -f https://raw.githubusercontent.com/sebrandon1/imagecertinfo-operator/main/dist/install.yaml

# Verify deployment
oc get pods -n imagecertinfo-operator-system
```

### SecurityContextConstraints

The operator runs with minimal privileges. If your cluster has restrictive SCCs,
the default `restricted` SCC should work. For clusters requiring explicit SCC
assignment:

```bash
# The operator uses the default service account
oc adm policy add-scc-to-user restricted -z imagecertinfo-controller-manager -n imagecertinfo-operator-system
```

## Container Image

The operator is available as a multi-architecture container image:

```
quay.io/bapalm/imagecertinfo-operator:latest
quay.io/bapalm/imagecertinfo-operator:stable
quay.io/bapalm/imagecertinfo-operator:v0.1.0
```

**Supported architectures:** `amd64`, `arm64`, `s390x`, `ppc64le`

---

Next: [Configuration](configuration.md)
