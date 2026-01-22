# ImageCertInfo Operator

Automatically discover, inventory, and track container image certifications
and security metadata across your Kubernetes cluster.

## Overview

The ImageCertInfo Operator is a Kubernetes operator that watches all running
containers in your cluster and creates a comprehensive, always-current inventory
of container images. It enriches this inventory with Red Hat certification data,
security vulnerabilities, and image lifecycle information from the Pyxis API.

**Perfect for organizations that require certified container images or need to
track which workloads are using vulnerable, uncertified, or end-of-life images.**

## Key Features

- **Automatic Discovery**: Watches pods cluster-wide and discovers all container images
- **Red Hat Certification**: Queries Red Hat's Pyxis API for certification status
- **Security Tracking**: Collects vulnerability counts (Critical/Important/Moderate/Low), CVE lists, and health grades (A-F)
- **Workload Mapping**: Tracks which pods use each image across all namespaces
- **Lifecycle Awareness**: Monitors EOL dates, release categories, and replacement images
- **Multi-Architecture Support**: Tracks supported architectures (amd64, arm64, s390x, ppc64le)
- **Zero Configuration**: Works without authentication for public Pyxis API access

## How It Differs from Red Hat ACS

| Capability | ImageCertInfo Operator | Red Hat ACS |
|------------|------------------------|-------------|
| **Primary Focus** | Image certification & inventory | Full security platform |
| **Deployment Model** | Lightweight operator (~50MB) | Multi-component platform (Central, Scanner, Sensor) |
| **Scope** | Image metadata & certification | Vulnerability scanning, policy enforcement, runtime protection |
| **Red Hat Integration** | Deep Pyxis API integration for certification data | Broader security scanning with Scanner V4/ClairCore |
| **Resource Usage** | Minimal (single pod) | Significant (multiple components, database) |
| **Policy Enforcement** | Observational only (no blocking) | Active enforcement via admission control |
| **Cost** | Free/Open Source | Commercial product |
| **Use Case** | Compliance tracking, image inventory | Enterprise container security |

**When to use ImageCertInfo Operator:**
- You need lightweight image certification tracking
- You want to audit Red Hat certified vs. non-certified images
- You need a simple inventory of all images in your cluster
- You want to track image lifecycle (EOL dates, deprecations)

**When to use Red Hat ACS:**
- You need comprehensive vulnerability scanning
- You require policy enforcement and admission control
- You need runtime threat detection
- You want CI/CD pipeline integration for security gates

## Quick Start

### Deploy the Operator

```bash
# Using the pre-built image
kubectl apply -f https://raw.githubusercontent.com/sebrandon1/imagecertinfo-operator/main/dist/install.yaml
```

### Or build and deploy from source

```bash
# Build and push to your registry
make docker-build docker-push IMG=quay.io/bapalm/imagecertinfo-operator:latest

# Install CRDs and deploy
make install
make deploy IMG=quay.io/bapalm/imagecertinfo-operator:latest
```

## Usage Examples

Once deployed, the operator automatically creates `ImageCertificationInfo` resources for each unique image in your cluster.

### View All Tracked Images

```bash
kubectl get imagecertificationinfo

# Example output:
# NAME                                              REGISTRY              TYPE     CERTIFIED   HEALTH   AGE
# registry.redhat.io.ubi9.ubi.a1b2c3d4              registry.redhat.io    RedHat   Certified   A        5m
# quay.io.sebrandon1.imagecertinfo-operator.e5f6    quay.io               Partner  Unknown     -        5m
# docker.io.library.nginx.7g8h9i0j                  docker.io             Community NotCertified -      5m
```

### View Detailed Image Information

```bash
kubectl describe imagecertificationinfo registry.redhat.io.ubi9.ubi.a1b2c3d4
```

**Example output:**
```yaml
Name:         registry.redhat.io.ubi9.ubi.a1b2c3d4
API Version:  security.telco.openshift.io/v1alpha1
Kind:         ImageCertificationInfo
Spec:
  Full Image Reference:  registry.redhat.io/ubi9/ubi@sha256:a1b2c3d4...
  Image Digest:          sha256:a1b2c3d4...
  Registry:              registry.redhat.io
  Repository:            ubi9/ubi
Status:
  Certification Status:  Certified
  Registry Type:         RedHat
  Pyxis Data:
    Architectures:
      - amd64
      - arm64
      - ppc64le
      - s390x
    Auto Rebuild Enabled:    true
    Catalog URL:             https://catalog.redhat.com/software/containers/ubi9/ubi/...
    Compressed Size Bytes:   82945123
    Health Index:            A
    Publisher:               Red Hat, Inc.
    Release Category:        Generally Available
    Vulnerabilities:
      Critical:   0
      Important:  2
      Low:        15
      Moderate:   5
  Pod References:
    - Container:  ubi-container
      Name:       my-app-pod
      Namespace:  default
```

### Find Images with Vulnerabilities

```bash
# Find images with critical vulnerabilities
kubectl get imagecertificationinfo -o json | jq '.items[] | select(.status.pyxisData.vulnerabilities.critical > 0) | .metadata.name'
```

### Find Non-Certified Images

```bash
kubectl get imagecertificationinfo --field-selector=status.certificationStatus=NotCertified
```

### Check for Deprecated Images

```bash
kubectl get imagecertificationinfo -o wide | grep -i deprecated
```

## Container Image

The operator is available as a multi-architecture container image:

```
quay.io/bapalm/imagecertinfo-operator:latest
quay.io/bapalm/imagecertinfo-operator:stable
quay.io/bapalm/imagecertinfo-operator:v0.1.0
```

**Supported architectures:** `amd64`, `arm64`, `s390x`, `ppc64le`

## Prerequisites

- Kubernetes v1.11.3+ or OpenShift 4.x
- kubectl or oc CLI
- Cluster-admin privileges (for CRD installation)

## Configuration

The operator can be configured via command-line flags:

| Flag | Description | Default |
|------|-------------|---------|
| `--enable-pyxis` | Enable Red Hat Pyxis API integration | `true` |
| `--pyxis-api-key` | Optional API key for higher rate limits | (none) |
| `--metrics-bind-address` | Address for metrics endpoint | `:8080` |
| `--health-probe-bind-address` | Address for health probes | `:8081` |
| `--leader-elect` | Enable leader election for HA | `false` |

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.
