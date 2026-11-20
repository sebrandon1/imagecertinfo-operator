# Usage

Once deployed, the operator automatically creates `ImageCertificationInfo`
resources for each unique image in your cluster.

## View All Tracked Images

```bash
kubectl get imagecertificationinfo

# Example output:
# NAME                                              REGISTRY              TYPE     CERTIFIED   HEALTH   AGE
# registry.redhat.io.ubi9.ubi.a1b2c3d4              registry.redhat.io    RedHat   Certified   A        5m
# quay.io.sebrandon1.imagecertinfo-operator.e5f6    quay.io               Partner  Unknown     -        5m
# docker.io.library.nginx.7g8h9i0j                  docker.io             Community NotCertified -      5m
```

## View Detailed Image Information

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
  Days Until EOL:  120
  Image Age:       45 days
```

## Docker Hub Images

For images from `docker.io`, the operator also populates `dockerHubData`:

```bash
kubectl describe imagecertificationinfo docker.io.library.nginx.7g8h9i0j
```

```yaml
Status:
  Certification Status: NotCertified
  Registry Type:        Community
  Docker Hub Data:
    Pull Count:          1234567890
    Star Count:          18000
    Is Official:         true
    Is Verified Publisher: false
    Last Updated:        "2026-01-15T10:00:00Z"
```

## Find Images with Vulnerabilities

```bash
# Find images with critical vulnerabilities
kubectl get imagecertificationinfo -o json | jq '.items[] | select(.status.pyxisData.vulnerabilities.critical > 0) | .metadata.name'
```

## Find Non-Certified Images

```bash
kubectl get imagecertificationinfo --field-selector=status.certificationStatus=NotCertified
```

## Check for Deprecated Images

```bash
kubectl get imagecertificationinfo -o wide | grep -i deprecated
```

## Supply Chain Metadata (SBOM and Attestations)

Two status fields carry supply-chain pointers:

| Field | JSON path | Meaning |
|-------|-----------|---------|
| `SBOMURI` | `.status.sbomURI` | Where the image's software bill of materials can be fetched |
| `AttestationURI` | `.status.attestationURI` | Where the image's signed provenance attestation can be fetched |

The operator does not populate either field. Neither Pyxis, Docker Hub nor Quay
exposes SBOM or attestation locations, so these fields are a contract for a
signing controller (for example one that publishes cosign attestations) to
write, and for consumers such as the
[tls-compliance-operator](https://github.com/sebrandon1/tls-compliance-operator)
to read:

```bash
kubectl patch imagecertificationinfo registry.redhat.io.ubi9.ubi.abc12345 \
  --subresource=status --type=merge \
  -p '{"status":{"sbomURI":"registry.redhat.io/ubi9/ubi@sha256:abc12345.att"}}'
kubectl get imagecertificationinfo registry.redhat.io.ubi9.ubi.abc12345 \
  -o jsonpath='{.status.sbomURI}'
```
