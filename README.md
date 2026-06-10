# ImageCertInfo Operator for OpenShift

![Tests](https://github.com/sebrandon1/imagecertinfo-operator/actions/workflows/test.yml/badge.svg)
![Lint](https://github.com/sebrandon1/imagecertinfo-operator/actions/workflows/lint.yml/badge.svg)
![E2E Tests](https://github.com/sebrandon1/imagecertinfo-operator/actions/workflows/test-e2e.yml/badge.svg)
![Build](https://github.com/sebrandon1/imagecertinfo-operator/actions/workflows/build-push.yml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/sebrandon1/imagecertinfo-operator)](https://goreportcard.com/report/github.com/sebrandon1/imagecertinfo-operator)
![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

Automatically discover, inventory, and track Red Hat certified container images
across your OpenShift or Kubernetes cluster.

## Overview

The ImageCertInfo Operator watches all running containers in your cluster and
creates a comprehensive, always-current inventory of container images. It
enriches this inventory with Red Hat certification data, security
vulnerabilities, and image lifecycle information from the Pyxis API and Docker
Hub metadata.

## Key Features

- **Automatic Discovery** — Watches pods cluster-wide and discovers all container images
- **Red Hat Certification** — Queries Red Hat's Pyxis API for certification status
- **Security Tracking** — Vulnerability counts (Critical/Important/Moderate/Low), CVE lists, health grades (A-F)
- **Workload Mapping** — Tracks which pods use each image across all namespaces
- **Lifecycle Awareness** — Monitors EOL dates, release categories, and replacement images
- **Multi-Architecture Support** — Tracks supported architectures (amd64, arm64, s390x, ppc64le)
- **Zero Configuration** — Works without authentication for public Pyxis API access
- **Prometheus Metrics** — Image inventory, certification status, vulnerability counts

## Quick Deploy

```bash
kubectl apply -f https://raw.githubusercontent.com/sebrandon1/imagecertinfo-operator/main/dist/install.yaml
```

To uninstall:

```bash
kubectl delete -f https://raw.githubusercontent.com/sebrandon1/imagecertinfo-operator/main/dist/install.yaml
```

## Guides

| Guide | Description |
|-------|-------------|
| [Installation](docs/installation.md) | Deploy to your cluster in one command |
| [Configuration](docs/configuration.md) | Flags and defaults |
| [Architecture](docs/architecture.md) | How the operator works, comparison with Red Hat ACS |
| [Usage](docs/usage.md) | View images, find vulnerabilities, check certification |
| [Prometheus Metrics](docs/metrics.md) | Metrics reference and example PromQL queries |
| [Troubleshooting](docs/troubleshooting.md) | Common issues and fixes |

## Prerequisites

- Kubernetes v1.11.3+ or OpenShift 4.x
- kubectl or oc CLI
- Cluster-admin privileges (for CRD installation)

## Development

```bash
make build          # Build binary
make test           # Run unit tests
make lint           # Run linter
make manifests generate  # After editing *_types.go
make test-e2e       # E2E tests (creates Kind cluster)
make docker-buildx IMG=quay.io/bapalm/imagecertinfo-operator:latest  # Multi-arch build
```

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.
