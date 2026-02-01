# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Kubernetes operator (Kubebuilder) that automatically discovers container images running in a cluster and enriches them with Red Hat certification data from the Pyxis API and Docker Hub metadata. Creates `ImageCertificationInfo` custom resources for each unique image.

## Common Commands

```bash
# Build and test
make build                    # Build binary to bin/manager
make test                     # Unit tests with envtest (real K8s API + etcd)
make lint                     # Run golangci-lint
make lint-fix                 # Auto-fix lint issues

# Run locally (uses current kubeconfig)
make run

# E2E tests
make test-e2e                 # Creates Kind cluster, runs tests, cleans up
make test-e2e-nightly         # Against existing cluster with label filter

# Code generation (run after editing *_types.go or markers)
make manifests                # Regenerate CRDs/RBAC from kubebuilder markers
make generate                 # Regenerate DeepCopy methods

# Docker
make docker-build IMG=<img>   # Build image
make docker-push IMG=<img>    # Push image
make docker-buildx IMG=<img>  # Multi-arch build (amd64, arm64, s390x, ppc64le)

# Deploy to cluster
make install                  # Install CRDs only
make deploy IMG=<img>         # Full deployment
make build-installer IMG=<img> # Generate dist/install.yaml
```

## Architecture

**Core Components:**
- `cmd/main.go` - Manager entry point, initializes Pyxis/Docker Hub clients and controllers
- `api/v1alpha1/` - CRD schema (`ImageCertificationInfo`), edit `*_types.go` here
- `internal/controller/pod_controller.go` - Watches Pods cluster-wide, creates/updates ImageCertificationInfo CRs
- `pkg/pyxis/` - Red Hat Pyxis API client with caching and rate limiting
- `pkg/dockerhub/` - Docker Hub API client for metadata enrichment (pull counts, verified publisher status)
- `pkg/image/` - Container image reference parser
- `internal/metrics/` - Prometheus metrics

**Key Patterns:**
- PodReconciler extracts image refs from running pods → queries Pyxis/Docker Hub → creates ImageCertificationInfo CR
- Pyxis client has configurable cache TTL (default 1hr), rate limiting (10 req/sec, burst 20)
- Docker Hub client has configurable cache TTL (default 1hr), rate limiting (5 req/sec, burst 10)
- Periodic cleanup loop removes stale pod references (every 5 min)
- Periodic refresh loop updates Pyxis certification data (default 24h)

**Config Structure:**
- `config/crd/` - Generated CRDs (DO NOT EDIT)
- `config/rbac/` - Generated RBAC (DO NOT EDIT)
- `config/manager/` - Deployment config
- `config/samples/` - Example CRs (safe to edit)

## Development Rules

**Never edit (auto-generated):**
- `config/crd/bases/*.yaml`
- `config/rbac/role.yaml`
- `**/zz_generated.*.go`
- `PROJECT` file

**Never remove:**
- `// +kubebuilder:scaffold:*` comments (CLI injects code here)

**After changing API types or markers:**
```bash
make manifests generate
```

**After editing Go files:**
```bash
make lint-fix && make test
```

**Use CLI to create new resources:**
```bash
kubebuilder create api --group <group> --version <version> --kind <Kind>
kubebuilder create webhook --group <group> --version <version> --kind <Kind> --defaulting --programmatic-validation
```

## Testing

- **Unit tests:** Ginkgo + Gomega with envtest (real K8s API)
- **E2E tests:** Kind cluster, build tag `//go:build e2e`, located in `test/e2e/`
- **Nightly tests:** Use label filter `Nightly || Certification`

Run single test:
```bash
go test -v ./internal/controller/... -run TestSpecificName
# Or with Ginkgo:
go test -v ./internal/controller/... -ginkgo.focus="specific description"
```

## Key Files

| File | Purpose |
|------|---------|
| `api/v1alpha1/imagecertificationinfo_types.go` | CRD schema definition |
| `internal/controller/pod_controller.go` | Main reconciliation logic |
| `pkg/pyxis/client.go` | Pyxis API HTTP client |
| `pkg/pyxis/cache.go` | Pyxis response caching |
| `pkg/dockerhub/client.go` | Docker Hub API HTTP client |
| `pkg/dockerhub/cache.go` | Docker Hub response caching |
| `pkg/image/parser.go` | Image reference parsing |
| `internal/metrics/metrics.go` | Prometheus metrics definitions |
