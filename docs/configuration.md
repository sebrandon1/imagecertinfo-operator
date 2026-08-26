# Configuration

The operator can be configured via command-line flags:

## Pyxis API

| Flag | Description | Default |
|------|-------------|---------|
| `--pyxis-enabled` | Enable Red Hat Pyxis API integration | `true` |
| `--pyxis-base-url` | Base URL for the Pyxis API | `https://catalog.redhat.com/api/containers/v1` |
| `--pyxis-api-key` | Optional API key for higher Pyxis rate limits (can also use `PYXIS_API_KEY` env var) | (none) |
| `--pyxis-refresh-interval` | Interval for periodic refresh of Pyxis certification data (`0` to disable) | `24h` |
| `--pyxis-cache-ttl` | TTL for cached Pyxis API responses | `1h` |
| `--pyxis-rate-limit` | Pyxis API requests per second | `10` |
| `--pyxis-rate-burst` | Burst size for Pyxis rate limiting | `20` |

## Pyxis API Key — Kubernetes Secret

Instead of passing the API key via flag or environment variable, you can store it in a Kubernetes Secret:

| Flag | Description | Default |
|------|-------------|---------|
| `--pyxis-api-key-secret-name` | Name of the Secret containing the Pyxis API key | (none) |
| `--pyxis-api-key-secret-namespace` | Namespace of the Secret (defaults to `POD_NAMESPACE` env var) | (none) |
| `--pyxis-api-key-secret-key` | Key within the Secret that holds the API key value | `api-key` |

Priority order: `--pyxis-api-key` flag → `PYXIS_API_KEY` env var → Secret.

## Docker Hub

| Flag | Description | Default |
|------|-------------|---------|
| `--dockerhub-enabled` | Enable Docker Hub metadata enrichment for `docker.io` images | `true` |
| `--dockerhub-cache-ttl` | TTL for cached Docker Hub API responses | `1h` |
| `--dockerhub-rate-limit` | Docker Hub API requests per second | `5` |
| `--dockerhub-rate-burst` | Burst size for Docker Hub rate limiting | `10` |

## Reconciliation

| Flag | Description | Default |
|------|-------------|---------|
| `--cleanup-interval` | Interval for cleaning up stale pod references | `5m` |

## Metrics and Health

| Flag | Description | Default |
|------|-------------|---------|
| `--metrics-bind-address` | Address for the metrics endpoint | `0` |
| `--metrics-secure` | Serve metrics over HTTPS | `true` |
| `--metrics-cert-path` | Directory containing the metrics TLS certificate | (none) |
| `--metrics-cert-name` | Metrics TLS certificate filename | `tls.crt` |
| `--metrics-cert-key` | Metrics TLS key filename | `tls.key` |
| `--health-probe-bind-address` | Address for health probes | `:8081` |

## Leader Election

| Flag | Description | Default |
|------|-------------|---------|
| `--leader-elect` | Enable leader election for HA deployments | `false` |

## Webhook TLS

| Flag | Description | Default |
|------|-------------|---------|
| `--webhook-cert-path` | Directory containing the webhook TLS certificate | (none) |
| `--webhook-cert-name` | Webhook TLS certificate filename | `tls.crt` |
| `--webhook-cert-key` | Webhook TLS key filename | `tls.key` |

## HTTP/2

| Flag | Description | Default |
|------|-------------|---------|
| `--enable-http2` | Enable HTTP/2 for the webhook and metrics servers | `false` |

---

Next: [Troubleshooting](troubleshooting.md)
