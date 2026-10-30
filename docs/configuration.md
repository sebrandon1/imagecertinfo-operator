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
| `--pyxis-cache-max-entries` | Maximum number of cached Pyxis responses (`0` or less for unlimited) | `10000` |
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

> [!WARNING]
> The shipped RBAC grants `get` on **one** Secret, named `pyxis-api-key`, in the
> operator namespace (`imagecertinfo-operator-system` by default). The Role is
> `imagecertinfo-operator-pyxis-secret-reader`; it is declared in
> [`config/rbac/pyxis_secret_role.yaml`](../config/rbac/pyxis_secret_role.yaml)
> with `resourceNames: ["pyxis-api-key"]`.
>
> Pointing `--pyxis-api-key-secret-name` at any other Secret — or at a Secret in
> another namespace — fails with `Forbidden`. The operator logs the error and
> exits, so it ends up in `CrashLoopBackOff`. Either rename the Secret to
> `pyxis-api-key` in the operator namespace, supply the key through
> `--pyxis-api-key` / `PYXIS_API_KEY`, or extend the RBAC:
>
> ```bash
> kubectl patch role imagecertinfo-operator-pyxis-secret-reader \
>   -n imagecertinfo-operator-system --type=json \
>   -p '[{"op":"replace","path":"/rules/0/resourceNames/0","value":"your-secret-name"}]'
> ```
>
> A different namespace also needs the Role itself and the RoleBinding subject
> moved, so editing `config/rbac/pyxis_secret_role.yaml` and re-running
> `make deploy` is usually simpler.

## Docker Hub

| Flag | Description | Default |
|------|-------------|---------|
| `--dockerhub-enabled` | Enable Docker Hub metadata enrichment for `docker.io` images | `true` |
| `--dockerhub-cache-ttl` | TTL for cached Docker Hub API responses | `1h` |
| `--dockerhub-cache-max-entries` | Maximum number of cached Docker Hub responses (`0` or less for unlimited) | `10000` |
| `--dockerhub-rate-limit` | Docker Hub API requests per second | `5` |
| `--dockerhub-rate-burst` | Burst size for Docker Hub rate limiting | `10` |

## Quay.io

| Flag | Description | Default |
|------|-------------|---------|
| `--quay-enabled` | Enable Quay.io metadata enrichment for `quay.io` images | `true` |
| `--quay-cache-ttl` | TTL for cached Quay.io repository responses | `1h` |
| `--quay-rate-limit` | Quay.io API requests per second | `5` |
| `--quay-rate-burst` | Burst size for Quay.io rate limiting | `10` |

Quay enrichment adds Clair vulnerability counts (`critical`/`important`/`moderate`/`low`
plus totals), manifest metadata (layer count, compressed size, manifest-list flag), and
the OCI labels Quay exposes (`vendor`, `architecture`, `build-date`,
`com.redhat.license_terms`, `vcs-ref`).

Only repository lookups are cached. The per-digest security scan, manifest, and label
calls go to Quay on every enrichment, so they are the calls the rate limit protects.
Unlike Pyxis and Docker Hub there is no `--quay-cache-max-entries` flag: the Quay cache
is bounded only by its TTL.

A successful call that returns no data clears the corresponding fields, so a repository
that stops publishing a value does not keep advertising the old one. A failed call
preserves the previous values and is retried.

One exception: when Quay answers `401` or `403`, the operator keeps the previous
enrichment and does **not** retry. Quay returns those statuses for repositories the
token may not see, which includes repositories that no longer exist, so the answer is
not proof of a deletion and no amount of backoff will change it. The event is logged
and counted with `status="denied"` on `imagecertinfo_quay_requests_total`. Because the
operator has no Quay token flag, a repository that requires authentication is simply
never enriched.

## Reconciliation

| Flag | Description | Default |
|------|-------------|---------|
| `--cleanup-interval` | Interval for cleaning up stale pod references | `5m` |
| `--enrichment-workers` | Number of concurrent workers enriching newly discovered images | `4` |

Failed enrichments are retried with exponential backoff up to 5 times before the
image is left for the next refresh cycle. Only the leader replica runs the
cleanup loop, the refresh loop, and the enrichment workers.

The periodic refresh loop starts only when `--pyxis-refresh-interval` is greater than
zero **and** the Pyxis client is enabled. Although the flag is named after Pyxis,
the loop refreshes Docker Hub and Quay.io CRs as well, so `--pyxis-enabled=false`
also disables periodic refresh for those registries — only the initial enrichment and
the retry queue keep them current.

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
