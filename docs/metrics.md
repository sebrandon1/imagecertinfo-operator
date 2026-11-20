# Prometheus Metrics

The operator exposes metrics at the `/metrics` endpoint. All metrics use the `imagecertinfo_` prefix.

## Image Inventory Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `imagecertinfo_images_total` | Gauge | `status` | Total images tracked by certification status |
| `imagecertinfo_images_by_health` | Gauge | `grade` | Images by health grade (A-F). Pyxis-only: Quay/Clair has no health grade |
| `imagecertinfo_vulnerabilities_total` | Gauge | `severity` | Total vulnerabilities by severity, summed across Pyxis certification data and Quay/Clair scans |
| `imagecertinfo_images_eol_within_days` | Gauge | `days` | Images approaching end-of-life |
| `imagecertinfo_images_past_eol` | Gauge | - | Images past their EOL date |

## Pyxis API Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `imagecertinfo_pyxis_requests_total` | Counter | `status`, `endpoint` | Total Pyxis API requests. `status` is `success`, `not_found`, or `error`; `endpoint` is `image`, `repository`, or `vulnerabilities` |
| `imagecertinfo_pyxis_request_duration_seconds` | Histogram | `endpoint` | Request duration in seconds (`image`, `repository`, `vulnerabilities`) |
| `imagecertinfo_pyxis_cache_hits_total` | Counter | `result` | Cache hits (`hit`) and misses (`miss`) |
| `imagecertinfo_pyxis_cache_entries` | Gauge | - | Number of entries resident in the cache |

## Quay.io API Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `imagecertinfo_quay_requests_total` | Counter | `status`, `endpoint` | Total Quay API requests. `status` is `success`, `error`, or `denied` (the request was answered with 401/403); `endpoint` is `repository`, `security`, `manifest`, or `labels` |
| `imagecertinfo_quay_request_duration_seconds` | Histogram | `endpoint` | Request duration in seconds |

A `denied` request is not retried and leaves the previous enrichment in place, so a
rising `denied` rate means the operator can no longer see the repository rather than
that Quay is failing.

## Reconciliation Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `imagecertinfo_reconcile_total` | Counter | `result` | Reconciliation attempts (success/error/requeue) |
| `imagecertinfo_reconcile_duration_seconds` | Histogram | `controller` | Reconciliation duration |
| `imagecertinfo_images_discovered_total` | Counter | - | New images discovered |

## Event Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `imagecertinfo_events_emitted_total` | Counter | `type`, `reason` | Kubernetes events emitted |

## Refresh Cycle Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `imagecertinfo_refresh_cycles_total` | Counter | - | Completed refresh cycles |
| `imagecertinfo_refresh_duration_seconds` | Histogram | - | Refresh cycle duration |
| `imagecertinfo_images_refreshed_total` | Counter | - | Individual images refreshed |
| `imagecertinfo_refresh_images_total` | Counter | `result` (`refreshed`, `skipped`, `error`) | Images processed per refresh cycle, by outcome |
| `imagecertinfo_refresh_image_errors_last_cycle` | Gauge | - | Images that failed in the last completed cycle; resets to `0` on a clean cycle |
| `imagecertinfo_certification_status_changes_total` | Counter | `from`, `to` | Certification status changes |

## Example PromQL Queries

```promql
# Percentage of certified images
sum(imagecertinfo_images_total{status="Certified"}) / sum(imagecertinfo_images_total) * 100

# Images with critical vulnerabilities (Pyxis and Quay/Clair combined)
imagecertinfo_vulnerabilities_total{severity="critical"}

# Images by Pyxis health grade (excludes quay.io images)
sum by (grade) (imagecertinfo_images_by_health)

# Pyxis API cache hit rate
sum(rate(imagecertinfo_pyxis_cache_hits_total{result="hit"}[5m])) /
sum(rate(imagecertinfo_pyxis_cache_hits_total[5m])) * 100

# Reconciliation error rate
sum(rate(imagecertinfo_reconcile_total{result="error"}[5m])) /
sum(rate(imagecertinfo_reconcile_total[5m])) * 100

# Images that failed in the last refresh cycle
imagecertinfo_refresh_image_errors_last_cycle > 0
```

## Docker Hub API Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `imagecertinfo_dockerhub_requests_total` | Counter | `status`, `endpoint` | Total Docker Hub API requests. `status` is `success`, `not_found`, or `error`; `endpoint` is `repository` or `orgs` |
| `imagecertinfo_dockerhub_request_duration_seconds` | Histogram | `endpoint` | Request duration in seconds |
| `imagecertinfo_dockerhub_cache_hits_total` | Counter | `result` | Cache hits (`hit`) and misses (`miss`) |
| `imagecertinfo_dockerhub_cache_entries` | Gauge | - | Number of entries resident in the cache |

## Built-in Alert Rules

`config/prometheus/prometheusrule.yaml` ships four `PrometheusRule` alerts:
`ImagesCertificationExpired`, `ImagesCriticalCVEs`, `ImagesHealthDegraded` and
`PyxisAPIDown`. They come with the `config/prometheus` kustomization, which
`config/default` does not include, so they are opt-in. The `PrometheusRule` CRD
must be installed (OpenShift user-workload monitoring or kube-prometheus-stack):

```bash
kubectl apply -k config/prometheus -n imagecertinfo-operator-system
```

`PyxisAPIDown` fires when requests are still being made but none has succeeded
in ten minutes, so an idle operator with the refresh loop disabled does not
alert.

## Grafana Dashboard

`config/grafana/dashboard-configmap.yaml` is a ready-to-import Grafana dashboard
covering certification status, vulnerabilities by severity, EOL pressure, health
grades and Pyxis request health. The `grafana_dashboard: "1"` label lets the
Grafana sidecar pick it up automatically; otherwise import the JSON by hand:

```bash
kubectl apply -k config/grafana -n imagecertinfo-operator-system
kubectl get configmap imagecertinfo-operator-dashboard -n imagecertinfo-operator-system \
  -o jsonpath='{.data.dashboard\.json}' > dashboard.json
```

Then in Grafana, **Dashboards → New → Import**, upload `dashboard.json` and pick
your Prometheus data source when prompted.

## OpenShift Monitoring Integration

To enable metrics scraping with OpenShift's built-in monitoring:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: imagecertinfo-operator
  namespace: imagecertinfo-operator-system
spec:
  endpoints:
  - port: https
    scheme: https
    tlsConfig:
      insecureSkipVerify: true
  selector:
    matchLabels:
      control-plane: controller-manager
```

---

Next: [Usage](usage.md)
