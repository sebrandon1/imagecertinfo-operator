# Prometheus Metrics

The operator exposes metrics at the `/metrics` endpoint. All metrics use the `imagecertinfo_` prefix.

## Image Inventory Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `imagecertinfo_images_total` | Gauge | `status` | Total images tracked by certification status |
| `imagecertinfo_images_by_health` | Gauge | `grade` | Images by health grade (A-F) |
| `imagecertinfo_vulnerabilities_total` | Gauge | `severity` | Total vulnerabilities by severity |
| `imagecertinfo_images_eol_within_days` | Gauge | `days` | Images approaching end-of-life |
| `imagecertinfo_images_past_eol` | Gauge | - | Images past their EOL date |

## Pyxis API Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `imagecertinfo_pyxis_requests_total` | Counter | `status`, `endpoint` | Total Pyxis API requests |
| `imagecertinfo_pyxis_request_duration_seconds` | Histogram | `endpoint` | Request duration in seconds |
| `imagecertinfo_pyxis_cache_hits_total` | Counter | `result` | Cache hits (`hit`) and misses (`miss`) |

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
| `imagecertinfo_certification_status_changes_total` | Counter | `from`, `to` | Certification status changes |

## Example PromQL Queries

```promql
# Percentage of certified images
sum(imagecertinfo_images_total{status="Certified"}) / sum(imagecertinfo_images_total) * 100

# Images with critical vulnerabilities
imagecertinfo_vulnerabilities_total{severity="critical"}

# Pyxis API cache hit rate
sum(rate(imagecertinfo_pyxis_cache_hits_total{result="hit"}[5m])) /
sum(rate(imagecertinfo_pyxis_cache_hits_total[5m])) * 100

# Reconciliation error rate
sum(rate(imagecertinfo_reconcile_total{result="error"}[5m])) /
sum(rate(imagecertinfo_reconcile_total[5m])) * 100
```

## Docker Hub API Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `imagecertinfo_dockerhub_requests_total` | Counter | `status`, `endpoint` | Total Docker Hub API requests |
| `imagecertinfo_dockerhub_request_duration_seconds` | Histogram | `endpoint` | Request duration in seconds |
| `imagecertinfo_dockerhub_cache_hits_total` | Counter | `result` | Cache hits (`hit`) and misses (`miss`) |

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
