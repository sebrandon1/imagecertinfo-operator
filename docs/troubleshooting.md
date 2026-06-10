# Troubleshooting

## Pyxis API Errors

**Symptoms:** Images show `Unknown` certification status, Pyxis-related errors in logs.

**Solutions:**
1. Check network connectivity to `catalog.redhat.com`:
   ```bash
   kubectl exec -it deploy/imagecertinfo-controller-manager -n imagecertinfo-operator-system -- curl -I https://catalog.redhat.com
   ```
2. Verify rate limiting isn't being triggered (check `imagecertinfo_pyxis_requests_total{status="429"}`)
3. Consider adding a Pyxis API key for higher rate limits via `--pyxis-api-key`

## No Images Being Discovered

**Symptoms:** No `ImageCertificationInfo` resources created.

**Solutions:**
1. Verify pods are running in the cluster:
   ```bash
   kubectl get pods --all-namespaces
   ```
2. Check controller logs for errors:
   ```bash
   kubectl logs -l control-plane=controller-manager -n imagecertinfo-operator-system
   ```
3. Ensure the operator has RBAC permissions to list pods cluster-wide

## Stale Pod References

**Symptoms:** `ImageCertificationInfo` resources list pods that no longer exist.

**Solutions:**
1. The cleanup loop runs every 5 minutes by default. Wait for the next cycle.
2. Adjust cleanup interval if needed: `--cleanup-interval=1m`
3. Check that the cleanup loop is running in logs

## Metrics Not Appearing

**Symptoms:** Prometheus scraping shows no `imagecertinfo_*` metrics.

**Solutions:**
1. Verify the metrics endpoint is enabled (`--metrics-bind-address` is not `0`):
   ```bash
   kubectl port-forward svc/imagecertinfo-controller-manager-metrics-service -n imagecertinfo-operator-system 8443:8443
   curl -k https://localhost:8443/metrics
   ```
2. Check ServiceMonitor/PodMonitor configuration matches the service labels
3. Verify Prometheus has permissions to scrape the namespace

## High Memory Usage

**Symptoms:** Operator pod OOMKilled or using excessive memory.

**Solutions:**
1. Reduce cache TTL to limit cached responses: `--pyxis-cache-ttl=30m`
2. Increase rate limiting to slow API requests: `--pyxis-rate-limit=5`
3. Check if cluster has an unusually high number of unique images
