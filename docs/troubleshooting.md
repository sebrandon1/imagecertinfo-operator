# Troubleshooting

## Logs Are JSON Instead of Readable Text

**Symptoms:** `kubectl logs` shows single-line JSON objects.

The operator logs JSON in production mode. For readable console output while
running from a host, use `make run` (which passes `--zap-devel`) or set
`--zap-devel=true` on the Deployment. Pipe JSON logs through `jq` to inspect
them:

```bash
kubectl logs -l control-plane=controller-manager -n imagecertinfo-operator-system | jq -r '.msg'
```

## Is the Pyxis API Reachable From the Operator?

**Symptoms:** Every image shows `Unknown` certification status, or enrichment is
silently failing.

The operator exposes a named health check per upstream API. Unlike `/readyz`,
these do real requests, so query them on demand rather than on a probe:

```bash
kubectl port-forward -n imagecertinfo-operator-system deploy/imagecertinfo-controller-manager 8081:8081
curl -s localhost:8081/healthz/pyxis
curl -s localhost:8081/healthz/dockerhub
```

An `ok` response means the API answered; `500` with `<name> API is not reachable`
means it did not. From inside the cluster:

```bash
kubectl exec -n imagecertinfo-operator-system deploy/imagecertinfo-controller-manager -- \
  curl -s localhost:8081/healthz/pyxis
```

These checks are not part of readiness on purpose: an upstream outage must not
unready or restart the operator. Pass `--api-health-checks=false` to register
none of them, for example on an air-gapped install where every check would fail.

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
