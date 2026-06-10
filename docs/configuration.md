# Configuration

The operator can be configured via command-line flags:

| Flag | Description | Default |
|------|-------------|---------|
| `--pyxis-enabled` | Enable Red Hat Pyxis API integration | `true` |
| `--pyxis-api-key` | Optional API key for higher rate limits | (none) |
| `--pyxis-refresh-interval` | Interval for periodic refresh of Pyxis certification data (0 to disable) | `24h` |
| `--pyxis-cache-ttl` | TTL for cached Pyxis API responses | `1h` |
| `--pyxis-rate-limit` | Rate limit for Pyxis API requests per second | `10` |
| `--pyxis-rate-burst` | Burst size for Pyxis API rate limiting | `20` |
| `--cleanup-interval` | Interval for cleaning up stale pod references | `5m` |
| `--metrics-bind-address` | Address for metrics endpoint | `0` |
| `--health-probe-bind-address` | Address for health probes | `:8081` |
| `--leader-elect` | Enable leader election for HA | `false` |

---

Next: [Troubleshooting](troubleshooting.md)
