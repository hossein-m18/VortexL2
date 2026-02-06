# HAProxy Port Forwarding for VortexL2 v2.0

VortexL2 v2.0 uses **HAProxy** for production-grade, high-performance port forwarding.

## Why HAProxy?

| Feature     | Python asyncio (v1.x) | HAProxy (v2.0)       |
| ----------- | --------------------- | -------------------- |
| Latency     | ~5-10ms overhead      | <1ms overhead        |
| Throughput  | ~100 Mbps             | **10+ Gbps**         |
| Connections | ~1,000                | **100,000+**         |
| CPU Usage   | High                  | **Very Low**         |
| Stability   | Moderate              | **Production-grade** |

## Installation

HAProxy is automatically installed by the VortexL2 installer:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/hossein-m18/VortexL2/main/install.sh)
```

Or manually:

```bash
sudo apt-get update
sudo apt-get install haproxy
```

## Configuration

HAProxy configuration is **automatically managed** by VortexL2:

- **Config Location:** `/etc/haproxy/haproxy.cfg`
- **Backup:** `/etc/haproxy/haproxy.cfg.bak` (created before first modification)

When you add/remove port forwards via the VortexL2 panel, HAProxy is automatically reconfigured and reloaded.

## Commands

```bash
# Check HAProxy status
sudo systemctl status haproxy

# View listening ports
ss -tlnp | grep haproxy

# View HAProxy statistics
echo "show stat" | socat stdio /var/run/haproxy.sock

# Manually reload HAProxy
sudo systemctl reload haproxy

# View HAProxy config
cat /etc/haproxy/haproxy.cfg
```

## Troubleshooting

### HAProxy fails to start

1. **Check configuration validity:**

   ```bash
   sudo haproxy -c -f /etc/haproxy/haproxy.cfg
   ```

2. **Check logs:**

   ```bash
   sudo journalctl -u haproxy -f
   ```

3. **Check for port conflicts:**
   ```bash
   ss -tlnp | grep <port>
   ```

### Port forward not working

1. **Verify HAProxy is running:**

   ```bash
   sudo systemctl status haproxy
   ```

2. **Check if port is listening:**

   ```bash
   ss -tlnp | grep haproxy
   ```

3. **Verify remote host is reachable:**

   ```bash
   ping <remote-forward-ip>
   ```

4. **Check HAProxy config was generated:**
   ```bash
   cat /etc/haproxy/haproxy.cfg | grep frontend
   ```

### Restore original config

If needed, restore the original HAProxy configuration:

```bash
sudo cp /etc/haproxy/haproxy.cfg.bak /etc/haproxy/haproxy.cfg
sudo systemctl restart haproxy
```

## Architecture

```
                     ┌─────────────────────┐
                     │    HAProxy (v2.0)   │
                     │                     │
  Client ──────────► │  frontend :443      │
  443,80,2053        │  frontend :80       │ ──► l2tpeth0 ──► Remote Server
                     │  frontend :2053     │
                     │                     │
                     │  ✓ TCP mode         │
                     │  ✓ Health checks    │
                     │  ✓ Auto-reload      │
                     └─────────────────────┘
```
