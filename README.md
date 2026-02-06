# VortexL2

**L2TPv3 Ethernet Tunnel Manager for Ubuntu/Debian**

A modular, production-quality CLI tool for managing multiple L2TPv3 tunnels with HAProxy-based port forwarding.

```
 __      __        _            _     ___
 \ \    / /       | |          | |   |__ \
  \ \  / /__  _ __| |_ _____  _| |      ) |
   \ \/ / _ \| '__| __/ _ \ \/ / |     / /
    \  / (_) | |  | ||  __/>  <| |____/ /_
     \/ \___/|_|   \__\___/_/\_\______|____|
                                    v2.0.0
```

## ✨ Features

- 🔧 Interactive TUI management panel with Rich
- 🌐 **Multiple L2TPv3 tunnels** on a single server
- 🚀 **HAProxy port forwarding**: High performance, manual activation
- 🔄 Systemd integration for persistence
- 📦 One-liner installation
- 🎯 Fully configurable tunnel IDs

## 📦 Quick Install

```bash
bash <(curl -Ls https://raw.githubusercontent.com/hossein-m18/VortexL2/main/install.sh)
```

## 🚀 First Run

### 1. Open the Management Panel

```bash
sudo vortexl2
```

### 2. Create Tunnels

Each tunnel needs:

- **Tunnel Name**: A unique identifier (e.g., `tunnel1`)
- **Local IP**: This server's public IP
- **Remote IP**: The other server's public IP
- **Interface IP**: Tunnel interface IP (e.g., `10.30.30.1/30`)
- **Tunnel IDs**: Unique IDs for the L2TP connection

### 3. Configure Both Sides

| Parameter      | IRAN Side     | KHAREJ Side   |
| -------------- | ------------- | ------------- |
| Local IP       | 1.2.3.4       | 5.6.7.8       |
| Remote IP      | 5.6.7.8       | 1.2.3.4       |
| Interface IP   | 10.30.30.1/30 | 10.30.30.2/30 |
| Tunnel ID      | 1000          | 2000          |
| Peer Tunnel ID | 2000          | 1000          |

### 4. Enable Port Forwarding (IRAN side only)

1. Select "Port Forwards" in the menu
2. **Enable HAProxy** (option 8 → select haproxy)
3. Add ports like: `443,80,2053`

> ⚠️ **Port forwarding is DISABLED by default.** You must enable HAProxy mode manually.

## 📋 Commands

| Command                   | Description           |
| ------------------------- | --------------------- |
| `sudo vortexl2`           | Open management panel |
| `sudo vortexl2 apply`     | Apply all tunnels     |
| `sudo vortexl2 --version` | Show version          |

## 🔧 Services

| Service                           | Description                     |
| --------------------------------- | ------------------------------- |
| `vortexl2-tunnel.service`         | Creates L2TP tunnels on boot    |
| `vortexl2-forward-daemon.service` | Manages HAProxy port forwarding |

```bash
# Check status
sudo systemctl status vortexl2-tunnel
sudo systemctl status vortexl2-forward-daemon

# View logs
journalctl -u vortexl2-forward-daemon -f
```

## 🔍 Troubleshooting

### Tunnel not working

1. Ensure matching tunnel IDs (swapped peer values)
2. Check firewall allows IP protocol 115
3. Verify modules: `lsmod | grep l2tp`

### Port forward not working

1. Check HAProxy mode is enabled (not `none`)
2. Verify tunnel: `ping 10.30.30.2`
3. Check daemon: `systemctl status vortexl2-forward-daemon`

## 🔧 Configuration

```yaml
# /etc/vortexl2/config.yaml (global)
forward_mode: haproxy # or: none

# /etc/vortexl2/tunnels/tunnel1.yaml
name: tunnel1
local_ip: "1.2.3.4"
remote_ip: "5.6.7.8"
interface_ip: "10.30.30.1/30"
remote_forward_ip: "10.30.30.2"
forwarded_ports:
  - 443
  - 80
```

## 🏗️ Architecture

```
                    ┌─────────────────┐
                    │   IRAN Server   │
                    │                 │
 Users ──────────►  │     HAProxy     │
 (443,80,2053)      │                 │
                    │  ┌───────────┐  │
                    │  │ l2tpeth0  │  │
                    │  │10.30.30.1 │  │
                    └────────┼────────┘
                             │
                      L2TPv3 Tunnel
                             │
                    ┌────────┼────────┐
                    │  ┌─────▼─────┐  │
                    │  │ l2tpeth0  │  │
                    │  │10.30.30.2 │  │
                    │  └───────────┘  │
                    │  KHAREJ Server  │
                    └─────────────────┘
```

## ⚠️ Security Notice

**L2TPv3 provides NO encryption!** Consider adding IPsec or use encrypted application protocols (TLS).

## 🔄 Uninstall

```bash
sudo systemctl stop vortexl2-tunnel vortexl2-forward-daemon
sudo systemctl disable vortexl2-tunnel vortexl2-forward-daemon
sudo rm -rf /opt/vortexl2 /etc/vortexl2 /var/lib/vortexl2 /var/log/vortexl2
sudo rm /usr/local/bin/vortexl2 /etc/systemd/system/vortexl2-*
sudo systemctl daemon-reload
```

## 📄 License

MIT License

## 👤 Author

Telegram: @iliyadevsh
