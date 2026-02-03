#!/bin/bash
#
# VortexL2 Installer
# L2TPv3 Tunnel Manager for Ubuntu/Debian
#
# Usage: curl -fsSL https://raw.githubusercontent.com/iliya-Developer/VortexL2/main/install.sh | sudo bash
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/vortexl2"
BIN_PATH="/usr/local/bin/vortexl2"
SYSTEMD_DIR="/etc/systemd/system"
CONFIG_DIR="/etc/vortexl2"
REPO_URL="https://github.com/iliya-Developer/VortexL2.git"
REPO_BRANCH="main"

echo -e "${CYAN}"
cat << 'EOF'
 __      __        _            _     ___  
 \ \    / /       | |          | |   |__ \ 
  \ \  / /__  _ __| |_ _____  _| |      ) |
   \ \/ / _ \| '__| __/ _ \ \/ / |     / / 
    \  / (_) | |  | ||  __/>  <| |____/ /_ 
     \/ \___/|_|   \__\___/_/\_\______|____|
EOF
echo -e "${NC}"
echo -e "${GREEN}VortexL2 Installer${NC}"
echo -e "${CYAN}L2TPv3 Tunnel Manager for Ubuntu/Debian${NC}"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root (use sudo)${NC}"
    exit 1
fi

# Check OS
if ! command -v apt-get &> /dev/null; then
    echo -e "${RED}Error: This installer requires apt-get (Debian/Ubuntu)${NC}"
    exit 1
fi

echo -e "${YELLOW}[1/6] Installing system dependencies...${NC}"
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv git socat iproute2

# Install kernel modules package
KERNEL_VERSION=$(uname -r)
echo -e "${YELLOW}[2/6] Installing kernel modules for ${KERNEL_VERSION}...${NC}"
apt-get install -y -qq "linux-modules-extra-${KERNEL_VERSION}" 2>/dev/null || \
    echo -e "${YELLOW}Warning: Could not install linux-modules-extra (may already be available)${NC}"

# Load L2TP modules
echo -e "${YELLOW}[3/6] Loading L2TP kernel modules...${NC}"
modprobe l2tp_core 2>/dev/null || true
modprobe l2tp_netlink 2>/dev/null || true
modprobe l2tp_eth 2>/dev/null || true

# Ensure modules load on boot
cat > /etc/modules-load.d/vortexl2.conf << 'EOF'
l2tp_core
l2tp_netlink
l2tp_eth
EOF

echo -e "${YELLOW}[4/6] Installing VortexL2...${NC}"

# Backup existing installation
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}Backing up existing installation...${NC}"
    BACKUP_DIR="${INSTALL_DIR}.backup.$(date +%Y%m%d%H%M%S)"
    mv "$INSTALL_DIR" "$BACKUP_DIR"
    echo -e "${CYAN}Backup saved to: ${BACKUP_DIR}${NC}"
fi

# Clone or download repository
if command -v git &> /dev/null; then
    git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$INSTALL_DIR" 2>/dev/null || {
        echo -e "${YELLOW}Git clone failed, trying manual download...${NC}"
        mkdir -p "$INSTALL_DIR"
        # If git fails, try downloading as archive
        curl -fsSL "https://github.com/iliya-Developer/VortexL2/archive/refs/heads/${REPO_BRANCH}.tar.gz" | \
            tar -xz -C "$INSTALL_DIR" --strip-components=1
    }
else
    mkdir -p "$INSTALL_DIR"
    curl -fsSL "https://github.com/iliya-Developer/VortexL2/archive/refs/heads/${REPO_BRANCH}.tar.gz" | \
        tar -xz -C "$INSTALL_DIR" --strip-components=1
fi

# Install Python dependencies
echo -e "${YELLOW}[5/6] Installing Python dependencies...${NC}"
# Try apt first (works on most systems), then fallback to pip
apt-get install -y -qq python3-rich python3-yaml 2>/dev/null || {
    echo -e "${YELLOW}Apt packages not available, trying pip...${NC}"
    pip3 install --quiet --break-system-packages rich pyyaml 2>/dev/null || \
    pip3 install --quiet rich pyyaml 2>/dev/null || {
        echo -e "${RED}Failed to install Python dependencies${NC}"
        echo -e "${YELLOW}Try manually: apt install python3-rich python3-yaml${NC}"
        exit 1
    }
}

# Create launcher script
cat > "$BIN_PATH" << 'EOF'
#!/bin/bash
# VortexL2 Launcher
exec python3 /opt/vortexl2/vortexl2/main.py "$@"
EOF
chmod +x "$BIN_PATH"

# Install systemd units
echo -e "${YELLOW}[6/6] Installing systemd services...${NC}"
cp "$INSTALL_DIR/systemd/vortexl2-tunnel.service" "$SYSTEMD_DIR/"
cp "$INSTALL_DIR/systemd/vortexl2-forward@.service" "$SYSTEMD_DIR/"

# Create config directory
mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

# Reload systemd
systemctl daemon-reload

# Enable tunnel service (but don't start - needs configuration first)
systemctl enable vortexl2-tunnel.service 2>/dev/null || true

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  VortexL2 Installation Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "${CYAN}Next steps:${NC}"
echo -e "  1. Run: ${GREEN}sudo vortexl2${NC}"
echo -e "  2. Select your role (IRAN or KHAREJ)"
echo -e "  3. Configure endpoint IPs"
echo -e "  4. Create tunnel"
echo ""
echo -e "${YELLOW}Quick start:${NC}"
echo -e "  ${GREEN}sudo vortexl2${NC}       - Open management panel"
echo ""
echo -e "${CYAN}For Iran side port forwarding:${NC}"
echo -e "  Use menu option 5 to add ports like: 443,80,2053"
echo ""
echo -e "${RED}Security Note:${NC}"
echo -e "  L2TPv3 has NO encryption. For sensitive traffic,"
echo -e "  consider adding IPsec or WireGuard on top."
echo ""
