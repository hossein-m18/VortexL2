"""
VortexL2 Source Routing Management

Handles automatic detection of public IPs and source routing setup
for secondary IPs to work with L2TP over IP encapsulation.
"""

import subprocess
import re
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass


@dataclass
class IPInfo:
    """Information about a network IP address."""
    ip: str
    interface: str
    is_main: bool = False
    
    def __str__(self):
        main_marker = " (Main)" if self.is_main else ""
        return f"{self.ip} on {self.interface}{main_marker}"


def run_command(cmd: str, timeout: int = 10) -> Tuple[bool, str, str]:
    """Execute a shell command and return (success, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return (
            result.returncode == 0,
            result.stdout.strip(),
            result.stderr.strip()
        )
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


def get_main_ip() -> Optional[str]:
    """
    Get the server's main/primary IP address.
    This is the IP used for outgoing connections by default.
    """
    success, stdout, _ = run_command(
        "ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \\K[0-9.]+'"
    )
    if success and stdout:
        return stdout.strip()
    
    # Fallback
    success, stdout, _ = run_command("hostname -I | awk '{print $1}'")
    if success and stdout:
        return stdout.strip()
    
    return None


def get_gateway() -> Optional[str]:
    """Get the default gateway IP."""
    success, stdout, _ = run_command(
        "ip route show default | grep -oP 'via \\K[0-9.]+' | head -1"
    )
    if success and stdout:
        return stdout.strip()
    return None


def get_gateway_interface() -> Optional[str]:
    """Get the interface name for the default gateway."""
    success, stdout, _ = run_command(
        "ip route show default | grep -oP 'dev \\K\\S+' | head -1"
    )
    if success and stdout:
        return stdout.strip()
    return None


def get_all_public_ips() -> List[IPInfo]:
    """
    Get all public IPv4 addresses on this server.
    Returns list of IPInfo objects with interface information.
    """
    success, stdout, _ = run_command(
        "ip -o -4 addr show scope global"
    )
    
    if not success or not stdout:
        return []
    
    main_ip = get_main_ip()
    ips = []
    
    # Parse output like: "2: eth0    inet 192.168.1.100/24 ..."
    for line in stdout.split('\n'):
        # Skip docker/virtual interfaces
        if any(skip in line for skip in ['docker', 'veth', 'br-', 'l2tp', 'tun', 'tap']):
            continue
        
        # Extract IP and interface
        match = re.search(r'(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            interface = match.group(1)
            ip = match.group(2)
            
            # Skip private/local IPs (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
            if ip.startswith('10.') or ip.startswith('192.168.'):
                continue
            if ip.startswith('172.'):
                second_octet = int(ip.split('.')[1])
                if 16 <= second_octet <= 31:
                    continue
            
            is_main = (ip == main_ip)
            ips.append(IPInfo(ip=ip, interface=interface, is_main=is_main))
    
    # Sort so main IP is first
    ips.sort(key=lambda x: (not x.is_main, x.ip))
    
    return ips


def is_secondary_ip(ip: str) -> bool:
    """Check if the given IP is a secondary (non-main) IP."""
    main_ip = get_main_ip()
    return ip != main_ip


def get_routing_table_name(tunnel_name: str) -> str:
    """Generate a unique routing table name for a tunnel."""
    # Use a simple naming scheme: vortex_<tunnel_name>
    safe_name = re.sub(r'[^a-zA-Z0-9]', '', tunnel_name)[:10]
    return f"vortex_{safe_name}"


def get_routing_table_id(tunnel_name: str) -> int:
    """
    Generate a unique routing table ID for a tunnel.
    Uses hash of tunnel name to generate ID in range 100-199.
    """
    # Simple hash to ID mapping
    hash_val = sum(ord(c) for c in tunnel_name)
    return 100 + (hash_val % 100)


def ensure_routing_table_exists(table_name: str, table_id: int) -> bool:
    """
    Ensure the routing table entry exists in /etc/iproute2/rt_tables.
    Returns True if successful.
    """
    rt_tables_file = "/etc/iproute2/rt_tables"
    
    # Check if table already exists
    success, stdout, _ = run_command(f"grep -E '^{table_id}\\s+{table_name}' {rt_tables_file}")
    if success:
        return True  # Already exists
    
    # Check if ID is already used with different name
    success, stdout, _ = run_command(f"grep -E '^{table_id}\\s' {rt_tables_file}")
    if success:
        # ID already used, try next available
        for new_id in range(100, 250):
            success, stdout, _ = run_command(f"grep -E '^{new_id}\\s' {rt_tables_file}")
            if not success:
                table_id = new_id
                break
    
    # Add entry
    success, _, stderr = run_command(
        f"echo '{table_id} {table_name}' >> {rt_tables_file}"
    )
    
    return success


def setup_source_routing(ip: str, tunnel_name: str) -> Tuple[bool, str]:
    """
    Set up source routing for a secondary IP.
    
    This creates:
    1. A routing table entry in /etc/iproute2/rt_tables
    2. A default route in that table via the gateway
    3. An ip rule to use that table for packets from the specified IP
    
    Returns (success, message).
    """
    if not is_secondary_ip(ip):
        return True, f"{ip} is main IP, no source routing needed"
    
    gateway = get_gateway()
    interface = get_gateway_interface()
    
    if not gateway:
        return False, "Could not determine default gateway"
    if not interface:
        return False, "Could not determine gateway interface"
    
    table_name = get_routing_table_name(tunnel_name)
    table_id = get_routing_table_id(tunnel_name)
    
    steps = []
    
    # Step 1: Ensure routing table exists
    if not ensure_routing_table_exists(table_name, table_id):
        return False, f"Failed to create routing table {table_name}"
    steps.append(f"Created routing table: {table_name} (id: {table_id})")
    
    # Step 2: Add default route to the table
    success, _, stderr = run_command(
        f"ip route add default via {gateway} dev {interface} table {table_name}"
    )
    if not success and "File exists" not in stderr:
        success, _, stderr = run_command(
            f"ip route replace default via {gateway} dev {interface} table {table_name}"
        )
        if not success:
            return False, f"Failed to set default route in table {table_name}: {stderr}"
    steps.append(f"Added route: default via {gateway} table {table_name}")
    
    # Step 3: Add ip rule for packets from this IP
    # First check if rule already exists
    success, stdout, _ = run_command(f"ip rule list | grep 'from {ip}'")
    if not success or table_name not in stdout:
        success, _, stderr = run_command(
            f"ip rule add from {ip} table {table_name}"
        )
        if not success and "File exists" not in stderr:
            return False, f"Failed to add routing rule: {stderr}"
    steps.append(f"Added rule: from {ip} lookup {table_name}")
    
    # Flush cache
    run_command("ip route flush cache")
    steps.append("Flushed routing cache")
    
    return True, "\n".join(steps)


def cleanup_source_routing(ip: str, tunnel_name: str) -> Tuple[bool, str]:
    """
    Remove source routing configuration for an IP.
    
    Returns (success, message).
    """
    if not ip:
        return True, "No IP to cleanup"
    
    table_name = get_routing_table_name(tunnel_name)
    steps = []
    
    # Remove ip rule
    success, _, _ = run_command(f"ip rule del from {ip} table {table_name} 2>/dev/null")
    steps.append(f"Removed rule: from {ip} lookup {table_name}")
    
    # Remove route from table
    run_command(f"ip route flush table {table_name} 2>/dev/null")
    steps.append(f"Flushed routes in table {table_name}")
    
    # Note: We don't remove the table entry from rt_tables as it's harmless
    # and might cause issues if removed while other tunnels use similar IDs
    
    # Flush cache
    run_command("ip route flush cache")
    steps.append("Flushed routing cache")
    
    return True, "\n".join(steps)


def verify_source_routing(ip: str) -> Tuple[bool, str]:
    """
    Verify that source routing is working for an IP.
    Returns (working, details).
    """
    success, stdout, _ = run_command(f"ip route get 8.8.8.8 from {ip}")
    
    if not success:
        return False, f"Failed to get route from {ip}"
    
    # Check if the source IP matches
    if f"from {ip}" not in stdout or f"src {ip}" in stdout:
        return True, stdout
    
    return False, f"Route exists but may not use correct source: {stdout}"


def get_source_routing_status(ip: str, tunnel_name: str) -> Dict:
    """
    Get detailed status of source routing for an IP.
    """
    table_name = get_routing_table_name(tunnel_name)
    
    status = {
        "ip": ip,
        "is_secondary": is_secondary_ip(ip),
        "table_name": table_name,
        "rule_exists": False,
        "route_exists": False,
        "working": False,
    }
    
    # Check rule
    success, stdout, _ = run_command(f"ip rule list | grep 'from {ip}'")
    status["rule_exists"] = success and table_name in stdout
    
    # Check route
    success, stdout, _ = run_command(f"ip route show table {table_name}")
    status["route_exists"] = success and "default" in stdout
    
    # Verify working
    if status["rule_exists"] and status["route_exists"]:
        working, _ = verify_source_routing(ip)
        status["working"] = working
    
    return status


def setup_iptables_nat(local_ip: str, remote_ip: str, tunnel_name: str) -> Tuple[bool, str]:
    """
    Setup iptables NAT rules to handle L2TP traffic for secondary IPs.
    
    This is a workaround for the kernel limitation where L2TP raw sockets
    don't properly bind to secondary IPs.
    
    Strategy:
    - SNAT outgoing L2TP packets from main IP to secondary IP
    - DNAT incoming L2TP packets from secondary IP to main IP
    """
    main_ip = get_main_ip()
    if not main_ip:
        return False, "Could not determine main IP"
    
    if local_ip == main_ip:
        return True, "Main IP used, no NAT needed"
    
    steps = []
    success_all = True
    
    # SNAT: Change source from main_ip to local_ip for outgoing L2TP to remote
    # This makes the packet appear to come from secondary IP
    snat_rule = (
        f"iptables -t nat -A POSTROUTING "
        f"-p 115 -s {main_ip} -d {remote_ip} "
        f"-j SNAT --to-source {local_ip}"
    )
    
    # First remove if exists
    run_command(snat_rule.replace("-A", "-D") + " 2>/dev/null")
    success, _, stderr = run_command(snat_rule)
    if success:
        steps.append(f"Added SNAT: {main_ip} -> {local_ip}")
    else:
        success_all = False
        steps.append(f"SNAT failed: {stderr}")
    
    # DNAT: Change destination from local_ip to main_ip for incoming L2TP
    # This routes packets destined for secondary IP to where kernel listens
    dnat_rule = (
        f"iptables -t nat -A PREROUTING "
        f"-p 115 -d {local_ip} -s {remote_ip} "
        f"-j DNAT --to-destination {main_ip}"
    )
    
    # First remove if exists
    run_command(dnat_rule.replace("-A", "-D") + " 2>/dev/null")
    success, _, stderr = run_command(dnat_rule)
    if success:
        steps.append(f"Added DNAT: {local_ip} -> {main_ip}")
    else:
        success_all = False
        steps.append(f"DNAT failed: {stderr}")
    
    return success_all, "\n".join(steps)


def cleanup_iptables_nat(local_ip: str, remote_ip: str, tunnel_name: str) -> Tuple[bool, str]:
    """
    Remove iptables NAT rules for a tunnel.
    """
    main_ip = get_main_ip()
    if not main_ip or local_ip == main_ip:
        return True, "No NAT rules to cleanup"
    
    steps = []
    
    # Remove SNAT rule
    snat_rule = (
        f"iptables -t nat -D POSTROUTING "
        f"-p 115 -s {main_ip} -d {remote_ip} "
        f"-j SNAT --to-source {local_ip} 2>/dev/null"
    )
    run_command(snat_rule)
    steps.append("Removed SNAT rule")
    
    # Remove DNAT rule
    dnat_rule = (
        f"iptables -t nat -D PREROUTING "
        f"-p 115 -d {local_ip} -s {remote_ip} "
        f"-j DNAT --to-destination {main_ip} 2>/dev/null"
    )
    run_command(dnat_rule)
    steps.append("Removed DNAT rule")
    
    return True, "\n".join(steps)


def setup_secondary_ip_tunnel(local_ip: str, remote_ip: str, tunnel_name: str) -> Tuple[bool, str]:
    """
    Complete setup for secondary IP tunnel:
    1. Source routing (for proper source IP on outgoing)
    2. IPTables NAT (for kernel binding workaround)
    """
    steps = []
    
    # Step 1: Source routing
    success, msg = setup_source_routing(local_ip, tunnel_name)
    steps.append(f"Source Routing: {msg}")
    if not success:
        return False, "\n".join(steps)
    
    # Step 2: IPTables NAT
    success, msg = setup_iptables_nat(local_ip, remote_ip, tunnel_name)
    steps.append(f"IPTables NAT: {msg}")
    if not success:
        # Roll back partial state if NAT setup failed.
        cleanup_iptables_nat(local_ip, remote_ip, tunnel_name)
        cleanup_source_routing(local_ip, tunnel_name)
        steps.append("Rollback: cleaned partial secondary-IP routing state")
        return False, "\n".join(steps)
    
    return True, "\n".join(steps)


def cleanup_secondary_ip_tunnel(local_ip: str, remote_ip: str, tunnel_name: str) -> Tuple[bool, str]:
    """
    Complete cleanup for secondary IP tunnel.
    """
    steps = []
    
    # Cleanup source routing
    success, msg = cleanup_source_routing(local_ip, tunnel_name)
    steps.append(f"Source Routing: {msg}")
    success_all = success
    
    # Cleanup iptables
    success, msg = cleanup_iptables_nat(local_ip, remote_ip, tunnel_name)
    steps.append(f"IPTables NAT: {msg}")
    success_all = success_all and success
    
    return success_all, "\n".join(steps)
