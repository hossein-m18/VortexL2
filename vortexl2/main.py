#!/usr/bin/env python3
"""
VortexL2 - L2TPv3 Tunnel Manager

Main entry point and CLI handler.
"""

import sys
import os
import argparse
import subprocess
import signal

# Ensure we can import the package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vortexl2 import __version__
from vortexl2.config import TunnelConfig, ConfigManager, GlobalConfig
from vortexl2.tunnel import TunnelManager
from vortexl2.forward import get_forward_manager, get_forward_mode, set_forward_mode, ForwardManager
from vortexl2.routing import setup_secondary_ip_tunnel, cleanup_secondary_ip_tunnel, is_secondary_ip
from vortexl2 import ui


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    print("\n")
    ui.console.print("[yellow]Interrupted. Goodbye![/]")
    sys.exit(0)


def check_root():
    """Check if running as root."""
    if os.geteuid() != 0:
        ui.show_error("VortexL2 must be run as root (use sudo)")
        sys.exit(1)


def restart_forward_daemon():
    """Restart the forward daemon service to pick up config changes.
    
    Only starts HAProxy if forward mode is 'haproxy'.
    """
    mode = get_forward_mode()
    
    # Only start HAProxy if in haproxy mode
    if mode == "haproxy":
        subprocess.run(
            "systemctl start haproxy",
            shell=True,
            capture_output=True
        )
    
    # Restart the forward daemon
    subprocess.run(
        "systemctl restart vortexl2-forward-daemon",
        shell=True,
        capture_output=True
    )


def cmd_apply():
    """
    Apply all tunnel configurations (idempotent).
    Used by systemd service on boot.
    Note: Port forwarding is managed by the forward-daemon service
    """
    manager = ConfigManager()
    tunnels = manager.get_all_tunnels()
    
    if not tunnels:
        print("VortexL2: No tunnels configured, skipping")
        return 0
    
    errors = 0
    for config in tunnels:
        if not config.is_configured():
            print(f"VortexL2: Tunnel '{config.name}' not fully configured, skipping")
            continue
        
        tunnel = TunnelManager(config)
        
        # Setup tunnel
        success, msg = tunnel.full_setup()
        print(f"Tunnel '{config.name}': {msg}")
        
        if not success:
            errors += 1
            continue
    
    print("VortexL2: Tunnel setup complete. Port forwarding managed by forward-daemon service")
    return 1 if errors > 0 else 0


def handle_prerequisites():
    """Handle prerequisites installation."""
    ui.show_banner()
    ui.show_info("Installing prerequisites...")
    
    # Use temp config for prerequisites (they're system-wide)
    tunnel = TunnelManager(TunnelConfig("temp"))
    
    success, msg = tunnel.install_prerequisites()
    ui.show_output(msg, "Prerequisites Installation")
    
    if success:
        ui.show_success("Prerequisites installed successfully")
    else:
        ui.show_error(msg)
    
    ui.wait_for_enter()


def handle_create_tunnel(manager: ConfigManager):
    """Handle tunnel creation (config + start)."""
    ui.show_banner()
    
    # Ask for side first
    side = ui.prompt_tunnel_side()
    if not side:
        return
    
    # Get tunnel name
    name = ui.prompt_tunnel_name()
    if not name:
        return
    
    if manager.tunnel_exists(name):
        ui.show_error(f"Tunnel '{name}' already exists")
        ui.wait_for_enter()
        return
    
    # Create tunnel config in memory (not saved yet)
    config = manager.create_tunnel(name)
    ui.show_info(f"Tunnel '{name}' will use interface {config.interface_name}")
    
    # Configure tunnel based on side
    if not ui.prompt_tunnel_config(config, side, manager):
        # User cancelled or error - no config file was created
        ui.show_error("Configuration cancelled.")
        ui.wait_for_enter()
        return
    
    # Setup source routing + iptables BEFORE creating tunnel (critical for secondary IPs)
    if is_secondary_ip(config.local_ip):
        ui.show_info("Setting up secondary IP routing (before tunnel creation)...")
        routing_success, routing_msg = setup_secondary_ip_tunnel(
            config.local_ip, config.remote_ip, name
        )
        ui.show_output(routing_msg, "Secondary IP Setup")
        if routing_success:
            ui.show_success("Secondary IP routing configured")
            config._config["has_source_routing"] = True
        else:
            ui.show_warning("Secondary IP routing setup failed")
            ui.show_warning("Tunnel may not work correctly with this IP")
    
    # Now create tunnel
    ui.show_info("Starting tunnel...")
    tunnel = TunnelManager(config)
    success, msg = tunnel.full_setup()
    ui.show_output(msg, "Tunnel Setup")
    
    if success:
        # Only save config after successful tunnel creation
        config.save()
        ui.show_success(f"Tunnel '{name}' created and started successfully!")
    else:
        # Cleanup routing if tunnel creation failed
        if config._config.get("has_source_routing"):
            cleanup_secondary_ip_tunnel(config.local_ip, config.remote_ip, name)
        ui.show_error("Tunnel creation failed. Config not saved.")
    
    ui.wait_for_enter()


def handle_delete_tunnel(manager: ConfigManager):
    """Handle tunnel deletion (stop + remove config)."""
    ui.show_banner()
    ui.show_tunnel_list(manager)
    
    tunnels = manager.list_tunnels()
    if not tunnels:
        ui.show_warning("No tunnels to delete")
        ui.wait_for_enter()
        return
    
    selected = ui.prompt_select_tunnel(manager)
    if not selected:
        return
    
    if not ui.confirm(f"Are you sure you want to delete tunnel '{selected}'?", default=False):
        return
    
    # Stop tunnel first
    config = manager.get_tunnel(selected)
    if config:
        tunnel = TunnelManager(config)
        forward = ForwardManager(config)
        
        # Remove all port forwards from config
        if config.forwarded_ports:
            ui.show_info("Clearing port forwards from config...")
            ports_to_remove = list(config.forwarded_ports)  # Copy list since we're modifying it
            for port in ports_to_remove:
                forward.remove_forward(port)
            ui.show_success(f"Removed {len(ports_to_remove)} port forward(s) from config")
        
        # Stop tunnel
        ui.show_info("Stopping tunnel...")
        success, msg = tunnel.full_teardown()
        ui.show_output(msg, "Tunnel Teardown")
        
        # Cleanup source routing + iptables if configured
        if config._config.get("has_source_routing") and config.local_ip:
            ui.show_info("Cleaning up secondary IP routing...")
            cleanup_success, cleanup_msg = cleanup_secondary_ip_tunnel(
                config.local_ip, config.remote_ip, selected
            )
            ui.show_output(cleanup_msg, "Secondary IP Cleanup")
            if cleanup_success:
                ui.show_success("Secondary IP routing cleaned up")
            else:
                ui.show_warning("Secondary IP cleanup issues")
    
    # Delete config
    manager.delete_tunnel(selected)
    ui.show_success(f"Tunnel '{selected}' deleted")
    ui.wait_for_enter()


def handle_list_tunnels(manager: ConfigManager):
    """Handle listing all tunnels."""
    ui.show_banner()
    ui.show_tunnel_list(manager)
    ui.wait_for_enter()


def handle_edit_tunnel(manager: ConfigManager):
    """Handle editing tunnel IPs (local and remote)."""
    ui.show_banner()
    ui.show_tunnel_list(manager)
    
    tunnels = manager.list_tunnels()
    if not tunnels:
        ui.show_warning("No tunnels to edit")
        ui.wait_for_enter()
        return
    
    selected = ui.prompt_select_tunnel(manager)
    if not selected:
        return
    
    config = manager.get_tunnel(selected)
    if not config:
        ui.show_error("Tunnel not found")
        ui.wait_for_enter()
        return
    
    # Show current config
    ui.console.print(f"\n[bold white]Current Configuration for '{selected}':[/]")
    ui.console.print(f"  Local IP:  [green]{config.local_ip}[/]")
    ui.console.print(f"  Remote IP: [cyan]{config.remote_ip}[/]")
    
    # Menu for what to edit
    ui.console.print("\n[bold white]What to edit:[/]")
    ui.console.print("  [bold cyan][1][/] Change Local IP")
    ui.console.print("  [bold cyan][2][/] Change Remote IP")
    ui.console.print("  [bold cyan][3][/] Change Both IPs")
    ui.console.print("  [bold cyan][0][/] Cancel")
    
    from rich.prompt import Prompt
    choice = Prompt.ask("\n[bold cyan]Select option[/]", default="0")
    
    if choice == "0":
        return
    
    old_local_ip = config.local_ip
    old_has_routing = config._config.get("has_source_routing", False)
    
    # Edit based on choice
    if choice in ["1", "3"]:
        ui.console.print("\n[bold green]Select New Local IP:[/]")
        new_local = ui.prompt_select_local_ip(current_ip=config.local_ip)
        if new_local:
            config.local_ip = new_local
        elif choice == "1":
            return  # Cancelled
    
    if choice in ["2", "3"]:
        new_remote = ui.prompt_valid_ip(
            "\n[bold cyan]New Remote IP[/]",
            default=config.remote_ip,
            required=True
        )
        if new_remote:
            config.remote_ip = new_remote
        elif choice == "2":
            return  # Cancelled
    
    # Confirm changes
    ui.console.print(f"\n[bold white]New Configuration:[/]")
    ui.console.print(f"  Local IP:  [green]{config.local_ip}[/]")
    ui.console.print(f"  Remote IP: [cyan]{config.remote_ip}[/]")
    
    if not ui.confirm("\nApply changes and recreate tunnel?", default=True):
        # Revert changes
        config.local_ip = old_local_ip
        return
    
    # Cleanup old routing if needed
    if old_has_routing and old_local_ip:
        ui.show_info("Cleaning up old secondary IP routing...")
        cleanup_secondary_ip_tunnel(old_local_ip, config.remote_ip, selected)
    
    # Recreate tunnel with new IPs
    ui.show_info("Stopping tunnel...")
    tunnel = TunnelManager(config)
    tunnel.full_teardown()
    
    ui.show_info("Starting tunnel with new IPs...")
    success, msg = tunnel.full_setup()
    ui.show_output(msg, "Tunnel Restart")
    
    if success:
        # Setup new source routing + iptables if using secondary IP
        if is_secondary_ip(config.local_ip):
            ui.show_info("Setting up secondary IP routing...")
            routing_success, routing_msg = setup_secondary_ip_tunnel(
                config.local_ip, config.remote_ip, selected
            )
            ui.show_output(routing_msg, "Secondary IP Setup")
            if routing_success:
                ui.show_success("Secondary IP routing configured")
                config._config["has_source_routing"] = True
            else:
                ui.show_warning("Secondary IP routing setup failed")
        else:
            config._config["has_source_routing"] = False
        
        config.save()
        ui.show_success(f"Tunnel '{selected}' updated successfully!")
    else:
        ui.show_error("Tunnel restart failed")
    
    ui.wait_for_enter()


def handle_forwards_menu(manager: ConfigManager):
    """Handle port forwards submenu."""
    ui.show_banner()
    
    # Select tunnel for forwards
    config = ui.prompt_select_tunnel_for_forwards(manager)
    if not config:
        return
    
    while True:
        ui.show_banner()
        
        # Get current forward mode
        current_mode = get_forward_mode()
        
        # Get the appropriate manager based on mode
        forward = get_forward_manager(config)
        
        ui.console.print(f"[bold]Managing forwards for tunnel: [magenta]{config.name}[/][/]\n")
        
        if current_mode == "none":
            ui.console.print("[yellow]⚠ Port forwarding is DISABLED. Select option 6 to enable.[/]\n")
        else:
            ui.console.print(f"[green]Forward mode: {current_mode.upper()}[/]\n")
        
        # Show current forwards if manager is available
        if forward:
            forwards = forward.list_forwards()
            if forwards:
                ui.show_forwards_list(forwards)
        else:
            # Show config-only forwards when mode is none
            from vortexl2.haproxy_manager import HAProxyManager
            temp_manager = HAProxyManager(config)
            forwards = temp_manager.list_forwards()
            if forwards:
                ui.show_forwards_list(forwards)
        
        choice = ui.show_forwards_menu(current_mode)
        
        if choice == "0":
            break
        elif choice == "1":
            # Add forwards - require mode selection first
            if current_mode == "none":
                ui.show_error("Please select a port forward mode first! (Option 6)")
            else:
                ports = ui.prompt_ports()
                if ports:
                    # Always use HAProxyManager to add to config (it just updates YAML)
                    from vortexl2.haproxy_manager import HAProxyManager
                    config_manager = HAProxyManager(config)
                    success, msg = config_manager.add_multiple_forwards(ports)
                    ui.show_output(msg, "Add Forwards to Config")
                    restart_forward_daemon()
                    ui.show_success("Forwards added. Daemon restarted to apply changes.")
            ui.wait_for_enter()
        elif choice == "2":
            # Remove forwards (from config)
            ports = ui.prompt_ports()
            if ports:
                from vortexl2.haproxy_manager import HAProxyManager
                config_manager = HAProxyManager(config)
                success, msg = config_manager.remove_multiple_forwards(ports)
                ui.show_output(msg, "Remove Forwards from Config")
                if current_mode != "none":
                    restart_forward_daemon()
                    ui.show_success("Forwards removed. Daemon restarted to apply changes.")
            ui.wait_for_enter()
        elif choice == "3":
            # List forwards (already shown above)
            ui.wait_for_enter()
        elif choice == "4":
            # Restart daemon
            if current_mode == "none":
                ui.show_error("Port forwarding is disabled. Enable a mode first.")
            else:
                restart_forward_daemon()
                ui.show_success("Forward daemon restarted.")
            ui.wait_for_enter()
        elif choice == "5":
            # Validate and reload
            if current_mode == "none":
                ui.show_error("Port forwarding is disabled. Enable a mode first.")
            elif forward:
                ui.show_info("Validating configuration and reloading...")
                success, msg = forward.validate_and_reload()
                ui.show_output(msg, "Validate & Reload")
                if success:
                    ui.show_success("Reloaded successfully")
                else:
                    ui.show_error(msg)
            ui.wait_for_enter()
        elif choice == "6":
            # Change forward mode
            mode_choice = ui.show_forward_mode_menu(current_mode)
            new_mode = None
            if mode_choice == "1":
                new_mode = "none"
            elif mode_choice == "2":
                new_mode = "haproxy"
            elif mode_choice == "3":
                new_mode = "socat"
            
            if new_mode and new_mode != current_mode:
                # Stop and cleanup current mode before switching
                if current_mode == "haproxy":
                    ui.show_info("Stopping HAProxy forwards...")
                    if forward:
                        import asyncio
                        try:
                            asyncio.run(forward.stop_all_forwards())
                            ui.show_success("✓ HAProxy forwards stopped")
                        except Exception as e:
                            ui.show_warning(f"Could not stop HAProxy gracefully: {e}")
                    # Always stop HAProxy service when switching away from haproxy mode
                    subprocess.run("systemctl stop haproxy", shell=True, capture_output=True)
                    subprocess.run("systemctl stop vortexl2-forward-daemon", shell=True, capture_output=True)
                
                elif current_mode == "socat":
                    ui.show_info("Stopping Socat forwards...")
                    try:
                        from vortexl2.socat_manager import stop_all_socat
                        success, msg = stop_all_socat()
                        if success:
                            ui.show_success(f"✓ {msg}")
                        else:
                            ui.show_warning(msg)
                    except Exception as e:
                        ui.show_warning(f"Could not stop Socat gracefully: {e}")
                    subprocess.run("systemctl stop vortexl2-forward-daemon", shell=True, capture_output=True)
                
                # Set new mode
                set_forward_mode(new_mode)
                ui.show_success(f"Forward mode changed to: {new_mode.upper()}")
                
                # If enabling a mode, offer to start
                if new_mode != "none":
                    if ui.Confirm.ask("Start port forwarding now?", default=True):
                        restart_forward_daemon()
                        ui.show_success("Forward daemon started.")
                else:
                    # Make sure everything is stopped when going to none
                    subprocess.run("systemctl stop haproxy", shell=True, capture_output=True)
                    subprocess.run("systemctl stop vortexl2-forward-daemon", shell=True, capture_output=True)
                    ui.show_info("All port forwarding stopped.")
            ui.wait_for_enter()
        elif choice == "7":
            # Setup auto-restart cron
            from vortexl2.cron_manager import (
                get_auto_restart_status,
                add_auto_restart_cron,
                remove_auto_restart_cron
            )
            
            enabled, status = get_auto_restart_status()
            ui.console.print(f"\n[bold]Current status:[/] {status}\n")
            
            ui.console.print("[bold white]Auto-Restart Setup:[/]")
            ui.console.print("  Configure automatic restart for HAProxy port forwarding daemon")
            ui.console.print("  (Note: This only restarts port forwarding, NOT tunnels)\n")
            ui.console.print("[bold cyan]Options:[/]")
            ui.console.print("  [bold cyan][1][/] Enable with custom interval")
            ui.console.print("  [bold cyan][2][/] Disable auto-restart")
            ui.console.print("  [bold cyan][0][/] Cancel\n")
            
            cron_choice = ui.Prompt.ask("[bold cyan]Select option[/]", default="0")
            
            if cron_choice == "1":
                ui.console.print("\n[dim]Enter restart interval in minutes (e.g., 30, 60, 120)[/]")
                ui.console.print("[dim]Recommended: 60 (every hour), 30 (every 30 min)[/]")
                interval_input = ui.Prompt.ask("[bold cyan]Interval (minutes)[/]", default="60")
                
                try:
                    interval = int(interval_input)
                    if interval < 1:
                        ui.show_error("Interval must be at least 1 minute")
                    elif interval > 1440:
                        ui.show_error("Interval cannot exceed 1440 minutes (24 hours)")
                    else:
                        success, msg = add_auto_restart_cron(interval)
                        if success:
                            ui.show_success(msg)
                        else:
                            ui.show_error(msg)
                except ValueError:
                    ui.show_error(f"Invalid interval: {interval_input}. Must be a number.")
            elif cron_choice == "2":
                success, msg = remove_auto_restart_cron()
                if success:
                    ui.show_success(msg)
                else:
                    ui.show_error(msg)
            
            ui.wait_for_enter()


def handle_logs(manager: ConfigManager):
    """Handle log viewing."""
    ui.show_banner()
    
    services = [
        "vortexl2-tunnel.service",
        "vortexl2-forward-daemon.service"
    ]
    
    for service in services:
        result = subprocess.run(
            f"journalctl -u {service} -n 20 --no-pager",
            shell=True,
            capture_output=True,
            text=True
        )
        output = result.stdout or result.stderr or "No logs available"
        ui.show_output(output, f"Logs: {service}")
    
    ui.wait_for_enter()


def handle_full_cleanup(manager: ConfigManager):
    """Handle full cleanup of all VortexL2 configurations."""
    ui.show_banner()
    ui.console.print("[bold red]⚠ FULL CLEANUP ⚠[/]")
    ui.console.print("\nThis will remove:")
    ui.console.print("  • All L2TP tunnels")
    ui.console.print("  • All port forwards")
    ui.console.print("  • All iptables NAT rules (protocol 115)")
    ui.console.print("  • All vortex routing rules")
    ui.console.print("  • All config files")
    
    if not ui.confirm("\n[bold red]Are you SURE you want to remove everything?[/]", default=False):
        ui.show_info("Cleanup cancelled")
        ui.wait_for_enter()
        return
    
    output_lines = []
    
    # 1. Remove all L2TP sessions and tunnels
    ui.show_info("Removing L2TP tunnels...")
    result = subprocess.run(
        "ip l2tp show tunnel 2>/dev/null | grep -oP 'Tunnel \\K\\d+'",
        shell=True, capture_output=True, text=True
    )
    for tunnel_id in result.stdout.strip().split('\n'):
        if tunnel_id:
            # Get sessions first
            sess_result = subprocess.run(
                f"ip l2tp show session 2>/dev/null | grep 'tunnel {tunnel_id}' | grep -oP 'Session \\K\\d+'",
                shell=True, capture_output=True, text=True
            )
            for session_id in sess_result.stdout.strip().split('\n'):
                if session_id:
                    subprocess.run(f"ip l2tp del session tunnel_id {tunnel_id} session_id {session_id}",
                                   shell=True, capture_output=True)
                    output_lines.append(f"Deleted session {session_id} in tunnel {tunnel_id}")
            subprocess.run(f"ip l2tp del tunnel tunnel_id {tunnel_id}", shell=True, capture_output=True)
            output_lines.append(f"Deleted tunnel {tunnel_id}")
    
    # 2. Remove l2tpeth interfaces
    ui.show_info("Removing interfaces...")
    result = subprocess.run("ip link show | grep -oP 'l2tpeth\\d+'", shell=True, capture_output=True, text=True)
    for iface in result.stdout.strip().split('\n'):
        if iface:
            subprocess.run(f"ip link del {iface}", shell=True, capture_output=True)
            output_lines.append(f"Deleted interface {iface}")
    
    # 3. Remove vortex routing rules
    ui.show_info("Removing routing rules...")
    result = subprocess.run("ip rule list", shell=True, capture_output=True, text=True)
    for line in result.stdout.split('\n'):
        if 'vortex' in line.lower() or 'gw138' in line:
            prio = line.split(':')[0].strip()
            subprocess.run(f"ip rule del prio {prio}", shell=True, capture_output=True)
            output_lines.append(f"Deleted routing rule priority {prio}")
    
    # 4. Flush vortex routing tables
    ui.show_info("Flushing routing tables...")
    result = subprocess.run("grep -E '^[0-9]+\\s+vortex' /etc/iproute2/rt_tables 2>/dev/null",
                           shell=True, capture_output=True, text=True)
    for line in result.stdout.strip().split('\n'):
        if line:
            table = line.split()[1] if len(line.split()) > 1 else None
            if table:
                subprocess.run(f"ip route flush table {table}", shell=True, capture_output=True)
                output_lines.append(f"Flushed table {table}")
    
    # 5. Remove iptables NAT rules for L2TP (protocol 115)
    ui.show_info("Removing iptables rules...")
    for chain in ['POSTROUTING', 'PREROUTING']:
        result = subprocess.run(f"iptables -t nat -S {chain} 2>/dev/null | grep -- '-p 115'",
                               shell=True, capture_output=True, text=True)
        for line in result.stdout.strip().split('\n'):
            if line:
                del_rule = line.replace('-A', '-D', 1)
                subprocess.run(f"iptables -t nat {del_rule}", shell=True, capture_output=True)
                output_lines.append(f"Deleted {chain} L2TP rule")
    
    # 6. Remove ALL port forward iptables rules (DNAT with --to-destination)
    ui.show_info("Removing port forward iptables rules...")
    result = subprocess.run("iptables -t nat -S PREROUTING 2>/dev/null",
                           shell=True, capture_output=True, text=True)
    for line in result.stdout.strip().split('\n'):
        if line and '--to-destination' in line:
            del_rule = line.replace('-A', '-D', 1)
            subprocess.run(f"iptables -t nat {del_rule}", shell=True, capture_output=True)
            output_lines.append("Deleted port forward DNAT rule")
    
    # Also remove MASQUERADE rules for tunnel IPs
    result = subprocess.run("iptables -t nat -S POSTROUTING 2>/dev/null | grep -E '10\\.30\\.30\\.'",
                           shell=True, capture_output=True, text=True)
    for line in result.stdout.strip().split('\n'):
        if line:
            del_rule = line.replace('-A', '-D', 1)
            subprocess.run(f"iptables -t nat {del_rule}", shell=True, capture_output=True)
            output_lines.append("Deleted MASQUERADE rule")
    
    # 7. Stop HAProxy
    ui.show_info("Stopping HAProxy...")
    subprocess.run("systemctl stop haproxy 2>/dev/null", shell=True, capture_output=True)
    subprocess.run("systemctl stop vortexl2-forward-daemon 2>/dev/null", shell=True, capture_output=True)
    output_lines.append("Stopped HAProxy services")
    
    # 8. Kill ALL socat processes (not just tunnel IPs)
    ui.show_info("Killing socat processes...")
    result = subprocess.run("pkill -9 -f 'socat.*TCP' 2>/dev/null", shell=True, capture_output=True)
    subprocess.run("pkill -9 -f 'socat.*UDP' 2>/dev/null", shell=True, capture_output=True)
    output_lines.append("Killed socat processes")
    
    # 8. Delete config files
    ui.show_info("Removing config files...")
    tunnels = manager.list_tunnels()
    for tunnel_name in tunnels:
        manager.delete_tunnel(tunnel_name)
        output_lines.append(f"Deleted config: {tunnel_name}")
    
    # Flush routing cache
    subprocess.run("ip route flush cache", shell=True, capture_output=True)
    
    ui.show_output("\n".join(output_lines), "Cleanup Results")
    ui.show_success("Full cleanup completed!")
    ui.wait_for_enter()


def main_menu():
    """Main interactive menu loop."""
    check_root()
    
    # Set up signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    # Clear screen before starting
    ui.clear_screen()
    
    # Initialize config manager
    manager = ConfigManager()
    
    while True:
        ui.show_banner()
        choice = ui.show_main_menu()
        
        try:
            if choice == "0":
                ui.console.print("\n[bold green]Goodbye![/]\n")
                break
            elif choice == "1":
                handle_prerequisites()
            elif choice == "2":
                handle_create_tunnel(manager)
            elif choice == "3":
                handle_edit_tunnel(manager)
            elif choice == "4":
                handle_delete_tunnel(manager)
            elif choice == "5":
                handle_list_tunnels(manager)
            elif choice == "6":
                handle_forwards_menu(manager)
            elif choice == "7":
                handle_logs(manager)
            elif choice == "8":
                handle_full_cleanup(manager)
            else:
                ui.show_warning("Invalid option")
                ui.wait_for_enter()
        except KeyboardInterrupt:
            ui.console.print("\n[yellow]Interrupted[/]")
            continue
        except Exception as e:
            ui.show_error(f"Error: {e}")
            ui.wait_for_enter()


def main():
    """CLI entry point."""
    # Set up signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(
        description="VortexL2 - L2TPv3 Tunnel Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  (none)     Open interactive management panel
  apply      Apply all tunnel configurations (used by systemd)

Examples:
  sudo vortexl2           # Open management panel
  sudo vortexl2 apply     # Apply all tunnels (for systemd)
        """
    )
    parser.add_argument(
        'command',
        nargs='?',
        choices=['apply'],
        help='Command to run'
    )
    parser.add_argument(
        '--version', '-v',
        action='version',
        version=f'VortexL2 {__version__}'
    )
    
    args = parser.parse_args()
    
    if args.command == 'apply':
        check_root()
        sys.exit(cmd_apply())
    else:
        main_menu()


if __name__ == "__main__":
    main()
