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
from vortexl2.config import Config
from vortexl2.tunnel import TunnelManager
from vortexl2.forward import ForwardManager
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


def cmd_apply(config: Config):
    """
    Apply tunnel configuration (idempotent).
    Used by systemd service on boot.
    """
    if not config.is_configured():
        print("VortexL2: Not configured, skipping tunnel setup")
        return 0
    
    tunnel = TunnelManager(config)
    forward = ForwardManager(config)
    
    # Setup tunnel
    success, msg = tunnel.full_setup()
    print(f"Tunnel setup: {msg}")
    
    if not success:
        return 1
    
    # On Iran side, also setup forwards template and start forwards
    if config.role == "IRAN":
        success, msg = forward.install_template()
        print(f"Forward template: {msg}")
        
        if config.forwarded_ports:
            success, msg = forward.start_all_forwards()
            print(f"Port forwards: {msg}")
    
    return 0


def handle_prerequisites(config: Config, tunnel: TunnelManager):
    """Handle prerequisites installation."""
    ui.show_banner(config)
    ui.show_info("Installing prerequisites...")
    
    success, msg = tunnel.install_prerequisites()
    ui.show_output(msg, "Prerequisites Installation")
    
    if success:
        ui.show_success("Prerequisites installed successfully")
    else:
        ui.show_error(msg)
    
    ui.wait_for_enter()


def handle_configure(config: Config):
    """Handle endpoint configuration."""
    ui.show_banner(config)
    
    # First configure role if not set
    if not config.role:
        role = ui.prompt_role()
        if not role:
            return
        config.role = role
    else:
        if ui.confirm(f"Current role is {config.role}. Change it?", default=False):
            role = ui.prompt_role()
            if role:
                config.role = role
    
    # Configure IPs
    ui.prompt_endpoints(config)
    ui.wait_for_enter()


def handle_create_tunnel(config: Config, tunnel: TunnelManager):
    """Handle tunnel creation."""
    ui.show_banner(config)
    
    if not config.is_configured():
        ui.show_error("Please configure endpoints first (option 2)")
        ui.wait_for_enter()
        return
    
    # Check if tunnel exists
    if tunnel.check_tunnel_exists():
        ui.show_warning("Tunnel already exists")
        if not ui.confirm("Delete existing tunnel and recreate?", default=False):
            ui.wait_for_enter()
            return
        
        success, msg = tunnel.full_teardown()
        ui.show_output(msg, "Teardown")
    
    ui.show_info("Creating tunnel...")
    success, msg = tunnel.full_setup()
    ui.show_output(msg, "Tunnel Setup")
    
    if success:
        ui.show_success("Tunnel created successfully")
    else:
        ui.show_error("Tunnel creation failed")
    
    ui.wait_for_enter()


def handle_delete_tunnel(config: Config, tunnel: TunnelManager, forward: ForwardManager):
    """Handle tunnel deletion."""
    ui.show_banner(config)
    
    if not ui.confirm("Are you sure you want to delete the tunnel?", default=False):
        return
    
    # Stop forwards first if Iran
    if config.role == "IRAN":
        ui.show_info("Stopping port forwards...")
        success, msg = forward.stop_all_forwards()
        ui.show_output(msg, "Stop Forwards")
    
    ui.show_info("Deleting tunnel...")
    success, msg = tunnel.full_teardown()
    ui.show_output(msg, "Tunnel Teardown")
    
    if success:
        ui.show_success("Tunnel deleted successfully")
    else:
        ui.show_error("Tunnel deletion failed")
    
    ui.wait_for_enter()


def handle_forwards_menu(config: Config, forward: ForwardManager):
    """Handle port forwards submenu."""
    if config.role != "IRAN":
        ui.show_banner(config)
        ui.show_error("Port forwarding is only available on IRAN side")
        ui.wait_for_enter()
        return
    
    while True:
        ui.show_banner(config)
        
        # Show current forwards
        forwards = forward.list_forwards()
        if forwards:
            ui.show_forwards_list(forwards)
        
        choice = ui.show_forwards_menu()
        
        if choice == "0":
            break
        elif choice == "1":
            # Add forwards
            ports = ui.prompt_ports()
            if ports:
                success, msg = forward.add_multiple_forwards(ports)
                ui.show_output(msg, "Add Forwards")
            ui.wait_for_enter()
        elif choice == "2":
            # Remove forwards
            ports = ui.prompt_ports()
            if ports:
                success, msg = forward.remove_multiple_forwards(ports)
                ui.show_output(msg, "Remove Forwards")
            ui.wait_for_enter()
        elif choice == "3":
            # List forwards (already shown above)
            ui.wait_for_enter()
        elif choice == "4":
            # Restart all
            success, msg = forward.restart_all_forwards()
            ui.show_output(msg, "Restart Forwards")
            ui.wait_for_enter()
        elif choice == "5":
            # Stop all
            success, msg = forward.stop_all_forwards()
            ui.show_output(msg, "Stop Forwards")
            ui.wait_for_enter()
        elif choice == "6":
            # Start all
            success, msg = forward.start_all_forwards()
            ui.show_output(msg, "Start Forwards")
            ui.wait_for_enter()


def handle_status(config: Config, tunnel: TunnelManager, forward: ForwardManager):
    """Handle status display."""
    ui.show_banner(config)
    
    # Tunnel status
    status = tunnel.get_status()
    ui.show_status(status)
    
    # Forward status (Iran only)
    if config.role == "IRAN":
        ui.console.print()
        forwards = forward.list_forwards()
        ui.show_forwards_list(forwards)
    
    ui.wait_for_enter()


def handle_logs(config: Config):
    """Handle log viewing."""
    ui.show_banner(config)
    
    services = ["vortexl2-tunnel"]
    
    # Add forward services
    if config.role == "IRAN":
        for port in config.forwarded_ports:
            services.append(f"vortexl2-forward@{port}")
    
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


def main_menu():
    """Main interactive menu loop."""
    check_root()
    
    # Set up signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    # Clear screen before starting
    ui.clear_screen()
    
    config = Config()
    tunnel = TunnelManager(config)
    forward = ForwardManager(config)
    
    while True:
        ui.show_banner(config)
        choice = ui.show_main_menu()
        
        try:
            if choice == "0":
                ui.console.print("\n[bold green]Goodbye![/]\n")
                break
            elif choice == "1":
                handle_prerequisites(config, tunnel)
            elif choice == "2":
                handle_configure(config)
            elif choice == "3":
                handle_create_tunnel(config, tunnel)
            elif choice == "4":
                handle_delete_tunnel(config, tunnel, forward)
            elif choice == "5":
                handle_forwards_menu(config, forward)
            elif choice == "6":
                handle_status(config, tunnel, forward)
            elif choice == "7":
                handle_logs(config)
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
  apply      Apply tunnel configuration (used by systemd)
  status     Show tunnel status

Examples:
  sudo vortexl2           # Open management panel
  sudo vortexl2 apply     # Apply config (for systemd)
  sudo vortexl2 status    # Show current status
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
        config = Config()
        sys.exit(cmd_apply(config))
    else:
        main_menu()


if __name__ == "__main__":
    main()
