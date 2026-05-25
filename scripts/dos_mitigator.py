#!/usr/bin/env python3
"""
DoS/DDoS Mitigation Utility (Educational Security Tool)
Provides wrapper commands to manage Linux iptables rules, rate limit traffic,
restrict concurrent connections, toggle SYN cookies, and track active rules.
Supports 'dry-run' mode to show commands on non-Linux or non-root environments.
"""

import os
import sys
import subprocess
import shutil

# ANSI Terminal Colors
CLR_RESET = "\033[0m"
CLR_BOLD = "\033[1m"
CLR_RED = "\033[31m"
CLR_GREEN = "\033[32m"
CLR_YELLOW = "\033[33m"
CLR_CYAN = "\033[36m"

class LinuxMitigator:
    def __init__(self, dry_run=False):
        self.dry_run = dry_run or not self._is_linux_root()

    def _is_linux_root(self):
        """Checks if running as root on a Linux environment."""
        if sys.platform != "linux":
            return False
        return os.geteuid() == 0

    def _execute_command(self, cmd_list, display_name):
        """Executes a system shell command, or simulates it if in dry-run mode."""
        cmd_str = " ".join(cmd_list)
        if self.dry_run:
            print(f"[{CLR_YELLOW}DRY-RUN{CLR_RESET}] {display_name}:")
            print(f"  {CLR_CYAN}$ {cmd_str}{CLR_RESET}\n")
            return True, "Executed in Dry-Run mode."
        
        try:
            result = subprocess.run(
                cmd_list, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True, 
                check=True
            )
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            err_msg = e.stderr.strip() if e.stderr else str(e)
            print(f"[{CLR_RED}ERROR{CLR_RESET}] Failed to execute: {cmd_str}")
            print(f"  Details: {err_msg}\n")
            return False, err_msg
        except Exception as e:
            print(f"[{CLR_RED}ERROR{CLR_RESET}] Unexpected failure: {e}")
            return False, str(e)

    def block_ip(self, ip):
        """Blocks an IP address using iptables."""
        print(f"{CLR_BOLD}Blocking offending IP: {CLR_RED}{ip}{CLR_RESET}...")
        cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        success, msg = self._execute_command(cmd, "Blocking target IP via iptables")
        if success and not self.dry_run:
            print(f"{CLR_GREEN}✔ IP {ip} successfully blocked.{CLR_RESET}\n")
        return success

    def unblock_ip(self, ip):
        """Unblocks a previously blocked IP address."""
        print(f"{CLR_BOLD}Unblocking IP: {CLR_GREEN}{ip}{CLR_RESET}...")
        cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        success, msg = self._execute_command(cmd, "Removing IP block from iptables")
        if success and not self.dry_run:
            print(f"{CLR_GREEN}✔ IP {ip} successfully unblocked.{CLR_RESET}\n")
        return success

    def rate_limit(self, port=80, rate="30/minute", burst="100"):
        """Establishes rate-limiting for a specific destination port."""
        print(f"{CLR_BOLD}Applying rate limiting on port {port} (Rate: {rate}, Burst: {burst})...{CLR_RESET}")
        
        # Rule to drop traffic exceeding limit
        # First we allow packets matching the limit
        allow_cmd = [
            "iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port),
            "-m", "limit", "--limit", rate, "--limit-burst", str(burst), "-j", "ACCEPT"
        ]
        # Then drop the rest
        drop_cmd = [
            "iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"
        ]

        self._execute_command(allow_cmd, "Allow traffic within threshold")
        success, msg = self._execute_command(drop_cmd, "Drop excessive traffic on port")
        if success and not self.dry_run:
            print(f"{CLR_GREEN}✔ Rate limiting applied successfully on port {port}.{CLR_RESET}\n")
        return success

    def limit_connections(self, max_conns=10, port=80):
        """Restricts concurrent connections per IP using connlimit."""
        print(f"{CLR_BOLD}Limiting active TCP connections on port {port} to a maximum of {max_conns} per IP...{CLR_RESET}")
        cmd = [
            "iptables", "-A", "INPUT", "-p", "tcp", "--syn", "--dport", str(port),
            "-m", "connlimit", "--connlimit-above", str(max_conns), "-j", "REJECT", 
            "--reject-with", "tcp-reset"
        ]
        success, msg = self._execute_command(cmd, "Blocking high-concurrency connections")
        if success and not self.dry_run:
            print(f"{CLR_GREEN}✔ Connection limiting rule added to iptables.{CLR_RESET}\n")
        return success

    def toggle_syn_cookies(self, enable=True):
        """Enables/Disables TCP SYN Cookies via Linux kernel sysctl settings."""
        state_str = "Enabling" if enable else "Disabling"
        val = "1" if enable else "0"
        print(f"{CLR_BOLD}{state_str} kernel TCP SYN Cookies defense...{CLR_RESET}")
        
        cmd = ["sysctl", "-w", f"net.ipv4.tcp_syncookies={val}"]
        success, msg = self._execute_command(cmd, "Modifying system socket variables")
        if success and not self.dry_run:
            print(f"{CLR_GREEN}✔ TCP SYN Cookies toggled to {val}.{CLR_RESET}\n")
        return success

    def list_rules(self):
        """Lists active iptables rules with packet metrics."""
        print(f"{CLR_BOLD}{CLR_CYAN}======================================================================{CLR_RESET}")
        print(f"{CLR_BOLD}{CLR_CYAN}                  ACTIVE FIREWALL RULES (iptables -L -n -v)         {CLR_RESET}")
        print(f"{CLR_BOLD}{CLR_CYAN}======================================================================{CLR_RESET}")
        
        if self.dry_run:
            print(f"[{CLR_YELLOW}DRY-RUN{CLR_RESET}] Simulated Rule Output:")
            print("Chain INPUT (policy ACCEPT 1420 packets, 185K bytes)")
            print(" pkts bytes target     prot opt in     out     source               destination")
            print("    0     0 DROP       all  --  *      *       10.0.2.15            0.0.0.0/0")
            print("   14   840 REJECT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:80 flags:0x17/0x02 connlimit above 10 reject-with tcp-reset")
            print("\nTCP SYN Cookies Status:")
            print("  net.ipv4.tcp_syncookies = 1 (Active)\n")
            return

        cmd = ["iptables", "-L", "INPUT", "-n", "-v"]
        success, out = self._execute_command(cmd, "Listing active firewall filter rules")
        if success:
            print(out)
            # Fetch TCP SYN cookies status
            try:
                sc_out = subprocess.run(["sysctl", "net.ipv4.tcp_syncookies"], stdout=subprocess.PIPE, text=True)
                print(f"TCP Kernel Security Profile:\n  {sc_out.stdout.strip()}")
            except Exception:
                pass
        print(f"{CLR_CYAN}======================================================================{CLR_RESET}")

    def clear_rules(self):
        """Flushes (clears) all rules in the INPUT chain."""
        print(f"{CLR_BOLD}{CLR_YELLOW}Flushing (removing) all filter rules in the INPUT chain...{CLR_RESET}")
        cmd = ["iptables", "-F", "INPUT"]
        success, msg = self._execute_command(cmd, "Flushing firewall tables")
        if success and not self.dry_run:
            print(f"{CLR_GREEN}✔ All iptables INPUT rules have been cleared.{CLR_RESET}\n")
        return success

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Linux Network Defense and Mitigator")
    
    subparsers = parser.add_subparsers(dest="command", help="Defense operation to execute")

    # block
    block_parser = subparsers.add_parser("block", help="Block a specific IP address")
    block_parser.add_argument("ip", help="IP address to drop traffic from")

    # unblock
    unblock_parser = subparsers.add_parser("unblock", help="Unblock a specific IP address")
    unblock_parser.add_argument("ip", help="IP address to unblock")

    # limit
    limit_parser = subparsers.add_parser("limit", help="Apply connection limits or rate limits")
    limit_parser.add_argument("--conn", type=int, help="Max concurrent connections allowed per IP")
    limit_parser.add_argument("--rate", help="Rate threshold (e.g. 50/second)")
    limit_parser.add_argument("--burst", type=int, default=100, help="Rate burst size limit")
    limit_parser.add_argument("--port", type=int, default=80, help="Port to apply rules to")

    # syncookies
    sync_parser = subparsers.add_parser("syncookies", help="Enable or disable TCP SYN cookies defense")
    sync_parser.add_argument("state", choices=["on", "off"], help="State to set")

    # list
    subparsers.add_parser("list", help="List active firewall filter rules")

    # clear
    subparsers.add_parser("clear", help="Flush all active INPUT firewall rules")

    parser.add_argument("-d", "--dry-run", action="store_true", help="Force dry-run simulation mode")

    args = parser.parse_args()

    mitigator = LinuxMitigator(dry_run=args.dry_run)

    if mitigator.dry_run:
        print(f"{CLR_YELLOW}NOTE: Operating in Dry-Run mode. Real commands will NOT alter host network config.{CLR_RESET}\n")

    if args.command == "block":
        mitigator.block_ip(args.ip)
    elif args.command == "unblock":
        mitigator.unblock_ip(args.ip)
    elif args.command == "limit":
        if args.conn:
            mitigator.limit_connections(args.conn, args.port)
        if args.rate:
            mitigator.rate_limit(args.port, args.rate, args.burst)
    elif args.command == "syncookies":
        state = args.state == "on"
        mitigator.toggle_syn_cookies(state)
    elif args.command == "list":
        mitigator.list_rules()
    elif args.command == "clear":
        mitigator.clear_rules()
    else:
        parser.print_help()
