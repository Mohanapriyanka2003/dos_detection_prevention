#!/usr/bin/env python3
"""
DoS/DDoS Anomaly Detection System (Educational Utility)
Analyzes incoming network traffic in real-time, computing packets-per-second (PPS)
rates, active connection counts, and Shannon Entropy of source IPs to distinguish
between legitimate traffic, single-source DoS attacks, and spoofed/distributed DDoS attacks.
"""

import os
import sys
import time
import math
import socket
import struct
import threading
from collections import Counter, defaultdict

# ANSI Terminal Colors
CLR_RESET = "\033[0m"
CLR_BOLD = "\033[1m"
CLR_RED = "\033[31m"
CLR_GREEN = "\033[32m"
CLR_YELLOW = "\033[33m"
CLR_CYAN = "\033[36m"
CLR_MAGENTA = "\033[35m"
CLR_WHITE = "\033[37m"
CLR_BG_RED = "\033[41m"
CLR_BG_YELLOW = "\033[43m"

class TrafficWindow:
    def __init__(self, size_seconds=2.0):
        self.size_seconds = size_seconds
        self.packets = []  # List of tuples: (timestamp, src_ip, proto, size)
        self.lock = threading.Lock()

    def add_packet(self, src_ip, proto, size):
        now = time.time()
        with self.lock:
            self.packets.append((now, src_ip, proto, size))
            self._prune(now)

    def _prune(self, now):
        cutoff = now - self.size_seconds
        # Keep only packets within the time window
        self.packets = [p for p in self.packets if p[0] >= cutoff]

    def get_stats(self):
        now = time.time()
        with self.lock:
            self._prune(now)
            if not self.packets:
                return 0, 0.0, {}, 0.0

            total_packets = len(self.packets)
            pps = total_packets / self.size_seconds
            
            # Count packet distribution by IP
            ip_counts = Counter(p[1] for p in self.packets)
            total_bytes = sum(p[3] for p in self.packets)
            kbps = (total_bytes * 8) / (1024 * self.size_seconds)

            # Shannon Entropy Calculation for Source IPs
            entropy = 0.0
            for ip, count in ip_counts.items():
                p_x = count / total_packets
                entropy -= p_x * math.log2(p_x)

            return pps, kbps, dict(ip_counts), entropy

class DoSDetector:
    def __init__(self, interface=None, pps_threshold=200, entropy_min=1.2, entropy_max=3.8):
        self.interface = interface
        self.pps_threshold = pps_threshold
        # Low entropy suggests single-source DoS; High entropy suggests highly distributed/spoofed DDoS
        self.entropy_min = entropy_min
        self.entropy_max = entropy_max
        self.window = TrafficWindow()
        self.is_running = False
        self.alerts = []
        self.alert_lock = threading.Lock()
        self.packet_count = 0

    def add_alert(self, level, message):
        timestamp = time.strftime("%H:%M:%S")
        alert_str = f"[{timestamp}] {level}: {message}"
        with self.alert_lock:
            self.alerts.append(alert_str)
            if len(self.alerts) > 10:
                self.alerts.pop(0)

    def packet_callback(self, src_ip, proto, size):
        self.packet_count += 1
        self.window.add_packet(src_ip, proto, size)

    def raw_sniff_linux(self):
        """Sniff packets using raw sockets on Linux."""
        try:
            # AF_PACKET is Linux-specific, ETH_P_ALL (0x0003) captures all IP packets
            sniff_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            if self.interface:
                sniff_sock.bind((self.interface, 0))
        except PermissionError:
            self.add_alert(f"{CLR_BG_RED}ERROR{CLR_RESET}", "Insufficient privileges to bind raw socket. Run as root/sudo.")
            return False
        except Exception as e:
            self.add_alert(f"{CLR_BG_RED}ERROR{CLR_RESET}", f"Failed to initialize raw socket: {e}")
            return False

        while self.is_running:
            try:
                raw_data, _ = sniff_sock.recvfrom(65535)
                # Parse Ethernet Header (14 bytes)
                eth_header = raw_data[:14]
                eth_proto = socket.ntohs(struct.unpack('!6s6sH', eth_header)[2])

                # Check if it's an IP packet (0x0800)
                if eth_proto == 0x0800:
                    ip_header = raw_data[14:34]
                    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                    
                    protocol = iph[6]
                    src_ip = socket.inet_ntoa(iph[8])
                    size = len(raw_data)

                    # Protocol mappings
                    proto_name = "OTHER"
                    if protocol == 6:
                        proto_name = "TCP"
                    elif protocol == 17:
                        proto_name = "UDP"
                    elif protocol == 1:
                        proto_name = "ICMP"

                    self.packet_callback(src_ip, proto_name, size)
            except Exception:
                continue
        return True

    def run_simulated_traffic(self):
        """Fallback simulation mode for testing on non-Linux systems or standard users."""
        import random
        self.add_alert("INFO", f"Running in {CLR_CYAN}SIMULATION MODE{CLR_RESET} (Perfect for Windows/macOS testing).")
        
        # Simulated IP lists
        legit_ips = [f"192.168.1.{i}" for i in range(10, 50)]
        attacker_ip = "10.0.2.15"
        ddos_ips = [f"203.0.113.{i}" for i in range(1, 255)]

        attack_type = "NONE" # NONE, DOS_SYN, DDOS_UDP, HTTP_FLOOD
        cycle_time = 0

        while self.is_running:
            cycle_time += 1
            # Cycle through phases: Clean (15s) -> DoS (15s) -> Clean (10s) -> DDoS (15s)
            phase = cycle_time % 55
            if phase < 15:
                attack_type = "NONE"
            elif phase < 30:
                attack_type = "DOS_SYN"
            elif phase < 40:
                attack_type = "NONE"
            else:
                attack_type = "DDOS_UDP"

            # Sleep briefly depending on attack intensity
            if attack_type == "NONE":
                # Clean traffic: 5-15 packets/sec
                delay = random.uniform(0.05, 0.2)
                src = random.choice(legit_ips)
                proto = random.choice(["TCP", "UDP", "ICMP"])
                size = random.randint(64, 1500)
            elif attack_type == "DOS_SYN":
                # Single-source SYN Flood: 500+ packets/sec
                delay = random.uniform(0.001, 0.003)
                src = attacker_ip
                proto = "TCP"
                size = 64
            else: # DDOS_UDP
                # Distributed UDP Flood: 800+ packets/sec with randomized/spoofed IPs
                delay = random.uniform(0.0005, 0.002)
                src = random.choice(ddos_ips)
                proto = "UDP"
                size = 512

            self.packet_callback(src, proto, size)
            time.sleep(delay)

    def display_loop(self):
        """Displays real-time analysis console UI."""
        while self.is_running:
            # Clear terminal
            os.system('cls' if os.name == 'nt' else 'clear')
            
            pps, kbps, ip_counts, entropy = self.window.get_stats()
            
            # Print Header
            print(f"{CLR_BOLD}{CLR_CYAN}======================================================================{CLR_RESET}")
            print(f"{CLR_BOLD}{CLR_CYAN}             DoS/DDoS ANOMALY DETECTION ENGINE v1.0{CLR_RESET}")
            print(f"{CLR_BOLD}{CLR_CYAN}======================================================================{CLR_RESET}")
            print(f"Interface:      {CLR_BOLD}{self.interface or 'Simulated Net'}{CLR_RESET}")
            print(f"Total Packets:  {CLR_BOLD}{self.packet_count}{CLR_RESET}")
            print(f"Running Time:   {CLR_BOLD}{int(time.process_time())}s{CLR_RESET}")
            print(f"----------------------------------------------------------------------")
            
            # Print Live Network Metrics
            print(f"{CLR_BOLD}LIVE TRAFFIC METRICS:{CLR_RESET}")
            
            # Format PPS metric
            pps_color = CLR_GREEN
            if pps > self.pps_threshold:
                pps_color = CLR_RED
            print(f"  * Packet Rate:     {pps_color}{pps:.1f} PPS{CLR_RESET} (Threshold: {self.pps_threshold} PPS)")
            print(f"  * Bandwidth:       {CLR_YELLOW}{kbps:.2f} Kbps{CLR_RESET}")
            
            # Format Entropy metric
            # High entropy means highly distributed (DDoS). Low entropy means highly focused (DoS/single IP)
            entropy_color = CLR_GREEN
            entropy_status = "NORMAL"
            if pps > self.pps_threshold:
                if entropy < self.entropy_min:
                    entropy_color = CLR_RED
                    entropy_status = f"{CLR_BG_RED}CRITICAL: HIGHLY CONCENTRATED (Single Source DoS){CLR_RESET}"
                    self.add_alert(f"{CLR_RED}ALERT (DoS){CLR_RESET}", f"Focused flood from {max(ip_counts, key=ip_counts.get) if ip_counts else 'Unknown'} - PPS: {pps:.1f}, IP Entropy: {entropy:.2f}")
                elif entropy > self.entropy_max:
                    entropy_color = CLR_RED
                    entropy_status = f"{CLR_BG_RED}CRITICAL: HIGHLY DISTRIBUTED (Botnet / Spoofed DDoS){CLR_RESET}"
                    self.add_alert(f"{CLR_RED}ALERT (DDoS){CLR_RESET}", f"Distributed flood from {len(ip_counts)} distinct IPs - PPS: {pps:.1f}, IP Entropy: {entropy:.2f}")
            
            print(f"  * Source IP Entropy: {entropy_color}{entropy:.3f}{CLR_RESET} (Range: [{self.entropy_min:.1f} - {self.entropy_max:.1f}])")
            print(f"  * IP Distribution:   {entropy_status}")
            print(f"----------------------------------------------------------------------")

            # Top Source IPs in current window
            print(f"{CLR_BOLD}TOP SOURCE IPs (Active Window):{CLR_RESET}")
            sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            if not sorted_ips:
                print("  No active traffic detected.")
            for ip, count in sorted_ips:
                percentage = (count / sum(ip_counts.values())) * 100 if sum(ip_counts.values()) > 0 else 0
                bar_len = int(percentage / 5)
                bar = "█" * bar_len + "░" * (20 - bar_len)
                print(f"  {ip:<15} | {bar} | {count:>4} pkts ({percentage:>5.1f}%)")

            # Print Recent Alerts
            print(f"----------------------------------------------------------------------")
            print(f"{CLR_BOLD}{CLR_RED}DETECTION ENGINE ALERTS:{CLR_RESET}")
            with self.alert_lock:
                if not self.alerts:
                    print(f"  {CLR_GREEN}✔ No malicious anomalies detected in traffic.{CLR_RESET}")
                else:
                    for alert in self.alerts:
                        print(f"  {alert}")
            
            print(f"======================================================================")
            print(f"Controls: Ctrl+C to terminate detector.")
            time.sleep(1.0)

    def start(self, mode="auto"):
        self.is_running = True
        
        # Spin up display thread
        display_thread = threading.Thread(target=self.display_loop)
        display_thread.daemon = True
        display_thread.start()

        # Packet gathering logic
        if mode == "raw" or (mode == "auto" and sys.platform.startswith("linux")):
            success = self.raw_sniff_linux()
            if not success and mode == "auto":
                # Failover to simulation
                self.run_simulated_traffic()
        else:
            self.run_simulated_traffic()

    def stop(self):
        self.is_running = False

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Real-Time Network DoS Anomaly Detector")
    parser.add_argument("-i", "--interface", help="Network interface to sniff (e.g. eth0, wlan0). Requires root privileges.")
    parser.add_argument("-t", "--threshold", type=int, default=150, help="PPS anomaly threshold (default: 150)")
    parser.add_argument("-m", "--mode", choices=["raw", "sim", "auto"], default="auto", 
                        help="Network sniffing mode. 'raw' for live socket sniffing (Linux root), 'sim' for simulator, 'auto' for failover (default).")
    args = parser.parse_args()

    detector = DoSDetector(
        interface=args.interface, 
        pps_threshold=args.threshold,
        entropy_min=1.4,
        entropy_max=3.5
    )

    try:
        detector.start(mode=args.mode)
    except KeyboardInterrupt:
        detector.stop()
        print(f"\n{CLR_GREEN}Detector stopped gracefully.{CLR_RESET}")
        sys.exit(0)
