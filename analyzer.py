import argparse
import sys
import requests
import ipaddress
import logging
import json
from pathlib import Path
from typing import Set, Dict
from collections import defaultdict
from datetime import datetime, timedelta
from scapy.all import PcapReader, IP, TCP, UDP

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Constants
THREAT_INTEL_CACHE_FILE = Path("threat_intel_cache.json")
THREAT_INTEL_CACHE_HOURS = 24  # Cache for 24 hours

SUSPICIOUS_PORTS = {
    4444: "Metasploit reverse shell",
    6667: "IRC botnet C2",
    1337: "Empire/CrackMapExec C2",
    31337: "Back Orifice/SliverC2",
    9001: "Tor relay",
    1604: "DarkComet/AsyncRAT",
    8080: "Ares C2 / Malicious Web Panel",
    9050: "Tor SOCKS proxy",
    13333: "XMRig coinminer",
    55553: "Metasploit RPC",
    21115: "RustDesk unauthorized RMM",
    50050: "Cobalt Strike default port"
}

def load_threat_intel() -> Set[str]:
    """Loads threat intel from cache or downloads from public feed with error handling."""
    # Try loading from cache first
    if THREAT_INTEL_CACHE_FILE.exists():
        try:
            with open(THREAT_INTEL_CACHE_FILE, "r") as f:
                cache_data = json.load(f)
                cache_time = datetime.fromisoformat(cache_data["timestamp"])
                
                if datetime.now() - cache_time < timedelta(hours=THREAT_INTEL_CACHE_HOURS):
                    ips = set(cache_data["ips"])
                    logging.info(f"Loaded {len(ips)} IPs from cache (age: {(datetime.now() - cache_time).seconds // 60} minutes)")
                    return ips
        except (json.JSONDecodeError, KeyError) as e:
            logging.warning(f"Cache corrupted: {e}. Downloading fresh data...")
    
    # Download threat intelligence feeds
    url = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
    ips = set()
    
    try:
        logging.info("Downloading threat intelligence feed...")
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        for line in response.text.splitlines():
            if line and not line.startswith("#"):
                ip = line.split()[0]
                if _validate_ip(ip):
                    ips.add(ip)
        
        # Save to cache
        try:
            with open(THREAT_INTEL_CACHE_FILE, "w") as f:
                json.dump({
                    "timestamp": datetime.now().isoformat(),
                    "ips": list(ips)
                }, f)
        except IOError as e:
            logging.warning(f"Could not save cache: {e}")
                
        logging.info(f"Loaded {len(ips)} known malicious IPs.")
    except requests.RequestException as e:
        logging.error(f"[!] Error downloading threat intel: {e}")
        logging.error("Continuing without threat intel validation...")
        
    return ips

def _validate_ip(ip: str) -> bool:
    """Validates if a string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_internal(ip: str) -> bool:
    """Returns True if the IP belongs to a private/internal network range."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False  # Handles malformed or unusual IPv6 addresses in PCAP

def analyze_pcap(file_path: str, threat_intel: Set[str]) -> Dict[str, any]:
    """Reads a pcap file and analyzes packets for suspicious activity."""
    file_path = Path(file_path)
    logging.info(f"Analyzing file: {file_path}")
    
    ips_seen: Dict[str, int] = defaultdict(int)  # More Pythonic approach
    alerts = set()  # Using SET to avoid "Alert Fatigue" (duplicate alerts)
    packet_count = 0

    try:
        with PcapReader(str(file_path)) as packets:
            for packet in packets:
                if IP not in packet:
                    continue
                
                packet_count += 1
                src = packet[IP].src
                dst = packet[IP].dst
                
                if dst == "255.255.255.255":
                    continue

                ips_seen[src] += 1  # defaultdict auto-initializes

                # Threat Intel Check
                if src in threat_intel:
                    alerts.add(f"THREAT INTEL HIT: Known malicious IP {src} -> {dst}")
                if dst in threat_intel:
                    alerts.add(f"THREAT INTEL HIT: {src} -> Known malicious IP {dst}")

                # Port Check (checks both TCP and UDP, does not break on first match)
                for proto in (TCP, UDP):
                    if proto in packet:
                        port = packet[proto].dport
                        if port in SUSPICIOUS_PORTS:
                            threat_name = SUSPICIOUS_PORTS[port]
                            alerts.add(f"ALERT: {src} -> {dst} on suspicious port {port} ({threat_name})")
                            
                            # Reverse shell logic
                            if is_internal(src) and not is_internal(dst):
                                alerts.add(f"REVERSE SHELL SUSPECTED: {src} -> {dst} on port {port}")
                        
    except FileNotFoundError:
        logging.error(f"[!] Error: PCAP file '{file_path}' not found.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"[!] Unexpected error reading PCAP: {e}")
        sys.exit(1)

    # Output Results
    logging.info(f"\nAnalyzed {packet_count} packets total.\n")
    print("Top 5 Active IPs:")
    for ip, count in sorted(ips_seen.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"   {ip} -> {count} packets")

    print(f"\nAlerts found ({len(alerts)}):")
    if alerts:
        for alert in sorted(alerts):
            print(f"   [*] {alert}")
    else:
        print("   [+] No alerts found.")
    
    return {"packet_count": packet_count, "alerts": len(alerts), "unique_ips": len(ips_seen)}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="PCAP Network Traffic Analyzer - Detects suspicious activity and malware signatures",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  python analyzer2.py capture.pcap\n  python analyzer2.py --no-threat-intel capture.pcap"
    )
    parser.add_argument("pcap_file", nargs="?", default="capture2.pcap", help="Path to the PCAP file (default: capture2.pcap)")
    parser.add_argument("--no-threat-intel", action="store_true", help="Skip threat intelligence loading")
    args = parser.parse_args()

    threat_intel = load_threat_intel() if not args.no_threat_intel else set()
    analyze_pcap(args.pcap_file, threat_intel)
