import sys
import requests
import ipaddress
from scapy.all import rdpcap, IP, TCP, UDP, ICMP

# Known suspicious ports commonly used by malware and reverse shells
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

def load_threat_intel():
    """Downloads a list of known malicious IPs from a public threat intel feed"""
    url = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
    response = requests.get(url)
    ips = set()  # using a set for fast lookup O(1) instead of list O(n)
    for line in response.text.splitlines():
        if not line.startswith("#"):  # skip comment lines
            ip = line.split()[0]      # grab only the IP, ignore the score
            ips.add(ip)
    return ips

def is_internal(ip):
    """Returns True if the IP belongs to a private/internal network range"""
    return ipaddress.ip_address(ip).is_private

def analyze_pcap(file, threat_intel):
    """Reads a pcap file and analyzes packets for suspicious activity"""
    print(f"\nAnalyzing file: {file}\n")
    packets = rdpcap(file)  # load all packets from the pcap file

    ips_seen = {}   # dictionary to count packets per IP
    alerts = []     # list to store all generated alerts

    for packet in packets:
        if IP in packet:
            src = packet[IP].src  # source IP
            dst = packet[IP].dst  # destination IP
            if dst == "255.255.255.255":
              continue

            # count how many times each source IP appears
            ips_seen[src] = ips_seen.get(src, 0) + 1

            # check threat intel for both source and destination IPs
            if src in threat_intel:
                alerts.append(f"THREAT INTEL HIT: Known malicious IP {src} -> {dst}")
            if dst in threat_intel:
                alerts.append(f"THREAT INTEL HIT: {src} -> Known malicious IP {dst}")

            if TCP in packet:
                port = packet[TCP].dport  # destination port
                if port in SUSPICIOUS_PORTS:
                    alerts.append(f"ALERT: {src} -> {dst} on suspicious port {port}")
                # reverse shell: internal IP connecting to external IP on suspicious port
                if is_internal(src) and not is_internal(dst) and port in SUSPICIOUS_PORTS:
                    alerts.append(f"REVERSE SHELL SUSPECTED: {src} -> {dst} on port {port}")
                    

            if UDP in packet:
                port = packet[UDP].dport
                if port in SUSPICIOUS_PORTS:
                    alerts.append(f"ALERT: {src} -> {dst} on suspicious port {port}")
                if is_internal(src) and not is_internal(dst) and port in SUSPICIOUS_PORTS:
                    alerts.append(f"REVERSE SHELL SUSPECTED: {src} -> {dst} on port {port}")

    # print top 5 most active IPs sorted by packet count
    print("Most active IPs:")
    for ip, count in sorted(ips_seen.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"   {ip} -> {count} packets")

    print("\nAlerts found:")
    if alerts:
        for alert in alerts:
            print(alert)
    else:
        print("   No alerts found.")
        

# load threat intel once before analyzing
print("Loading threat intelligence feed...")
threat_intel = load_threat_intel()
print(f"Loaded {len(threat_intel)} known malicious IPs\n")

# accepts any pcap file as argument or defaults to capture.pcap
if len(sys.argv) > 1:
    analyze_pcap(sys.argv[1], threat_intel)
else:
    analyze_pcap("bah.pcap", threat_intel)
