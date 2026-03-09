import sys
from scapy.all import rdpcap, IP, TCP, UDP, ICMP

# Known suspicious ports
SUSPICIOUS_PORTS = [4444, 6667, 1337, 31337, 9001]

def analyze_pcap(file):
    print(f"\nAnalyzing file: {file}\n")
    packets = rdpcap(file)

    ips_seen = {}
    alerts = []

    for packet in packets:
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst

            # Count how many times each IP appears
            ips_seen[src] = ips_seen.get(src, 0) + 1

            # Check for suspicious ports
            if TCP in packet:
                port = packet[TCP].dport
                if port in SUSPICIOUS_PORTS:
                    alerts.append(f"ALERT: {src} -> {dst} on suspicious port {port}")

            if UDP in packet:
                port = packet[UDP].dport
                if port in SUSPICIOUS_PORTS:
                    alerts.append(f"ALERT: {src} -> {dst} on suspicious port {port}")

    # Final report
    print("Most active IPs:")
    for ip, count in sorted(ips_seen.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"   {ip} -> {count} packets")

    print("\nAlerts found:")
    if alerts:
        for alert in alerts:
            print(alert)
    else:
        print("   No alerts found.")

# Accepts any pcap file as argument or defaults to capture.pcap
if len(sys.argv) > 1:
    analyze_pcap(sys.argv[1])
else:
    analyze_pcap("capture.pcap")
