# SOC Home Lab — Network Traffic Analyzer

A Python-based network traffic analyzer built for SOC (Security Operations Center) practice.

## What it does
- Reads `.pcap` files captured with Wireshark
- Identifies the most active IPs in the network
- Detects suspicious ports commonly used by malware
- Identifies possible reverse shell connections
- Cross-references IPs against a real threat intelligence feed (597k+ known malicious IPs)
- Generates an alert report like a SOC N1 analyst would

## Technologies
- Python 3
- Scapy
- Requests
- ipaddress (native)
- Wireshark
- Threat Intel: stamparm/ipsum

## Detection Capabilities
| Detection | Description |
|-----------|-------------|
| Suspicious Ports | Flags traffic on ports known to be used by malware |
| Reverse Shell | Detects internal IPs connecting to external IPs on suspicious ports |
| Threat Intel | Cross-references IPs against 597k+ known malicious IPs |

## Suspicious Ports Monitored

| Port | Known Usage | Severity |
|------|-------------|----------|
| 4444 | Metasploit reverse shell | High |
| 6667 | IRC botnet C2 | High |
| 1337 | Empire/CrackMapExec C2 | High |
| 31337 | Back Orifice / SliverC2 | High |
| 9001 | Tor relay | High |
| 1604 | DarkComet / AsyncRAT | High |
| 8080 | Ares C2 / Malicious Web Panel | Medium |
| 9050 | Tor SOCKS proxy | High |
| 13333 | XMRig coinminer | High |
| 55553 | Metasploit RPC | High |
| 21115 | RustDesk unauthorized RMM | High |
| 50050 | Cobalt Strike default port | High |

## How to run
```bash
pip install scapy requests
python analyzer.py capture.pcap
```

## Sample Output
```
Loading threat intelligence feed...
Loaded 597601 known malicious IPs

Analyzing file: capture.pcap

Most active IPs:
   192.168.1.8 -> 97 packets
   162.159.133.234 -> 69 packets

Alerts found:
   THREAT INTEL HIT: Known malicious IP 31.184.253.37 -> 192.168.1.8
   REVERSE SHELL SUSPECTED: 192.168.1.8 -> 203.0.113.50 on port 4444 (Metasploit reverse shell)
```

## Author
Isaac | Security Analyst Student | Blue Team
