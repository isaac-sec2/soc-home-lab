# SOC Home Lab — Network Traffic Analyzer

A Python-based network traffic analyzer built for SOC (Security Operations Center) practice.

## What it does
- Reads `.pcap` files using memory-efficient streaming (PcapReader)
- Identifies the most active IPs in the network
- Detects suspicious ports commonly used by malware and C2 frameworks
- Identifies possible reverse shell connections (internal → external on suspicious port)
- Cross-references IPs against a real threat intelligence feed (100k+ known malicious IPs)
- Caches threat intel locally for 24 hours to avoid redundant downloads
- Deduplicates alerts using sets to prevent alert fatigue
- Generates structured output ready for SIEM ingestion

## Technologies
- Python 3
- Scapy
- Requests
- ipaddress (native)
- argparse (native)
- Wireshark
- Threat Intel: stamparm/ipsum

## Detection Capabilities
| Detection | Description |
|-----------|-------------|
| Suspicious Ports | Flags traffic on ports known to be used by malware and C2 frameworks |
| Reverse Shell | Detects internal IPs connecting to external IPs on suspicious ports |
| Threat Intel | Cross-references IPs against 100k+ known malicious IPs |
| Alert Deduplication | Uses sets to prevent duplicate alerts and reduce alert fatigue |

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

# Analyze a specific file
python analyzer.py capture.pcap

# Analyze file in subdirectory
python analyzer.py pcaps/capture.pcap

# Skip threat intel loading (faster, offline)
python analyzer.py --no-threat-intel capture.pcap
```

## Sample Output
```
2026-04-18 13:57:01 - INFO - Loaded 119863 IPs from cache (age: 12 minutes)
2026-04-18 13:57:01 - INFO - Analyzing file: capture.pcap
2026-04-18 13:57:02 - INFO - Analyzed 15420 packets total.

Top 5 Active IPs:
   192.168.1.8 -> 97 packets
   162.159.133.234 -> 69 packets

Alerts found (3):
   [*] ALERT: 192.168.1.8 -> 203.0.113.50 on suspicious port 4444 (Metasploit reverse shell)
   [*] REVERSE SHELL SUSPECTED: 192.168.1.8 -> 203.0.113.50 on port 4444
   [*] THREAT INTEL HIT: Known malicious IP 31.184.253.37 -> 192.168.1.8
```

## Author
Isaac | Security Analyst Student | Blue Team
Commit com:
Update: refactor analyzer with caching, deduplication and argparse
