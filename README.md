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
| Port | Known Usage |
|------|------------|
| 4444 | Metasploit reverse shell |
| 6667 | IRC botnet C2 |
| 1337 | Common malware port |
| 31337 | Elite hacker port |
| 9001 | Tor relay |

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
   REVERSE SHELL SUSPECTED: 192.168.1.6 -> 255.255.255.255 on port 6667
```

## Author
Isaac | Security Analyst Student | Blue Team
```
