# SOC Home Lab — Network Traffic Analyzer

A Python-based network traffic analyzer built for SOC (Security Operations Center) practice.

## What it does
- Reads `.pcap` files captured with Wireshark
- Identifies the most active IPs in the network
- Detects suspicious ports commonly used by malware (IRC botnets, reverse shells)
- Generates a simple alert report like a SOC N1 analyst would

## Technologies
- Python 3
- Scapy
- Wireshark

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
pip install scapy
python3 analyzer.py
```

## Sample Output
```
Most active IPs:
   192.168.1.8 -> 97 packets
   162.159.133.234 -> 69 packets

Alerts found:
   ALERT: 192.168.1.6 -> 255.255.255.255 on suspicious port 6667
```

## Author
Isaac | Security Analyst Student | Blue Team
