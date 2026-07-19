# CodeAlpha_NetworkSniffer

A basic Python network sniffer built for the CodeAlpha Cyber Security Internship (Task 1).
It captures live packets on the network interface and displays source/destination IPs,
protocol type, ports, and a payload preview.

## Features
- Captures live traffic using `scapy`
- Identifies protocol (TCP / UDP / ICMP / Other)
- Displays source & destination IP and ports
- Shows a safe, truncated preview of packet payload
- Prints a summary report (packet counts per protocol) when stopped

## Requirements
- Python 3.8+
- `scapy` library
- Windows: [Npcap](https://npcap.com/) installed
- Administrator (Windows) or root (Linux/Mac) privileges

## Installation
```bash
pip install scapy
```

## Usage
Windows (run terminal as Administrator):
```bash
python network_sniffer.py
```

Linux / Mac:
```bash
sudo python3 network_sniffer.py
```

Press `Ctrl+C` to stop capturing and see the summary report.

## Sample Output
```
Starting Network Sniffer... (Ctrl+C to stop)
[14:32:10] #1 | 192.168.1.5 -> 142.250.66.14 | Protocol: TCP | Src Port: 51322 -> Dst Port: 443
--------------------------------------------------------------------------------
[14:32:10] #2 | 142.250.66.14 -> 192.168.1.5 | Protocol: TCP | Src Port: 443 -> Dst Port: 51322
--------------------------------------------------------------------------------
```

## How it works
1. `scapy.sniff()` puts the network interface into promiscuous mode and captures packets.
2. Each packet is passed to a callback function (`process_packet`).
3. The IP layer is inspected for source/destination addresses and protocol number.
4. If a TCP or UDP layer is present, port numbers are extracted.
5. A short payload preview is decoded and printed (binary-safe).

## Disclaimer
This tool is built strictly for educational purposes as part of the CodeAlpha internship.
Only run it on networks you own or have explicit permission to monitor. Unauthorized packet
capture on networks you don't control may be illegal in your jurisdiction.

## Author
Eman — BSCS Student, KICSIT
