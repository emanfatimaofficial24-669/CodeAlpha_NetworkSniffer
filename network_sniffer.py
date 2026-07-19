"""
CodeAlpha Cyber Security Internship — Task 1: Basic Network Sniffer
Author: Eman

Description:
    Captures live network packets on the machine, parses their headers,
    and displays source/destination IPs, protocol, ports, and a snippet
    of the payload (raw data) for TCP/UDP packets.

Requirements:
    pip install scapy

Run (MUST be run with administrator/root privileges, since raw packet
capture requires elevated access to the network interface):
    Windows (as Administrator): python network_sniffer.py
    Linux/Mac:                  sudo python3 network_sniffer.py

Notes:
    - On Windows, you also need Npcap installed (https://npcap.com/)
      with "Support raw 802.11 traffic" checked during install.
    - Press Ctrl+C to stop capturing at any time.
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

# Maps protocol numbers to human-readable names.
# (IP header 'proto' field stores a number, not a name — RFC 790)
PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

# Simple counters for a summary report at the end
packet_count = 0
protocol_stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}


def get_protocol_name(proto_num):
    """Convert numeric protocol field to a readable name."""
    return PROTOCOL_MAP.get(proto_num, "OTHER")


def format_payload(packet):
    """
    Extract a short, printable preview of the payload (Raw layer).
    We only show the first 50 bytes to keep output readable, and we
    decode safely since payloads are often binary, not plain text.
    """
    if packet.haslayer(Raw):
        raw_bytes = bytes(packet[Raw].load)
        preview = raw_bytes[:50]
        try:
            text = preview.decode("utf-8", errors="replace")
        except Exception:
            text = str(preview)
        return text.replace("\n", " ").replace("\r", " ")
    return "(no payload)"


def process_packet(packet):
    """
    Callback function executed on EVERY captured packet.
    This is where we parse and display packet details.
    """
    global packet_count

    # We only care about packets that have an IP layer
    if packet.haslayer(IP):
        packet_count += 1
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto_name = get_protocol_name(ip_layer.proto)

        # Track protocol distribution for the final summary
        if proto_name in protocol_stats:
            protocol_stats[proto_name] += 1
        else:
            protocol_stats["OTHER"] += 1

        timestamp = datetime.now().strftime("%H:%M:%S")

        # Base info common to all packets
        info_line = f"[{timestamp}] #{packet_count} | {src_ip} -> {dst_ip} | Protocol: {proto_name}"

        # Add port info for TCP/UDP (ports live inside the transport layer, not IP layer)
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            info_line += f" | Src Port: {sport} -> Dst Port: {dport}"
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            info_line += f" | Src Port: {sport} -> Dst Port: {dport}"

        print(info_line)

        # Show a payload preview only if one exists
        payload_preview = format_payload(packet)
        if payload_preview != "(no payload)":
            print(f"    Payload preview: {payload_preview}")
        print("-" * 80)


def print_summary():
    """Print a summary report once sniffing stops (Ctrl+C)."""
    print("\n" + "=" * 40)
    print("CAPTURE SUMMARY")
    print("=" * 40)
    print(f"Total IP packets captured: {packet_count}")
    for proto, count in protocol_stats.items():
        print(f"  {proto}: {count}")
    print("=" * 40)


def main():
    print("Starting Network Sniffer... (Ctrl+C to stop)")
    print("Make sure you are running this with administrator/root privileges.\n")
    try:
        # count=0 means capture indefinitely until interrupted
        sniff(prn=process_packet, store=False, count=0)
    except KeyboardInterrupt:
        print_summary()
    except PermissionError:
        print("ERROR: Permission denied. Run this script as Administrator (Windows) or with sudo (Linux/Mac).")


if __name__ == "__main__":
    main()
