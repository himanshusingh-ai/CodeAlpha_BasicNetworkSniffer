#Basic Network Sniffer
'''
Install Scapy:
First, install the scapy library using pip:
pip install scapy

Project Overview:
We'll create a Python script that:
Captures network traffic.
Filters and analyzes the captured packets (IP, TCP, UDP).
Displays important packet details like source/destination IP, port, and protocols.
'''

#Code Implementation:
from scapy.all import sniff, IP, TCP, UDP
import datetime

# Function to analyze the packet and extract useful information
def packet_analyzer(packet):
    # Check if packet has IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        # Get current timestamp
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Initialize protocol name
        proto_name = "Unknown"

        # Check for TCP packets
        if protocol == 6 and TCP in packet:
            proto_name = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"[{timestamp}] {proto_name} Packet: {ip_src}:{src_port} -> {ip_dst}:{dst_port}")

        # Check for UDP packets
        elif protocol == 17 and UDP in packet:
            proto_name = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"[{timestamp}] {proto_name} Packet: {ip_src}:{src_port} -> {ip_dst}:{dst_port}")

        # Otherwise, print IP packet info
        else:
            print(f"[{timestamp}] IP Packet: {ip_src} -> {ip_dst} (Protocol: {protocol})")

# Function to start the sniffer
def start_sniffer(interface="Wi-Fi"):
    print(f"[*] Starting network sniffer on interface: {interface}")
    # Start sniffing, prn calls packet_analyzer for every captured packet
    sniff(iface=interface, prn=packet_analyzer)

if __name__ == "__main__":
    # Start the sniffer on default network interface (change as per your environment)
    start_sniffer(interface="Wi-Fi")

'''
Explanation:

Libraries Used:
scapy.all: This is the core of the packet sniffer, providing methods to capture and dissect network packets.

datetime: Used to add timestamps to the captured packets.

packet_analyzer function:
This function processes each packet and extracts important information:
1. Source and destination IP addresses.
2. Source and destination ports (for TCP and UDP).
3. Protocol type (TCP, UDP, or general IP packets).
It also logs the timestamp when the packet was captured.

start_sniffer function:
This function starts the sniffer on the specified network interface (e.g., Wi-Fi).
It uses scapy.sniff() to capture live traffic and sends each packet to the packet_analyzer function.
'''
#Scapy uses the PyX library for generating PostScript (ps) and PDF dumps of packets.
#Scapy uses the cryptography library for features like TLS, WEP decryption, and IPsec.
#Scapy uses libpcap to capture network traffic at a low level,often relies on WinPcap or Npcap.
