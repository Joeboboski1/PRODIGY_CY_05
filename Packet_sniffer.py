from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
import datetime

# Define a function to process each packet
def process_packet(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        timestamp = datetime.datetime.now()

        # Determine protocol type
        if packet.haslayer(TCP):
            protocol_type = "TCP"
        elif packet.haslayer(UDP):
            protocol_type = "UDP"
        elif packet.haslayer(ICMP):
            protocol_type = "ICMP"
        else:
            protocol_type = "Other"

        # Extract payload data (may contain sensitive information, use responsibly)
        payload = bytes(packet[IP].payload).decode('utf-8', errors='replace')

        # Display packet information
        print(f"Timestamp: {timestamp}")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {protocol_type}")
        print(f"Payload Data: {payload}")
        print("-" * 50)

# Start sniffing packets
print("Starting packet capture...")
sniff(filter="ip", prn=process_packet, store=False)