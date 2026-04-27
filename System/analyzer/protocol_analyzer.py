import pandas as pd
from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, DHCP

def identify_protocol(packet):
    if packet.haslayer(ARP):
        return "ARP"
    elif packet.haslayer(DNS):
        return "DNS"
    elif packet.haslayer(TCP):
        if packet.haslayer('HTTP'): 
            return "HTTP"
        return "TCP"
    elif packet.haslayer(UDP):
        if packet.haslayer(DHCP):
            return "DHCP"
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    return "Other"

def analyze_protocols(file_path="data/packets.csv"):
    try:
        data = pd.read_csv(file_path)
        protocol_counts = data["protocol"].value_counts()
        print("Protocol Usage:")
        print(protocol_counts)
        return protocol_counts
    except FileNotFoundError:
        print(f"Error: {file_path} not found.")
        return pd.Series()