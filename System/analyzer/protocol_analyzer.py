from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, DHCP

def identify_protocol(packet):
    if packet.haslayer(ARP):
        return "ARP"
    elif packet.haslayer(DNS):
        return "DNS"
    elif packet.haslayer(TCP):
        if packet.haslayer('HTTP'): # Requires loading scapy.layers.http
            return "HTTP"
        return "TCP"
    elif packet.haslayer(UDP):
        if packet.haslayer(DHCP):
            return "DHCP"
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    return "Other"