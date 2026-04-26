from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
import pandas as pd
from datetime import datetime
import os
import psutil
import time
import sys

# Add parent directory to path so we can import analyzer
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analyzer.threat_detector import ThreatDetector

PORT_PROCESS_CACHE = {}
LAST_CACHE_UPDATE = 0
CACHE_TTL = 5 # seconds

# Instantiate the global threat detector
detector = ThreatDetector()

def get_process_for_port(port):
    global PORT_PROCESS_CACHE, LAST_CACHE_UPDATE
    
    if port is None:
        return "Unknown"
        
    current_time = time.time()
    if current_time - LAST_CACHE_UPDATE > CACHE_TTL:
        new_cache = {}
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr and getattr(conn, 'status', None) == 'ESTABLISHED':
                    try:
                        if conn.pid:
                            proc = psutil.Process(conn.pid)
                            new_cache[conn.laddr.port] = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                        pass
        except (psutil.AccessDenied, PermissionError):
            pass 
            
        PORT_PROCESS_CACHE = new_cache
        LAST_CACHE_UPDATE = current_time
        
    return PORT_PROCESS_CACHE.get(port, "Unknown")


def process_packet(packet):
    time_now = datetime.now() 
    source_ip = "Unknown"
    destination_ip = "Unknown"
    length = len(packet)
    
    # Default everything to "Others" initially
    protocol = "Others"
    port = None
    sport = None
    process_name = "Unknown"

    # 1. Check for ARP / RARP (These operate below the IP layer)
    if ARP in packet:
        source_ip = packet[ARP].psrc
        destination_ip = packet[ARP].pdst
        
        if packet[ARP].op in (1, 2):      # ARP Request/Reply
            protocol = "ARP"
        elif packet[ARP].op in (3, 4):    # RARP Request/Reply
            protocol = "RARP"
            
    # 2. Check for IP layer protocols
    elif IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        
        if TCP in packet:
            port = packet[TCP].dport
            sport = packet[TCP].sport
            
            # Identify HTTPS (Port 443) or DNS over TCP (Port 53)
            if port == 443 or sport == 443:
                protocol = "HTTPS"
            elif port == 53 or sport == 53:
                protocol = "DNS"
            else:
                protocol = "TCP"
                
        elif UDP in packet:
            port = packet[UDP].dport
            sport = packet[UDP].sport
            
            # Identify DNS (Port 53) or mDNS (Port 5353)
            if port in (53, 5353) or sport in (53, 5353):
                protocol = "DNS"
            # Identify DHCP (Ports 67 and 68) 
            elif port in (67, 68) or sport in (67, 68):
                protocol = "DHCP"
            else:
                protocol = "UDP"
                
        # ICMP IS ALREADY IDENTIFIED HERE
        elif ICMP in packet:
            protocol = "ICMP"
            
        elif packet[IP].proto == 2:
            protocol = "IGMP"

    if port is not None or sport is not None:
        p_name = get_process_for_port(port)
        if p_name == "Unknown" and sport is not None:
            p_name = get_process_for_port(sport)
        process_name = p_name

    packet_data = {
        "time": time_now,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "port": port if port is not None else "",
        "process_name": process_name,
        "length": length
    }
    
    # Run intrusion detection
    detector.analyze_packet(packet_data)
    
    print(f"Captured: {protocol} from {source_ip} to {destination_ip} (Process: {process_name})") 
    save_packet(packet_data)


def save_packet(packet_data):
    file_path = "data/packets.csv"
    # Ensure the directory exists
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
    df = pd.DataFrame([packet_data])

    if os.path.exists(file_path):
        df.to_csv(file_path, mode='a', header=False, index=False)
    else:
        df.to_csv(file_path, index=False)    


def start_capture():
    print("Starting packet capture...")
    sniff(prn=process_packet, store=False)   


if __name__ == "__main__":
    start_capture()