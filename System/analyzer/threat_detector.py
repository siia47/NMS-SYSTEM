import time
import os
import pandas as pd
from datetime import datetime

class ThreatDetector:
    def __init__(self):
        self.ip_history = {}
        self.port_scan_threshold = 15  # Distinct ports in short time
        self.flood_threshold = 1000    # Packets in short time
        self.time_window = 10          # Seconds
        self.alert_file = "data/alerts.csv"
        
    def analyze_packet(self, packet_data):
        src_ip = packet_data.get("source_ip", "Unknown")
        dst_ip = packet_data.get("destination_ip", "Unknown")
        port = packet_data.get("port", "")
        
        if src_ip == "Unknown" or not src_ip:
            return

        current_time = time.time()
        
        if src_ip not in self.ip_history:
            self.ip_history[src_ip] = {
                "packets": 0,
                "ports": set(),
                "start_time": current_time,
                "last_alert_time": 0
            }
            
        history = self.ip_history[src_ip]
        
        # Reset window if time exceeded
        if current_time - history["start_time"] > self.time_window:
            history["packets"] = 0
            history["ports"] = set()
            history["start_time"] = current_time
            
        history["packets"] += 1
        if port:
            history["ports"].add(port)
            
        # Check for attacks
        # Only alert once every few seconds per IP to avoid spamming
        if current_time - history["last_alert_time"] > 10:
            alert_type = None
            severity = "Low"
            description = ""
            
            if len(history["ports"]) >= self.port_scan_threshold:
                alert_type = "Port Scan Detected"
                severity = "High"
                description = f"IP {src_ip} accessed {len(history['ports'])} distinct ports within {self.time_window}s."
                
            elif history["packets"] >= self.flood_threshold:
                alert_type = "Traffic Flood Detected"
                severity = "Medium"
                description = f"IP {src_ip} sent {history['packets']} packets within {self.time_window}s."
                
            if alert_type:
                self.log_alert(src_ip, dst_ip, alert_type, severity, description)
                history["last_alert_time"] = current_time
                print(f"[!] THREAT ALERT: {alert_type} from {src_ip}")

    def log_alert(self, src_ip, dst_ip, alert_type, severity, description):
        alert_data = {
            "time": datetime.now(),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "alert_type": alert_type,
            "severity": severity,
            "description": description
        }
        
        os.makedirs(os.path.dirname(self.alert_file), exist_ok=True)
        df = pd.DataFrame([alert_data])
        
        if os.path.exists(self.alert_file):
            df.to_csv(self.alert_file, mode='a', header=False, index=False)
        else:
            df.to_csv(self.alert_file, index=False)