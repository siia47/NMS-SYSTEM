import pandas as pd
import os

def generate_statistics(file_path="data/packets.csv"):
    if not os.path.exists(file_path):
        print(f"Error: {file_path} not found.")
        return None

    data = pd.read_csv(file_path)

    if data.empty:
        print("Warning: CSV file is empty. No stats to generate.")
        return None

    total_packets = len(data)
    protocol_counts = data["protocol"].value_counts()
    source_ip_counts = data["source_ip"].value_counts().head(5)
    destination_ip_counts = data["destination_ip"].value_counts().head(5)
    port_counts = data["port"].value_counts().head(5)

    stats = {
        "total_packets": total_packets,
        "protocol_counts": protocol_counts,
        "top_source_ips": source_ip_counts,
        "top_destination_ips": destination_ip_counts,
        "top_ports": port_counts
    }

    return stats