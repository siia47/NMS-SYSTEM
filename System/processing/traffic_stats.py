import pandas as pd
def generate_statistics(file_path="data/packets.csv"):

    data = pd.read_csv(file_path)

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