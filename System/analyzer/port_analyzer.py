import pandas as pd

def analyze_ports(file_path="data/packets.csv"):
    try:
        data = pd.read_csv(file_path)
        port_counts = data["port"].value_counts()
        print("Port Usage:")
        print(port_counts)
        return port_counts
    except FileNotFoundError:
        print(f"Error: {file_path} not found.")
        return pd.Series()