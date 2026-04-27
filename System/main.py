import os
from analyzer.protocol_analyzer import analyze_protocols
from analyzer.port_analyzer import analyze_ports
from processing.traffic_stats import generate_statistics
from visualization.graphs import plot_protocol_distribution, plot_port_usage, plot_active_ips

def main():
    if not os.path.exists("data/packets.csv"):
        print("Error: data/packets.csv not found. Run 'packet_capture/capture.py' first.")
        return

    print("Running Packet Analysis...\n")
    protocol_stats = analyze_protocols()
    port_stats = analyze_ports()

    print("\nGenerating Traffic Statistics...\n")
    stats = generate_statistics()
    
    if stats is None:
        return

    print("Total Packets:", stats["total_packets"])

    print("\nTop Source IPs:")
    print(stats["top_source_ips"])

    print("\nTop Destination IPs:")
    print(stats["top_destination_ips"])

    print("\nTop Ports:")
    print(stats["top_ports"])

    # Executing the imported graphing functions 
    print("\nGenerating visualizations...")
    plot_protocol_distribution(stats["protocol_counts"])
    plot_port_usage(stats["top_ports"])
    plot_active_ips(stats["top_source_ips"])

if __name__ == "__main__":
    main()