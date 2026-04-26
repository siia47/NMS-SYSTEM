from analyzer.protocol_analyzer import analyze_protocols
from analyzer.port_analyzer import analyze_ports
from analyzer.protocol_analyzer import analyze_protocols
from analyzer.port_analyzer import analyze_ports
from processing.traffic_stats import generate_statistics
from visualization.graphs import plot_protocol_distribution
from visualization.graphs import plot_port_usage
from visualization.graphs import plot_active_ips

print("Running Packet Analysis...\n")

protocol_stats = analyze_protocols()
port_stats = analyze_ports()

print("\nGenerating Traffic Statistics...\n")

stats = generate_statistics()

print("Total Packets:", stats["total_packets"])

print("\nTop Source IPs:")
print(stats["top_source_ips"])

print("\nTop Destination IPs:")
print(stats["top_destination_ips"])

print("\nTop Ports:")
print(stats["top_ports"])
print("Running Packet Analysis...\n")

protocol_stats = analyze_protocols()
port_stats = analyze_ports()