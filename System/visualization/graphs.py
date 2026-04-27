import matplotlib.pyplot as plt

def plot_protocol_distribution(protocol_counts):
    if protocol_counts.empty:
        return
    plt.figure()
    protocol_counts.plot(kind="bar")
    plt.title("Protocol Distribution")
    plt.xlabel("Protocol")
    plt.ylabel("Number of Packets")
    plt.tight_layout()
    plt.show()

def plot_port_usage(port_counts):
    if port_counts.empty:
        return
    plt.figure()
    port_counts.plot(kind="bar")
    plt.title("Port Usage")
    plt.xlabel("Port")
    plt.ylabel("Number of Packets")
    plt.tight_layout()
    plt.show()

def plot_active_ips(source_ip_counts):
    if source_ip_counts.empty:
        return
    plt.figure()
    source_ip_counts.plot(kind="barh")
    plt.title("Top Source IP Addresses")
    plt.xlabel("Number of Packets")
    plt.ylabel("Source IP")
    plt.tight_layout()
    plt.show()