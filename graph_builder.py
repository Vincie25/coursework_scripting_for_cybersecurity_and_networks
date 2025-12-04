"""Used modules"""
import socket
import matplotlib.pyplot as plt 
import networkx as nx
from pcap_reader import main


def graph(pcap) -> None:
    """
    Generate and visualize a directed IP communication graph from a pcap packet list.

    Each packet is evaluated based on its source and destination IP address. 
    The function counts occurrences of each (src → dst) flow, constructs a 
    directed NetworkX graph where edge weights represent communication frequency, 
    and visualizes it using matplotlib. Graph statistics are printed to stdout.
    """
    counts:dict = {}
    plt.figure(figsize=(28,12))
    ## Add your code here
    for unused_ts, i in pcap:
        eth = i
        ip = eth.data
        source_ip = socket.inet_ntoa(ip.src)
        destination_ip = socket.inet_ntoa(ip.dst)
        key = (source_ip, destination_ip)
        counts[key] = counts.get(key, 0) + 1
    IP = nx.DiGraph()
    edge_list = [(src, dst, count) for (src, dst), count in counts.items()]
    IP.add_weighted_edges_from(edge_list)
    pos = nx.shell_layout(IP)
    nx.draw_networkx(IP, pos, with_labels=True, font_weight='bold')
    edge_labels = nx.get_edge_attributes(IP, 'weight')
    nx.draw_networkx_edge_labels(IP, pos, edge_labels=edge_labels)
    print(f"Anzahl Knoten: {IP.number_of_nodes()}")
    print(f"Anzahl Kanten: {IP.number_of_edges()}")
    print(f"Schwach zusammenhängend: {nx.is_weakly_connected(IP)}")
    print(f"Anzahl Komponenten: {len(list(nx.weakly_connected_components(IP)))}")
    plt.savefig("network_graph.png")
    plt.show()

if __name__ == "__main__":
    packets = main("evidence-packet-analysis.pcap", print_out=False, break_first=False)
    graph(packets)
