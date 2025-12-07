"""Used modules"""
import socket
import sys
from typing import Any
import matplotlib.pyplot as plt
import networkx as nx
from pcap_reader import main


def graph(pcap: Any) -> None:
    """
    Generate a directed IP communication graph from a pcap packet list.
    Each packet is evaluated based on its source and destination IP address.
    The function counts occurrences of each (src → dst) flow, constructs a
    directed graph where edge weights represent communication frequency,
    and visualizes it using matplotlib. Graph statistics are printed to stdout.
    """
    try:
        counts: dict[tuple[str, str], int] = {}
        plt.figure(figsize=(20, 10))
        for unused_ts, i in pcap:
            eth = i
            ip = eth.data
            source_ip = socket.inet_ntoa(ip.src)
            destination_ip = socket.inet_ntoa(ip.dst)
            key = (source_ip, destination_ip)
            counts[key] = counts.get(key, 0) + 1
    except AttributeError as e:
        sys.stderr.write(f"Invalid packet structure: {e}\n")
        return
    except OSError as e:
        sys.stderr.write(f"IP conversion error: {e}\n")
        return
    try:
        ip_graph: Any = nx.DiGraph()
        edge_list = [(src, dst, count) for (src, dst), count in counts.items()]
        ip_graph.add_weighted_edges_from(edge_list)
        pos = nx.shell_layout(ip_graph)
        nx.draw_networkx(ip_graph, pos, with_labels=True, font_weight='bold')
        edge_labels = nx.get_edge_attributes(ip_graph, 'weight')
        nx.draw_networkx_edge_labels(ip_graph, pos, edge_labels=edge_labels)
        print(f"Nodes: {ip_graph.number_of_nodes()}")
        print(f"Edges: {ip_graph.number_of_edges()}")
        print(f"Weakly connected: {nx.is_weakly_connected(ip_graph)}")
        print(
            f"Components:{len(list(nx.weakly_connected_components(ip_graph)))}"
              )
        plt.savefig("network_graph.png")
    except IOError as e:
        sys.stderr.write(f"Failed to save graph: {e}\n")


if __name__ == "__main__":
    PCAP = "evidence-packet-analysis.pcap"
    packets = main(PCAP, printout=False, brkfirst=False)
    graph(packets)
