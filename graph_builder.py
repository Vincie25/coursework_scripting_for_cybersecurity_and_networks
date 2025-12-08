"""Used modules"""
import sys
from typing import Any
import matplotlib.pyplot as plt
import networkx as nx
from pcap_reader import main
from pcap_analyzer import analyzer


def graph(flow: dict[str, int]) -> None:
    """
    Generate a directed IP communication graph from a pcap packet list.
    Each packet is evaluated based on its source and destination IP address.
    The function counts occurrences of each (src → dst) flow, constructs a
    directed graph where edge weights represent communication frequency,
    and visualizes it using matplotlib. Graph statistics are printed to stdout.
    """
    try:
        plt.figure(figsize=(15, 10))
        ip_graph: Any = nx.DiGraph()
        edge_list = []
        for path, count in flow.items():
            src, dst = path.split("->")
            edge_list.append((src, dst, count))
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
    flows = analyzer(packets)
    sorted_flows = sorted(flows.items(), key=lambda x: x[1], reverse=True)
    for k, v in sorted_flows:
        print(k, v)
    graph(flows)
