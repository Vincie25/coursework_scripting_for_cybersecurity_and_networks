"""Used modules"""
import socket
import matplotlib.pyplot as plt 
import networkx as nx
from pcap_reader import main
from pcap_analyzer import analyzer


def graph() -> None:
    plt.figure(figsize=(28,12))
    packets = main(print_out=False, break_first=False)
    IP = nx.DiGraph()
    ## Add your code here
    for unused_ts, i in packets:
        eth = i
        ip = eth.data
        tcp = ip.data
        source_ip = ip.src
        destination_ip = ip.dst
        IP.add_edges_from([(socket.inet_ntoa(destination_ip), socket.inet_ntoa(source_ip))])
    nx.draw_networkx(IP, pos=nx.shell_layout(IP))
    plt.show()

if __name__ == "__main__":
    graph()
