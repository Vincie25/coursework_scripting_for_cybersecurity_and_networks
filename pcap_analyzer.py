"""used modules"""
import socket
import dpkt
from pcap_reader import main

def analyzer() -> None:
    """Analyzing readed Data"""
    packets = main(print_out=False, break_first=False)
    flows:dict = {}

    ## Add your code here
    for unused_ts, i in packets:
        eth = i
        ip = eth.data
        source_ip = ip.src
        destination_ip = ip.dst
        details = f"{socket.inet_ntoa(source_ip)} -> {socket.inet_ntoa(destination_ip)}"
        flows[details] = flows.get(details, 0) + 1
        sorted_flows = sorted(flows.items(), key=lambda x: x[1], reverse=True)
        for key, value in sorted_flows:
            print(f"{key} - {value}")

if __name__ == "__main__":
    analyzer()
