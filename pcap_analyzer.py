"""used modules"""
import socket
from pcap_reader import main


def analyzer(pcap) -> None:
    """Analyzing readed Data"""
    flows: dict = {}

    for unused_ts, i in pcap:
        eth = i
        ip = eth.data
        src_ip = ip.src
        dst_ip = ip.dst
        details = f"{socket.inet_ntoa(src_ip)} -> {socket.inet_ntoa(dst_ip)}"
        flows[details] = flows.get(details, 0) + 1
        sorted_flows = sorted(flows.items(), key=lambda x: x[1], reverse=True)
        for key, value in sorted_flows:
            print(f"{key} - {value}")


if __name__ == "__main__":
    PCAP = "evidence-packet-analysis.pcap"
    packets = main(PCAP, printout=False, brkfirst=False)
    analyzer(packets)
