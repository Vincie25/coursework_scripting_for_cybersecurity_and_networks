"""Used libaries"""
import dpkt
from pcap_reader import main


def stats(packets) ->None:
    """Compute basic protocol statistics from a list of parsed packets.

    This function iterates through all Ethernet frames, identifies IP packets,
    categorizes them by protocol (TCP, UDP, IGMP), and records both the packet
    count and the timestamps of their occurrences. Additionally, it prints the
    earliest and latest timestamp for each protocol."""
    protocols:dict = {
    dpkt.ip.IP_PROTO_TCP: {"name": "TCP", "counter": 0, "timestamps": []},
    dpkt.ip.IP_PROTO_UDP: {"name": "UDP", "counter": 0, "timestamps": []},
    dpkt.ip.IP_PROTO_IGMP: {"name": "IGMP", "counter": 0, "timestamps": []},
    dpkt.ip.IP_PROTO_ICMP: {"name": "IGMP", "counter": 0, "timestamps": []},
    dpkt.ip.IP_PROTO_ICMP6: {"name": "IGMP", "counter": 0, "timestamps": []},
    dpkt.ip.IP_PROTO_IP6: {"name": "IGMP", "counter": 0, "timestamps": []},
    }
    for ts, pkt in packets:
        eth = pkt
        if eth.type==dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data
            if ip.p in protocols:
                protocols[ip.p]["counter"]+=1
                protocols[ip.p]["timestamps"].append(ts)
        mean_value = len(pkt)
    print(f"The mean value: {mean_value}")
    for unused_protocol, data in protocols.items():
        if data["timestamps"]:
            data["timestamps"].sort()
            print(f"{data['name']}:"
                  f"{data['counter']}," 
                  f"{data['timestamps'][0]},"
                  f"{data['timestamps'][-1]}")


if __name__ == "__main__":
    packets = main("evidence-packet-analysis.pcap", print_out=False, break_first=False)
    stats(packets)
