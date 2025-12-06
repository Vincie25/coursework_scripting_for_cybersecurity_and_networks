"""Used libaries"""
import dpkt
from pcap_reader import main


def stats(packets) ->None:
    """Compute basic protocol statistics from a list of parsed packets.
    This function iterates through all Ethernet frames, identifies IP packets,
    categorizes them by protocol (e.g. TCP, UDP, IGMP), and records both the packet
    count and the timestamps of their occurrences. Additionally, it prints the
    earliest and latest timestamp for each protocol."""
    protocols:dict = {}
    for ts, pkt in packets:
        eth = pkt
        if eth.type==dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data
            if ip.p not in protocols:
                protocols[ip.p] = {
                    "name": f"Protocol-{ip.p}",
                    "counter": 0,
                    "timestamps": [],
                    "lengths": []
                }
            protocols[ip.p]["counter"] += 1
            protocols[ip.p]["timestamps"].append(ts)
            protocols[ip.p]["lengths"].append(len(eth))
    print(f"{'Protocol':<12} {'Count':>8} {'First':>27} {'Last':>27} {'Mean Length':>15}")
    print("-" * 100)
    for unused_protocol, data in protocols.items():
        name = data['name']
        count = data['counter']
        if data["timestamps"]:
            data["timestamps"].sort()
        first = f"{data['timestamps'][0]}"
        last = f"{data['timestamps'][-1]}"
        mean = sum(data["lengths"])/len(data["lengths"])
        print(f"{name:<12} {count:>8} {first:>27} {last:>27} {mean:>12.2f}")


if __name__ == "__main__":
    packets = main("evidence-packet-analysis.pcap", print_out=False, break_first=False)
    stats(packets)
