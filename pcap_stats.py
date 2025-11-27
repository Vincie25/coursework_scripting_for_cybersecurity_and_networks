"""Used libaries"""
import dpkt
from pcap_reader import main


def stats() ->None:
    """total amount of packages and there type"""
    packets = main(print_out=False, break_first=False)
    protocols = {
    dpkt.ip.IP_PROTO_TCP: {
        "name": "TCP",
        "counter": 0,
        "timestamps": []
    },
    dpkt.ip.IP_PROTO_UDP: {
        "name": "UDP",
        "counter": 0,
        "timestamps": []
    },
    dpkt.ip.IP_PROTO_IGMP: {
        "name": "IGMP",
        "counter": 0,
        "timestamps": []
    } }
    for ts, pkt in packets:
        eth = pkt
        if eth.type==dpkt.ethernet.ETH_TYPE_IP:
            ip =eth.data
            if ip.p in protocols:
                protocols[ip.p]["counter"]+=1
                protocols[ip.p]["timestamps"].append(ts)
    mean_value = len(pkt)
    print(f"The mean value: {mean_value}")
    for protocol, data in protocols.items():
        if data["timestamps"]:
            data["timestamps"].sort()
            print(f"{data['name']}: {data['counter']}, {data['timestamps'][0]}, {data['timestamps'][-1]}")

if __name__ == "__main__":
    stats()
