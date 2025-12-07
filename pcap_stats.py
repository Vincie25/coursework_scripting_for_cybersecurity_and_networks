"""Used libaries"""
import sys
import dpkt
from pcap_reader import main


def stats(packets: list) -> None:
    """Compute basic protocol statistics from a list of parsed packets.
    This function iterates through all Ethernet frames, identifies IP packets,
    categorizes them by protocol, and records both the packet
    count and the timestamps of their occurrences. Additionally, it prints the
    earliest and latest timestamp for each protocol."""
    protocols: dict = {}
    try:
        for ts, pkt in packets:
            eth = pkt
            if eth.type == dpkt.ethernet.ETH_TYPE_IP:
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
    except AttributeError as e:
        sys.stderr.write(f"Invalid packet structure: {e}\n")
    except (TypeError, ValueError) as e:
        sys.stderr.write(f"Data processing error: {e}\n")
    print(f"{'Protocol':<12}"
          f"{'Count':>8}"
          f"{'First':>27}"
          f"{'Last':>27}"
          f"{'Mean Length':>15}")
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
    PCAP = "evidence-packet-analysis.pcap"
    packet = main(PCAP, printout=False, brkfirst=False)
    stats(packet)
