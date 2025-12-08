"""Used libaries"""
import sys
from typing import Any
import dpkt  # type: ignore[import-untyped]
from pcap_reader import main


def stats(packets: Any) -> None:
    """Compute and display protocol statistics from parsed packets.
       Analyzes all Ethernet frames, identifies IP packets,
       and categorizes them adaptively by protocol.
       For each protocol, calculates packet count, first/last timestamps,
       and mean packet length. Results are displayed in
       tabular format.
    """
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
    except TypeError as e:
        sys.stderr.write(f"Data processing TypeError: invalid data type {e}\n")
    except ValueError as e:
        sys.stderr.write(f"Data processing ValueError: invalid value {e}\n")
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
