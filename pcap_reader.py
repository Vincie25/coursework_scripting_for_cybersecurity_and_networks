"""import dpkt to read the in the frame"""
from datetime import datetime
import sys
from typing import Any
import dpkt


def main(pcapfile: str, printout: bool = True, brkfirst: bool = True) -> Any:
    """Parse a pcap file and extract timestamped Ethernet frames.
    This function opens a pcap file, iterates through its packets, and converts
    each buffer into a dpkt Ethernet object. The result is returned as a list
    of tuples containing the packet timestamp (converted to a datetime object)
    and the decoded Ethernet frame."""
    packets: list = []
    try:
        with open(pcapfile, "rb") as open_file:
            pcap = dpkt.pcap.Reader(open_file)
            for ts, buf in pcap:
                # each tuple contains a timestamp
                eth = dpkt.ethernet.Ethernet(buf)
                if printout:
                    sys.stderr.write(f"#<INFO> eth ethernet packet: {repr(eth)}\n")
                ip_ad = eth.data
                if printout:
                    sys.stderr.write(f"#<INFO> eth.data: {repr(ip_ad)}\n")
                packets.append((datetime.fromtimestamp(ts), eth))
                if brkfirst:  # stop after the first packet
                    break
    except IOError:
        sys.stderr.write("File not found\n")
    except dpkt.UnpackError:
        sys.stderr.write("Unable to unpack the file\n")
    except (ValueError, AttributeError) as e:
        sys.stderr.write(f"Parser error: {e}\n")
    return packets


if __name__ == "__main__":
    main("evidence-packet-analysis.pcap")
