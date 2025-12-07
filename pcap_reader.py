"""import dpkt to read the in the frame"""
from datetime import datetime
import sys
import dpkt


def main(pcapfile: str, printout: bool = True, brkfirst: bool = True) -> list:
    """Parse a pcap file and extract timestamped Ethernet frames.

    This function opens a pcap file, iterates through its packets, and converts
    each buffer into a dpkt Ethernet object. The result is returned as a list
    of tuples containing the packet timestamp (converted to a datetime object)
    and the decoded Ethernet frame."""
    packets = []
    try:
        with open(pcapfile, "rb") as open_file:
            pcap = dpkt.pcap.Reader(open_file)
            sys.stderr.write("File opened")
            for ts, buf in pcap:
                # each tuple contains a timestamp
                # prefixing the variable name with unused_ makes this clear and
                # avoids pylint W0612: Unused Variable warning
                eth = dpkt.ethernet.Ethernet(buf)
                if printout:
                    sys.stderr.write(f"#<INFO> eth ethernet packet: {repr(eth)}\n")
                ip_ad = eth.data
                if printout:
                    sys.stderr.write(f"#<INFO> eth.data: {repr(ip_ad)}")
                packets.append((datetime.fromtimestamp(ts), eth))
                if brkfirst:  # stop after the first packet
                    break
    except IOError:
        sys.stderr.write("File not found")
    except dpkt.UnpackError:
        print("Unable to unpack the file")
    except Exception:
        sys.stderr.write("Parser error")
    finally:
        sys.stderr.write("File closed")
    return packets


if __name__ == "__main__":
    main("evidence-packet-analysis.pcap")
