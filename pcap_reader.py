"""import dpkt to read the in the frame"""
from datetime import datetime
import sys
import dpkt


def main(pcapfile:str, print_out:bool=True, break_first:bool=True) -> list:
    """Going through the ethernetframe of the 1st package"""
    packets = []
    try:
        open_file = open(pcapfile, "rb")
        pcap = dpkt.pcap.Reader(open_file)
        for ts, buf in pcap:
            # each tuple contains a timestamp
            # prefixing the variable name with unused_ makes this clear and
            # avoids pylint W0612: Unused Variable warning
            eth = dpkt.ethernet.Ethernet(buf)
            if print_out:
                sys.stderr.write(f"#<INFO> eth ethernet packet: {repr(eth)}\n")

            ip_ad = eth.data
            if print_out:
                sys.stderr.write(f"#<INFO> eth.data: {repr(ip_ad)}")

            packets.append((datetime.fromtimestamp(ts), eth))

            if break_first:  # stop after the first packet
                break
    except IOError:
        sys.stderr.write("File not found")
    except dpkt.UnpackError:
        print("Unable to unpack the file")
    except Exception:
        sys.stderr.write("Parser error")
    finally:
        open_file.close()
    return packets


if __name__ == "__main__":
    main("evidence-packet-analysis.pcap")
