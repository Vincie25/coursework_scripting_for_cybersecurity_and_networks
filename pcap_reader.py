"""import dpkt to read the in the frame"""
from datetime import datetime
import dpkt
def main(print_out=True, break_first=True) -> list:
    """Going through the ethernetframe of the 1st package"""
    packets = []
    try:
        pcapfile = "evidence-packet-analysis.pcap"
        open_file = open(pcapfile, "rb")
        pcap = dpkt.pcap.Reader(open_file)
        for ts, buf in pcap:
            # each tuple contains a timestamp
            # prefixing the variable name with unused_ makes this clear and
            # avoids pylint W0612: Unused Variable warning
            eth = dpkt.ethernet.Ethernet(buf)
            if print_out:
                print(f"#<INFO> eth ethernet packet: {repr(eth)}\n")

            ip_ad = eth.data
            if print_out:
                print(f"#<INFO> eth.data: {repr(ip_ad)}")

            packets.append((datetime.fromtimestamp(ts), eth))

            if break_first:  # stop after the first packet
                break    
    except IOError:
        print("File not found")
    except dpkt.UnpackError:
        print("Unable to unpack the file")
    except Exception:
        print("Parser error")
    finally:
        open_file.close()
    return packets


if __name__ == "__main__":
    main()
