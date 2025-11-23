import dpkt

def main(print_out=True, break_first=True) -> list:
    """Going through the ethernetframe of the 1st package"""
    pcapfile = "evidence-packet-analysis.pcap"
    open_file = open(pcapfile, "rb")
    pcap = dpkt.pcap.Reader(open_file)
    packets = []
    for unused_ts, buf in pcap:
        # each tuple contains a timestamp
        # prefixing the variable name with unused_ makes this clear and
        # avoids pylint W0612: Unused Variable warning
        eth = dpkt.ethernet.Ethernet(buf)
        if print_out:
            print(f"#<INFO> eth ethernet packet: {repr(eth)}\n")

        ip_ad = eth.data
        if print_out:
            print(f"#<INFO> eth.data: {repr(ip_ad)}")

        packets.append(eth)

        if break_first:  # stop after the first packet
            break

    open_file.close()
    return packets

if __name__ == "__main__":
    main()
