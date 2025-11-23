"""used modules"""
import socket
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
        ip = eth.data
        #tcp = ip.data
        source_ip = ip.src
        destination_ip = ip.dst
        #source_port = tcp.sport
        #destination_port = tcp.dport
        details_source = f"{socket.inet_ntoa(source_ip)}"
        details_destination = f"{socket.inet_ntoa(destination_ip)}"
        details = f"{details_source} -> {details_destination}"
        packets.append(details)
        if break_first:  # stop after the first packet
            break

    open_file.close()
    return packets


if __name__ == "__main__":
    packets = main(print_out=False, break_first=True)
    print(packets)
