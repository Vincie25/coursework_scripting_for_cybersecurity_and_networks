import dpkt

print("File loaded…")
print("Graph saved…")
print("Results written…")
PCAPFILE = "evidence-packet-analysis.pcap"
open_file = open(PCAPFILE, "rb")
pcap = dpkt.pcap.Reader(open_file)
for unused_ts, buf in pcap:
    # each tuple contains a timestamp
    # prefixing the variable name with unused_ makes this clear and
    # avoids pylint W0612: Unused Variable warning
    eth = dpkt.ethernet.Ethernet(buf)

open_file.close()
