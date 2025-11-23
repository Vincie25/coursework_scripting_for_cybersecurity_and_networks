"""Used libaries"""
import dpkt
from pcap_reader import main
from datetime import datetime

def stats() ->None:
    packets = main(print_out=False, break_first=False)
    ipcounter = 0
    tcpcounter = 0
    udpcounter = 0
    igmcounter = 0
    tcp_timestamps: list = []
    udp_timestamps: list = []
    igm_timestamps: list = []
    for ts, pkt in packets:
        eth =  pkt
        if eth.type==dpkt.ethernet.ETH_TYPE_IP:
            ipcounter+=1
        ip =eth.data
        if ip.p==dpkt.ip.IP_PROTO_TCP:
            tcpcounter+=1
            tcp_timestamps.append(ts)
        if ip.p==dpkt.ip.IP_PROTO_UDP:
            udpcounter+=1
            udp_timestamps.append(ts)
        if ip.p==dpkt.ip.IP_PROTO_IGMP:
            igmcounter+=1
            igm_timestamps.append(ts)
    tcp_timestamps.sort()
    udp_timestamps.sort()
    igm_timestamps.sort()

    print(f"{ipcounter}")
    print(f"{tcpcounter} {tcp_timestamps[0]} {tcp_timestamps[-1]}")
    print(f"{udpcounter} {udp_timestamps[0]} {udp_timestamps[-1]}")
    print(f"{igmcounter} {igm_timestamps[0]} {igm_timestamps[-1]}")


if __name__ == "__main__":
    stats()
