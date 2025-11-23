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
    first_tcpts = datetime.fromtimestamp(tcp_timestamps[0])
    last_tcpts = datetime.fromtimestamp(tcp_timestamps[-1])
    first_udpts = datetime.fromtimestamp(udp_timestamps[0])
    last_udpts = datetime.fromtimestamp(udp_timestamps[-1])
    first_igmts = datetime.fromtimestamp(igm_timestamps[0])
    last_igmts = datetime.fromtimestamp(igm_timestamps[-1])

    print(f"{ipcounter}")
    print(f"{tcpcounter} {first_tcpts} {last_tcpts}")
    print(f"{udpcounter} {first_udpts} {last_udpts}")
    print(f"{igmcounter} {first_igmts} {last_igmts}")


if __name__ == "__main__":
    stats()
