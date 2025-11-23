"""used modules"""
import socket
from pcap_reader import main

def analyzer() -> None:
    """Analyzing readed Data"""
    packets = main(print_out=False, break_first=False)

    ## Add your code here
    for i in packets:
        eth = i
        ip = eth.data
        #tcp = ip.data
        source_ip = ip.src
        destination_ip = ip.dst
        #source_port = tcp.sport
        #destination_port = tcp.dport
        details = f"{socket.inet_ntoa(source_ip)} -> {socket.inet_ntoa(destination_ip)}"
        print(f"Connection details: {details}")

if __name__ == "__main__":
    analyzer()
