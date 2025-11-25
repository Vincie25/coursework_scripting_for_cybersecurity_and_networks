import dpkt
import matplotlib.pyplot as plt
import socket
from pcap_reader import main


def time_plot():
    packets = main(print_out=False, break_first=False)
    data_type = 'size'
    timestamps = []
    data_to_plot = []
    for ts, pkt in packets:
        eth = pkt
        ip = eth.data
        if isinstance(ip, dpkt.ip.IP):
            timestamps.append(ts)
            if data_type == 'size':
                data_to_plot.append(len(pkt))
    if data_type == 'size':
        plt.figure(figsize=(12, 6))
        plt.plot(timestamps, data_to_plot)
        plt.xlabel("Timestamp")
        plt.ylabel("Packet Size (bytes)")
        plt.title("Packet Size over Time")
        plt.grid(True)
        plt.show()


if __name__ == "__main__":
    time_plot()
