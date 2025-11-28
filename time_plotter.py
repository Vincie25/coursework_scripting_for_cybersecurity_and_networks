import dpkt
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from pcap_reader import main


def time_plot():
    packets = main(print_out=False, break_first=False)
    data_type = 'size'
    data = {'Time':[],
            'Data to plot':[],}
    data_df = pd.DataFrame(data)
    timestamps = []
    data_to_plot = []
    for ts, pkt in packets:
        eth = pkt
        ip = eth.data
        if isinstance(ip, dpkt.ip.IP):
            data['Time'].append(ts)
            if data_type == 'size':
                data['Data to plot'].append(len(pkt))
    if data_type == 'size':
        data_df,
        plt.figure(figsize=(12, 6))
        plt.plot(data['Time'], data['Data to plot'])
        plt.xlabel("Timestamp")
        plt.ylabel("Packet Size (bytes)")
        plt.title("Packet Size over Time")
        plt.grid(True)
        plt.show()


if __name__ == "__main__":
    time_plot()
