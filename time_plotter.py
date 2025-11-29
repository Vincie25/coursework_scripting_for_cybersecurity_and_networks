"""Needed modules"""
from datetime import timedelta
from statistics import mean, stdev
import matplotlib.pyplot as plt
from pcap_reader import main

def time_plot():
    packets = main(print_out=False, break_first=False)
    interval_size = timedelta(seconds=5)
    start = packets[0][0]
    end = start + interval_size
    count = 0
    interval_times = []
    interval_counts = []
    for ts, pkt in packets:
        if ts < end:
            count += 1
        else:
            interval_times.append(start)
            interval_counts.append(count)
            start = end
            end = start + interval_size
            count = 1
    plt.plot(interval_times, interval_counts)
    threshold = mean(interval_counts) + 2*stdev(interval_counts)
    plt.axhline(y=threshold)
    plt.savefig("timeplot1.png")
    plt.show()


if __name__ == "__main__":
    time_plot()
