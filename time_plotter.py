"""Needed modules"""
from datetime import timedelta
from statistics import mean, stdev
import matplotlib.pyplot as plt
from pcap_reader import main

def time_plot(packets) -> None:
    """Analyzes the timestamps of all packets in the PCAP file, groups them into
    fixed-size time intervals, and visualizes the number of packets per interval
    in a line plot. This provides an overview of the network traffic volume
    over time."""
    interval_size = timedelta(seconds=5)
    start = packets[0][0]
    end = start + interval_size
    count = 0
    interval_times: list = []
    interval_counts: list = []
    for ts, unsused_pkt in packets:
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
    packet = main("evidence-packet-analysis" ,print_out=False, break_first=False)
    time_plot(packet)
