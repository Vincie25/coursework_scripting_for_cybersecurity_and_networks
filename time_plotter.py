"""Needed modules"""
import sys
from datetime import timedelta
from statistics import mean, stdev
from typing import Any
import matplotlib.pyplot as plt
from pcap_reader import main


def time_plot(packets: Any) -> None:
    """Analyzes the timestamps of all packets in the file, groups them into
    fixed-size intervals, and visualizes the number of packets per interval
    in a line plot. This provides an overview of the network traffic volume
    over time."""
    try:
        interval_size = timedelta(seconds=5)
        start = packets[0][0]
        end = start + interval_size
        count: int = 0
        interval_times: list = []
        interval_counts: list[int] = []
        for ts, unused_pkt in packets:
            if ts < end:
                count += 1
            else:
                interval_times.append(start)
                interval_counts.append(count)
                start = end
                end = start + interval_size
                count = 1
    except (IndexError, TypeError) as e:
        sys.stderr.write(f"Packet processing error: {e}\n")
        return
    try:
        plt.plot(interval_times, interval_counts)
        threshold = mean(interval_counts) + 2*stdev(interval_counts)
        plt.axhline(y=threshold)
        plt.savefig("timeplot1.png")
        plt.show()
    except (IOError, ValueError) as e:
        sys.stderr.write(f"Plot creation error: {e}\n")


if __name__ == "__main__":
    PCAP = "evidence-packet-analysis.pcap"
    packet = main(PCAP, printout=False, brkfirst=False)
    time_plot(packet)
