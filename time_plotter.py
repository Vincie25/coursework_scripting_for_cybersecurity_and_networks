"""Needed modules"""
import sys
from datetime import timedelta
from statistics import mean, stdev
from typing import Any
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from pcap_reader import main


def time_plot(packets: Any) -> None:
    """Analyzes the timestamps of all packets in the file, groups them into
    fixed-size intervals, and visualizes the number of packets per interval
    in a line plot. This provides an overview of the network traffic volume
    over time."""
    try:
        interval_size = timedelta(seconds=10)
        start = packets[0][0]
        end = start + interval_size
        count: int = 0
        interval_times: list = []
        interval_counts: list = []
        for ts, unused_pkt in packets:
            if ts < end:
                count += 1
            else:
                interval_times.append(start)
                interval_counts.append(count)
                start = end
                end = start + interval_size
                count = 1
    except IndexError as e:
        sys.stderr.write(f"Index error: {e}\n")
        return
    except TypeError as e:
        sys.stderr.write(f"Type error: {e}\n")
        return
    try:
        plt.plot(interval_times, interval_counts)
        threshold = mean(interval_counts) + 2*stdev(interval_counts)
        plt.axhline(y=threshold)
        ax = plt.gca()
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        ax.xaxis.set_major_locator(mdates.SecondLocator(interval=25))
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig("timeplot.png")
    except IOError as e:
        sys.stderr.write(f"Plot creation error: {e}\n")
    except ValueError as e:
        sys.stderr.write(f"Value error: {e}")


if __name__ == "__main__":
    PCAP = "evidence-packet-analysis.pcap"
    packet = main(PCAP, printout=False, brkfirst=False)
    time_plot(packet)
