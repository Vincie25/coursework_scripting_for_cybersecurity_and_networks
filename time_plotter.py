"""Needed modules"""
import sys
from datetime import timedelta
from statistics import mean, stdev
from typing import Any
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from pcap_reader import main


def time_plot(packets: Any) -> None:
    """Analyze and visualize packet traffic over time.
       Groups packets into fixed-size time intervals
       and plots packet count per interval.
       Calculates anomaly threshold (mean + 2 standard deviations)
       and highlights it in the plot.
    """
    try:
        interval_size = timedelta(seconds=10)  # Intervall size
        start = packets[0][0]  # Start of the 1st interval
        end = start + interval_size  # End of the 1st interval
        count: int = 0
        interval_times: list = []
        interval_counts: list = []
        for ts, unused_pkt in packets:
            if ts < end:  # counting packages from start-end
                count += 1
            else:  # if ts is over end save all counts before, start new
                interval_times.append(start)
                interval_counts.append(count)
                start = end
                end = start + interval_size
                count = 1  # 1st package of new interval
    except IndexError as e:
        sys.stderr.write(f"Index error: {e}\n")
        return
    except TypeError as e:
        sys.stderr.write(f"Type error: {e}\n")
        return
    try:
        plt.plot(interval_times, interval_counts)
        # to recognize a suspiciously high number of packages
        threshold = mean(interval_counts) + 2*stdev(interval_counts)
        plt.axhline(y=threshold)
        ax = plt.gca()  # Get current axes
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
