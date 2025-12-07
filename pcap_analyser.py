"""Main PCAP analysis script."""
from pcap_reader import main as read_pcap
from pcap_stats import stats
from pcap_analyzer import analyzer
from url_email_extractor import reader  # oder find_emails_and_images?
from graph_builder import graph
from time_plotter import time_plot


def main():
    """Run complete PCAP analysis pipeline.
    Reads evidence-packet-analysis.pcap and performs:
    1. Protocol statistics
    2. Email/URL extraction
    3. IP flow analysis
    4. Network graph generation
    5. Time-based traffic analysis
    """
    pcap_file = "evidence-packet-analysis.pcap"
    print("[STATUS] File opened...")
    print("[STATUS] Reading pcap file...")
    packets = read_pcap(pcap_file, printout=False, brkfirst=False)
    print(f"[STATUS] Read {len(packets)} packets\n")
    print("[STATUS] Generating protocol statistics...")
    stats(packets)
    print("[STATUS] Extracting emails and URLs...")
    reader(pcap_file)
    print("[STATUS] Analyzing IP flows...")
    analyzer(packets)
    print("[STATUS] Creating network graph...")
    graph(packets)
    print("[STATUS] Graph saved to network_graph.png\n")
    print("[STATUS] Creating time-based analysis...")
    time_plot(packets)
    print("[STATUS] Plot saved to timeplot1.png\n")
    print("[STATUS] File closed")
    print("[STATUS] Analysis complete!")


if __name__ == '__main__':
    main()
