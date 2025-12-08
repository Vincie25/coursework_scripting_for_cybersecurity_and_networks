"""Main PCAP analysis script."""
from pcap_reader import main as read_pcap
from pcap_stats import stats
from pcap_analyzer import analyzer
from url_email_extractor import reader
from graph_builder import graph
from time_plotter import time_plot


def main() -> None:
    """Run complete PCAP analysis pipeline.
    Reads evidence-packet-analysis.pcap and performs:
    1. Protocol statistics
    2. Email/URL extraction
    3. IP flow analysis
    4. Time-based traffic analysis
    5. Network graph generation
    """
    pcap_file = "evidence-packet-analysis.pcap"
    print("[STATUS] File opened...")
    print("[STATUS] Reading pcap file...")
    packets = list(read_pcap(pcap_file, printout=False, brkfirst=False))
    print(f"[STATUS] Read {len(packets)} packets\n")
    print("[STATUS] File closed")
    print("[STATUS] Extracting emails and URLs...")
    reader(packets)
    print("[STATUS] Generating protocol statistics...")
    stats(packets)
    print("[STATUS] Creating time-based analysis...")
    time_plot(packets)
    print("[STATUS] Plot saved to timeplot.png\n")
    print("[STATUS] Analyzing IP flows...")
    flow = analyzer(packets)
    print("[STATUS] Creating network graph...")
    graph(flow)
    print("[STATUS] Graph saved to network_graph.png")
    print("[STATUS] Analysis complete!")


if __name__ == '__main__':
    main()
