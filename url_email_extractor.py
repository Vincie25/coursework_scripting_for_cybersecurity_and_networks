"""Used module"""
import os
import re
import dpkt


def find_emails_and_images(pcap) -> tuple[set, set, set, set]:
    """in current form, finds any gif files downloaded and prints
       request source (Downloader), gif URI and destination (provider) IP"""
    to_emails = set()
    from_emails = set()
    image_urls = set()
    image_filenames = set()
    for (unused_time_s, buf) in pcap:
        try:
            ip_ad = dpkt.ethernet.Ethernet(buf).data
            if not isinstance(ip_ad, dpkt.ip.IP):
                continue
            tcp = ip_ad.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            uri = ""
            filename = ""
            # HTTP parsing
            if tcp.dport == 80:
                http = dpkt.http.Request(tcp.data)
                if http.method == "GET":
                    uri = http.uri
                if uri and re.search(r"\.(jpg|jpeg|gif|png)($|\?)",
                                     uri, re.IGNORECASE):
                    host = http.headers.get("host", "")
                    if host:
                        image_urls.add(f"http://{host}{uri}")
                        filename = os.path.basename(uri.split("?")[0])
                    if filename:
                        image_filenames.add(filename)
            # Mail parsing
            if tcp.sport in (25, 587) or tcp.dport in (25, 587):
                payload = tcp.data.decode('utf-8', errors='ignore')
                match = re.search(r"^To:\s*(.+)$",
                                  payload,
                                  re.MULTILINE | re.IGNORECASE)
                if match:
                    to_emails.update(
                        re.findall(
                            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                            match.group(1))
                        )
                match = re.search(r"^From:\s*(.+)$",
                                  payload,
                                  re.MULTILINE | re.IGNORECASE)
                if match:
                    from_emails.update(
                        re.findall(
                            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                            match.group(1)))
        except Exception:
            pass

    return to_emails, from_emails, image_urls, image_filenames


def reader():
    """Reading data of the pcap file"""
    # should get results with filtered2.pcap but none with filtered3.pcap
    pcap_file = "evidence-packet-analysis.pcap"
    with open(pcap_file, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        print("============ URL and E-Mail extractor ============")
        print(f'[*] Analysing {pcap_file}')
        (to_emails,
         from_emails,
         image_urls,
         image_filenames) = find_emails_and_images(pcap)
        print("To Emails:")
        print("----------- Mails -----------")
        for email in sorted(to_emails):
            print(f"  {email}")
        print("From Emails:")
        print("----------- Mails -----------")
        for email in sorted(from_emails):
            print(f"  {email}")
        print("Image URLs:")
        print("----------- URLs -----------")
        for url in sorted(image_urls):
            print(f"  {url}")
        print("Image Filenames:")
        print("----------- Filenames -----------")
        for filename in sorted(image_filenames):
            print(f"  {filename}")
        print("============== End ===============")


if __name__ == '__main__':
    reader()
