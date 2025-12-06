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
    email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    for (unused_time_s, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip_ad = eth.data
            if not isinstance(ip_ad, dpkt.ip.IP):
                continue
            tcp = ip_ad.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            src_port = tcp.sport
            dst_port = tcp.dport
            if dst_port==80:
                http = dpkt.http.Request(tcp.data)
                if http.method == "GET":
                    uri = http.uri
                    if re.search(r"\.(jpg|jpeg|gif|png)($|\?)", uri, re.IGNORECASE):
                        host = http.headers.get("host", "")
                        if host:
                            full_url = f"http://{host}{uri}"
                            image_urls.add(full_url)
                            uri_without_params = uri.split('?')[0]
                            filename =os.path.basename(uri_without_params)
                            if filename:
                                image_filenames.add(filename)
            if src_port==25 or dst_port==25 or src_port==587 or dst_port==587:
                payload = tcp.data.decode('utf-8', errors='ignore')
                to_match = re.search(r"^To:\s*(.+)$", payload, re.MULTILINE|re.IGNORECASE)
                if to_match:
                    emails = re.findall(email_pattern, to_match.group(1))
                    to_emails.update(emails)
                from_match = re.search(r"^From:\s*(.+)$", payload, re.MULTILINE|re.IGNORECASE)
                if from_match:
                    emails = re.findall(email_pattern, from_match.group(1))
                    from_emails.update(emails)
        except Exception:
            # necessary as many packets would otherwise generate an error
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
        to_emails, from_emails, image_urls, image_filenames = find_emails_and_images(pcap)
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
