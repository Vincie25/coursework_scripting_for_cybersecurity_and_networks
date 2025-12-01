import socket
import dpkt
import re
import os


def find_emails_and_images(pcap):
    """in current form, finds any gif files downloaded and prints
       request source (Downloader), gif URI and destination (provider) IP"""
    to_emails = set()
    from_emails = set()
    image_urls = set()
    image_filenames = set()

    email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    for (time_s, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip_ad = eth.data
            src = socket.inet_ntoa(ip_ad.src)
            dst = socket.inet_ntoa(ip_ad.dst)
            pkt = ip_ad.data
            
            try:
                http = dpkt.http.Request(pkt.data)
                if http.method == "GET":
                    uri = http.uri.lower()
                    if re.search(r"\.(jpg|jpeg|gif|png)($|\?)", uri, re.IGNORECASE):
                        host = http.headers.get("host", "")
                        if host:
                            full_url = f"https://{host}{uri}"
                            image_urls.add(full_url)
                            uri_without_params = uri.split('?')[0]
                            filename =os.path.basename(uri_without_params)
                            if filename:
                                image_filenames.add(filename)
            except Exception:
                pass
            if pkt.dport==25 or pkt.sport==25:
                try:
                    payload = pkt.data.decode('utf-8')
                    to_match = re.search('^To:\s*(.+)$', payload, re.MULTILINE|re.IGNORECASE)
                    if to_match:
                        emails = re.findall(email_pattern, to_match.group(1))
                        to_emails.update(emails)
                    from_match = re.search('^From:\s*(.+)$', payload, re.MULTILINE|re.IGNORECASE)
                    if to_match:
                        emails = re.findall(email_pattern, from_match.group(1))
                        from_emails.update(emails)
                except Exception:
                    pass
        except Exception:
            # necessary as many packets would otherwise generate an error
            pass
    return to_emails, from_emails, image_urls, image_filenames


def main():
    # should get results with filtered2.pcap but none with filtered3.pcap
    pcap_file = "evidence-packet-analysis.pcap"
    with open(pcap_file, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        print(f'[*] Analysing {pcap_file} for jpg files')
        to_emails, from_emails, image_urls, image_filenames = find_emails_and_images(pcap)
        for email in sorted(to_emails):
            print(f"  {email}")
        for email in sorted(from_emails):
            print(f"  {email}")
        for url in sorted(image_urls):
            print(f" {url}")
        for filename in sorted(image_filenames):
            print(f" {filename}")


if __name__ == '__main__':
    main()
