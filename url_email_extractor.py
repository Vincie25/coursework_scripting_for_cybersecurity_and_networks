"""Used module"""
import os
import sys
import re
from typing import Any
import dpkt  # type: ignore[import-untyped]
from pcap_reader import main


def find_emails_and_images(pcap: Any) -> tuple[set, set, set, set]:
    """Extract email addresses and image URLs from network packets.
       Parses HTTP traffic (port 80) for image file requests
       and SMTP traffic for email addresses in To:/From: fields.
    """
    to_emails = set()
    from_emails = set()
    image_urls = set()
    image_filenames = set()
    for (unused_time_s, eth) in pcap:
        try:
            ip_ad = eth.data
            tcp = ip_ad.data
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
        except (dpkt.UnpackError, dpkt.NeedData):
            pass
        except UnicodeDecodeError:
            pass
        except (AttributeError, KeyError):
            pass
    return to_emails, from_emails, image_urls, image_filenames


def reader(pcap: Any) -> None:
    """Display extracted emails and image URLs in formatted output."""
    try:
        print("============ URL and E-Mail extractor ============")
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
    except IOError as e:
        sys.stderr.write(f"Failed to open file: {e}\n")
    except dpkt.NeedData as e:
        sys.stderr.write(f"Failed to parse pcap: {e}\n")


if __name__ == '__main__':
    PCAP = "evidence-packet-analysis.pcap"
    packet = main(PCAP, printout=False, brkfirst=False)
    reader(packet)
