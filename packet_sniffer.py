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


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(str(packet[scapy.Raw].load))
# process_sniffed_packet


sniff("eth0")
