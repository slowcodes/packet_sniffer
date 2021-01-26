#!/usr/bin/env/ python2.7

import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)


def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        # if packet.haslayer(scapy.Raw):
        print (packet.show())  # print (packet[scapy.Raw])


sniff("eth0")
