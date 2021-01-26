#!/usr/bin/env/ python2.7

import scapy.all as scapy


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)


def process_packet(packet):
    print (packet)


sniff("eth0")
