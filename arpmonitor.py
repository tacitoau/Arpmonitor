#!/usr/bin/python3

from scapy.all import *

def arp_display(pkt):
    if pkt[ARP].op == 1:
       return "\nRequisição: " + pkt[ARP].psrc + " está perguntado por " + pkt[ARP].pdst
    if pkt[ARP].op == 2:
       return "Resposta: " + pkt[ARP].hwsrc + " contém o endereço " + pkt[ARP].psrc
print(sniff(prn=arp_display, filter="arp", store=0))
