import scapy.all as scapy
from scapy.layers import http

def listening_packet(interface):
    scapy.sniff(iface = interface,store=False,prn=analyze_packet)
def analyze_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load)


listening_packet("eth0")



