from scapy.all import *

from quic_packets import *

def main():
    p = IP(dst="192.168.64.8") / UDP(sport=10930, dport=443) / QUICPacket()
    send(p)


if __name__ == "__main__":
    main()
