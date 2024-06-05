import argparse
from scapy.all import sniff, rdpcap
from quic_packets import QUICPacket


def packet_callback(packet):
    """
    Callback function to be called for each captured packet.
    Prints a summary of the packet.
    """
    print(packet.summary())
    print(QUICPacket(packet))


def main():
    # parse arguments
    parser = argparse.ArgumentParser(description="QUIC server")
    parser.add_argument("ip", metavar="server_IP", type=str, help="the IP of the server to connect to")
    parser.add_argument("port", metavar="server_port", type=int, help="port -||-")
    parser.add_argument("interface", metavar="interface", type=str, help="interface to sniff for packets on")
    args = parser.parse_args()

    # Start sniffing
    print(f"Sniffing on interface {args.interface}, IP {args.ip}, port {args.port}...")
    sniff(iface=args.interface, filter=f"ip dst {args.ip} and udp dport {str(args.port)}", prn=packet_callback, store=False)


if __name__ == "__main__":
    main()
