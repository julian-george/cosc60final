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
    # Define the network interface to sniff on
    interface = (
        "ens3"  # Change this to your network interface (e.g., "wlan0" for Wi-Fi)
    )

    # Start sniffing
    print(f"Sniffing on interface {interface}...")
    sniff(iface=interface, prn=packet_callback, store=False)


if __name__ == "__main__":
    main()
