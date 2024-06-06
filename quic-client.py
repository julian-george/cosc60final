import argparse
from scapy.all import sniff, rdpcap
from scapy.layers.inet import IP, UDP

from quic_common import Connection, UNIDIRECTIONAL, PEER_INITIATED, States
from quic_frames import QUICStreamFrame, QUICACKFrame, QUICResetStreamFrame
from quic_packets import QUICPacket, QUICInitialPacket, parse_packet, QUIC0RTTPacket

connection = Connection(None, None)


def handle_stream_frame(frame):
    # get stream
    stream = connection.get_stream(frame.stream_id)
    # no stream; open new one
    if stream is None:
        stream = connection.new_stream(UNIDIRECTIONAL, PEER_INITIATED, frame.stream_id)

    if stream.receiver.state == States.RECV:
        stream.receiver.add_to_buffer(frame.payload)

    # send ACK
    pkt = IP() / UDP() / QUIC0RTTPacket() / QUICACKFrame()
    pkt.send()

    # if it's a fin, change state to size_known
    if frame.FIN:
        stream.receiver.state = States.SIZE_KNOWN
        # read data and change state to data_read
        data = stream.receiver.get_from_buffer()
        stream.receiver.state = States.DATA_READ


def handle_reset(frame):
    stream = connection.get_stream(frame.stream_id)
    # no stream; do nothing
    if stream is None:
        return

    # change state to reset received
    stream.receiver.state = States.RESRT_RECVD
    # close connection
    stream.receiver.state = States.RESET_READ
    connection.remove_stream(frame.stream_id)


def handle_frame(frame):
    """ this function handles each individual frame received in a packet """
    if type(frame) == QUICStreamFrame:
        handle_stream_frame(frame)
    elif type(frame) == QUICResetStreamFrame:
        handle_reset(frame)


def packet_callback(packet):
    """ Callback function to be called for each captured packet. """
    print(packet.summary())
    print(QUICPacket(packet))

    if not (IP in packet and UDP in packet and packet[UDP].dport == 443):
        return

    quic_packet = parse_packet(packet[UDP].payload)  # get object from bytes

    # grab packet frames and handle each one
    for frame in quic_packet.frames:
        handle_frame(frame)


def main():
    # parse arguments
    parser = argparse.ArgumentParser(description="QUIC client")
    parser.add_argument("s_ip", metavar="server_IP", type=str, help="the IP of the server to connect to")
    parser.add_argument("s_port", metavar="server_port", type=int, help="port -||-")
    parser.add_argument("c_ip", metavar="server_IP", type=str, help="the IP of the server to connect to")
    parser.add_argument("c_port", metavar="server_port", type=int, help="port -||-")
    parser.add_argument("interface", metavar="interface", type=str, help="interface to sniff for packets on")
    args = parser.parse_args()

    # initiate connection with server
    print(f"Connecting to server {args.s_ip}:{args.s_port}...")
    global connection
    connection = Connection(args.s_ip, args.s_port)
    # p = IP(dst="192.168.64.8") / UDP(sport=10930, dport=443) / QUICInitialPacket()
    # send(p)

    # sniff for responses
    print(f"Sniffing on interface {args.interface}, address {args.c_ip}:{args.c_port}...")
    sniff(iface=args.interface, filter=f"ip dst {args.c_ip} and udp dport {str(args.c_port)}", prn=packet_callback, store=False)


if __name__ == "__main__":
    main()
