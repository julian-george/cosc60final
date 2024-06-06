from scapy.all import *
import argparse
from scapy.layers.inet import IP, UDP

from quic_common import Connections, UNIDIRECTIONAL, I_INITIATED, States
from quic_frames import QUICStreamFrame, QUICACKFrame
from quic_packets import QUICPacket, parse_packet, QUIC1RTTPacket

connections = Connections()


def send_stream(conn, data, max_stream_data):
    # create stream
    stream = conn.new_stream(UNIDIRECTIONAL, I_INITIATED, None)
    # split into max_stream_data lengths and send packets to client
    sent_bytes = 0
    fin = False
    while sent_bytes < len(data):
        payload = data[sent_bytes:sent_bytes+max_stream_data]
        sent_bytes += len(payload)
        if sent_bytes >= len(data):
            # finished sending, add fin bit to packet
            fin = True
        pkt = IP() / UDP() / QUIC1RTTPacket() / QUICStreamFrame(payload = payload, FIN = fin)
        pkt.send()

    # update state
    stream.sender.state = States.DATA_SENT


def handle_ack(frame):
    conn = connections.get_connection(frame.connection_id)
    stream = conn.get_stream(frame.stream_id)
    if stream.sender.state == States.RESET_SENT:
        stream.sender.state = States.RESET_RECVD


def handle_frame(frame):
    if type(frame) == QUICACKFrame:
        handle_ack(frame)


def packet_callback(packet):
    """
    Callback function to be called for each captured packet.
    Prints a summary of the packet.
    """
    if not (IP in packet and UDP in packet and packet[UDP].dport == 443):
        return

    print(packet[IP].summary())

    quic_packet = parse_packet(packet[UDP.payload])  # get object from bytes

    for frame in quic_packet.frames:
        handle_frame(frame)


def main():
    # parse arguments
    parser = argparse.ArgumentParser(description="QUIC server")
    parser.add_argument("s_ip", metavar="server_IP", type=str, help="the IP of the server")
    parser.add_argument("s_port", metavar="server_port", type=int, help="port -||-")
    parser.add_argument("c_ip", metavar="client_IP", type=str, help="the IP of the client to send data to")
    parser.add_argument("c_port", metavar="client_port", type=int, help="port -||-")
    parser.add_argument("interface", metavar="interface", type=str, help="interface to sniff for packets on")
    args = parser.parse_args()

    # Start sniffing
    def get_response():
        print(f"Sniffing on interface {args.interface}, IP {args.s_ip}, port {args.s_port}...")
        sniff(iface=args.interface, filter=f"ip dst {args.s_ip} and udp dport {str(args.s_port)}", prn=packet_callback, store=False)
    Thread(target=get_response).start()

    # start sending stream
    conn = connections.new_connection(args.c_ip, args.c_port)
    max_stream_data = 1000  # this would be received from client during handshake
    # load bytes from video
    data = load_video("./data/video.mp4")

    send_stream(conn, data, max_stream_data)


if __name__ == "__main__":
    main()
