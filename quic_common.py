from numpy.random import randint, choice
from scapy.layers.inet import IP, UDP

from quic_packets import QUICInitialPacket

UNIDIRECTIONAL = "unidirectional"
BIDIRECTIONAL = "bidirectional"
I_INITIATED = "i initiated"
PEER_INITIATED = "peer initiated"


class States:
    # common states
    DATA_RECVD = "Data Recvd"
    RESET_SENT = "Reset Sent"
    RESET_RECVD = "Reset Recvd"

    # sender states
    READY = "Ready"
    SEND = "Send"
    DATA_SENT = "Data Sent"

    # receiver states
    RECV = "Recv"
    SIZE_KNOWN = "Size Known"
    DATA_READ = "Data Read"
    RESET_READ = "Reset Read"


def new_id():
    return randint(1000, 10000)


class Direction:
    """ things common to senders and receivers of streams """
    def __init__(self):
        self.state = None


class Sender(Direction):
    def __init__(self):
        super().__init__()
        self.state = States.READY

    def send_packet(self):
        pkt = (
            IP()
            / UDP()
            / QUICInitialPacket(
                version=1, dcid_len=4, dcid="abcd", scid_len=4, scid="1234", packet_number=900
            )
        )
        pkt.send()


class Receiver(Direction):
    def __init__(self):
        super().__init__()
        self.buffer = []
        self.state = States.RECV

    def add_to_buffer(self, payload):
        self.buffer.append(payload)

    def get_from_buffer(self):
        """ returns all data that has been received in order so far """
        return self.buffer


class Stream:
    def __init__(self, direction, initiator):
        if direction == BIDIRECTIONAL:
            self.sender = Sender()
            self.receiver = Receiver()
        elif direction == UNIDIRECTIONAL:
            self.sender = Sender() if initiator == I_INITIATED else None
            self.receiver = Receiver() if initiator == PEER_INITIATED else None


class Connection:
    def __init__(self, ip, port):
        self.available_ids = set()
        self.streams = dict()
        # peer address
        self.ip = ip
        self.port = port

    def get_stream(self, stream_id):
        if stream_id not in self.streams:
            return None
        return self.streams[stream_id]

    def new_stream(self, direction, initiator, stream_id):
        new_stream = Stream(direction, initiator)
        self.streams[stream_id if stream_id is not None else new_id()] = new_stream
        return new_stream

    def remove_stream(self, stream_id):
        self.streams.pop(stream_id)

    def get_id(self):
        """ get a random id that can be used to send packets """
        return choice(self.available_ids)


class Connections:
    def __init__(self):
        self.connections = set()

    def get_connection(self, conn_id):
        """ get the connection that accepts this ID, or None if no such connection found """
        # loop over all connections, see if any have this id available
        for conn in self.connections:
            if conn_id in conn.available_ids:
                return conn
        return None

    def new_connection(self, ip, port):
        self.connections.add(Connection(ip, port))

    def remove_connection(self, conn_id):
        for conn in self.connections:
            if conn_id in conn.available_ids:
                self.connections.remove(conn)
