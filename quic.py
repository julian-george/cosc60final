from scapy.all import *
from scapy.fields import *


# Base class for QUIC packets
class QUIC(Packet):
    name = "QUIC"
    fields_desc = [
        BitEnumField("header_form", 1, 1, {0: "short", 1: "long"}),
        BitField("fixed_bit", 1, 1),
    ]

    def guess_payload_class(self, payload):
        if self.header_form == 1:  # Long Header
            return QUICLongHeader
        else:  # Short Header
            return QUICShortHeader

    def extract_padding(self, s):
        return "", s


PacketNumberField = XIntField("packet_number", 0)


# Long header base class
class QUICLongHeader(QUIC):
    fields_desc = QUIC.fields_desc + [
        BitEnumField(
            "type", 0, 2, {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
        ),
        BitField("reserved", 0, 4),
        XIntField("version", 0),
        XByteField("dcid_len", 0),
        XStrLenField("dcid", "", length_from=lambda pkt: pkt.dcid_len),
        XByteField("scid_len", 0),
        XStrLenField("scid", "", length_from=lambda pkt: pkt.scid_len),
    ]


# Short header class
class QUICShortHeader(QUIC):
    fields_desc = QUIC.fields_desc + [
        BitField("key_phase", 0, 1),
        BitField("packet_number", 0, 7),
        ConditionalField(
            XStrFixedLenField("dcid", "", length=8), lambda pkt: pkt.key_phase == 1
        ),
    ]


# Specific packet types as subclasses of QUICLongHeader


class QUICInitial(QUICLongHeader):
    fields_desc = QUICLongHeader.fields_desc + [
        XByteField("token_length", 0),
        StrLenField("token", "", length_from=lambda pkt: pkt.token_length),
        XByteField("length", 0),
        PacketNumberField,
    ]

    def __init__(self, *args, packet_number_length=0, **kwargs):
        """
        :param packet_number_length: one less than the packet number's size in bytes
        """
        if not 0 <= packet_number_length <= 3:
            raise ValueError("packet_number_length must be a 2-bit value (0-3)")
        super(QUICInitial, self).__init__(*args, **kwargs)
        self.type = 0
        self.reserved = packet_number_length


class QUIC0RTT(QUICLongHeader):
    def __init__(self, *args, **kwargs):
        super(QUIC0RTT, self).__init__(*args, **kwargs)
        self.type = 1


class QUICHandshake(QUICLongHeader):
    def __init__(self, *args, **kwargs):
        super(QUICHandshake, self).__init__(*args, **kwargs)
        self.type = 2


class QUICRetry(QUICLongHeader):
    def __init__(self, *args, **kwargs):
        super(QUICRetry, self).__init__(*args, **kwargs)
        self.type = 3


# Binding layers
bind_layers(UDP, QUIC, dport=443)
bind_layers(UDP, QUIC, sport=443)
bind_layers(QUIC, QUICLongHeader, header_form=1)
bind_layers(QUIC, QUICShortHeader, header_form=0)
bind_layers(QUICLongHeader, QUICInitial, type=0)
bind_layers(QUICLongHeader, QUIC0RTT, type=1)
bind_layers(QUICLongHeader, QUICHandshake, type=2)
bind_layers(QUICLongHeader, QUICRetry, type=3)

# Test Example
pkt = (
    Ether()
    / IP()
    / UDP()
    / QUICInitial(
        version=1, dcid_len=4, dcid="abcd", scid_len=4, scid="1234", packet_number=1
    )
)
pkt.show()
