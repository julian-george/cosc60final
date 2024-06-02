from scapy.all import *
from scapy.fields import *
from scapy.layers import *


# Base class for QUIC packets
class QUICPacket(Packet):
    name = "QUIC"
    fields_desc = [
        BitEnumField("header_form", 1, 1, {0: "short", 1: "long"}),
        BitField("fixed_bit", 1, 1),
    ]

    def guess_payload_class(self, payload):
        if self.header_form == 1:  # Long Header
            return QUICLongHeader
        else:  # Short Header
            return QUIC1RTT

    def extract_padding(self, s):
        return "", s


# TODO: link this to packet_number_length
PacketNumberField = XIntField("packet_number", 0)


# Payload should be integer list of supported QUIC versions
# This is considered a "long header packet" but only shares length, not fields, with the rest of the category
class QUICVersionNegotiation(QUICPacket):
    fields_desc = QUICPacket.fields_desc + [
        # Set to arbitrary value
        BitField("unused", 0, 7),
        # Must be zero for this packet type
        BitField("version", 0, 32),
        XByteField("dcid_len", 0),
        XStrLenField("dcid", "", length_from=lambda pkt: pkt.dcid_len),
        XByteField("scid_len", 0),
        XStrLenField("scid", "", length_from=lambda pkt: pkt.scid_len),
    ]


# Long header base class
class QUICLongHeader(QUICPacket):
    fields_desc = QUICPacket.fields_desc + [
        BitEnumField(
            "type", 0, 2, {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
        ),
        ConditionalField(BitField("type_specific", 0, 4), lambda pkt: pkt.type == 3),
        ConditionalField(BitField("reserved", 0, 2), lambda pkt: pkt.type != 3),
        ConditionalField(
            BitField("packet_number_length", 0, 2), lambda pkt: pkt.type != 3
        ),
        BitField("version", 0, 32),
        XByteField("dcid_len", 0),
        XStrLenField("dcid", "", length_from=lambda pkt: pkt.dcid_len),
        XByteField("scid_len", 0),
        XStrLenField("scid", "", length_from=lambda pkt: pkt.scid_len),
    ]

    def guess_payload_class(self, payload):
        if self.type == 0:
            return QUICInitial
        elif self.type == 1:
            return QUIC0RTT
        elif self.type == 2:
            return QUICHandshake
        elif self.type == 3:
            return QUICRetry


class QUICInitial(QUICLongHeader):
    fields_desc = QUICLongHeader.fields_desc + [
        XByteField("token_length", 0),
        StrLenField("token", "", length_from=lambda pkt: pkt.token_length),
        XByteField("length", 0),
        PacketNumberField,
    ]

    def __init__(self, *args, packet_number_length=0, **kwargs):
        super(QUICInitial, self).__init__(*args, **kwargs)
        self.type = 0


class QUIC0RTT(QUICLongHeader):
    fields_desc = QUICLongHeader.fields_desc + [
        XByteField("length", 0),
        PacketNumberField,
    ]

    def __init__(self, *args, packet_number_length=0, **kwargs):
        super(QUIC0RTT, self).__init__(*args, **kwargs)
        self.type = 1


class QUICHandshake(QUICLongHeader):
    fields_desc = QUICLongHeader.fields_desc + [
        XByteField("length", 0),
        PacketNumberField,
    ]

    def __init__(self, *args, packet_number_length=0, **kwargs):
        super(QUIC0RTT, self).__init__(*args, **kwargs)
        self.type = 2


# Has no payload
class QUICRetry(QUICLongHeader):
    fields_desc = QUICLongHeader.fields_desc + [
        # Our implementation uses 128 bit retry tokens
        XStrFixedLenField("retry_token", "", 16),
        BitField("retry_integrity_tag", 0, 128),
    ]

    def __init__(self, *args, **kwargs):
        super(QUICRetry, self).__init__(*args, **kwargs)
        self.type = 3


# The only short header packet defined in the RFC
class QUIC1RTT(QUICPacket):
    fields_desc = QUICPacket.fields_desc + [
        BitField("spin", 0, 1),
        # Must be 0
        BitField("reserved", 0, 2),
        BitField("key_phase", 0, 1),
        BitField("packet_number_length", 0, 2),
        # TODO: what should be the length of this?
        XStrFixedLenField("dcid", "", 20),
        PacketNumberField,
    ]


# Binding layers
bind_layers(UDP, QUICPacket, dport=443)
bind_layers(UDP, QUICPacket, sport=443)
bind_layers(QUICPacket, QUICLongHeader, header_form=1)
bind_layers(QUICPacket, QUIC1RTT, header_form=0)
bind_layers(QUICLongHeader, QUICInitial, type=0)
bind_layers(QUICLongHeader, QUIC0RTT, type=1)
bind_layers(QUICLongHeader, QUICHandshake, type=2)
bind_layers(QUICLongHeader, QUICRetry, type=3)

# Test Example
pkt = (
    IP()
    / UDP()
    / QUICInitial(
        version=1, dcid_len=4, dcid="abcd", scid_len=4, scid="1234", packet_number=900
    )
)
pkt.show()
