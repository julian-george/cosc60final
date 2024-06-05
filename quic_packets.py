from scapy.all import *
from scapy.fields import *
from scapy.layers.inet import IP, UDP

from quic_frames import VarLenIntField


# Base class for QUIC packets
class QUICPacket(Packet):
    name = "QUIC"
    fields_desc = [
        BitEnumField("header_form", 1, 1, {0: "short", 1: "long"}),
        BitField("fixed_bit", 1, 1),
    ]

    def guess_payload_class(self, payload):
        if self.header_form == 1:  # Long Header
            return QUICLongHeaderPacket
        else:  # Short Header
            return QUIC1RTTPacket

    def extract_padding(self, s):
        return "", s


# TODO: link this to packet_number_length
PacketNumberField = XIntField("packet_number", 0)


# Long header base class
class QUICLongHeaderPacket(QUICPacket):
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
            return QUICInitialPacket
        elif self.type == 1:
            return QUIC0RTTPacket
        elif self.type == 2:
            return QUICHandshakePacket
        elif self.type == 3:
            return QUICRetryPacket


# Payload should be integer list of supported QUIC versions
# This is considered a "long header packet" but only shares length, not fields, with the rest of the category
# TODO: should this inherit at all?
class QUICVersionNegotiationPacket(QUICLongHeaderPacket):
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


class QUICInitialPacket(QUICLongHeaderPacket):
    fields_desc = QUICLongHeaderPacket.fields_desc + [
        VarLenIntField("token_length", 0),
        StrLenField("token", "", length_from=lambda pkt: pkt.token_length),
        VarLenIntField("length", 0),
        PacketNumberField,
    ]

    def __init__(self, *args, **kwargs):
        super(QUICInitialPacket, self).__init__(*args, **kwargs)
        self.type = 0


class QUIC0RTTPacket(QUICLongHeaderPacket):
    fields_desc = QUICLongHeaderPacket.fields_desc + [
        VarLenIntField("length", 0),
        PacketNumberField,
    ]

    def __init__(self, *args, **kwargs):
        super(QUIC0RTTPacket, self).__init__(*args, **kwargs)
        self.type = 1


class QUICHandshakePacket(QUICLongHeaderPacket):
    fields_desc = QUICLongHeaderPacket.fields_desc + [
        VarLenIntField("length", 0),
        PacketNumberField,
    ]

    def __init__(self, *args, **kwargs):
        super(QUICHandshakePacket, self).__init__(*args, **kwargs)
        self.type = 2


# Has no payload
class QUICRetryPacket(QUICLongHeaderPacket):
    fields_desc = QUICLongHeaderPacket.fields_desc + [
        # Our implementation uses 128 bit retry tokens
        XStrFixedLenField("retry_token", "", 16),
        BitField("retry_integrity_tag", 0, 128),
    ]

    def __init__(self, *args, **kwargs):
        super(QUICRetryPacket, self).__init__(*args, **kwargs)
        self.type = 3


# TODO: is this weird?
class QUICShortHeaderPacket(QUICPacket):
    pass


# The only short header packet defined in the RFC
class QUIC1RTTPacket(QUICShortHeaderPacket):
    fields_desc = QUICShortHeaderPacket.fields_desc + [
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
bind_layers(QUICPacket, QUICLongHeaderPacket, header_form=1)
bind_layers(QUICPacket, QUICShortHeaderPacket, header_form=0)
bind_layers(QUICLongHeaderPacket, QUICInitialPacket, type=0)
bind_layers(QUICLongHeaderPacket, QUIC0RTTPacket, type=1)
bind_layers(QUICLongHeaderPacket, QUICHandshakePacket, type=2)
bind_layers(QUICLongHeaderPacket, QUICRetryPacket, type=3)

# Test Example
if __name__ == "main":
    pkt = (
        IP()
        / UDP()
        / QUICInitialPacket(
            version=1, dcid_len=4, dcid="abcd", scid_len=4, scid="1234", packet_number=900
        )
    )
    pkt.show()
