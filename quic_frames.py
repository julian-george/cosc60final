from scapy.all import *

from quic_fields import VarLenIntField


class ACKRangeField(Field):
    def __init__(self, name, default, count_from):
        Field.__init__(self, name, default, fmt="")
        self.count_from = count_from

    def i2m(self, pkt, val):
        # val is expected to be a list of tuples [(Gap, ACK Range Length), ...]
        encoded = b""
        for gap, ack_range_len in val:
            encoded += VarLenIntField(None, None).i2m(pkt, gap)
            encoded += VarLenIntField(None, None).i2m(pkt, ack_range_len)
        return encoded

    def m2i(self, pkt, val):
        decoded = []
        count = getattr(pkt, self.count_from)
        while len(decoded) < count:
            gap, val = VarLenIntField(None, None).getfield(pkt, val)
            ack_range_len, val = VarLenIntField(None, None).getfield(pkt, val)
            decoded.append((gap, ack_range_len))
        return decoded

    def getfield(self, pkt, s):
        count = getattr(pkt, self.count_from)
        length = len(s)
        return s[length:], self.m2i(pkt, s[:length])

    def i2len(self, pkt, val):
        length = 0
        for gap, ack_range_len in val:
            length += VarLenIntField(None, None).i2len(pkt, gap)
            length += VarLenIntField(None, None).i2len(pkt, ack_range_len)
        return length


class QUICFrame(Packet):
    fields_desc = [VarLenIntField("type")]

    def guess_payload_class(self, payload):
        if self.type == 0x00:
            return QUICPaddingFrame
        elif self.type == 0x01:
            return QUICPingFrame
        elif self.type == 0x02 or self.type == 0x03:
            return QUICACKFrame
        elif self.type == 0x04:
            return QUICResetStreamFrame
        elif self.type == 0x05:
            return QUICStopSendingFrame
        elif self.type == 0x06:
            return QUICCryptoFrame
        elif self.type == 0x07:
            return QUICNewTokenFrame
        elif self.type >= 0x08 and self.type <= 0x0F:
            return QUICStreamFrame
        elif self.type == 0x10:
            return QUICMaxDataFrame
        elif self.type == 0x11:
            return QUICMaxStreamDataFrame
        elif self.type == 0x12 or self.type == 0x13:
            return QUICMaxStreamsFrame
        elif self.type == 0x14:
            return QUICDataBlockedFrame
        elif self.type == 0x15:
            return QUICStreamDataBlockedFrame
        elif self.type == 0x16 or self.type == 0x17:
            return QUICStreamsBlockedFrame
        elif self.type == 0x18:
            return QUICNewConnectionIDFrame


class QUICPaddingFrame(QUICFrame):
    pass


class QUICPingFrame(QUICFrame):
    pass


class QUICACKFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [
        VarLenIntField("largest_acknowledged"),
        VarLenIntField("ack_delay"),
        VarLenIntField("ack_range_count"),
        VarLenIntField("first_ack_range"),
        ACKRangeField("ack_range", 0, count_from="ack_range_count"),
        ConditionalField(VarLenIntField("ECT0_count"), lambda pkt: pkt.type == 0x03),
        ConditionalField(VarLenIntField("ECT1_count"), lambda pkt: pkt.type == 0x03),
        ConditionalField(VarLenIntField("ECN_CE_count"), lambda pkt: pkt.type == 0x03),
    ]


class QUICResetStreamFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [
        VarLenIntField("stream_id"),
        VarLenIntField("application_protocol_error_code"),
        VarLenIntField("final_siZe"),
    ]


class QUICStopSendingFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [
        VarLenIntField("stream_id"),
        VarLenIntField("application_protocol_error_code"),
    ]


# Requires payload containing TLS handshake data
class QUICCryptoFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [
        VarLenIntField("offset"),
        VarLenIntField("length"),
    ]


# Requires payload containing token for use in future 0-RTT Initial packets
class QUICNewTokenFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [VarLenIntField("token_length")]


# Takes payload containing stream data
class QUICStreamFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [
        VarLenIntField("stream_id"),
        ConditionalField(
            VarLenIntField("offset"), lambda pkt: bin(pkt.type)[-3] == "1"
        ),
        ConditionalField(
            VarLenIntField("length"),
            lambda pkt: bin(pkt.type)[-2] == "1",
        ),
    ]


class QUICMaxDataFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [VarLenIntField("maximum_data")]


class QUICMaxStreamDataFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [
        VarLenIntField("stream_id"),
        VarLenIntField("maximum_data"),
    ]


class QUICMaxStreamsFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [VarLenIntField("maximum_streams")]


class QUICDataBlockedFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [VarLenIntField("maximum_data")]


class QUICStreamDataBlockedFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [
        VarLenIntField("stream_id"),
        VarLenIntField("maximum_stream_data"),
    ]


class QUICStreamsBlockedFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [VarLenIntField("maximum_streams")]


class QUICNewConnectionIDFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [
        VarLenIntField("sequence_number"),
        VarLenIntField("retire_prior_to"),
        VarLenIntField("length"),
    ]
