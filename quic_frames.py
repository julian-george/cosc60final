from scapy.all import *

from quic_fields import VarLenIntField


class ACKRangeField(Field):

    __slots__ = ['count_from']
    def __init__(self, name, default, count_from):
        super().__init__(name, default, fmt="B")
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
        elif self.type == 0x19:
            return QUICRetireConnectionIDFrame
        elif self.type == 0x1A:
            return QUICPathChallengeFrame
        elif self.type == 0x1B:
            return QUICPathResponseFrame
        elif self.type == 0x1C or self.type == 0x1D:
            return QUICConnectionCloseFrame
        elif self.type == 0x1E:
            return QUICHandshakeDoneFrame


class QUICPaddingFrame(QUICFrame):
    def __init__(self, *args, **kwargs):
        super(QUICFrame, self).__init__(*args, **kwargs)
        self.type = 0x00



class QUICPingFrame(QUICFrame):
    def __init__(self, *args, **kwargs):
        super(QUICFrame, self).__init__(*args, **kwargs)
        self.type = 0x01


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

    def __init__(self, *args, **kwargs):
        super(QUICFrame, self).__init__(*args, **kwargs)
        if self.type != 0x02 or self.type != 0x03:
            self.type = 0x02


class QUICResetStreamFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [
        VarLenIntField("stream_id"),
        VarLenIntField("application_protocol_error_code"),
        VarLenIntField("final_siZe"),
    ]
    def __init__(self, *args, **kwargs):
        super(QUICFrame, self).__init__(*args, **kwargs)
        self.type = 0x04


class QUICStopSendingFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [
        VarLenIntField("stream_id"),
        VarLenIntField("application_protocol_error_code"),
    ]
    def __init__(self, *args, **kwargs):
        super(QUICFrame, self).__init__(*args, **kwargs)
        self.type = 0x05


# Requires payload containing TLS handshake data
class QUICCryptoFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [
        VarLenIntField("offset"),
        VarLenIntField("length"),
    ]
    def __init__(self, *args, **kwargs):
        super(QUICFrame, self).__init__(*args, **kwargs)
        self.type = 0x06


# Requires payload containing token for use in future 0-RTT Initial packets
class QUICNewTokenFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [VarLenIntField("token_length")]
    def __init__(self, *args, **kwargs):
        super(QUICFrame, self).__init__(*args, **kwargs)
        self.type = 0x07


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
    def __init__(self, *args, **kwargs):
        super(QUICFrame, self).__init__(*args, **kwargs)
        if self.type <0x08  or self.type >= 0x0f:
            self.type = 0x08
    


class QUICMaxDataFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [VarLenIntField("maximum_data")]
    def __init__(self, *args, **kwargs):
        super(QUICFrame, self).__init__(*args, **kwargs)
        self.type = 0x10


class QUICMaxStreamDataFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [
        VarLenIntField("stream_id"),
        VarLenIntField("maximum_data"),
    ]
    def __init__(self, *args, **kwargs):
        super(QUICFrame, self).__init__(*args, **kwargs)
        self.type = 0x11


class QUICMaxStreamsFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [VarLenIntField("maximum_streams")]
    def __init__(self, *args, **kwargs):
        super(QUICFrame, self).__init__(*args, **kwargs)
        if self.type != 0x12 or self.type != 0x13:
            self.type = 0x12


class QUICDataBlockedFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [VarLenIntField("maximum_data")]
    def __init__(self, *args, **kwargs):
        super(QUICFrame, self).__init__(*args, **kwargs)
        self.type = 0x14


class QUICStreamDataBlockedFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [
        VarLenIntField("stream_id"),
        VarLenIntField("maximum_stream_data"),
    ]
    def __init__(self, *args, **kwargs):
        super(QUICFrame, self).__init__(*args, **kwargs)
        self.type = 0x15


class QUICStreamsBlockedFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [VarLenIntField("maximum_streams")]
    def __init__(self, *args, **kwargs):
        super(QUICFrame, self).__init__(*args, **kwargs)
        if self.type != 0x16 or self.type != 0x17:
            self.type = 0x16


class QUICNewConnectionIDFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [
        VarLenIntField("sequence_number"),
        VarLenIntField("retire_prior_to"),
        ByteField("length", 1),
        XStrLenField("connection_id", "", length_from=lambda frame: frame.length),
        ByteField("stateless_reset_token", 16),
    ]
    def __init__(self, *args, **kwargs):
        super(QUICFrame, self).__init__(*args, **kwargs)
        self.type = 0x18


class QUICRetireConnectionIDFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [VarLenIntField("sequence_number")]
    def __init__(self, *args, **kwargs):
        super(QUICFrame, self).__init__(*args, **kwargs)
        self.type = 0x19


class QUICPathChallengeFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [ByteField("data", 8)]
    def __init__(self, *args, **kwargs):
        super(QUICFrame, self).__init__(*args, **kwargs)
        self.type = 0x1a


class QUICPathResponseFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [ByteField("data", 8)]
    def __init__(self, *args, **kwargs):
        super(QUICFrame, self).__init__(*args, **kwargs)
        self.type = 0x1b


class QUICConnectionCloseFrame(QUICFrame):
    fields_desc = QUICFrame.fields_desc + [
        VarLenIntField("error_code"),
        ConditionalField(
            VarLenIntField("frame_type"), lambda frame: frame.type == 0x1C
        ),
        VarLenIntField("reason_phrase_length"),
        XStrLenField(
            "reason_phrase", "", length_from=lambda frame: frame.reason_phrase_length
        ),
    ]
    def __init__(self, *args, **kwargs):
        super(QUICFrame, self).__init__(*args, **kwargs)
        if self.type != 0x1c or self.type != 0x1d:
            self.type = 0x1c


class QUICHandshakeDoneFrame(QUICFrame):
    def __init__(self, *args, **kwargs):
        super(QUICFrame, self).__init__(*args, **kwargs)
        self.type = 0x1e
            
