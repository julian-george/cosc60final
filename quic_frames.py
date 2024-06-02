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
    fields_desc = [XIntField("type", None)]

    def guess_payload_class(self, payload):
        if self.type == 0x00:
            return QUICPaddingFrame
        elif self.type == 0x01:
            return QUICPingFrame
        elif self.type == 0x02 or self.type == 0x03:
            return QUICACKFrame
        elif self.type == 3:
            return QUICRetryPacket


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
