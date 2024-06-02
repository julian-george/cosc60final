import struct
from scapy.fields import *


class VarLenIntField(Field):
    def __init__(self, name, default=0):
        Field.__init__(self, name, default, fmt="!Q")

    def i2m(self, pkt, val):
        if val < (1 << 6):
            return struct.pack("!B", val & 0x3F)
        elif val < (1 << 14):
            return struct.pack("!H", (val & 0x3FFF) | 0x4000)
        elif val < (1 << 30):
            return struct.pack("!L", (val & 0x3FFFFFFF) | 0x80000000)
        elif val < (1 << 62):
            return struct.pack("!Q", (val & 0x3FFFFFFFFFFFFFFF) | 0xC000000000000000)
        else:
            raise ValueError("Value too large for QUIC variable-length integer")

    def m2i(self, pkt, val):
        byte0 = val[0]
        if byte0 < 0x40:
            return byte0
        elif byte0 < 0x80:
            return struct.unpack("!H", val[:2])[0] & 0x3FFF
        elif byte0 < 0xC0:
            return struct.unpack("!L", val[:4])[0] & 0x3FFFFFFF
        else:
            return struct.unpack("!Q", val[:8])[0] & 0x3FFFFFFFFFFFFFFF

    def getfield(self, pkt, s):
        byte0 = s[0]
        if byte0 < 0x40:
            return s[1:], self.m2i(pkt, s[:1])
        elif byte0 < 0x80:
            return s[2:], self.m2i(pkt, s[:2])
        elif byte0 < 0xC0:
            return s[4:], self.m2i(pkt, s[:4])
        else:
            return s[8:], self.m2i(pkt, s[:8])

    def i2len(self, pkt, val):
        if val < (1 << 6):
            return 1
        elif val < (1 << 14):
            return 2
        elif val < (1 << 30):
            return 4
        elif val < (1 << 62):
            return 8
        else:
            raise ValueError("Value too large for QUIC variable-length integer")
