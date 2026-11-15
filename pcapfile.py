"""
pcapfile.py - Writes and reads the classic libpcap (.pcap) file format, the
format opened by Wireshark and tcpdump.

File = global header (24 bytes) + for each packet a record header (16 bytes)
       followed by the raw frame bytes.

  Global header : magic, version 2.4, timezone, accuracy, snaplen, link type
  Record header : seconds, microseconds, captured length, original length
"""

import struct

MAGIC_US = 0xA1B2C3D4        # timestamps in microseconds
MAGIC_NS = 0xA1B23C4D        # timestamps in nanoseconds (also accepted)
LINKTYPE_ETHERNET = 1
SNAPLEN = 65535


class PcapWriter:
    def __init__(self, path, linktype=LINKTYPE_ETHERNET):
        self.f = open(path, "wb")
        self.count = 0
        # "<" = little-endian, the byte order used by most PCs
        self.f.write(struct.pack("<IHHiIII", MAGIC_US, 2, 4, 0, 0,
                                 SNAPLEN, linktype))

    def write(self, raw, timestamp):
        seconds = int(timestamp)
        micros = int(round((timestamp - seconds) * 1_000_000))
        if micros == 1_000_000:                       # rounding overflow
            seconds, micros = seconds + 1, 0
        data = raw[:SNAPLEN]
        self.f.write(struct.pack("<IIII", seconds, micros,
                                 len(data), len(raw)))
        self.f.write(data)
        self.count += 1

    def close(self):
        self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def read_pcap(path):
    """Yield (timestamp, raw_bytes) for every packet in a .pcap file.
    Works for both byte orders and for micro- or nanosecond files."""
    with open(path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            raise ValueError("not a pcap file (too short)")
        for order in ("<", ">"):
            magic = struct.unpack(order + "I", header[:4])[0]
            if magic in (MAGIC_US, MAGIC_NS):
                break
        else:
            raise ValueError("not a classic pcap file (pcapng is not supported)")
        divisor = 1e9 if magic == MAGIC_NS else 1e6
        linktype = struct.unpack(order + "I", header[20:24])[0]
        if linktype != LINKTYPE_ETHERNET:
            raise ValueError(f"link type {linktype} not supported (only Ethernet = 1)")
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            sec, frac, incl, _orig = struct.unpack(order + "IIII", rec)
            yield sec + frac / divisor, f.read(incl)
