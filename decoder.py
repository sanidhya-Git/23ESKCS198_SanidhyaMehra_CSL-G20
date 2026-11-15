"""
decoder.py - Decodes raw frame bytes into Ethernet, ARP, IPv4, IPv6, TCP,
UDP and ICMP headers using Python's struct module.

Project : Python Packet Sniffer & Protocol Analyzer (Scapy)   [CSL-G20]
Author  : Sanidhya Mehra (23ESKCS198)

Scapy is used only to capture frames. Every header field shown by the tool
is read from the raw bytes here, following the layouts in the RFCs:
  Ethernet II (IEEE 802.3), ARP (RFC 826), IPv4 (RFC 791), IPv6 (RFC 8200),
  TCP (RFC 9293), UDP (RFC 768), ICMP (RFC 792).

"!" in a struct format means network byte order (big-endian).
"""

import socket
import struct

ETHER_TYPES = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x8100: "VLAN"}
IP_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
ICMP_TYPES = {0: "Echo Reply", 3: "Destination Unreachable", 5: "Redirect",
              8: "Echo Request", 11: "Time Exceeded"}
UNREACHABLE_CODES = {0: "Network Unreachable", 1: "Host Unreachable",
                     2: "Protocol Unreachable", 3: "Port Unreachable"}
# Display order follows Wireshark: "SYN, ACK", "PSH, ACK", "FIN, ACK"
TCP_FLAGS = [(0x002, "SYN"), (0x001, "FIN"), (0x004, "RST"), (0x008, "PSH"),
             (0x010, "ACK"), (0x020, "URG"), (0x040, "ECE"), (0x080, "CWR")]
SERVICES = {20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
            123: "NTP", 143: "IMAP", 443: "HTTPS", 993: "IMAPS", 3306: "MySQL",
            5353: "mDNS", 8080: "HTTP-alt"}


class DecodeError(Exception):
    """Frame too short or a header field has an impossible value."""


class Packet:
    """One decoded frame.

    layers : list of (layer name, dict of fields) from outermost to innermost
    proto  : highest decoded protocol, e.g. "TCP"
    src/dst, sport/dport : addresses and ports (ports are None if not TCP/UDP)
    info   : one-line description like Wireshark's Info column
    """

    def __init__(self, raw, timestamp=0.0):
        self.raw = raw
        self.time = timestamp
        self.length = len(raw)
        self.layers = []
        self.proto = "Ethernet"
        self.src = self.dst = ""
        self.sport = self.dport = None
        self.tcp_flags = None
        self.info = ""
        self.payload = b""
        self.errors = []          # e.g. bad checksum or truncated header

    def layer(self, name):
        for layer_name, fields in self.layers:
            if layer_name == name:
                return fields
        return None


# ---------------------------------------------------------------- helpers
def mac_str(b):
    return ":".join(f"{x:02x}" for x in b)


def ipv4_str(b):
    return socket.inet_ntoa(b)


def ipv6_str(b):
    return socket.inet_ntop(socket.AF_INET6, b)


def internet_checksum(data):
    """RFC 1071: one's complement of the one's complement sum of 16-bit
    words. Over a header that already contains its checksum the result
    is 0 if the header is undamaged."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:                       # fold carries back in
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def flag_names(flags):
    return [name for bit, name in TCP_FLAGS if flags & bit]


def service(port):
    return SERVICES.get(port, "")


# ---------------------------------------------------------------- layers
def parse_ethernet(data):
    if len(data) < 14:
        raise DecodeError("Ethernet header needs 14 bytes")
    dst, src, ethertype = struct.unpack("!6s6sH", data[:14])
    fields = {"dst": mac_str(dst), "src": mac_str(src),
              "type": f"{ETHER_TYPES.get(ethertype, 'Unknown')} (0x{ethertype:04x})"}
    offset = 14
    if ethertype == 0x8100 and len(data) >= 18:          # 802.1Q VLAN tag
        tci, ethertype = struct.unpack("!HH", data[14:18])
        fields["vlan"] = tci & 0x0FFF
        fields["type"] = f"{ETHER_TYPES.get(ethertype, 'Unknown')} (0x{ethertype:04x})"
        offset = 18
    return fields, ethertype, data[offset:]


def parse_arp(data):
    if len(data) < 28:
        raise DecodeError("ARP packet needs 28 bytes")
    (htype, ptype, hlen, plen, op,
     sha, spa, tha, tpa) = struct.unpack("!HHBBH6s4s6s4s", data[:28])
    return {"hw_type": htype, "proto_type": f"0x{ptype:04x}",
            "opcode": f"{op} ({'request' if op == 1 else 'reply' if op == 2 else '?'})",
            "sender_mac": mac_str(sha), "sender_ip": ipv4_str(spa),
            "target_mac": mac_str(tha), "target_ip": ipv4_str(tpa)}, op


def parse_ipv4(data):
    if len(data) < 20:
        raise DecodeError("IPv4 header needs 20 bytes")
    (ver_ihl, tos, total_len, ident, flags_frag, ttl, proto,
     csum, src, dst) = struct.unpack("!BBHHHBBH4s4s", data[:20])
    version, ihl = ver_ihl >> 4, (ver_ihl & 0x0F) * 4
    if version != 4 or ihl < 20 or len(data) < ihl:
        raise DecodeError("invalid IPv4 version or header length")
    flags = flags_frag >> 13
    fields = {
        "version": version, "header_len": ihl, "tos": f"0x{tos:02x}",
        "total_len": total_len, "id": f"0x{ident:04x}",
        "flags": ",".join(n for b, n in ((2, "DF"), (1, "MF"))
                          if flags & b) or "none",
        "frag_offset": (flags_frag & 0x1FFF) * 8, "ttl": ttl,
        "protocol": f"{IP_PROTOCOLS.get(proto, 'Other')} ({proto})",
        "checksum": f"0x{csum:04x}",
        "checksum_ok": internet_checksum(data[:ihl]) == 0,
        "src": ipv4_str(src), "dst": ipv4_str(dst),
    }
    end = min(len(data), total_len) if total_len >= ihl else len(data)
    return fields, proto, data[ihl:end]


def parse_ipv6(data):
    if len(data) < 40:
        raise DecodeError("IPv6 header needs 40 bytes")
    vtf, plen, nxt, hop, src, dst = struct.unpack("!IHBB16s16s", data[:40])
    return {"version": vtf >> 28, "traffic_class": (vtf >> 20) & 0xFF,
            "flow_label": f"0x{vtf & 0xFFFFF:05x}", "payload_len": plen,
            "next_header": f"{IP_PROTOCOLS.get(nxt, 'Other')} ({nxt})",
            "hop_limit": hop, "src": ipv6_str(src), "dst": ipv6_str(dst)}, nxt, data[40:40 + plen]


def parse_tcp(data):
    if len(data) < 20:
        raise DecodeError("TCP header needs 20 bytes")
    (sport, dport, seq, ack, off_flags,
     window, csum, urg) = struct.unpack("!HHIIHHHH", data[:20])
    header_len = (off_flags >> 12) * 4
    flags = off_flags & 0x1FF
    if header_len < 20 or len(data) < header_len:
        raise DecodeError("invalid TCP header length")
    return {"src_port": sport, "dst_port": dport, "seq": seq, "ack": ack,
            "header_len": header_len,
            "flags": "|".join(flag_names(flags)) or "none",
            "window": window, "checksum": f"0x{csum:04x}",
            "urgent_ptr": urg,
            "options_len": header_len - 20}, flags, data[header_len:]


def parse_udp(data):
    if len(data) < 8:
        raise DecodeError("UDP header needs 8 bytes")
    sport, dport, length, csum = struct.unpack("!HHHH", data[:8])
    return {"src_port": sport, "dst_port": dport, "length": length,
            "checksum": f"0x{csum:04x}"}, data[8:length] if length >= 8 else data[8:]


def parse_icmp(data):
    if len(data) < 8:
        raise DecodeError("ICMP header needs 8 bytes")
    icmp_type, code, csum, ident, seq = struct.unpack("!BBHHH", data[:8])
    fields = {"type": f"{icmp_type} ({ICMP_TYPES.get(icmp_type, 'Other')})", "code": code,
              "checksum": f"0x{csum:04x}", "checksum_ok": internet_checksum(data) == 0}
    if icmp_type in (0, 8):                          # echo: id and sequence
        fields["id"], fields["seq"] = ident, seq
    return fields, icmp_type, data[8:]


# ---------------------------------------------------------------- frame
def decode(raw, timestamp=0.0):
    """Decode one Ethernet frame. Never raises: a damaged or unknown layer
    is recorded in pkt.errors and decoding stops at that layer."""
    pkt = Packet(raw, timestamp)
    try:
        eth, ethertype, data = parse_ethernet(raw)
        pkt.layers.append(("Ethernet II", eth))
        pkt.src, pkt.dst = eth["src"], eth["dst"]

        if ethertype == 0x0806:
            arp, op = parse_arp(data)
            pkt.layers.append(("ARP", arp))
            pkt.proto, pkt.src, pkt.dst = "ARP", arp["sender_ip"], arp["target_ip"]
            pkt.info = (f"Who has {arp['target_ip']}? Tell {arp['sender_ip']}" if op == 1
                        else f"{arp['sender_ip']} is at {arp['sender_mac']}")
            return pkt

        if ethertype == 0x0800:
            ip, proto, data = parse_ipv4(data)
            pkt.layers.append(("IPv4", ip))
            if not ip["checksum_ok"]:
                pkt.errors.append("bad IPv4 header checksum")
        elif ethertype == 0x86DD:
            ip, proto, data = parse_ipv6(data)
            pkt.layers.append(("IPv6", ip))
        else:
            pkt.info = f"EtherType {eth['type']} (not decoded)"
            return pkt
        pkt.proto, pkt.src, pkt.dst = pkt.layers[-1][0], ip["src"], ip["dst"]

        if proto == 6:
            tcp, flags, payload = parse_tcp(data)
            pkt.layers.append(("TCP", tcp))
            pkt.proto, pkt.sport, pkt.dport, pkt.tcp_flags = "TCP", tcp["src_port"], tcp["dst_port"], flags
            pkt.payload = payload
            pkt.info = (f"{pkt.sport} \u2192 {pkt.dport} [{', '.join(flag_names(flags))}] "
                        f"Seq={tcp['seq']} Ack={tcp['ack']} Win={tcp['window']} Len={len(payload)}")
        elif proto == 17:
            udp, payload = parse_udp(data)
            pkt.layers.append(("UDP", udp))
            pkt.proto, pkt.sport, pkt.dport = "UDP", udp["src_port"], udp["dst_port"]
            pkt.payload = payload
            pkt.info = f"{pkt.sport} \u2192 {pkt.dport} Len={len(payload)}"
        elif proto == 1:
            icmp, icmp_type, payload = parse_icmp(data)
            pkt.layers.append(("ICMP", icmp))
            pkt.proto, pkt.payload = "ICMP", payload
            pkt.info = ICMP_TYPES.get(icmp_type, f"Type {icmp_type}")
            if "id" in icmp:
                pkt.info += f" id={icmp['id']} seq={icmp['seq']}"
            elif icmp_type == 3:
                pkt.info += f" ({UNREACHABLE_CODES.get(icmp['code'], 'code ' + str(icmp['code']))})"
        else:
            pkt.info = f"IP protocol {proto} (not decoded)"

        name = (service(pkt.dport) or service(pkt.sport)) if pkt.sport is not None else ""
        if name:
            pkt.info += f"  ({name})"
    except DecodeError as exc:
        pkt.errors.append(str(exc))
        pkt.info = pkt.info or f"[malformed: {exc}]"
    return pkt
