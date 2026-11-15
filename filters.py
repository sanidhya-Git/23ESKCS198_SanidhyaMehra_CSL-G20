"""
filters.py - Display filter applied to decoded packets.

Example: PacketFilter(protocols={"tcp"}, port=80, host="192.168.1.5")
keeps only TCP packets to or from port 80 that involve 192.168.1.5.
Every given condition must match (logical AND); a condition left as None
matches everything.
"""

PROTOCOLS = ("tcp", "udp", "icmp", "arp", "ipv4", "ipv6")


class PacketFilter:
    def __init__(self, protocols=None, port=None, host=None):
        self.protocols = {p.lower() for p in protocols} if protocols else None
        bad = (self.protocols or set()) - set(PROTOCOLS)
        if bad:
            raise ValueError(f"unknown protocol(s): {', '.join(sorted(bad))}")
        if port is not None and not 0 <= port <= 65535:
            raise ValueError("port must be between 0 and 65535")
        self.port = port
        self.host = host

    def match(self, pkt):
        if self.protocols:
            names = {name.lower().replace("ethernet ii", "ethernet")
                     for name, _ in pkt.layers}
            if not self.protocols & names:
                return False
        if self.port is not None and self.port not in (pkt.sport, pkt.dport):
            return False
        if self.host is not None and self.host not in (pkt.src, pkt.dst):
            return False
        return True

    def describe(self):
        parts = []
        if self.protocols:
            parts.append(" or ".join(sorted(self.protocols)))
        if self.port is not None:
            parts.append(f"port {self.port}")
        if self.host:
            parts.append(f"host {self.host}")
        return " and ".join(parts) or "none (all packets)"
