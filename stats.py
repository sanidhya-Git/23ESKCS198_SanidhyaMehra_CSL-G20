"""
stats.py - Running statistics and a simple SYN-scan alert.

A port scanner sends TCP packets with only the SYN flag set to many
different ports of one host. If one source sends SYN-only packets to more
than SCAN_PORTS different destination ports, it is reported.
"""

from collections import Counter, defaultdict

SYN, ACK = 0x002, 0x010
FLAG_BITS = {"SYN": 0x002, "ACK": 0x010, "FIN": 0x001, "RST": 0x004, "PSH": 0x008}
SCAN_PORTS = 15


class Statistics:
    def __init__(self):
        self.packets = 0
        self.bytes = 0
        self.first = self.last = None
        self.protocols = Counter()
        self.talkers = Counter()           # source address -> packets
        self.ports = Counter()             # destination port -> packets
        self.tcp_flags = Counter()
        self.errors = 0
        self.syn_targets = defaultdict(set)   # (src, dst) -> ports probed

    def add(self, pkt):
        self.packets += 1
        self.bytes += pkt.length
        self.first = pkt.time if self.first is None else self.first
        self.last = pkt.time
        self.protocols[pkt.proto] += 1
        if pkt.src:
            self.talkers[pkt.src] += 1
        if pkt.dport is not None:
            self.ports[pkt.dport] += 1
        if pkt.errors:
            self.errors += 1
        if pkt.tcp_flags is not None:
            for name, bit in FLAG_BITS.items():
                if pkt.tcp_flags & bit:
                    self.tcp_flags[name] += 1
            if pkt.tcp_flags & SYN and not pkt.tcp_flags & ACK:
                self.syn_targets[(pkt.src, pkt.dst)].add(pkt.dport)

    def alerts(self):
        return [f"Possible port scan: {src} sent SYN to {len(ports)} "
                f"ports on {dst}"
                for (src, dst), ports in self.syn_targets.items()
                if len(ports) > SCAN_PORTS]

    def report(self):
        duration = (self.last - self.first) if self.packets > 1 else 0.0
        lines = ["", "=" * 64, "Capture summary", "=" * 64,
                 f"Packets: {self.packets}   Bytes: {self.bytes}   Duration: {duration:.2f} s"
                 + (f"   Rate: {self.packets / duration:.1f} pkt/s" if duration > 0 else ""),
                 "Protocols: " + ", ".join(f"{p} {n}" for p, n in self.protocols.most_common()),
                 "Top sources: " + ", ".join(f"{a} ({n})" for a, n in self.talkers.most_common(3)),
                 "Top destination ports: " + ", ".join(f"{p} ({n})" for p, n in self.ports.most_common(5)),
                 "TCP flags: " + (", ".join(f"{f} {n}" for f, n in self.tcp_flags.most_common()) or "-"),
                 f"Malformed or bad-checksum packets: {self.errors}"]
        alerts = self.alerts()
        lines += ["ALERT: " + a for a in alerts] if alerts else ["Alerts: none"]
        return "\n".join(lines)
