"""
verify_with_tshark.py - Cross-checks our decoder against tshark (the
command-line version of Wireshark) on the same .pcap file.

  python tools/verify_with_tshark.py capture.pcap

For every packet it compares source/destination IP, IP TTL, protocol,
ports, TCP flags, sequence numbers and ICMP type. Needs tshark installed.
"""

import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from decoder import decode  # noqa: E402
from pcapfile import read_pcap  # noqa: E402

FIELDS = ["ip.src", "ip.dst", "ip.ttl", "ip.proto", "tcp.srcport", "tcp.dstport",
          "tcp.flags", "tcp.seq_raw", "udp.srcport", "udp.dstport", "icmp.type"]


def ours(pkt):
    ip, tcp, udp, icmp = (pkt.layer(n) for n in ("IPv4", "TCP", "UDP", "ICMP"))
    if not ip:
        return None
    flags = 0
    if tcp:
        flags = pkt.tcp_flags
    return [ip["src"], ip["dst"], str(ip["ttl"]), ip["protocol"].split("(")[1].rstrip(")"),
            str(tcp["src_port"]) if tcp else "", str(tcp["dst_port"]) if tcp else "",
            f"0x{flags:04x}" if tcp else "", str(tcp["seq"]) if tcp else "",
            str(udp["src_port"]) if udp else "", str(udp["dst_port"]) if udp else "",
            icmp["type"].split(" ")[0] if icmp else ""]


def pkt_is_icmp(fields):
    return fields[3] == "1"


def main(path):
    cmd = ["tshark", "-r", path, "-T", "fields", "-E", "separator=\t"]
    for f in FIELDS:
        cmd += ["-e", f]
    theirs = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.splitlines()
    checked = mismatches = 0
    for no, ((ts, raw), line) in enumerate(zip(read_pcap(path), theirs), 1):
        mine = ours(decode(raw, ts))
        if mine is None:
            continue
        t = (line.split("\t") + [""] * len(FIELDS))[:len(FIELDS)]
        # ICMP error messages quote the original IP + UDP/TCP header; tshark
        # lists outer and inner values ("a,b"). Compare the outer value and
        # skip the quoted transport fields, which our decoder does not parse.
        t = [v.split(",")[0] for v in t]
        if pkt_is_icmp(mine):
            t = [v if not f.startswith(("tcp.", "udp.")) else "" for f, v in zip(FIELDS, t)]
        checked += 1
        for name, a, b in zip(FIELDS, mine, t):
            if a != b:
                mismatches += 1
                print(f"packet {no}: {name} ours={a!r} tshark={b!r}")
    print(f"Compared {checked} IPv4 packets x {len(FIELDS)} fields with tshark: "
          f"{mismatches} mismatch(es)")
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
