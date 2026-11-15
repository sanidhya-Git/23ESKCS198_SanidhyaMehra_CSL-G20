"""
sniffer.py - Packet sniffer and protocol analyzer.

Project : Python Packet Sniffer & Protocol Analyzer (Scapy)   [CSL-G20]
Author  : Sanidhya Mehra (23ESKCS198)

Live capture needs administrator rights (sudo on Linux/macOS, an
Administrator terminal + Npcap on Windows). Capture ONLY on your own
computer or a network you own, e.g. your own phone hotspot.

Examples
  python sniffer.py --list
  sudo python sniffer.py -i eth0 -c 50
  sudo python sniffer.py -i eth0 -p tcp --port 443 -v -w https.pcap
  python sniffer.py -r capture.pcap -p udp --stats
"""

import argparse
import sys
import time

from decoder import decode
from display import HEADER, detail, hexdump, summary
from filters import PROTOCOLS, PacketFilter
from pcapfile import PcapWriter, read_pcap
from stats import Statistics

WARNING = ("Capture only on your own computer or a network you are authorised to "
           "monitor (IT Act 2000, Sec. 43/66).")


class Analyzer:
    """Decodes, filters, prints, saves and counts every frame it is given."""

    def __init__(self, args):
        self.filter = PacketFilter(args.proto, args.port, args.host)
        self.verbose, self.hex = args.verbose, args.hex
        self.writer = PcapWriter(args.write) if args.write else None
        self.stats = Statistics()
        self.seen = 0
        self.shown = 0
        self.start = None
        self.limit = args.count

    def handle(self, raw, timestamp):
        self.seen += 1
        pkt = decode(raw, timestamp)
        if not self.filter.match(pkt):
            return
        if self.start is None:
            self.start = timestamp
        self.shown += 1
        print(summary(self.shown, pkt, self.start), flush=True)
        if self.verbose:
            print(detail(pkt))
        if self.hex:
            print(hexdump(raw))
        if self.verbose or self.hex:
            print()
        if self.writer:
            self.writer.write(raw, timestamp)
        self.stats.add(pkt)

    def done(self):
        return self.limit and self.shown >= self.limit

    def finish(self):
        if self.writer:
            self.writer.close()
            print(f"\nSaved {self.writer.count} packet(s) to {self.writer.f.name}")
        print(f"Frames seen: {self.seen}, matched filter: {self.shown}")
        print(self.stats.report())


def list_interfaces():
    from scapy.all import get_if_list
    print("Available interfaces:")
    for name in get_if_list():
        print("  ", name)


def live_capture(args, analyzer):
    from scapy.all import conf, sniff        # imported here: only needed live
    print(f"Capturing on {args.iface or conf.iface}  |  filter: {analyzer.filter.describe()}"
          f"  |  Ctrl+C to stop")
    print(HEADER)
    loopback = (args.iface or str(conf.iface)).startswith("lo")
    last = {"raw": None}

    def on_packet(p):
        raw = bytes(p)
        # On Linux loopback every frame is delivered twice (once as sent,
        # once as received) and both copies are identical. Skip the copy.
        if loopback and raw == last["raw"]:
            last["raw"] = None
            return
        last["raw"] = raw
        analyzer.handle(raw, float(p.time))

    sniff(iface=args.iface, filter=args.bpf, store=False,
          timeout=args.timeout or None, prn=on_packet,
          stop_filter=lambda p: analyzer.done())


def offline(args, analyzer):
    print(f"Reading {args.read}  |  filter: {analyzer.filter.describe()}")
    print(HEADER)
    for timestamp, raw in read_pcap(args.read):
        analyzer.handle(raw, timestamp)
        if analyzer.done():
            break


def build_parser():
    p = argparse.ArgumentParser(description="Packet sniffer and protocol analyzer")
    p.add_argument("-i", "--iface", help="interface to capture on (default: Scapy's default)")
    p.add_argument("-r", "--read", metavar="FILE", help="analyse a .pcap file instead of capturing")
    p.add_argument("-c", "--count", type=int, default=0, help="stop after N matching packets")
    p.add_argument("-t", "--timeout", type=int, default=0, help="stop after N seconds (live)")
    p.add_argument("-p", "--proto", nargs="+", choices=PROTOCOLS, help="keep only these protocols")
    p.add_argument("--port", type=int, help="keep only packets to/from this port")
    p.add_argument("--host", help="keep only packets to/from this IP address")
    p.add_argument("--bpf", help='kernel BPF filter passed to libpcap, e.g. "tcp port 80"')
    p.add_argument("-w", "--write", metavar="FILE", help="save matching packets to a .pcap file")
    p.add_argument("-v", "--verbose", action="store_true", help="show every header field")
    p.add_argument("-x", "--hex", action="store_true", help="show a hex dump of each frame")
    p.add_argument("--list", action="store_true", help="list capture interfaces and exit")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.list:
        list_interfaces()
        return 0
    try:
        analyzer = Analyzer(args)
    except (ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    if not args.read:
        print(WARNING)
    t0 = time.time()
    try:
        if args.read:
            offline(args, analyzer)
        else:
            live_capture(args, analyzer)
    except KeyboardInterrupt:
        print("\nStopped by user.")
    except PermissionError:
        print("Error: live capture needs administrator rights (use sudo / an Administrator terminal).",
              file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    finally:
        analyzer.finish()
        print(f"(ran for {time.time() - t0:.1f} s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
