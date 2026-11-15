"""
Unit tests. Frames are built with Scapy, then decoded by OUR decoder, and
every field is compared with Scapy's own dissection.
Run:  python -m unittest -v tests/test_sniffer.py
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, IPv6, Raw, rdpcap, wrpcap  # noqa: E402

from decoder import decode, internet_checksum  # noqa: E402
from filters import PacketFilter  # noqa: E402
from pcapfile import PcapWriter, read_pcap  # noqa: E402
from stats import Statistics  # noqa: E402

MAC1, MAC2 = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"


def frame(*layers):
    pkt = Ether(src=MAC1, dst=MAC2)
    for layer in layers:
        pkt = pkt / layer
    return bytes(pkt)          # bytes() makes Scapy fill lengths and checksums


class TestDecoder(unittest.TestCase):

    def test_ethernet(self):
        p = decode(frame(IP(src="10.0.0.1", dst="10.0.0.2") / TCP()))
        eth = p.layer("Ethernet II")
        self.assertEqual((eth["src"], eth["dst"]), (MAC1, MAC2))
        self.assertTrue(eth["type"].startswith("IPv4"))

    def test_ipv4_fields_match_scapy(self):
        raw = frame(IP(src="192.168.1.5", dst="8.8.8.8", ttl=57, id=0x1c46, flags="DF") / UDP())
        ref = Ether(raw)[IP]
        ip = decode(raw).layer("IPv4")
        self.assertEqual(ip["src"], ref.src)
        self.assertEqual(ip["dst"], ref.dst)
        self.assertEqual(ip["ttl"], ref.ttl)
        self.assertEqual(ip["total_len"], ref.len)
        self.assertEqual(ip["id"], f"0x{ref.id:04x}")
        self.assertEqual(ip["checksum"], f"0x{ref.chksum:04x}")
        self.assertEqual(ip["flags"], "DF")
        self.assertTrue(ip["checksum_ok"])

    def test_bad_ip_checksum_detected(self):
        raw = bytearray(frame(IP(src="1.1.1.1", dst="2.2.2.2") / ICMP()))
        raw[14 + 8] ^= 0xFF                      # damage the TTL byte
        p = decode(bytes(raw))
        self.assertFalse(p.layer("IPv4")["checksum_ok"])
        self.assertIn("bad IPv4 header checksum", p.errors)

    def test_tcp_fields_and_flags(self):
        raw = frame(IP() / TCP(sport=51514, dport=443, seq=1000, ack=2000, flags="SA", window=64240))
        ref = Ether(raw)[TCP]
        p = decode(raw)
        tcp = p.layer("TCP")
        self.assertEqual((tcp["src_port"], tcp["dst_port"]), (ref.sport, ref.dport))
        self.assertEqual((tcp["seq"], tcp["ack"], tcp["window"]), (1000, 2000, 64240))
        self.assertEqual(tcp["flags"], "SYN|ACK")
        self.assertIn("[SYN, ACK]", p.info)
        self.assertEqual(p.proto, "TCP")
        self.assertIn("(HTTPS)", p.info)

    def test_tcp_options_and_payload(self):
        raw = frame(IP() / TCP(dport=80, options=[("MSS", 1460), ("NOP", None), ("WScale", 7)])
                    / Raw(b"GET / HTTP/1.1\r\n"))
        p = decode(raw)
        self.assertEqual(p.layer("TCP")["header_len"], Ether(raw)[TCP].dataofs * 4)
        self.assertEqual(p.payload, b"GET / HTTP/1.1\r\n")

    def test_udp(self):
        raw = frame(IP() / UDP(sport=5353, dport=53) / Raw(b"x" * 12))
        p = decode(raw)
        self.assertEqual((p.sport, p.dport, p.proto), (5353, 53, "UDP"))
        self.assertEqual(p.layer("UDP")["length"], 20)
        self.assertIn("(DNS)", p.info)

    def test_icmp_echo(self):
        raw = frame(IP(src="10.0.0.1", dst="10.0.0.9") / ICMP(type=8, id=7, seq=3) / Raw(b"abcd"))
        p = decode(raw)
        icmp = p.layer("ICMP")
        self.assertEqual((icmp["id"], icmp["seq"]), (7, 3))
        self.assertTrue(icmp["checksum_ok"])
        self.assertEqual(p.info, "Echo Request id=7 seq=3")

    def test_icmp_port_unreachable(self):
        p = decode(frame(IP() / ICMP(type=3, code=3) / IP() / UDP(dport=9999)))
        self.assertEqual(p.info, "Destination Unreachable (Port Unreachable)")

    def test_arp(self):
        p = decode(bytes(Ether(src=MAC1, dst="ff:ff:ff:ff:ff:ff") /
                         ARP(op=1, hwsrc=MAC1, psrc="192.168.1.5", pdst="192.168.1.1")))
        self.assertEqual(p.proto, "ARP")
        self.assertEqual(p.info, "Who has 192.168.1.1? Tell 192.168.1.5")

    def test_ipv6_tcp(self):
        p = decode(frame(IPv6(src="fe80::1", dst="fe80::2", hlim=64) / TCP(dport=22)))
        self.assertEqual(p.layer("IPv6")["src"], "fe80::1")
        self.assertEqual((p.proto, p.dport), ("TCP", 22))

    def test_truncated_frame_does_not_crash(self):
        raw = frame(IP() / TCP())[:30]           # cut inside the IP header
        p = decode(raw)
        self.assertTrue(p.errors)
        self.assertIn("malformed", p.info)

    def test_checksum_rfc1071_example(self):
        # RFC 1071 section 3 example words: 0001 f203 f4f5 f6f7 -> sum ddf2
        self.assertEqual(internet_checksum(bytes.fromhex("0001f203f4f5f6f7")), 0xFFFF - 0xDDF2)


class TestFilter(unittest.TestCase):

    def setUp(self):
        self.tcp80 = decode(frame(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40000, dport=80)))
        self.udp53 = decode(frame(IP(src="10.0.0.3", dst="10.0.0.4") / UDP(dport=53)))

    def test_protocol(self):
        f = PacketFilter(protocols=["tcp"])
        self.assertTrue(f.match(self.tcp80))
        self.assertFalse(f.match(self.udp53))

    def test_port_either_direction(self):
        self.assertTrue(PacketFilter(port=40000).match(self.tcp80))
        self.assertFalse(PacketFilter(port=443).match(self.tcp80))

    def test_combined_and_host(self):
        f = PacketFilter(protocols=["udp"], port=53, host="10.0.0.4")
        self.assertTrue(f.match(self.udp53))
        self.assertFalse(PacketFilter(host="10.0.0.9").match(self.udp53))

    def test_invalid_values(self):
        with self.assertRaises(ValueError):
            PacketFilter(protocols=["http"])
        with self.assertRaises(ValueError):
            PacketFilter(port=70000)


class TestPcap(unittest.TestCase):

    def test_our_file_opens_in_scapy(self):
        frames = [frame(IP() / TCP(dport=p)) for p in (80, 443, 22)]
        path = os.path.join(tempfile.mkdtemp(), "t.pcap")
        with PcapWriter(path) as w:
            for i, raw in enumerate(frames):
                w.write(raw, 1762337000.25 + i)
        back = rdpcap(path)
        self.assertEqual([bytes(p) for p in back], frames)
        self.assertAlmostEqual(float(back[1].time), 1762337001.25, places=5)

    def test_we_read_scapy_files(self):
        pkts = [Ether() / IP() / UDP(dport=53), Ether() / IP() / ICMP()]
        path = os.path.join(tempfile.mkdtemp(), "s.pcap")
        wrpcap(path, pkts)
        self.assertEqual([raw for _, raw in read_pcap(path)], [bytes(p) for p in pkts])


class TestStatistics(unittest.TestCase):

    def test_counts_and_syn_scan_alert(self):
        s = Statistics()
        for port in range(1, 31):                # 30 SYN-only probes
            s.add(decode(frame(IP(src="10.0.0.66", dst="10.0.0.1") / TCP(dport=port, flags="S")), port))
        s.add(decode(frame(IP() / UDP(dport=53)), 31))
        self.assertEqual(s.packets, 31)
        self.assertEqual(s.protocols["TCP"], 30)
        self.assertEqual(s.tcp_flags["SYN"], 30)
        self.assertEqual(len(s.alerts()), 1)
        self.assertIn("10.0.0.66", s.alerts()[0])

    def test_normal_traffic_no_alert(self):
        s = Statistics()
        for i in range(40):
            s.add(decode(frame(IP(src="10.0.0.5", dst="10.0.0.1") / TCP(dport=443, flags="S")), i))
        self.assertEqual(s.alerts(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
