# Python Packet Sniffer & Protocol Analyzer (Scapy)

Project code: CSL-G20 | Sanidhya Mehra (23ESKCS198)
Cyber Security Lab (7CS4-22), SKIT Jaipur | Linked experiment: Exp 4 (Wireshark / tcpdump, TCP & UDP)

Captures live packets (with Scapy), decodes the Ethernet, ARP, IPv4, IPv6,
TCP, UDP and ICMP headers with its own struct-based decoder, filters by
protocol / port / host, saves to .pcap (own writer, opens in Wireshark),
prints statistics and warns about possible port scans.

> Capture ONLY on your own computer or a network you own (e.g. your own
> phone hotspot). Never on the college network. (IT Act 2000, Sec. 43/66)

## Setup

    pip install -r requirements.txt
    Windows: also install Npcap (https://npcap.com) and use an Administrator terminal.
    Linux/macOS: run live capture with sudo.

## Usage

    python sniffer.py --list                         # show interfaces
    sudo python sniffer.py -i eth0 -c 20             # 20 packets
    sudo python sniffer.py -i eth0 -p tcp --port 443 # only HTTPS
    sudo python sniffer.py -i eth0 -p udp icmp -v    # full header tree
    sudo python sniffer.py -i eth0 -x -c 5           # hex dump
    sudo python sniffer.py -i eth0 -t 30 -w out.pcap # 30 s, save to file
    python sniffer.py -r out.pcap --host 10.0.0.5    # analyse a saved file

Options: -i iface, -r file, -c count, -t seconds, -p protocols, --port,
--host, --bpf "kernel filter", -w file.pcap, -v verbose, -x hex dump.

## Demo on your own machine only (Linux loopback)

    sudo python sniffer.py -i lo -t 15 -w demo.pcap      # terminal 1
    python tools/local_traffic.py all                    # terminal 2
    python tools/verify_with_tshark.py demo.pcap         # compare with Wireshark's tshark

## Tests

    python -m unittest -v tests/test_sniffer.py          # 19 tests

## Files

    sniffer.py        command-line program (capture, offline reading, output)
    decoder.py        header decoding with struct (Ethernet ... ICMP), checksums
    filters.py        protocol / port / host filter
    pcapfile.py       .pcap writer and reader
    stats.py          statistics and SYN port-scan alert
    display.py        summary line, layer tree, hex dump
    tools/local_traffic.py      test traffic on 127.0.0.1 only
    tools/verify_with_tshark.py cross-check against tshark
    tests/test_sniffer.py       unit tests
