"""
display.py - Text output: one summary line per packet (like Wireshark's
packet list), a detailed layer tree, and a hex dump.
"""

HEADER = f"{'No.':>5}  {'Time':>9}  {'Source':<17} {'Destination':<17} {'Proto':<5} {'Len':>5}  Info"


def summary(no, pkt, start):
    src = pkt.src if len(pkt.src) <= 17 else pkt.src[:16] + "\u2026"
    dst = pkt.dst if len(pkt.dst) <= 17 else pkt.dst[:16] + "\u2026"
    flag = "  !" + "; ".join(pkt.errors) if pkt.errors else ""
    return (f"{no:>5}  {pkt.time - start:>9.4f}  {src:<17} {dst:<17} "
            f"{pkt.proto:<5} {pkt.length:>5}  {pkt.info}{flag}")


def detail(pkt):
    lines = []
    for name, fields in pkt.layers:
        lines.append(f"    {name}")
        for key, value in fields.items():
            if key == "checksum_ok":
                value = "correct" if value else "WRONG"
            lines.append(f"        {key:<13} {value}")
    if pkt.payload:
        lines.append(f"    Payload: {len(pkt.payload)} bytes")
    return "\n".join(lines)


def hexdump(data, width=16):
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"    {off:04x}  {hexpart:<{width * 3}} {text}")
    return "\n".join(lines)
