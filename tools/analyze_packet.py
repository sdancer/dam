#!/usr/bin/env python3
"""Parse plog hexdump, XOR-decrypt with discovered key, decode fields."""

import re
import struct
import json
from collections import Counter

XOR_KEY = bytes.fromhex("9aa78420d0c978b3")

# Load opcode map
with open("packet_opcodes.json") as f:
    OPCODES = json.load(f)["opcode_map"]

with open("packet_definitions.json") as f:
    DEFS = json.load(f)["packets"]


def parse_plog(path):
    entries = []
    current = None
    with open(path) as f:
        for line in f:
            line = line.rstrip()
            m = re.match(r'\[hexdump\]\s+(.*?)\s+pkt#(\d+)\s+\((\d+) bytes\)', line)
            if m:
                desc, pkt_num, nbytes = m.group(1), int(m.group(2)), int(m.group(3))
                direction = "C->S" if "client ->" in desc else "S->C"
                current = {"dir": direction, "pkt": pkt_num, "size": nbytes, "data": bytearray()}
                entries.append(current)
                continue
            if current and re.match(r'^[0-9a-f]{4}  ', line):
                hex_part = line[6:54].strip()
                current["data"].extend(bytes.fromhex(hex_part.replace(" ", "")))
            elif line.startswith("["):
                current = None
    return entries


def reassemble(entries):
    streams = {}
    for e in entries:
        streams.setdefault(e["dir"], bytearray()).extend(e["data"])
    result = {}
    for d, stream in streams.items():
        pkts = []
        off = 0
        while off + 2 <= len(stream):
            pkt_len = struct.unpack_from("<H", stream, off)[0]
            if pkt_len < 4 or off + pkt_len > len(stream):
                break
            pkts.append(bytes(stream[off:off + pkt_len]))
            off += pkt_len
        result[d] = pkts
    return result


def xor_decrypt(data):
    return bytes(data[i] ^ XOR_KEY[i % len(XOR_KEY)] for i in range(len(data)))


def hexdump(data, indent=4, limit=None):
    if limit and len(data) > limit:
        data = data[:limit]
    lines = []
    for row in range(0, len(data), 16):
        chunk = data[row:row + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        ascpart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{' '*indent}{row:04x}  {hexpart:<48s}  {ascpart}")
    return "\n".join(lines)


def try_decode_utf8(data):
    """Try to decode bytes as UTF-8, return string or hex."""
    try:
        return data.decode("utf-8")
    except:
        return data.hex()


def extract_strings(data, max_strings=50):
    """Extract length-prefixed strings from serialized data."""
    strings = []
    off = 0
    while off + 2 <= len(data) and len(strings) < max_strings:
        slen = struct.unpack_from("<H", data, off)[0]
        if 1 <= slen <= 500 and off + 2 + slen <= len(data):
            raw = data[off + 2:off + 2 + slen]
            # Check if it looks like a valid string (UTF-8 or ASCII)
            try:
                s = raw.decode("utf-8")
                if all(c.isprintable() or c in '\n\r\t' for c in s):
                    strings.append((off, slen, s))
                    off += 2 + slen
                    continue
            except:
                pass
        off += 1
    return strings


def parse_pkt_fields(dec, direction):
    """Try to identify the packet structure."""
    if len(dec) < 2:
        return

    # First byte seems to always be 0x9a (magic/version)
    magic = dec[0]
    rest = dec[1:]

    # Try to find opcode - scan for known patterns
    # In small packets: byte[1] might be opcode
    # In larger packets: might be at different offset
    possible_opcodes = []
    for off in range(0, min(8, len(rest))):
        if off + 1 < len(rest):
            op8 = rest[off]
            if str(op8) in OPCODES:
                possible_opcodes.append((off + 1, op8, OPCODES[str(op8)]))
        if off + 2 <= len(rest):
            op16 = struct.unpack_from("<H", rest, off)[0]
            if str(op16) in OPCODES:
                possible_opcodes.append((off + 1, op16, OPCODES[str(op16)]))

    if possible_opcodes:
        # Pick the most likely (smallest offset)
        best = possible_opcodes[0]
        print(f"  Likely opcode: {best[1]} = {best[2]} (at body offset {best[0]})")
        opcode = best[1]
        if str(opcode) in DEFS:
            fields = DEFS[str(opcode)].get("fields", [])
            print(f"  Expected fields: {fields}")

    # Extract strings
    strings = extract_strings(dec[1:])
    if strings:
        print(f"  Strings found ({len(strings)}):")
        for off, slen, s in strings:
            # Truncate display of long strings
            display = s if len(s) <= 80 else s[:77] + "..."
            print(f"    @{off:4d} [{slen:3d}] {display}")


def main():
    entries = parse_plog("plog")
    packets = reassemble(entries)

    print(f"XOR Key: {XOR_KEY.hex()}")
    print(f"Packets: C->S={len(packets.get('C->S',[]))}, S->C={len(packets.get('S->C',[]))}")

    for direction in ["C->S", "S->C"]:
        pkts = packets.get(direction, [])
        for i, pkt in enumerate(pkts):
            body = pkt[2:]  # skip length
            dec = xor_decrypt(body)
            zeros = dec.count(0)
            total = len(dec)

            print(f"\n{'='*70}")
            print(f"{direction} Pkt[{i}] | raw={len(pkt)} bytes | zeros={zeros}/{total}")
            print(f"{'='*70}")

            # Show hex dump (first 128 bytes)
            show_bytes = min(len(dec), 128)
            print(hexdump(dec[:show_bytes]))
            if len(dec) > show_bytes:
                print(f"    ... ({len(dec) - show_bytes} more bytes)")

            # Parse fields
            parse_pkt_fields(dec, direction)


if __name__ == "__main__":
    main()
