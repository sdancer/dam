#!/usr/bin/env python3
"""Decode all packets from plog with XOR key, extract server list."""

import re
import struct
import json

XOR_KEY = bytes.fromhex("9aa78420d0c978b3")

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
                desc = m.group(1)
                direction = "C->S" if "client ->" in desc else "S->C"
                current = {"dir": direction, "data": bytearray()}
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


def read_u8(data, off):
    return data[off], off + 1

def read_u16(data, off):
    return struct.unpack_from("<H", data, off)[0], off + 2

def read_u32(data, off):
    return struct.unpack_from("<I", data, off)[0], off + 4

def read_str(data, off):
    slen, off = read_u16(data, off)
    raw = data[off:off + slen]
    try:
        return raw.decode("utf-8"), off + slen
    except:
        return raw.hex(), off + slen


def decode_pkt_version(dec):
    """Decode PktVersion (opcode 1) C->S."""
    # Header: 9a XX XX XX 00 01 00 00
    off = 9  # skip to first field
    fields = {}
    for name in ["ClientVersion", "ClientAssetVersion", "OsVersion",
                  "DeviceModelName", "DeviceId"]:
        if off + 2 > len(dec):
            break
        # Check if there's a flag byte before some strings
        if off < len(dec) and dec[off] in (0, 1) and name not in ("ClientVersion",):
            flag, off = read_u8(dec, off)
        val, off = read_str(dec, off)
        fields[name] = val
    return fields


def decode_server_list(dec):
    """Decode the large S->C packet (server/world list)."""
    # Skip: 9a, some header bytes, until we find the list
    # Structure seems to be: [header][count: u16][entries...]
    # Each entry: [u32 id][u16 strlen][utf8 name]

    off = 7  # skip 9a + header
    count, off = read_u16(dec, off)
    print(f"  Entry count: {count}")

    # Parse character/NPC name table
    names = {}
    for _ in range(count):
        if off + 6 > len(dec):
            break
        npc_id, off = read_u32(dec, off)
        name, off = read_str(dec, off)
        names[npc_id] = name

    print(f"\n  NPC/Character Name Table ({len(names)} entries):")
    for npc_id, name in sorted(names.items()):
        print(f"    {npc_id:4d} = {name}")

    # After the name table, look for server list entries
    # Format appears to be: [count][server entries...]
    # Each server: [u32 id][str name][str ip][str message][flags...]
    print(f"\n  Remaining data from offset {off}:")

    # Try to parse as server list
    servers = []
    remaining = dec[off:]

    # Scan for IP-like patterns to identify server entries
    # Look for entries with format: [name_str][ip_str][msg_str]
    pos = 0
    while pos + 2 < len(remaining):
        slen = struct.unpack_from("<H", remaining, pos)[0]
        if 3 <= slen <= 50 and pos + 2 + slen < len(remaining):
            try:
                s = remaining[pos + 2:pos + 2 + slen].decode("utf-8")
                if all(c.isprintable() for c in s):
                    # Check if next field is an IP
                    next_off = pos + 2 + slen
                    if next_off + 2 < len(remaining):
                        next_slen = struct.unpack_from("<H", remaining, next_off)[0]
                        if 7 <= next_slen <= 15 and next_off + 2 + next_slen < len(remaining):
                            try:
                                ip = remaining[next_off + 2:next_off + 2 + next_slen].decode("ascii")
                                if re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                                    # Found server name + IP pair
                                    # Try to get the message after IP
                                    msg_off = next_off + 2 + next_slen
                                    msg = ""
                                    if msg_off + 2 < len(remaining):
                                        msg_slen = struct.unpack_from("<H", remaining, msg_off)[0]
                                        if 1 <= msg_slen <= 200 and msg_off + 2 + msg_slen <= len(remaining):
                                            try:
                                                msg = remaining[msg_off + 2:msg_off + 2 + msg_slen].decode("utf-8")
                                            except:
                                                pass
                                    servers.append({
                                        "name": s,
                                        "ip": ip,
                                        "message": msg
                                    })
                                    pos = next_off + 2 + next_slen
                                    if msg:
                                        pos = msg_off + 2 + len(msg.encode("utf-8"))
                                    continue
                            except:
                                pass
            except:
                pass
        pos += 1

    if servers:
        print(f"\n  Server List ({len(servers)} servers):")
        print(f"  {'Name':<12s} {'IP':<18s} Message")
        print(f"  {'-'*11:<12s} {'-'*17:<18s} {'-'*50}")
        for srv in servers:
            print(f"  {srv['name']:<12s} {srv['ip']:<18s} {srv['message'][:60]}")

    return names, servers


def main():
    entries = parse_plog("plog")
    packets = reassemble(entries)

    print(f"XOR Key: {XOR_KEY.hex()}\n")

    # Decode C->S packets
    for i, pkt in enumerate(packets.get("C->S", [])):
        dec = xor_decrypt(pkt[2:])
        print(f"=== C->S Pkt[{i}] ({len(pkt)} bytes) ===")

        if i == 0:
            fields = decode_pkt_version(dec)
            print(f"  PktVersion (opcode 1):")
            for k, v in fields.items():
                print(f"    {k}: {v}")
        else:
            # Second packet - continuation with hashes/tokens
            strings = []
            off = 0
            while off + 2 < len(dec):
                slen = struct.unpack_from("<H", dec, off)[0]
                if 1 <= slen <= 200 and off + 2 + slen <= len(dec):
                    try:
                        s = dec[off + 2:off + 2 + slen].decode("utf-8")
                        if all(c.isprintable() or c in ' \t' for c in s):
                            strings.append((off, s))
                            off += 2 + slen
                            continue
                    except:
                        pass
                off += 1
            print(f"  Strings: {[s for _, s in strings]}")
        print()

    # Decode S->C packets
    for i, pkt in enumerate(packets.get("S->C", [])):
        dec = xor_decrypt(pkt[2:])
        print(f"=== S->C Pkt[{i}] ({len(pkt)} bytes) ===")

        if i == 0:
            # PktVersionResult
            print(f"  PktVersionResult (opcode 2):")
            print(f"    magic=0x{dec[0]:02x}, opcode_byte=0x{dec[1]:02x}")
            if len(dec) >= 10:
                # Try to extract result fields
                print(f"    Raw fields: {dec[2:].hex()}")
        elif len(pkt) > 100:
            # Large packet - server/world list
            print(f"  Large data packet ({len(pkt)} bytes) - server/world list:")
            names, servers = decode_server_list(dec)
        print()


if __name__ == "__main__":
    main()
