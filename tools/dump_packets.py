#!/usr/bin/env python3
"""
dump_packets.py - Extract Pkt*-prefixed packet type names from libUnreal.so

Scans the .rodata section (and .dynstr) of the ARM64 ELF binary for
null-terminated strings matching /^Pkt[A-Z]/, plus specific format strings.

Outputs packet_names.json with sorted packet names and format string addresses.
"""

import json
import mmap
import os
import re
import sys
import time
from pathlib import Path

from elftools.elf.elffile import ELFFile

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BINARY_PATH = Path(__file__).resolve().parent.parent / "lib" / "arm64-v8a" / "libUnreal.so"
OUTPUT_PATH = Path(__file__).resolve().parent.parent / "packet_names.json"

# Format strings we want to locate
FORMAT_STRINGS = [
    b"invalid packetId: %d",
    b"invalid packetId( %d ), packetName( %s )",
    b"PacketDestInfo",
]

# Regex for a valid Pkt packet name: starts with Pkt, then uppercase letter,
# then any combination of alphanumerics and underscores.
PKT_PATTERN = re.compile(rb"^Pkt[A-Z][A-Za-z0-9_]*$")


def extract_strings_from_range(mm: mmap.mmap, offset: int, size: int,
                                pattern: re.Pattern, label: str,
                                progress_interval: int = 10_000_000) -> set[str]:
    """
    Scan a byte range in the mmap for null-terminated strings matching `pattern`.
    Returns a set of decoded (UTF-8) string values.
    """
    results = set()
    end = offset + size
    pos = offset
    last_progress = offset

    print(f"  Scanning {label}: {size:,} bytes ({size / (1024*1024):.1f} MB)")

    while pos < end:
        # Show progress every ~10 MB
        if pos - last_progress >= progress_interval:
            pct = (pos - offset) / size * 100
            print(f"    ... {pct:.0f}% ({len(results)} matches so far)")
            last_progress = pos

        # Find the next null byte from current position
        null_pos = mm.find(b"\x00", pos, end)
        if null_pos == -1:
            break

        # The string is from pos..null_pos (exclusive)
        length = null_pos - pos
        if 4 <= length <= 256:
            # Only read strings in a plausible length range
            candidate = mm[pos:null_pos]
            if pattern.match(candidate):
                try:
                    results.add(candidate.decode("utf-8"))
                except UnicodeDecodeError:
                    pass

        # Advance past the null byte
        pos = null_pos + 1

    print(f"    Done: {len(results)} matches")
    return results


def find_format_strings(mm: mmap.mmap, offset: int, size: int,
                        targets: list[bytes]) -> dict[str, str | None]:
    """
    Search for specific byte sequences in a range and return their virtual
    addresses (as hex strings). We need the section's virtual address to
    compute this.
    """
    results = {}
    end = offset + size
    for target in targets:
        # Produce a short key from the target
        key = target.decode("utf-8", errors="replace")
        pos = mm.find(target, offset, end)
        if pos != -1:
            results[key] = pos - offset  # offset within section
        else:
            results[key] = None
    return results


def scan_dynstr(mm: mmap.mmap, offset: int, size: int) -> set[str]:
    """
    Scan the .dynstr section for any symbol names starting with Pkt[A-Z].
    .dynstr is a sequence of null-terminated strings.
    """
    results = set()
    end = offset + size
    pos = offset

    print(f"  Scanning .dynstr: {size:,} bytes")

    while pos < end:
        null_pos = mm.find(b"\x00", pos, end)
        if null_pos == -1:
            break
        length = null_pos - pos
        if length >= 4:
            candidate = mm[pos:null_pos]
            # In dynstr, symbol names may be mangled or have prefixes.
            # Look for Pkt anywhere in the name, but prefer exact starts.
            if candidate[:3] == b"Pkt" and len(candidate) <= 256:
                if PKT_PATTERN.match(candidate):
                    try:
                        results.add(candidate.decode("utf-8"))
                    except UnicodeDecodeError:
                        pass
        pos = null_pos + 1

    print(f"    Done: {len(results)} matches from .dynstr")
    return results


def main():
    t0 = time.time()
    binary = str(BINARY_PATH)
    print(f"Binary: {binary}")
    print(f"Size:   {os.path.getsize(binary) / (1024*1024):.1f} MB")
    print()

    # ------------------------------------------------------------------
    # Step 1: Open the ELF and locate sections of interest
    # ------------------------------------------------------------------
    print("[1/4] Parsing ELF headers ...")
    with open(binary, "rb") as f:
        elf = ELFFile(f)
        print(f"  Architecture: {elf.get_machine_arch()}")
        print(f"  Sections: {elf.num_sections()}")

        sections_info = {}
        for sec in elf.iter_sections():
            name = sec.name
            if name in (".rodata", ".dynstr", ".strtab"):
                sections_info[name] = {
                    "offset": sec["sh_offset"],
                    "size": sec["sh_size"],
                    "addr": sec["sh_addr"],  # virtual address
                }
                print(f"  Found {name}: offset=0x{sec['sh_offset']:x}, "
                      f"size={sec['sh_size']:,}, vaddr=0x{sec['sh_addr']:x}")

    if ".rodata" not in sections_info:
        print("ERROR: .rodata section not found!")
        sys.exit(1)

    # ------------------------------------------------------------------
    # Step 2: mmap the file and scan for packet names
    # ------------------------------------------------------------------
    print()
    print("[2/4] Scanning for Pkt* strings ...")

    fd = os.open(binary, os.O_RDONLY)
    try:
        mm = mmap.mmap(fd, 0, access=mmap.ACCESS_READ)
        try:
            # Scan .rodata for Pkt* strings
            rodata = sections_info[".rodata"]
            pkt_names = extract_strings_from_range(
                mm, rodata["offset"], rodata["size"],
                PKT_PATTERN, ".rodata"
            )

            # Also scan .strtab if present
            if ".strtab" in sections_info:
                strtab = sections_info[".strtab"]
                pkt_names |= extract_strings_from_range(
                    mm, strtab["offset"], strtab["size"],
                    PKT_PATTERN, ".strtab"
                )

            # Scan .dynstr
            print()
            print("[3/4] Scanning .dynstr for exported Pkt symbols ...")
            if ".dynstr" in sections_info:
                ds = sections_info[".dynstr"]
                dynstr_names = scan_dynstr(mm, ds["offset"], ds["size"])
                pkt_names |= dynstr_names
            else:
                print("  .dynstr not found, skipping")

            # ----------------------------------------------------------
            # Step 3: Locate format strings
            # ----------------------------------------------------------
            print()
            print("[4/4] Locating format strings ...")

            format_results: dict[str, str | None] = {}

            # Search in .rodata
            rodata_off = rodata["offset"]
            rodata_sz = rodata["size"]
            rodata_vaddr = rodata["addr"]

            for target in FORMAT_STRINGS:
                key = target.decode("utf-8", errors="replace")
                pos = mm.find(target, rodata_off, rodata_off + rodata_sz)
                if pos != -1:
                    vaddr = rodata_vaddr + (pos - rodata_off)
                    format_results[key] = f"0x{vaddr:x}"
                    print(f"  Found \"{key}\" at file offset 0x{pos:x}, "
                          f"vaddr 0x{vaddr:x}")
                else:
                    # Fallback: search entire file
                    pos = mm.find(target)
                    if pos != -1:
                        format_results[key] = f"0x{pos:x} (file offset, section unknown)"
                        print(f"  Found \"{key}\" at file offset 0x{pos:x} "
                              f"(outside .rodata)")
                    else:
                        format_results[key] = None
                        print(f"  NOT FOUND: \"{key}\"")

        finally:
            mm.close()
    finally:
        os.close(fd)

    # ------------------------------------------------------------------
    # Step 4: Build and write output
    # ------------------------------------------------------------------
    sorted_names = sorted(pkt_names)

    output = {
        "packet_names": sorted_names,
        "count": len(sorted_names),
        "format_strings": format_results,
    }

    output_path = str(OUTPUT_PATH)
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    elapsed = time.time() - t0
    print()
    print(f"Results written to {output_path}")
    print(f"Total packet names: {len(sorted_names)}")
    print(f"Elapsed: {elapsed:.1f}s")
    print()
    # Show first 10 and last 10 for a quick sanity check
    print("First 10:")
    for name in sorted_names[:10]:
        print(f"  {name}")
    print("Last 10:")
    for name in sorted_names[-10:]:
        print(f"  {name}")


if __name__ == "__main__":
    main()
