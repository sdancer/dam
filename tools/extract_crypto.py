#!/usr/bin/env python3
"""
Extract AES-CBC crypto keys (_InitialKey and _InitialIV) from libnmsssa.so.

This script parses the ARM64 shared library using LIEF to locate the
exported _InitialKey and _InitialIV symbols, reads their 16-byte values
from the .data section, and writes the results to crypto_keys.json.

Usage:
    python tools/extract_crypto.py [--so-path PATH] [--output PATH]
"""

import argparse
import json
import sys
from pathlib import Path

try:
    import lief
except ImportError:
    print("Error: lief is required. Install with: pip install lief", file=sys.stderr)
    sys.exit(1)


DEFAULT_SO_PATH = Path(__file__).resolve().parent.parent / "lib" / "arm64-v8a" / "libnmsssa.so"
DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "crypto_keys.json"


def find_section_for_va(binary, va):
    """Find the section containing the given virtual address."""
    for section in binary.sections:
        sec_start = section.virtual_address
        sec_end = sec_start + section.size
        if sec_start <= va < sec_end:
            return section
    return None


def read_bytes_at_va(binary, va, size):
    """Read `size` bytes from the binary at virtual address `va`."""
    section = find_section_for_va(binary, va)
    if section is None:
        raise ValueError(f"No section found containing VA 0x{va:x}")

    offset_in_section = va - section.virtual_address
    content = bytes(section.content)

    if offset_in_section + size > len(content):
        raise ValueError(
            f"Read of {size} bytes at VA 0x{va:x} exceeds section "
            f"'{section.name}' bounds (section size: 0x{len(content):x})"
        )

    return content[offset_in_section : offset_in_section + size]


def extract_crypto_keys(so_path):
    """
    Extract _InitialKey and _InitialIV from the given .so file.

    Returns a dict with keys:
        - initial_key_hex: hex string of the 16-byte AES key
        - initial_iv_hex: hex string of the 16-byte AES IV
        - initial_key_bytes: list of integer byte values
        - initial_iv_bytes: list of integer byte values
        - symbol_info: metadata about the symbols (address, size, section)
    """
    binary = lief.parse(str(so_path))
    if binary is None:
        raise RuntimeError(f"Failed to parse binary: {so_path}")

    results = {}
    targets = {
        "_InitialKey": {"output_prefix": "initial_key", "expected_size": 16},
        "_InitialIV": {"output_prefix": "initial_iv", "expected_size": 16},
    }

    symbol_info = {}

    for sym in binary.symbols:
        if sym.name in targets:
            cfg = targets[sym.name]
            prefix = cfg["output_prefix"]
            expected = cfg["expected_size"]

            # Use the symbol's own size if available, otherwise fall back to expected
            read_size = sym.size if sym.size > 0 else expected

            section = find_section_for_va(binary, sym.value)
            section_name = section.name if section else "unknown"

            data = read_bytes_at_va(binary, sym.value, read_size)

            results[f"{prefix}_hex"] = data.hex()
            results[f"{prefix}_bytes"] = list(data)

            symbol_info[sym.name] = {
                "virtual_address": f"0x{sym.value:x}",
                "size": sym.size,
                "section": section_name,
                "type": str(sym.type).split(".")[-1],
            }

    # Verify we found both symbols
    for name in targets:
        if name not in symbol_info:
            raise RuntimeError(f"Symbol '{name}' not found in {so_path}")

    results["symbol_info"] = symbol_info
    results["source_binary"] = str(so_path)
    results["algorithm"] = "AES-128-CBC"
    results["key_size_bits"] = 128

    return results


def main():
    parser = argparse.ArgumentParser(description="Extract AES-CBC crypto keys from libnmsssa.so")
    parser.add_argument(
        "--so-path",
        type=Path,
        default=DEFAULT_SO_PATH,
        help=f"Path to libnmsssa.so (default: {DEFAULT_SO_PATH})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Output JSON file path (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args()

    if not args.so_path.exists():
        print(f"Error: Binary not found at {args.so_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Parsing binary: {args.so_path}")
    keys = extract_crypto_keys(args.so_path)

    print(f"\nExtracted keys:")
    print(f"  _InitialKey : {keys['initial_key_hex']}")
    print(f"  _InitialIV  : {keys['initial_iv_hex']}")
    print(f"  Algorithm   : {keys['algorithm']}")
    print(f"  Key size    : {keys['key_size_bits']} bits")
    print()

    for sym_name, info in keys["symbol_info"].items():
        print(f"  {sym_name}: VA={info['virtual_address']}, size={info['size']}, "
              f"section={info['section']}, type={info['type']}")

    # Write output
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(keys, f, indent=2)

    print(f"\nKeys written to: {args.output}")


if __name__ == "__main__":
    main()
