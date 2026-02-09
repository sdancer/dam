#!/usr/bin/env python3
"""
parse_ue_reflection.py - Extract packet field definitions from libUnreal.so

Approach:
  This game (com.netmarble.thered) uses a custom packet serialization system
  rather than standard UE5 USTRUCT reflection. Each packet class (Pkt*) has a
  vtable with a serialize function (vtable slot 9) that calls FName::Init
  (at 0x17fb400) with field name strings loaded via ADRP+ADD into X1.

  The extraction pipeline is:
    1. Load the existing packet_opcodes.json for handler -> packet name mappings
    2. For each handler, trace: handler -> constructor BL -> ADRP+ADD to vtable
    3. Read vtable[9] to get the serialize function VA
    4. Disassemble the serialize function, tracking ADRP+ADD pairs that load
       .rodata string addresses into X1 followed by BL to FName::Init
    5. Each such string is a field name in the packet

  Additionally, the script examines vtable slots 0, 2, 4, 13, 14, 15 for
  potential deserialize/encode methods that may reference additional fields.

Output: packet_definitions.json with field names for each packet.
"""

import json
import mmap
import os
import struct
import sys
import time
from collections import OrderedDict
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BINARY_PATH = Path(__file__).resolve().parent.parent / "lib" / "arm64-v8a" / "libUnreal.so"
OPCODES_PATH = Path(__file__).resolve().parent.parent / "packet_opcodes.json"
OUTPUT_PATH = Path(__file__).resolve().parent.parent / "packet_definitions.json"

# Section layout (from ELF headers)
TEXT_VA = 0x017b4000
TEXT_OFF = 0x017b0000
TEXT_SIZE = 0x06ab8378
RODATA_VA = 0x059480
RODATA_OFF = 0x059480
RODATA_SIZE = 0x9232ac
DATAREL_VA = 0x082726b0
DATAREL_OFF = 0x0826a6b0
DATAREL_DIFF = DATAREL_VA - DATAREL_OFF  # 0x8000

OPERATOR_NEW = 0x06d007f0
FNAME_INIT = 0x17fb400  # FName::Init helper (takes X1 = const char* name)

# Stub/empty functions that should be ignored when extracting fields.
# These are base class methods or no-ops shared by many packet classes.
STUB_FUNCTIONS = {
    0x017b9e88,  # 2-instruction stub: store regs + RET (124 packets share this)
    0x017b4060,  # return 0 stub (appears in many vtable slots)
}

# Known base class serialize functions (shared by many packets).
# Fields from these are still included but marked as base_class_fields.
BASE_CLASS_SERIALIZE = {
    0x05d741fc,  # Base "Result" serializer (81+ packets)
}


# ---------------------------------------------------------------------------
# ARM64 instruction decoders
# ---------------------------------------------------------------------------

def read_u32(mm, off):
    return struct.unpack('<I', mm[off:off + 4])[0]


def read_u64(mm, off):
    return struct.unpack('<Q', mm[off:off + 8])[0]


def va_to_text_off(va):
    return TEXT_OFF + (va - TEXT_VA)


def va_to_datarel_off(va):
    return va - DATAREL_DIFF


def decode_adrp(mm, pc):
    """Decode an ADRP instruction and return the target page address."""
    off = va_to_text_off(pc)
    if off < 0 or off + 4 > len(mm):
        return None
    raw = read_u32(mm, off)
    if (raw & 0x9F000000) != 0x90000000:
        return None
    immhi = (raw >> 5) & 0x7FFFF
    immlo = (raw >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return ((pc & ~0xFFF) + (imm << 12)) & 0xFFFFFFFFFFFFFFFF


def decode_add_imm_full(mm, pc):
    """Decode ADD Xd, Xn, #imm and return (rd, rn, imm) or None."""
    off = va_to_text_off(pc)
    if off < 0 or off + 4 > len(mm):
        return None
    raw = read_u32(mm, off)
    if (raw & 0xFF000000) != 0x91000000:
        return None
    rd = raw & 0x1F
    rn = (raw >> 5) & 0x1F
    imm12 = (raw >> 10) & 0xFFF
    shift = (raw >> 22) & 0x3
    if shift == 1:
        imm12 <<= 12
    return (rd, rn, imm12)


def decode_bl_target(mm, pc):
    """Decode a BL instruction and return the target address."""
    off = va_to_text_off(pc)
    if off < 0 or off + 4 > len(mm):
        return None
    raw = read_u32(mm, off)
    if (raw & 0xFC000000) != 0x94000000:
        return None
    imm26 = raw & 0x03FFFFFF
    if imm26 & (1 << 25):
        imm26 -= (1 << 26)
    return pc + (imm26 << 2)


def is_ret(mm, pc):
    off = va_to_text_off(pc)
    if off < 0 or off + 4 > len(mm):
        return False
    return read_u32(mm, off) == 0xD65F03C0


def read_string_at(mm, addr, max_len=256):
    """Read a null-terminated ASCII string at a file offset (= VA for .rodata)."""
    if addr <= 0 or addr >= len(mm):
        return None
    nul = mm.find(b'\x00', addr, addr + max_len)
    if nul is None or nul <= addr:
        return None
    try:
        return mm[addr:nul].decode('ascii')
    except (UnicodeDecodeError, ValueError):
        return None


def is_in_text(va):
    return TEXT_VA <= va < TEXT_VA + TEXT_SIZE


def is_in_datarel(va):
    return DATAREL_VA <= va < DATAREL_VA + 0x12df7f8


def is_in_rodata(va):
    return RODATA_VA <= va < RODATA_VA + RODATA_SIZE


# ---------------------------------------------------------------------------
# Field name extraction from serialize functions
# ---------------------------------------------------------------------------

def extract_field_names_from_func(mm, func_va, max_instructions=600):
    """
    Extract field names from a serialize/deserialize function.

    The serialize function repeatedly does:
        ADRP Xn, <page>
        ADD  X1, Xn, #<offset>   ; X1 = pointer to field name string
        ...
        BL   FName::Init          ; at 0x17fb400

    We track ADRP pages per register and look for ADD into X1 followed
    by BL to FNAME_INIT within 6 instructions.
    """
    if not is_in_text(func_va):
        return []

    fields = []
    seen = set()  # avoid duplicates within same function
    adrp_pages = {}  # reg -> page_address

    for i in range(max_instructions):
        pc = func_va + i * 4
        off = va_to_text_off(pc)
        if off < 0 or off + 4 > len(mm):
            break
        raw = read_u32(mm, off)

        # RET - end of function
        if raw == 0xD65F03C0:
            break

        # ADRP Xd, page
        if (raw & 0x9F000000) == 0x90000000:
            rd = raw & 0x1F
            page = decode_adrp(mm, pc)
            if page is not None:
                adrp_pages[rd] = page
            continue

        # ADD Xd, Xn, #imm
        if (raw & 0xFF000000) == 0x91000000:
            result = decode_add_imm_full(mm, pc)
            if result is None:
                continue
            rd, rn, imm = result

            # We want ADD X1, Xn, #imm where Xn has a known ADRP page
            if rd == 1 and rn in adrp_pages:
                page = adrp_pages[rn]
                addr = page + imm
                if is_in_rodata(addr):
                    s = read_string_at(mm, addr)
                    if s and 1 <= len(s) < 100:
                        # Verify: next BL within 6 instructions should be FName::Init
                        for lookahead in range(1, 7):
                            la_pc = pc + lookahead * 4
                            la_off = va_to_text_off(la_pc)
                            if la_off < 0 or la_off + 4 > len(mm):
                                break
                            la_raw = read_u32(mm, la_off)
                            if (la_raw & 0xFC000000) == 0x94000000:
                                target = decode_bl_target(mm, la_pc)
                                if target == FNAME_INIT and s not in seen:
                                    fields.append(s)
                                    seen.add(s)
                                break  # Stop at first BL regardless
            continue

    return fields


# ---------------------------------------------------------------------------
# Vtable extraction from handlers/constructors
# ---------------------------------------------------------------------------

def get_constructor_from_handler(mm, handler_va):
    """Extract the constructor VA from a packet handler."""
    for i in range(8):
        pc = handler_va + i * 4
        off = va_to_text_off(pc)
        if off < 0 or off + 4 > len(mm):
            break
        raw = read_u32(mm, off)

        # BL instruction
        if (raw & 0xFC000000) == 0x94000000:
            target = decode_bl_target(mm, pc)
            if target and target != OPERATOR_NEW:
                return target

        # B (unconditional branch) or RET = end of handler
        if (raw & 0xFC000000) == 0x14000000 and i > 0:
            break
        if raw == 0xD65F03C0:
            break

    return None


def get_vtable_from_constructor(mm, ctor_va):
    """Find the vtable VA stored by the constructor (first .data.rel.ro ref)."""
    for i in range(30):
        pc = ctor_va + i * 4
        page = decode_adrp(mm, pc)
        if page is None:
            continue
        if not is_in_datarel(page) and not (page < DATAREL_VA + 0x12df7f8):
            continue

        for j in range(1, 6):
            result = decode_add_imm_full(mm, pc + j * 4)
            if result is None:
                continue
            rd, rn, imm = result
            if rn == (read_u32(mm, va_to_text_off(pc)) & 0x1F):  # same register as ADRP
                vt = page + imm
                if is_in_datarel(vt):
                    return vt

    return None


def get_vtable_from_handler_inline(mm, handler_va):
    """Some handlers set vtable inline without a separate constructor."""
    for i in range(15):
        pc = handler_va + i * 4
        page = decode_adrp(mm, pc)
        if page is None or not is_in_datarel(page):
            continue

        for j in range(1, 6):
            result = decode_add_imm_full(mm, pc + j * 4)
            if result is None:
                continue
            rd, rn, imm = result
            if rn == (read_u32(mm, va_to_text_off(pc)) & 0x1F):
                vt = page + imm
                if is_in_datarel(vt):
                    return vt

    return None


def find_vtable_for_handler(mm, handler_va):
    """Find vtable VA for a packet handler, trying multiple strategies."""
    # Strategy 1: constructor-based
    ctor_va = get_constructor_from_handler(mm, handler_va)
    if ctor_va:
        vt = get_vtable_from_constructor(mm, ctor_va)
        if vt:
            return vt

    # Strategy 2: inline vtable in handler
    vt = get_vtable_from_handler_inline(mm, handler_va)
    if vt:
        return vt

    return None


# ---------------------------------------------------------------------------
# Extract allocation size from handler (MOV W0, #size before operator_new)
# ---------------------------------------------------------------------------

def get_alloc_size_from_handler(mm, handler_va):
    """Extract the allocation size from MOV W0, #imm before BL operator_new."""
    for i in range(4):
        pc = handler_va + i * 4
        off = va_to_text_off(pc)
        if off < 0 or off + 4 > len(mm):
            break
        raw = read_u32(mm, off)

        # MOV W0, #imm16 (MOVZ W0, #imm16, LSL#0)
        if (raw & 0xFFE00000) == 0x52800000:
            rd = raw & 0x1F
            if rd == 0:
                imm16 = (raw >> 5) & 0xFFFF
                return imm16

        # Also check for MOVZ with shift
        if (raw & 0x7F800000) == 0x52800000:
            rd = raw & 0x1F
            if rd == 0:
                hw = (raw >> 21) & 0x3
                imm16 = (raw >> 5) & 0xFFFF
                return imm16 << (hw * 16)

    return None


# ---------------------------------------------------------------------------
# Main extraction
# ---------------------------------------------------------------------------

def main():
    t0 = time.time()
    print(f"Binary: {BINARY_PATH}")
    print(f"Opcodes: {OPCODES_PATH}")
    print()

    # Load existing opcode map
    if not OPCODES_PATH.exists():
        print("ERROR: packet_opcodes.json not found. Run build_opcode_map.py first.")
        sys.exit(1)

    with open(OPCODES_PATH) as f:
        opcodes_data = json.load(f)

    opcode_map = opcodes_data["opcode_map"]  # str(id) -> name
    handler_map = opcodes_data["handler_addresses"]  # str(id) -> hex_str

    print(f"Loaded {len(opcode_map)} packet opcodes")
    print(f"Loaded {len(handler_map)} handler addresses")
    print()

    # Open binary
    with open(BINARY_PATH, 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    # Process each packet
    print("Extracting packet field definitions...")
    print()

    packet_defs = {}
    stats = {
        "total_opcodes": len(opcode_map),
        "vtable_found": 0,
        "vtable_failed": 0,
        "fields_extracted": 0,
        "empty_packets": 0,
        "total_fields": 0,
    }

    # Collect all unique serialize functions to avoid redundant work
    # (some packets may share serialize implementations)
    vtable_cache = {}  # handler_va -> vtable_va
    serialize_cache = {}  # serialize_va -> field_list

    for pid_str in sorted(opcode_map.keys(), key=lambda x: int(x)):
        name = opcode_map[pid_str]
        pid = int(pid_str)

        if pid_str not in handler_map:
            continue

        handler_va = int(handler_map[pid_str], 16)

        # Find vtable
        vtable_va = find_vtable_for_handler(mm, handler_va)
        if vtable_va is None:
            stats["vtable_failed"] += 1
            continue

        stats["vtable_found"] += 1
        vtable_off = va_to_datarel_off(vtable_va)

        # Get allocation size
        alloc_size = get_alloc_size_from_handler(mm, handler_va)

        # Read serialize function at vtable[9] (primary serialize method)
        serialize_va = read_u64(mm, vtable_off + 9 * 8)

        # Skip stub functions for the primary slot
        if serialize_va in STUB_FUNCTIONS or not is_in_text(serialize_va):
            serialize_va = None

        # Extract field names from primary serialize function
        primary_fields = []
        is_base_class = False
        if serialize_va:
            if serialize_va in serialize_cache:
                primary_fields = serialize_cache[serialize_va]
            else:
                primary_fields = extract_field_names_from_func(mm, serialize_va)
                serialize_cache[serialize_va] = primary_fields
            if serialize_va in BASE_CLASS_SERIALIZE:
                is_base_class = True

        # Check additional vtable slots for more field references.
        # Only scan slots that have unique, non-stub function pointers.
        # Prioritize slot 4 (often a decoder) and slots 13-15 (often
        # encode/decode variants for network serialization).
        seen_funcs = {serialize_va} | STUB_FUNCTIONS
        additional_fields = []
        for extra_slot in [4, 13, 14, 15, 0, 2]:
            if vtable_off + (extra_slot + 1) * 8 > len(mm):
                continue
            extra_va = read_u64(mm, vtable_off + extra_slot * 8)
            if extra_va in seen_funcs or not is_in_text(extra_va):
                continue
            seen_funcs.add(extra_va)
            if extra_va in serialize_cache:
                extra_fields = serialize_cache[extra_va]
            else:
                extra_fields = extract_field_names_from_func(
                    mm, extra_va, max_instructions=400
                )
                serialize_cache[extra_va] = extra_fields
            for ef in extra_fields:
                if ef not in primary_fields and ef not in additional_fields:
                    additional_fields.append(ef)

        all_fields = primary_fields + additional_fields

        if all_fields:
            stats["fields_extracted"] += 1
            stats["total_fields"] += len(all_fields)
        else:
            stats["empty_packets"] += 1

        # Build field list with source annotation
        field_list = []
        for f in primary_fields:
            entry = {"name": f}
            if is_base_class:
                entry["source"] = "base_class"
            field_list.append(entry)
        for f in additional_fields:
            field_list.append({"name": f, "source": "extra_slot"})

        packet_defs[name] = {
            "opcode": pid,
            "fields": field_list,
            "field_count": len(all_fields),
            "alloc_size": alloc_size,
            "vtable_va": f"0x{vtable_va:08x}" if vtable_va else None,
            "serialize_va": f"0x{serialize_va:08x}" if serialize_va else None,
        }

    mm.close()

    # Build output
    elapsed = time.time() - t0

    output = {
        "metadata": {
            "binary": str(BINARY_PATH),
            "extraction_method": "vtable_serialize_fname_tracking",
            "description": (
                "Field names extracted from packet serialize functions by "
                "tracking ADRP+ADD->X1 pairs followed by BL to FName::Init "
                "(0x17fb400). Each Pkt* class has a vtable; slot 9 is the "
                "primary serialize function. Additional fields come from "
                "vtable slots 0, 2, 4, 13, 14, 15."
            ),
            "stats": {
                "total_opcodes": stats["total_opcodes"],
                "vtable_found": stats["vtable_found"],
                "vtable_failed": stats["vtable_failed"],
                "packets_with_fields": stats["fields_extracted"],
                "packets_without_fields": stats["empty_packets"],
                "total_field_names": stats["total_fields"],
            },
            "elapsed_seconds": round(elapsed, 1),
        },
        "packets": OrderedDict(
            sorted(packet_defs.items(), key=lambda x: x[1]["opcode"])
        ),
    }

    # Write output
    with open(OUTPUT_PATH, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"Results written to {OUTPUT_PATH}")
    print()
    print(f"Statistics:")
    print(f"  Total opcodes:           {stats['total_opcodes']}")
    print(f"  Vtables found:           {stats['vtable_found']}")
    print(f"  Vtables failed:          {stats['vtable_failed']}")
    print(f"  Packets with fields:     {stats['fields_extracted']}")
    print(f"  Packets without fields:  {stats['empty_packets']}")
    print(f"  Total field names:       {stats['total_fields']}")
    print(f"  Elapsed:                 {elapsed:.1f}s")
    print()

    # Show sample output
    print("Sample packet definitions:")
    sample_count = 0
    for name, pdef in output["packets"].items():
        if pdef["field_count"] > 0 and sample_count < 15:
            fields_str = ", ".join(f["name"] for f in pdef["fields"][:8])
            if pdef["field_count"] > 8:
                fields_str += f", ... ({pdef['field_count']} total)"
            print(f"  {pdef['opcode']:5d} {name}: [{fields_str}]")
            sample_count += 1

    # Show packets with most fields
    print()
    print("Packets with most fields:")
    by_field_count = sorted(
        output["packets"].items(),
        key=lambda x: x[1]["field_count"],
        reverse=True,
    )
    for name, pdef in by_field_count[:10]:
        print(f"  {name}: {pdef['field_count']} fields")


if __name__ == "__main__":
    main()
