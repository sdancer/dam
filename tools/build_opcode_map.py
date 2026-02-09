#!/usr/bin/env python3
"""
build_opcode_map.py - Extract packet ID -> packet name mappings from libUnreal.so

Approach:
  1. Locate the packet dispatch function by finding xrefs to "invalid packetId: %d"
  2. Parse the multi-level jump tables in the dispatch function
  3. For each jump table entry (handler), trace:
       handler -> operator_new + constructor BL
       constructor -> ADRP+ADD storing vtable pointer to [x0]
       vtable[8] -> getName() thunk that returns a string via ADRP+ADD
  4. Output the mapping as JSON.
"""

import json
import mmap
import struct
import sys
from pathlib import Path
from collections import OrderedDict

BINARY_PATH = Path(__file__).resolve().parent.parent / "lib" / "arm64-v8a" / "libUnreal.so"
OUTPUT_PATH = Path(__file__).resolve().parent.parent / "packet_opcodes.json"

# Section layout (from ELF headers)
TEXT_VA     = 0x017b4000
TEXT_OFF    = 0x017b0000
TEXT_SIZE   = 0x06ab8378
RODATA_VA   = 0x059480
RODATA_OFF  = 0x059480
RODATA_SIZE = 0x9232ac
DATAREL_VA  = 0x082726b0
DATAREL_OFF = 0x0826a6b0
DATAREL_DIFF = DATAREL_VA - DATAREL_OFF  # 0x8000

OPERATOR_NEW = 0x06d007f0
DISPATCH_EXIT = 0x05dffe60
DISPATCH_FUNC = 0x05df9a64


def va_to_text_off(va):
    """Convert a .text VA to file offset."""
    return TEXT_OFF + (va - TEXT_VA)


def va_to_datarel_off(va):
    """Convert a .data.rel.ro VA to file offset."""
    return va - DATAREL_DIFF


def read_u32(mm, off):
    return struct.unpack('<I', mm[off:off+4])[0]


def read_u16(mm, off):
    return struct.unpack('<H', mm[off:off+2])[0]


def read_u64(mm, off):
    return struct.unpack('<Q', mm[off:off+8])[0]


def decode_adrp(mm, pc):
    """Decode an ADRP instruction and return the target page address."""
    off = va_to_text_off(pc)
    raw = read_u32(mm, off)
    if (raw & 0x9F000000) != 0x90000000:
        return None
    immhi = (raw >> 5) & 0x7FFFF
    immlo = (raw >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return ((pc & ~0xFFF) + (imm << 12)) & 0xFFFFFFFFFFFFFFFF


def decode_add_imm(mm, pc):
    """Decode an ADD immediate instruction and return the immediate value."""
    off = va_to_text_off(pc)
    raw = read_u32(mm, off)
    if (raw & 0xFF000000) != 0x91000000:
        return None
    imm12 = (raw >> 10) & 0xFFF
    shift = (raw >> 22) & 0x3
    if shift == 1:
        imm12 <<= 12
    return imm12


def decode_bl_target(mm, pc):
    """Decode a BL instruction and return the target address."""
    off = va_to_text_off(pc)
    raw = read_u32(mm, off)
    if (raw & 0xFC000000) != 0x94000000:
        return None
    imm26 = raw & 0x03FFFFFF
    if imm26 & (1 << 25):
        imm26 -= (1 << 26)
    return pc + (imm26 << 2)


def is_bl(mm, pc):
    off = va_to_text_off(pc)
    raw = read_u32(mm, off)
    return (raw & 0xFC000000) == 0x94000000


def is_b(mm, pc):
    off = va_to_text_off(pc)
    raw = read_u32(mm, off)
    return (raw & 0xFC000000) == 0x14000000


def is_ret(mm, pc):
    off = va_to_text_off(pc)
    raw = read_u32(mm, off)
    return raw == 0xD65F03C0


def read_string_at(mm, addr, max_len=256):
    """Read a null-terminated ASCII string from file offset = addr."""
    if addr <= 0 or addr >= len(mm):
        return None
    nul = mm.find(b'\x00', addr, addr + max_len)
    if nul is None or nul <= addr:
        return None
    try:
        return mm[addr:nul].decode('ascii')
    except (UnicodeDecodeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Step 1: Find xrefs to "invalid packetId: %d" to confirm the dispatch func
# ---------------------------------------------------------------------------

def find_string_va(mm, needle):
    """Find the VA of a string in .rodata (VA == file offset for .rodata)."""
    idx = mm.find(needle, RODATA_OFF, RODATA_OFF + RODATA_SIZE)
    if idx == -1:
        return None
    return idx  # VA == file offset for .rodata


# ---------------------------------------------------------------------------
# Step 2: Parse the dispatch function's multi-level jump tables
# ---------------------------------------------------------------------------

def parse_jump_table(mm, table_va, base_va, max_entries):
    """
    Parse a jump table of uint16 entries.
    Each entry is an offset in units of 4 bytes from base_va.
    Returns list of (index, target_va).
    """
    # table_va is in .rodata where VA == file offset
    table_off = table_va
    entries = []
    for i in range(max_entries):
        off = table_off + i * 2
        if off + 2 > len(mm):
            break
        val = read_u16(mm, off)
        target = base_va + val * 4
        entries.append((i, target))
    return entries


def parse_dispatch_function(mm):
    """
    Parse the multi-level dispatch function at DISPATCH_FUNC.
    Returns dict mapping packet_id -> handler_va for all valid entries.

    The function structure (from disassembly):
      and w8, w1, #0xffff          ; w8 = packet_id
      mov w9, #0x7594
      cmp w8, w9
      b.gt secondary_tables

      ; Primary table (IDs 1..0x28B9):
      sub w9, w8, #1               ; index = packet_id - 1
      lsr w10, w9, #2
      cmp w10, #0xa2e
      b.hi third_group
      adrp x8, table1_page
      add x8, x8, table1_off
      adr x10, base1               ; base1 = PC of next block (0x05df9aa8)
      ldrh w11, [x8, x9, lsl #1]
      add x10, x10, x11, lsl #2
      br x10

    Secondary tables handle higher ID ranges.
    """
    handlers = {}
    default_handler = 0x05dfa0fc  # "invalid packetId" error handler

    # --- Table 1: IDs 1..0x28B9 ---
    # Jump table at VA 0x008638fc (rodata, VA==file_off)
    # Base address: 0x05df9aa8
    # Index: packet_id - 1
    # Size check: (packet_id - 1) >> 2 <= 0xa2e => packet_id - 1 <= 0x28BB
    # But actually the table is indexed by (packet_id - 1) directly
    table1_va = 0x008638fc
    base1 = 0x05df9aa8
    table1_count = 0x28B9  # IDs 1..0x28B9

    entries1 = parse_jump_table(mm, table1_va, base1, table1_count)
    for idx, target in entries1:
        pid = idx + 1
        if target != default_handler:
            handlers[pid] = target

    print(f"  Table 1 (IDs 1..{table1_count}): {len([e for _, e in entries1 if e != default_handler])} valid entries")

    # --- Table 2: IDs around 0x86E7 range ---
    # Entry condition: w8 > 0x7594
    # mov w9, #-0x7919 (= 0xFFFF86E7)  => w9 = 0x86E7
    # add w9, w8, w9 => w9 = w8 - 0x7919 (but actually w8 + (-0x7919))
    # Wait: mov w9, #-0x7919 loads 0xFFFF86E7, but in 32-bit: w9 = 0x86E7 (top bits zeroed by mov w)
    # Actually ARM64 MOV (wide immediate): mov w9, #-0x7919 means w9 = -0x7919 = 0xFFFF86E7
    # But as w (32-bit), the sign-extension: 0x86E7? No...
    # Let me re-examine: at 0x05df9abc:
    #   mov w9, #-0x7919  -> This is MOVN w9, #0x7918 -> w9 = ~0x7918 = 0xFFFF86E7 (but 32-bit) = 0x86E7? No.
    #   Actually for 32-bit: w9 = 0xFFFF86E7 & 0xFFFFFFFF = 0xFFFF86E7
    #   add w9, w8, w9 -> w9 = packet_id + 0xFFFF86E7 (mod 2^32) = packet_id - 0x7919
    #   cmp w9, #0x34 -> if (packet_id - 0x7919) <= 0x34
    #   So IDs: 0x7919..0x794D (30101..31053)

    # Wait, 0x86E7 unsigned would be interpreted differently.
    # mov w9, #-0x7919: this is actually the assembler showing the signed form.
    # The actual value: -0x7919 = 0xFFFF86E7. As a 32-bit unsigned: 0xFFFF86E7.
    # w8 + 0xFFFF86E7 (mod 2^32) = w8 - 0x7919
    # So the index = packet_id - 0x7919, range 0..0x34

    table2_va = 0x00868d60
    base2 = 0x05df9ae4
    table2_base_id = 0x7919
    table2_count = 0x35

    # Verify by decoding ADRP+ADD at 0x05df9acc..0x05df9ad0
    adrp_page = decode_adrp(mm, 0x05df9acc)
    add_val = decode_add_imm(mm, 0x05df9ad0)
    actual_table2_va = adrp_page + add_val if (adrp_page is not None and add_val is not None) else None
    print(f"  Table 2 VA check: expected 0x{table2_va:08x}, got {f'0x{actual_table2_va:08x}' if actual_table2_va else 'None'}")

    if actual_table2_va:
        table2_va = actual_table2_va

    entries2 = parse_jump_table(mm, table2_va, base2, table2_count)
    count2 = 0
    for idx, target in entries2:
        pid = table2_base_id + idx
        if target != default_handler:
            handlers[pid] = target
            count2 += 1

    print(f"  Table 2 (IDs 0x{table2_base_id:x}..0x{table2_base_id + table2_count - 1:x}): {count2} valid entries")

    # --- Table 3: IDs around 0x8F1B range ---
    # From 0x05df9af8:
    #   mov w9, #-0x70e5 (= 0xFFFF8F1B => subtract 0x70E5)
    #   add w8, w8, w9 => index = packet_id - 0x70E5
    #   Wait: -0x70E5 = 0xFFFF8F1B. w8 + 0xFFFF8F1B = w8 - 0x70E5.
    #   cmp w8, #0x105 -> range 0..0x105
    #   b.hi default

    # Actually let me re-read the code. At 0x05df9af8:
    #   This is the fallthrough from table1's size check (w10 > 0xa2e)
    #   So we're still in the w8 <= 0x7594 branch
    #   mov w9, #-0x70e5 => w9 = 0xFFFF8F1B
    #   add w8, w8, w9 => w8 = original_packet_id + 0xFFFF8F1B (mod 2^32) = original_packet_id - 0x70E5
    #   Wait, but original_packet_id <= 0x7594 (from the first branch)
    #   And original_packet_id > table1 range (> 0x28B9)
    #   So index = packet_id - 0x70E5 would be negative for small IDs...
    #   Hmm, let me reconsider.

    # Actually: the sub w9, w8, #1 / lsr w10, w9, #2 / cmp w10, #0xa2e
    # If w10 > 0xa2e (i.e., (pid-1)/4 > 0xa2e => pid > 0x28BB), falls through to 0x05df9af8
    # Then: pid + (-0x70E5) = pid - 0x70E5
    # For pid = 0x70E5: index = 0. For pid = 0x70E5 + 0x105 = 0x71EA: index = 0x105.
    # But these are <= 0x7594, so this range makes sense.

    table3_base_id = 0x70E5
    table3_count = 0x106  # 0..0x105

    adrp_page = decode_adrp(mm, 0x05df9b08)
    add_val = decode_add_imm(mm, 0x05df9b0c)
    table3_va = (adrp_page + add_val) if (adrp_page is not None and add_val is not None) else 0x0868a74
    base3 = 0x05df9b20

    entries3 = parse_jump_table(mm, table3_va, base3, table3_count)
    count3 = 0
    for idx, target in entries3:
        pid = table3_base_id + idx
        if target != default_handler:
            handlers[pid] = target
            count3 += 1

    print(f"  Table 3 (IDs 0x{table3_base_id:x}..0x{table3_base_id + table3_count - 1:x}): {count3} valid entries")

    # --- Table 4: IDs around 0x8A07 range ---
    # From 0x05df9b34 (secondary, w8 > 0x7594):
    #   mov w9, #-0x75f9 (= 0xFFFF8A07 => subtract 0x75F9)
    #   add w9, w8, w9 => w9 = packet_id - 0x75F9
    #   Wait: -0x75F9 = 0xFFFF8A07. So w9 = pid + 0xFFFF8A07 (mod 2^32) = pid - 0x75F9
    #   But pid > 0x7594 here, so pid = 0x75F9 -> index 0, max pid = 0x75F9 + 0x6B = 0x7664
    #   cmp w9, #0x6b -> range 0..0x6b

    # Actually wait: the condition at start is w8 > 0x7594 (b.gt secondary_tables)
    # Then at 0x05df9abc: it does mov w9, #-0x7919 / add / cmp #0x34 / b.hi next
    # So -0x7919 means: index = w8 - 0x7919
    # But w8 > 0x7594... so 0x7595 - 0x7919 = negative (underflow)... that doesn't work.
    # Unless the wrapping works out: 0x7595 + 0xFFFF86E7 = 0x10000FC7C (mod 2^32) = 0xFC7C > 0x34
    # So this branch skips to the next table for most IDs > 0x7594.

    # Let me reconsider: for the b.gt branch at 0x05df9a7c, we need w8 > 0x7594.
    # Then at 0x05df9abc: index = w8 - 0x7919, check <= 0x34
    # w8 = 0x7919 -> index=0, w8 = 0x794D -> index=0x34
    # So valid IDs: 0x7919..0x794D
    # But w8 > 0x7594 is a prerequisite. 0x7919 > 0x7594? Yes.

    # Next: 0x05df9b34: index = w8 - 0x75F9, check <= 0x6B
    # IDs: 0x75F9..0x7664
    # But w8 > 0x7594 is prerequisite. 0x75F9 > 0x7594? Yes.
    # And the previous table (0x7919..0x794D) didn't match, so this handles 0x75F9..0x7664
    # Wait, but 0x75F9 < 0x7919. The b.hi at 0x05df9ac8 means we skip table2 if index > 0x34.
    # For w8 = 0x75F9: table2 index = 0x75F9 - 0x7919 = underflows to 0xFFFFFCE0, which > 0x34.
    # So yes, table4 handles IDs that don't fit in table2.

    table4_base_id = 0x75F9
    table4_count = 0x6C  # 0..0x6B

    adrp_page = decode_adrp(mm, 0x05df9b44)
    add_val = decode_add_imm(mm, 0x05df9b48)
    table4_va = (adrp_page + add_val) if (adrp_page is not None and add_val is not None) else 0x0868c88
    base4 = 0x05df9b5c

    entries4 = parse_jump_table(mm, table4_va, base4, table4_count)
    count4 = 0
    for idx, target in entries4:
        pid = table4_base_id + idx
        if target != default_handler:
            handlers[pid] = target
            count4 += 1

    print(f"  Table 4 (IDs 0x{table4_base_id:x}..0x{table4_base_id + table4_count - 1:x}): {count4} valid entries")

    # --- Table 5: IDs around 0x8A6B range ---
    # From 0x05df9b70:
    #   mov w9, #-0x7595 (= 0xFFFF8A6B => subtract 0x7595)
    #   add w8, w8, w9 => index = w8 - 0x7595
    #   cmp w8, #3 -> range 0..3
    #   IDs: 0x7595..0x7598

    table5_base_id = 0x7595
    table5_count = 4  # 0..3

    adrp_page = decode_adrp(mm, 0x05df9b80)
    add_val = decode_add_imm(mm, 0x05df9b84)
    table5_va = (adrp_page + add_val) if (adrp_page is not None and add_val is not None) else 0x0868c80
    base5 = 0x05df9b98

    entries5 = parse_jump_table(mm, table5_va, base5, table5_count)
    count5 = 0
    for idx, target in entries5:
        pid = table5_base_id + idx
        if target != default_handler:
            handlers[pid] = target
            count5 += 1

    print(f"  Table 5 (IDs 0x{table5_base_id:x}..0x{table5_base_id + table5_count - 1:x}): {count5} valid entries")

    return handlers


# ---------------------------------------------------------------------------
# Step 3: Extract vtable VA from each constructor
# ---------------------------------------------------------------------------

def get_constructor_from_handler(mm, handler_va):
    """
    From a handler like:
        mov w0, #size
        bl operator_new
        mov x19, x0
        bl constructor   <-- we want this
        b exit
    Or sometimes the handler directly calls an init function that stores the vtable.
    Extract the constructor VA (2nd BL target, skipping operator_new).
    """
    bl_targets = []
    for i in range(6):
        pc = handler_va + i * 4
        if is_bl(mm, pc):
            target = decode_bl_target(mm, pc)
            if target and target != OPERATOR_NEW:
                bl_targets.append(target)
        elif is_b(mm, pc) and i > 0:
            # Unconditional branch = end of handler
            break
        elif is_ret(mm, pc):
            break

    return bl_targets[0] if bl_targets else None


def get_vtable_from_constructor(mm, ctor_va):
    """
    Scan the constructor for the first ADRP+ADD that computes a .data.rel.ro
    address and stores it to [x0] (the vtable pointer).

    Pattern:
        adrp x8, page
        ...
        add  x8, x8, #offset
        ...
        str  x8, [x0]   or  str x8, [x19]
    """
    # Scan first 40 instructions
    for i in range(40):
        pc = ctor_va + i * 4
        off = va_to_text_off(pc)
        if off + 4 > len(mm):
            break
        raw = read_u32(mm, off)

        # Look for ADRP
        if (raw & 0x9F000000) == 0x90000000:
            rd = raw & 0x1F
            page = decode_adrp(mm, pc)
            if page is None:
                continue

            # Look for matching ADD within next 4 instructions
            for j in range(1, 5):
                pc2 = pc + j * 4
                off2 = va_to_text_off(pc2)
                if off2 + 4 > len(mm):
                    break
                raw2 = read_u32(mm, off2)

                # ADD Xd, Xn, #imm where Xn == rd from ADRP
                if (raw2 & 0xFF000000) == 0x91000000:
                    add_rn = (raw2 >> 5) & 0x1F
                    add_rd = raw2 & 0x1F
                    if add_rn == rd:
                        add_val = decode_add_imm(mm, pc2)
                        if add_val is not None:
                            vtable_va = page + add_val
                            # Check if it's in .data.rel.ro range
                            if DATAREL_VA <= vtable_va < DATAREL_VA + 0x12df7f8:
                                # Verify it's stored to the object (STR to [x0] or similar)
                                # We trust the first .data.rel.ro address found
                                return vtable_va
    return None


def get_vtable_from_handler_inline(mm, handler_va):
    """
    Some handlers have the vtable stored inline (no separate constructor call).
    Pattern:
        mov w0, #size
        bl operator_new
        adrp x8, page
        mov x19, x0
        add x8, x8, #offset    <-- same register as ADRP
        str x8, [x0]
    """
    for i in range(12):
        pc = handler_va + i * 4
        off = va_to_text_off(pc)
        if off + 4 > len(mm):
            break
        raw = read_u32(mm, off)

        # Check for ADRP
        if (raw & 0x9F000000) == 0x90000000:
            rd = raw & 0x1F
            page = decode_adrp(mm, pc)
            if page is None or not (DATAREL_VA <= page < DATAREL_VA + 0x12df7f8):
                continue

            for j in range(1, 6):
                pc2 = pc + j * 4
                off2 = va_to_text_off(pc2)
                if off2 + 4 > len(mm):
                    break
                raw2 = read_u32(mm, off2)

                # ADD Xd, Xn, #imm where Xn must match the ADRP register
                if (raw2 & 0xFF000000) == 0x91000000:
                    add_rn = (raw2 >> 5) & 0x1F
                    if add_rn == rd:
                        add_val = decode_add_imm(mm, pc2)
                        if add_val is not None:
                            vtable_va = page + add_val
                            if DATAREL_VA <= vtable_va < DATAREL_VA + 0x12df7f8:
                                return vtable_va
    return None


# ---------------------------------------------------------------------------
# Step 4: Extract packet name from vtable[8] (getName virtual function)
# ---------------------------------------------------------------------------

def get_name_from_vtable(mm, vtable_va):
    """
    vtable[8] is the getName() virtual function.
    It's typically a thunk:
        adrp x1, page
        mov  x0, x8
        add  x1, x1, #offset
        b    helper
    The string at page+offset is the packet name.
    """
    vtable_file_off = va_to_datarel_off(vtable_va)
    if vtable_file_off < 0 or vtable_file_off + 72 > len(mm):
        return None

    func_va = read_u64(mm, vtable_file_off + 8 * 8)
    if not (TEXT_VA <= func_va < TEXT_VA + TEXT_SIZE):
        return None

    # Disassemble the getName function to find the string reference
    # Try multiple patterns
    for offset_to_adrp in range(4):
        adrp_pc = func_va + offset_to_adrp * 4
        page = decode_adrp(mm, adrp_pc)
        if page is None:
            continue

        # Look for ADD in next few instructions
        for add_delta in range(1, 5):
            add_pc = adrp_pc + add_delta * 4
            off = va_to_text_off(add_pc)
            if off + 4 > len(mm):
                continue
            raw = read_u32(mm, off)
            if (raw & 0xFF000000) == 0x91000000:
                add_val = decode_add_imm(mm, add_pc)
                if add_val is not None:
                    str_addr = page + add_val
                    # String should be in .rodata
                    if RODATA_VA <= str_addr < RODATA_VA + RODATA_SIZE:
                        name = read_string_at(mm, str_addr)
                        if name and name.startswith("Pkt"):
                            return name

    return None


# ---------------------------------------------------------------------------
# Step 5: Also extract packet names from the first dispatch function
# ---------------------------------------------------------------------------

def parse_first_dispatch(mm):
    """
    Parse the first (smaller) dispatch function that also has "invalid packetId: %d".
    This one is around 0x05de6ffc with its own set of handlers.
    Each handler is a small function that returns a packet object.
    """
    handlers = {}

    # Find all branches to the common exit of the second dispatch region
    # The first dispatch is different - it has inline factories with direct RET
    # Let me scan the area around 0x05de6e00..0x05de6ffc for the factory pattern

    # Actually, the first dispatch function at 0x05de6ffc appears to be part of the
    # same dispatch or a related one. The key handlers all branch to 0x5dffe60.
    # So the parse_dispatch_function above should cover it.

    return handlers


# ---------------------------------------------------------------------------
# Step 6: Scan for Pkt* strings and try to build a name->ID map via FName
# ---------------------------------------------------------------------------

def find_all_pkt_strings(mm):
    """Find all Pkt* strings in .rodata."""
    pkt_strings = {}
    pos = RODATA_OFF
    end = RODATA_OFF + RODATA_SIZE

    while pos < end:
        idx = mm.find(b'Pkt', pos, end)
        if idx == -1:
            break
        # Check it's the start of a string (preceded by null byte)
        if idx > 0 and mm[idx-1:idx] == b'\x00':
            nul = mm.find(b'\x00', idx, idx + 256)
            if nul and nul > idx:
                try:
                    s = mm[idx:nul].decode('ascii')
                    if len(s) > 3 and all(c.isalnum() or c == '_' for c in s):
                        pkt_strings[s] = idx
                except (UnicodeDecodeError, ValueError):
                    pass
        pos = idx + 1

    return pkt_strings


# ---------------------------------------------------------------------------
# Main extraction logic
# ---------------------------------------------------------------------------

def main():
    print(f"Opening binary: {BINARY_PATH}")
    with open(BINARY_PATH, 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    # Verify key strings exist
    s1 = find_string_va(mm, b"invalid packetId: %d")
    s2 = find_string_va(mm, b"invalid packetId( %d ), packetName( %s )")
    print(f"  'invalid packetId: %%d' at VA 0x{s1:08x}" if s1 else "  'invalid packetId: %%d' NOT FOUND")
    print(f"  'invalid packetId( %%d ), ...' at VA 0x{s2:08x}" if s2 else "  'invalid packetId( %%d ), ...' NOT FOUND")

    # Parse dispatch function
    print(f"\nParsing dispatch function at 0x{DISPATCH_FUNC:08x}...")
    handlers = parse_dispatch_function(mm)
    print(f"  Total handlers found: {len(handlers)}")

    # Extract packet names from each handler
    print("\nExtracting packet names...")
    opcode_map = {}
    failed_ctor = 0
    failed_vtable = 0
    failed_name = 0
    alternative_names = 0

    for pid in sorted(handlers.keys()):
        handler_va = handlers[pid]

        # Collect candidate vtable VAs from multiple sources
        vtable_candidates = []

        # Try inline vtable in handler first (most specific to the packet class)
        inline_vtable = get_vtable_from_handler_inline(mm, handler_va)
        if inline_vtable is not None:
            vtable_candidates.append(inline_vtable)

        # Try constructor-based vtable
        ctor_va = get_constructor_from_handler(mm, handler_va)
        if ctor_va:
            ctor_vtable = get_vtable_from_constructor(mm, ctor_va)
            if ctor_vtable is not None and ctor_vtable not in vtable_candidates:
                vtable_candidates.append(ctor_vtable)

        if not vtable_candidates:
            if ctor_va is None:
                failed_ctor += 1
            else:
                failed_vtable += 1
            continue

        # Try each candidate vtable until we find a name
        name = None
        for vtable_va in vtable_candidates:
            name = get_name_from_vtable(mm, vtable_va)
            if name:
                break

        # If still no name, try alternative vtable indices on each candidate
        if name is None:
            for vtable_va in vtable_candidates:
                for alt_idx in [6, 7, 9, 10, 4]:
                    vtable_file_off = va_to_datarel_off(vtable_va)
                    if vtable_file_off < 0 or vtable_file_off + (alt_idx + 1) * 8 > len(mm):
                        continue
                    func_va = read_u64(mm, vtable_file_off + alt_idx * 8)
                    if TEXT_VA <= func_va < TEXT_VA + TEXT_SIZE:
                        page = decode_adrp(mm, func_va)
                        if page is not None:
                            for add_delta in range(1, 5):
                                add_pc = func_va + add_delta * 4
                                add_val = decode_add_imm(mm, add_pc)
                                if add_val is not None:
                                    str_addr = page + add_val
                                    if RODATA_VA <= str_addr < RODATA_VA + RODATA_SIZE:
                                        n = read_string_at(mm, str_addr)
                                        if n and n.startswith("Pkt"):
                                            name = n
                                            alternative_names += 1
                                            break
                            if name:
                                break
                if name:
                    break

        if name is None:
            failed_name += 1
            continue

        opcode_map[pid] = name

    print(f"  Successfully extracted: {len(opcode_map)} packet names")
    print(f"  Failed (no constructor): {failed_ctor}")
    print(f"  Failed (no vtable): {failed_vtable}")
    print(f"  Failed (no name): {failed_name}")
    print(f"  Names from alternative vtable slots: {alternative_names}")

    # Find all Pkt* strings for reference
    print("\nScanning for all Pkt* strings in .rodata...")
    all_pkt_strings = find_all_pkt_strings(mm)
    print(f"  Found {len(all_pkt_strings)} Pkt* strings")

    # Check for packet names we found in the dispatch but also exist as strings
    mapped_names = set(opcode_map.values())
    unmapped_pkt_strings = {k: v for k, v in all_pkt_strings.items() if k not in mapped_names}

    # Build output
    output = {
        "metadata": {
            "binary": str(BINARY_PATH),
            "dispatch_function_va": f"0x{DISPATCH_FUNC:08x}",
            "dispatch_exit_va": f"0x{DISPATCH_EXIT:08x}",
            "total_handlers": len(handlers),
            "total_mapped": len(opcode_map),
            "total_pkt_strings": len(all_pkt_strings),
            "unmapped_pkt_strings": len(unmapped_pkt_strings),
        },
        "opcode_map": OrderedDict(
            (str(pid), name) for pid, name in sorted(opcode_map.items())
        ),
        "handler_addresses": OrderedDict(
            (str(pid), f"0x{handlers[pid]:08x}") for pid in sorted(handlers.keys())
        ),
        "unmapped_packet_names": sorted(unmapped_pkt_strings.keys()),
    }

    mm.close()

    # Write output
    print(f"\nWriting output to {OUTPUT_PATH}...")
    with open(OUTPUT_PATH, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"Done. Mapped {len(opcode_map)} packet IDs to names.")

    # Print a sample of mappings
    print("\nSample mappings (first 30):")
    for pid, name in sorted(opcode_map.items())[:30]:
        print(f"  {pid:5d} (0x{pid:04x}) = {name}")

    if len(opcode_map) > 30:
        print(f"  ... and {len(opcode_map) - 30} more")


if __name__ == "__main__":
    main()
