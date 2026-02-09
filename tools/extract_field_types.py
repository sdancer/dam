#!/usr/bin/env python3
"""
Extract field types from packet serialize functions (vtable slot 2/15).

Type identification patterns found in ARM64:
  - BL 0x50f6924 with ADD X1, Xn, #off  → FString (string)
  - LDR W1, [Xn, #off] + BLR/BR via vtable → int32
  - LDRB W1, [Xn, #off] + BLR/BR via vtable → uint8/bool
  - LDR X1, [Xn, #off] + BR via vtable     → pointer/buffer
  - ADD X1, Xn, #off + BL to other funcs    → struct/complex type
"""

import json
import mmap
import struct
import sys
from collections import OrderedDict

BINARY = "lib/arm64-v8a/libUnreal.so"
TEXT_VA = 0x017b4000
TEXT_OFF = 0x017b0000
TEXT_SIZE = 0x06ab8378
DATAREL_VA = 0x082726b0
DATAREL_OFF = 0x0826a6b0
DATAREL_DIFF = DATAREL_VA - DATAREL_OFF
RODATA_VA = 0x059480
RODATA_SIZE = 0x9232ac

FNAME_INIT = 0x17fb400
STRING_SERIALIZE = 0x50f6924  # FString serialize function

# Map BL targets to human-readable type names
# Identified via disassembly of serialize functions
STRUCT_TYPE_MAP = {
    # Primitive type serializers
    0x3a4dc94:  "struct",                       # vtable[2] dispatch for nested struct
    0x50f661c:  "FName",                        # vtable[4] dispatch for FName
    0x50f6634:  "FName",                        # FName implementation (after thunk)
    0x50f67fc:  "FVector2D",                    # 2 floats via vtable[14]
    0x50f6a68:  "FVector",                      # 3 doubles->3 floats via vtable[28]
    0x50f6ae4:  "FVector2D",                    # 2 doubles->2 floats variant
    0x50f6ae8:  "FVector2D",                    # 2 doubles->2 floats via vtable[28]
    # TArray serializers (ldrh count + element loop)
    0x5e11084:  "TArray<struct>",               # stride=32, elements via struct_dispatch
    0x5e77990:  "TArray<FString>",              # stride=16, elements via FString
    0x5e7e588:  "TArray<FString>",              # stride=20, variant
    0x5dacf34:  "TArray<struct>",               # stride=64
    0x5dacff4:  "TArray<struct>",               # stride=64
    0x5dad0a0:  "TArray<struct>",               # stride=32
    0x5dad4ac:  "TArray<struct>",               # stride=32
    0x5db5ab0:  "TArray<struct>",               # stride=32
    0x5d80810:  "TArray<struct>",               # stride=16
    0x5e026d8:  "TArray<struct>",               # stride=64
    0x5e128c4:  "TArray<struct>",
    0x5e12804:  "TArray<struct>",
    0x5e12984:  "TArray<struct>",               # stride=32
    0x5e14c14:  "TArray<struct>",               # stride=32, with FName
    0x5e889ec:  "TArray",
    0x5d79378:  "TArray",
    # TMap/TSet serializers (TSparseArray with bitfield iteration)
    0x5da4054:  "TMap<FString,int32>",           # stride=24
    0x5e0f48c:  "TMap<FString,bool>",            # stride=24
    0x5d92d18:  "TMap<uint8,FString>",           # stride=24
    0x5e29c14:  "TSet<int32>",                   # stride=12
    0x5db8c88:  "TMap<FString,int8>",            # stride=24
    0x5db67b8:  "TMap<uint8,int8>",              # stride=12
    0x5d8fe20:  "TMap",                          # complex variant
    0x5e9101c:  "TSet<int32>",                   # stride=12
    0x5e2978c:  "TMap<uint8,bool>",              # stride=12
}


def va_to_off(va):
    return TEXT_OFF + (va - TEXT_VA)


def in_text(va):
    return TEXT_VA <= va < TEXT_VA + TEXT_SIZE


def read_u32(mm, off):
    return struct.unpack('<I', mm[off:off + 4])[0]


def read_u64(mm, off):
    return struct.unpack('<Q', mm[off:off + 8])[0]


def decode_bl(raw, pc):
    if (raw & 0xFC000000) != 0x94000000:
        return None
    imm26 = raw & 0x03FFFFFF
    if imm26 & (1 << 25):
        imm26 -= (1 << 26)
    return pc + (imm26 << 2)


def analyze_serialize_func(mm, func_va, max_insns=400):
    """
    Analyze a serialize function to extract field types.
    Returns list of (obj_offset, type_str) tuples.
    """
    if not in_text(func_va):
        return []

    fields = []
    base_reg = None  # register holding 'this' pointer (usually X20 or X0)

    for i in range(max_insns):
        pc = func_va + i * 4
        off = va_to_off(pc)
        if off < 0 or off + 4 > len(mm):
            break
        raw = read_u32(mm, off)

        # RET
        if raw == 0xD65F03C0:
            break

        # Track which register holds the object pointer
        # Pattern: MOV X20, X0 (at function start)
        if (raw & 0xFFE0FFE0) == 0xAA0003E0:  # MOV Xd, Xm
            rd = raw & 0x1F
            rm = (raw >> 16) & 0x1F
            if rm == 0 and rd in (19, 20, 21):
                base_reg = rd

        # Pattern 1: ADD X1, Xbase, #offset → BL STRING_SERIALIZE
        # This means: pass address of FString field to string serializer
        if (raw & 0xFF00001F) == 0x91000001:  # ADD X1, Xn, #imm (dest=X1)
            rn = (raw >> 5) & 0x1F
            imm12 = (raw >> 10) & 0xFFF
            shift = (raw >> 22) & 0x3
            if shift == 1:
                imm12 <<= 12

            if rn == base_reg or rn == 0:
                # Check next few instructions for BL to string serializer
                for j in range(1, 4):
                    npc = pc + j * 4
                    noff = va_to_off(npc)
                    if noff + 4 > len(mm):
                        break
                    nraw = read_u32(mm, noff)
                    bl_target = decode_bl(nraw, npc)
                    if bl_target == STRING_SERIALIZE:
                        fields.append((imm12, "string"))
                        break
                    elif bl_target is not None:
                        # Look up known type or use raw address
                        type_name = STRUCT_TYPE_MAP.get(bl_target, f"struct(BL 0x{bl_target:x})")
                        fields.append((imm12, type_name))
                        break
                continue

        # Pattern 2: LDR W1, [Xbase, #offset] → virtual call = int32
        if (raw & 0xFFC0001F) == 0xB9400001:  # LDR W1, [Xn, #imm]
            rn = (raw >> 5) & 0x1F
            imm = ((raw >> 10) & 0xFFF) * 4
            if rn == base_reg or rn == 0:
                # Check if followed by virtual call (BLR or BR)
                for j in range(1, 6):
                    npc = pc + j * 4
                    noff = va_to_off(npc)
                    if noff + 4 > len(mm):
                        break
                    nraw = read_u32(mm, noff)
                    if (nraw & 0xFFFFFC1F) in (0xD63F0000, 0xD61F0000):  # BLR/BR Xn
                        fields.append((imm, "int32"))
                        break
                    bl_target = decode_bl(nraw, npc)
                    if bl_target is not None:
                        fields.append((imm, "int32"))
                        break
                continue

        # Pattern 3: LDRB W1, [Xbase, #offset] → uint8/bool
        if (raw & 0xFFC0001F) == 0x39400001:  # LDRB W1, [Xn, #imm]
            rn = (raw >> 5) & 0x1F
            imm = ((raw >> 10) & 0xFFF)
            if rn == base_reg or rn == 0:
                fields.append((imm, "uint8"))
                continue

        # Pattern 4: LDRH W1, [Xbase, #offset] → uint16
        if (raw & 0xFFC0001F) == 0x79400001:  # LDRH W1, [Xn, #imm]
            rn = (raw >> 5) & 0x1F
            imm = ((raw >> 10) & 0xFFF) * 2
            if rn == base_reg or rn == 0:
                fields.append((imm, "uint16"))
                continue

        # Pattern 5: LDR X1, [Xbase, #offset] → pointer/int64
        if (raw & 0xFFC0001F) == 0xF9400001:  # LDR X1, [Xn, #imm]
            rn = (raw >> 5) & 0x1F
            imm = ((raw >> 10) & 0xFFF) * 8
            if rn == base_reg or rn == 0:
                # Check next: BR (tail call) suggests pointer/buffer type
                for j in range(1, 4):
                    npc = pc + j * 4
                    noff = va_to_off(npc)
                    if noff + 4 > len(mm):
                        break
                    nraw = read_u32(mm, noff)
                    if (nraw & 0xFFFFFC1F) == 0xD61F0000:  # BR Xn
                        fields.append((imm, "int64/ptr"))
                        break
                continue

    return fields


def main():
    with open("packet_definitions.json") as f:
        defs = json.load(f)

    with open(BINARY, 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    results = {}
    type_stats = {}

    for name, pdef in defs["packets"].items():
        vtable_va_str = pdef.get("vtable_va")
        if not vtable_va_str:
            continue
        vtable_va = int(vtable_va_str, 16)
        vtable_off = vtable_va - DATAREL_DIFF

        field_names = [f["name"] if isinstance(f, dict) else f for f in pdef["fields"]]

        # Find best slot, then supplement from others if needed
        slot_results = {}
        for slot in [2, 15, 4, 17]:
            slot_off = vtable_off + slot * 8
            if slot_off + 8 > len(mm):
                continue
            func_va = read_u64(mm, slot_off)
            if not in_text(func_va) or func_va in (0x017b4060, 0x017b9e88, 0x017b408c):
                continue
            tf = analyze_serialize_func(mm, func_va)
            if tf:
                slot_results[slot] = tf

        # Pick the slot with most fields as primary
        type_fields = []
        if slot_results:
            best_slot = max(slot_results, key=lambda s: len(slot_results[s]))
            type_fields = list(slot_results[best_slot])

            # If we still need more fields, supplement from other slots
            if len(type_fields) < len(field_names):
                known_offsets = {off for off, _ in type_fields}
                for slot, tf in slot_results.items():
                    if slot == best_slot:
                        continue
                    for off, ftype in tf:
                        if off not in known_offsets:
                            type_fields.append((off, ftype))
                            known_offsets.add(off)

        if type_fields:
            # Sort by object offset
            type_fields.sort(key=lambda x: x[0])

            # Match to field names by position
            typed_fields = []
            for idx, fname in enumerate(field_names):
                if idx < len(type_fields):
                    obj_off, ftype = type_fields[idx]
                    typed_fields.append({
                        "name": fname,
                        "type": ftype,
                        "obj_offset": f"0x{obj_off:x}"
                    })
                    type_stats[ftype] = type_stats.get(ftype, 0) + 1
                else:
                    typed_fields.append({"name": fname, "type": "unknown"})
                    type_stats["unknown"] = type_stats.get("unknown", 0) + 1

            results[name] = {
                "opcode": pdef["opcode"],
                "fields": typed_fields,
                "alloc_size": pdef.get("alloc_size"),
            }

    mm.close()

    # Output
    print(f"Analyzed {len(results)} packets with type information\n")

    # Type distribution
    print("Type distribution:")
    for t, c in sorted(type_stats.items(), key=lambda x: -x[1]):
        print(f"  {t:<30s} {c:5d}")
    print()

    # Show sample packets
    print("Sample decoded packets:")
    samples = ["PktVersion", "PktVersionResult", "PktLogin", "PktKeyChangeNotify",
               "PktCharacterCreateResult", "PktLogout", "PktPing", "PktTimeSync"]
    for name in samples:
        if name in results:
            r = results[name]
            print(f"\n  {name} (opcode {r['opcode']}):")
            for f in r["fields"]:
                print(f"    {f['name']:<30s} {f['type']:<15s} {f.get('obj_offset','')}")

    # Write full output
    output = {
        "metadata": {
            "description": "Field types extracted from serialize functions (vtable slots 2/15)",
            "type_identification": {
                "string": "BL 0x50f6924 with ADD X1 (FString serialize)",
                "int32": "LDR W1 + virtual call (32-bit integer)",
                "uint8": "LDRB W1 (8-bit integer/bool)",
                "uint16": "LDRH W1 (16-bit integer)",
                "int64/ptr": "LDR X1 + BR (64-bit/pointer)",
            },
            "total_packets": len(results),
            "type_stats": type_stats,
        },
        "packets": OrderedDict(sorted(results.items(), key=lambda x: x[1]["opcode"])),
    }

    with open("packet_field_types.json", "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nFull results written to packet_field_types.json")


if __name__ == "__main__":
    main()
