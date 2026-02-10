#!/usr/bin/env python3
"""
Extract field types from packet serialize functions - V2.

Combines two approaches for maximum coverage:
1. FArchive vtable dispatch: tracks which FArchive virtual method is called
   for each field, using the vtable offset to identify the type precisely.
2. Instruction pattern fallback (from V1): infers types from ARM64 load
   instructions when FArchive vtable tracking fails.

FArchive vtable offset -> type:
  0x50 = int32       0x60 = uint64      0x98 = bool
  0xa0 = int8        0xa8 = uint8       0xb0 = uint16
  0xb8 = int16       0xc0 = int32       0xc8 = uint32
  0xd0 = int64       0xd8 = FName       0xe0 = float
"""

import json
import mmap
import struct
import sys
from collections import OrderedDict, Counter

BINARY = "lib/arm64-v8a/libUnreal.so"
TEXT_VA = 0x017b4000
TEXT_OFF = 0x017b0000
TEXT_SIZE = 0x06ab8378
DATAREL_VA = 0x082726b0
DATAREL_OFF = 0x0826a6b0
DATAREL_DIFF = DATAREL_VA - DATAREL_OFF

FNAME_INIT = 0x17fb400

# FArchive vtable offset -> precise type name
FARCHIVE_TYPE_MAP = {
    0x28: "uint8",
    0x38: "int8",
    0x40: "bytes",
    0x50: "int32",
    0x60: "uint64",
    0x88: "int64",
    0x90: "int64",
    0x98: "bool",
    0xa0: "int8",
    0xa8: "uint8",
    0xb0: "uint16",
    0xb8: "int16",
    0xc0: "int32",
    0xc8: "uint32",
    0xd0: "int64",
    0xd8: "FName",
    0xe0: "float",
}

# Known direct BL targets -> type
BL_TYPE_MAP = {
    0x3a4dc94:  "struct",
    0x50f661c:  "FName",
    0x50f6634:  "FName",
    0x50f67fc:  "FVector2D",
    0x50f6a68:  "FVector",
    0x50f6ae4:  "FVector2D",
    0x50f6ae8:  "FVector2D",
    0x50f6924:  "string",
    # TArray serializers
    0x5e11084:  "TArray<struct>",
    0x5e77990:  "TArray<FString>",
    0x5e7e588:  "TArray<FString>",
    0x5dacf34:  "TArray<struct>",
    0x5dacff4:  "TArray<struct>",
    0x5dad0a0:  "TArray<struct>",
    0x5dad4ac:  "TArray<struct>",
    0x5db5ab0:  "TArray<struct>",
    0x5d80810:  "TArray<struct>",
    0x5e026d8:  "TArray<struct>",
    0x5e128c4:  "TArray<struct>",
    0x5e12804:  "TArray<struct>",
    0x5e12984:  "TArray<struct>",
    0x5e14c14:  "TArray<struct>",
    0x5e889ec:  "TArray",
    0x5d79378:  "TArray",
    # TMap/TSet serializers
    0x5da4054:  "TMap<FString,int32>",
    0x5e0f48c:  "TMap<FString,bool>",
    0x5d92d18:  "TMap<uint8,FString>",
    0x5e29c14:  "TSet<int32>",
    0x5db8c88:  "TMap<FString,int8>",
    0x5db67b8:  "TMap<uint8,int8>",
    0x5d8fe20:  "TMap",
    0x5e9101c:  "TSet<int32>",
    0x5e2978c:  "TMap<uint8,bool>",
}

STUB_VAS = {0x017b4060, 0x017b9e88, 0x017b408c}


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


def decode_b(raw, pc):
    """Decode unconditional B (tail call) instruction."""
    if (raw & 0xFC000000) != 0x14000000:
        return None
    imm26 = raw & 0x03FFFFFF
    if imm26 & (1 << 25):
        imm26 -= (1 << 26)
    return pc + (imm26 << 2)


def _check_obj_reg(jrn, obj_reg):
    """Accept X0 (entry arg), saved obj_reg, or any callee-saved if unknown."""
    return jrn == 0 or jrn == obj_reg or (obj_reg is None and jrn >= 19)


def find_field_offset(insns, call_idx, obj_reg):
    """Look backward from a call instruction to find the X1 field offset setup."""
    for j in range(call_idx - 1, max(call_idx - 10, -1), -1):
        _, jraw = insns[j]

        # ADD X1, Xn, #imm12 (pass field by reference)
        if (jraw & 0xFF00001F) == 0x91000001:
            jrn = (jraw >> 5) & 0x1F
            jimm12 = (jraw >> 10) & 0xFFF
            jshift = (jraw >> 22) & 0x3
            if jshift == 1:
                jimm12 <<= 12
            if _check_obj_reg(jrn, obj_reg):
                return jimm12

        # LDR W1, [Xn, #imm*4] (pass int32 by value)
        if (jraw & 0xFFC0001F) == 0xB9400001:
            jrn = (jraw >> 5) & 0x1F
            jimm = ((jraw >> 10) & 0xFFF) * 4
            if _check_obj_reg(jrn, obj_reg):
                return jimm

        # LDRB W1, [Xn, #imm] (pass uint8 by value)
        if (jraw & 0xFFC0001F) == 0x39400001:
            jrn = (jraw >> 5) & 0x1F
            jimm = (jraw >> 10) & 0xFFF
            if _check_obj_reg(jrn, obj_reg):
                return jimm

        # LDRH W1, [Xn, #imm*2] (pass uint16 by value)
        if (jraw & 0xFFC0001F) == 0x79400001:
            jrn = (jraw >> 5) & 0x1F
            jimm = ((jraw >> 10) & 0xFFF) * 2
            if _check_obj_reg(jrn, obj_reg):
                return jimm

        # LDR X1, [Xn, #imm*8] (pass int64/ptr by value)
        if (jraw & 0xFFC0001F) == 0xF9400001:
            jrn = (jraw >> 5) & 0x1F
            jimm = ((jraw >> 10) & 0xFFF) * 8
            if _check_obj_reg(jrn, obj_reg):
                return jimm

        # LDR S0, [Xn, #imm*4] (pass float by value via float register)
        if (jraw & 0xFFC0001F) == 0xBD400000:
            jrn = (jraw >> 5) & 0x1F
            jimm = ((jraw >> 10) & 0xFFF) * 4
            if _check_obj_reg(jrn, obj_reg):
                return jimm

        # Stop at another call (BL, B, BLR, BR)
        if (decode_bl(jraw, insns[j][0]) is not None or
            decode_b(jraw, insns[j][0]) is not None or
            (jraw & 0xFFFFFC1F) in (0xD63F0000, 0xD61F0000)):
            break

    return None


def find_v1_type_from_x1_setup(insns, call_idx, obj_reg):
    """V1-style: infer type from how X1 was loaded before a BLR call."""
    for j in range(call_idx - 1, max(call_idx - 8, -1), -1):
        _, jraw = insns[j]

        # ADD X1, Xn, #imm → passing address = complex type (string/struct)
        if (jraw & 0xFF00001F) == 0x91000001:
            jrn = (jraw >> 5) & 0x1F
            jimm12 = (jraw >> 10) & 0xFFF
            jshift = (jraw >> 22) & 0x3
            if jshift == 1:
                jimm12 <<= 12
            if _check_obj_reg(jrn, obj_reg):
                return jimm12, "int32"  # V1 can't distinguish further

        # LDR W1 → int32
        if (jraw & 0xFFC0001F) == 0xB9400001:
            jrn = (jraw >> 5) & 0x1F
            jimm = ((jraw >> 10) & 0xFFF) * 4
            if _check_obj_reg(jrn, obj_reg):
                return jimm, "int32"

        # LDRB W1 → uint8
        if (jraw & 0xFFC0001F) == 0x39400001:
            jrn = (jraw >> 5) & 0x1F
            jimm = (jraw >> 10) & 0xFFF
            if _check_obj_reg(jrn, obj_reg):
                return jimm, "uint8"

        # LDRH W1 → uint16
        if (jraw & 0xFFC0001F) == 0x79400001:
            jrn = (jraw >> 5) & 0x1F
            jimm = ((jraw >> 10) & 0xFFF) * 2
            if _check_obj_reg(jrn, obj_reg):
                return jimm, "uint16"

        # LDR X1 → int64/ptr
        if (jraw & 0xFFC0001F) == 0xF9400001:
            jrn = (jraw >> 5) & 0x1F
            jimm = ((jraw >> 10) & 0xFFF) * 8
            if _check_obj_reg(jrn, obj_reg):
                return jimm, "int64"

        # LDR S0, [Xn, #imm*4] → float (loaded via float register)
        if (jraw & 0xFFC0001F) == 0xBD400000:
            jrn = (jraw >> 5) & 0x1F
            jimm = ((jraw >> 10) & 0xFFF) * 4
            if _check_obj_reg(jrn, obj_reg):
                return jimm, "float"

        if decode_bl(jraw, insns[j][0]) is not None or (jraw & 0xFFFFFC1F) == 0xD63F0000:
            break

    return None, None


def analyze_serialize(mm, func_va, max_insns=500):
    """
    Combined V1+V2 analysis of a serialize function.

    Priority:
    1. FArchive vtable dispatch (BLR) → precise type from FARCHIVE_TYPE_MAP
    2. Direct BL to known targets → type from BL_TYPE_MAP
    3. V1-style fallback for BLR without FArchive pattern → instruction-inferred type
    """
    if not in_text(func_va):
        return []

    insns = []
    for i in range(max_insns):
        pc = func_va + i * 4
        off = va_to_off(pc)
        if off < 0 or off + 4 > len(mm):
            break
        raw = read_u32(mm, off)
        insns.append((pc, raw))
        if raw == 0xD65F03C0:
            break

    if len(insns) < 3:
        return []

    # Identify registers from prologue
    obj_reg = None
    archive_reg = None
    for idx, (pc, raw) in enumerate(insns[:15]):
        if (raw & 0xFFE0FFE0) == 0xAA0003E0:
            rd = raw & 0x1F
            rm = (raw >> 16) & 0x1F
            if rd >= 19:
                if rm == 0 and obj_reg is None:
                    obj_reg = rd
                elif rm == 1 and archive_reg is None:
                    archive_reg = rd

    fields = []

    for i, (pc, raw) in enumerate(insns):
        bl_target = decode_bl(raw, pc)
        b_target = decode_b(raw, pc)  # unconditional B (tail call)
        is_blr = (raw & 0xFFFFFC1F) == 0xD63F0000  # BLR Xn
        is_br = (raw & 0xFFFFFC1F) == 0xD61F0000    # BR Xn (tail call)

        if bl_target is None and b_target is None and not is_blr and not is_br:
            continue

        field_type = None
        field_offset = None

        # Handle direct calls (BL) and direct tail calls (B)
        call_target = bl_target or b_target
        if call_target is not None:
            if call_target in BL_TYPE_MAP:
                field_type = BL_TYPE_MAP[call_target]
                field_offset = find_field_offset(insns, i, obj_reg)
            elif call_target == FNAME_INIT:
                continue
            elif in_text(call_target):
                field_offset = find_field_offset(insns, i, obj_reg)
                if field_offset is not None:
                    field_type = "struct"
            else:
                continue

        elif is_blr or is_br:
            dispatch_reg = (raw >> 5) & 0x1F

            # Try FArchive vtable dispatch first
            farchive_matched = False
            for j in range(i - 1, max(i - 8, -1), -1):
                _, jraw = insns[j]
                if (jraw & 0xFFC00000) == 0xF9400000:
                    jrd = jraw & 0x1F
                    jrn = (jraw >> 5) & 0x1F
                    jimm = ((jraw >> 10) & 0xFFF) * 8

                    if jrd == dispatch_reg and jimm > 0:
                        # Found method load. Verify vtable base load.
                        for k in range(j - 1, max(j - 6, -1), -1):
                            _, kraw = insns[k]
                            if (kraw & 0xFFC00000) == 0xF9400000:
                                krd = kraw & 0x1F
                                krn = (kraw >> 5) & 0x1F
                                kimm = ((kraw >> 10) & 0xFFF) * 8
                                if krd == jrn and kimm == 0:
                                    if (krn == archive_reg or
                                        krn == 1 or
                                        (archive_reg is None and krn >= 19)):
                                        ft = FARCHIVE_TYPE_MAP.get(jimm)
                                        if ft:
                                            field_type = ft
                                            field_offset = find_field_offset(insns, i, obj_reg)
                                            farchive_matched = True
                                    break
                                elif krd == jrn:
                                    break
                        break
                    elif jrd == dispatch_reg:
                        break

            # V1 fallback: infer type from X1 load instruction
            if not farchive_matched:
                fo, ft = find_v1_type_from_x1_setup(insns, i, obj_reg)
                if fo is not None and ft is not None:
                    field_offset = fo
                    field_type = ft

        if field_offset is not None and field_type is not None:
            fields.append((field_offset, field_type))

    return fields


def main():
    with open("packet_definitions.json") as f:
        defs = json.load(f)

    with open(BINARY, 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    print("Analyzing serialize functions (FArchive vtable + instruction fallback)...")

    results = {}
    type_stats = Counter()

    for name, pdef in defs["packets"].items():
        vtable_va_str = pdef.get("vtable_va")
        if not vtable_va_str:
            continue
        vtable_va = int(vtable_va_str, 16)
        vtable_off = vtable_va - DATAREL_DIFF

        field_names = [f["name"] if isinstance(f, dict) else f for f in pdef["fields"]]

        slot_results = {}
        for slot in [2, 15, 4, 17]:
            slot_off = vtable_off + slot * 8
            if slot_off + 8 > len(mm):
                continue
            func_va = read_u64(mm, slot_off)
            if not in_text(func_va) or func_va in STUB_VAS:
                continue
            tf = analyze_serialize(mm, func_va)
            if tf:
                slot_results[slot] = tf

        type_fields = []
        if slot_results:
            best_slot = max(slot_results, key=lambda s: len(slot_results[s]))
            type_fields = list(slot_results[best_slot])

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
            # Deduplicate by offset (keep first seen from best slot)
            seen_offsets = set()
            deduped = []
            for off, ftype in type_fields:
                if off not in seen_offsets:
                    deduped.append((off, ftype))
                    seen_offsets.add(off)
            type_fields = deduped

            type_fields.sort(key=lambda x: x[0])

            # If we found more fields than names, the extras at offsets < 0x10
            # are likely base class fields (vtable ptr at 0x0, base fields at 0x8/0xc).
            # Only trim those, not arbitrary excess.
            if len(type_fields) > len(field_names):
                # Count how many excess fields we have
                excess = len(type_fields) - len(field_names)
                # Only drop fields at offsets < 0x10 (definitely base class)
                drop = 0
                for off, _ in type_fields:
                    if off < 0x10 and drop < excess:
                        drop += 1
                    else:
                        break
                if drop > 0:
                    type_fields = type_fields[drop:]

            typed_fields = []
            for idx, fname in enumerate(field_names):
                if idx < len(type_fields):
                    obj_off, ftype = type_fields[idx]
                    typed_fields.append({
                        "name": fname,
                        "type": ftype,
                        "obj_offset": f"0x{obj_off:x}"
                    })
                    type_stats[ftype] += 1
                else:
                    typed_fields.append({"name": fname, "type": "unknown"})
                    type_stats["unknown"] += 1

            results[name] = {
                "opcode": pdef["opcode"],
                "fields": typed_fields,
                "alloc_size": pdef.get("alloc_size"),
            }

    mm.close()

    print(f"\nAnalyzed {len(results)} packets with type information\n")

    print("Type distribution:")
    for t, c in sorted(type_stats.items(), key=lambda x: -x[1]):
        print(f"  {t:<35s} {c:5d}")
    print(f"  {'TOTAL':<35s} {sum(type_stats.values()):5d}")

    # Samples
    print("\nSample decoded packets:")
    samples = ["PktVersion", "PktVersionResult", "PktLogin", "PktKeyChangeNotify",
               "PktCharacterCreateResult", "PktLogout", "PktPing", "PktTimeSync"]
    for name in samples:
        if name in results:
            r = results[name]
            print(f"\n  {name} (opcode {r['opcode']}):")
            for f in r["fields"]:
                print(f"    {f['name']:<30s} {f['type']:<20s} {f.get('obj_offset','')}")

    # Write output
    output = {
        "metadata": {
            "description": "Field types via FArchive vtable dispatch + instruction fallback (V2)",
            "farchive_vtable_map": {f"0x{k:x}": v for k, v in sorted(FARCHIVE_TYPE_MAP.items())},
            "total_packets": len(results),
            "type_stats": dict(type_stats),
        },
        "packets": OrderedDict(sorted(results.items(), key=lambda x: x[1]["opcode"])),
    }

    with open("packet_field_types_v2.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nFull results written to packet_field_types_v2.json")

    # === Compare with V1 ===
    try:
        with open("packet_field_types.json") as f:
            v1 = json.load(f)
    except FileNotFoundError:
        print("\nV1 results not found for comparison")
        return

    print("\n\n" + "=" * 70)
    print("COMPARISON WITH V1")
    print("=" * 70)

    v1p = v1["packets"]
    v2p = results

    only_v1 = set(v1p) - set(v2p)
    only_v2 = set(v2p) - set(v1p)
    both = set(v1p) & set(v2p)

    print(f"\nPacket coverage:")
    print(f"  V1 only:  {len(only_v1)}")
    print(f"  V2 only:  {len(only_v2)}")
    print(f"  Both:     {len(both)}")
    print(f"  V1 total: {len(v1p)}")
    print(f"  V2 total: {len(v2p)}")

    # Field-level comparison by obj_offset
    agree = 0
    v2_refined = 0  # V2 has more precise type (e.g., bool vs uint8, uint32 vs int32)
    v2_better = 0   # V2 resolved unknown
    v1_better = 0   # V1 has type where V2 unknown
    disagree = 0
    disagreements = []
    v2_new_types = []

    # Build V1 lookup by (name, obj_offset)
    v1_by_offset = {}
    for name in both:
        for f in v1p[name]["fields"]:
            if "obj_offset" in f:
                v1_by_offset[(name, f["obj_offset"])] = f["type"]

    # Types that are compatible (V2 is more precise)
    REFINED_PAIRS = {
        ("uint8", "bool"), ("uint8", "int8"), ("uint8", "uint8"),
        ("int32", "int32"), ("int32", "uint32"), ("int32", "int16"),
        ("int64/ptr", "int64"), ("int64/ptr", "uint64"),
        ("uint16", "uint16"), ("uint16", "int16"),
    }

    for name in sorted(both):
        v2f = v2p[name]["fields"]
        for f in v2f:
            if "obj_offset" not in f:
                continue
            v2t = f["type"]
            v1t = v1_by_offset.get((name, f["obj_offset"]))

            if v1t is None:
                if v2t != "unknown":
                    v2_better += 1
                continue

            if v2t == "unknown":
                v1_better += 1
            elif v1t == "unknown":
                v2_better += 1
                if len(v2_new_types) < 20:
                    v2_new_types.append(f"  {name}.{f['name']}: unknown -> {v2t}")
            elif v1t == v2t:
                agree += 1
            elif (v1t, v2t) in REFINED_PAIRS:
                v2_refined += 1
            else:
                disagree += 1
                if len(disagreements) < 30:
                    disagreements.append(f"  {name}.{f['name']}@{f['obj_offset']}: v1={v1t} vs v2={v2t}")

    total = agree + v2_refined + v2_better + v1_better + disagree
    print(f"\nField-level comparison by obj_offset ({total} fields):")
    print(f"  Exact agree:    {agree:5d}")
    print(f"  V2 refined:     {v2_refined:5d}  (compatible but more precise)")
    print(f"  V2 new:         {v2_better:5d}  (V2 typed, V1 unknown/missing)")
    print(f"  V1 better:      {v1_better:5d}  (V1 typed, V2 unknown)")
    print(f"  Disagree:       {disagree:5d}")

    if v2_new_types:
        print(f"\nSample fields V2 newly resolved:")
        for t in v2_new_types:
            print(t)

    if disagreements:
        print(f"\nType disagreements ({len(disagreements)} shown):")
        for d in disagreements:
            print(d)


if __name__ == "__main__":
    main()
