# Wire Protocol Format

Observed wire-level packet structure for the game server TCP connection (port 12000).

Verified against live traffic captures from v1.4.14.

---

## 1. Framing

All data is a stream of length-prefixed packets:

```
[u16 LE total_length][packet_body]
```

- `total_length` includes itself (2 bytes) + the body
- `body_length = total_length - 2`
- Minimum `total_length` is 4 (2-byte length + at least 2 bytes of body)
- Length prefix is **cleartext** (not encrypted)

---

## 2. Packet Body Structure

The first byte of the body is a **cleartext flag** that determines how the rest is processed:

```
[1B flag][encrypted_or_compressed_payload]
```

| Flag | Meaning | Processing |
|------|---------|------------|
| `0x00` | Normal (XOR only) | XOR decrypt payload directly |
| `0x80` | LZ4 compressed | LZ4 block decompress, then XOR decrypt |

The flag byte is **not encrypted**. It is consumed before decryption.

---

## 3. Encryption: XOR Stream Cipher

### Key

```
9A A7 84 20 D0 C9 78 B3  (8 bytes, static)
```

Extracted from `libnmsssa.so` and confirmed via `tools/analyze_packet.py`.
Used for the entire session on the game server connection.

### XOR Operation

```
plaintext[i] = ciphertext[i] XOR key[(i + offset) % 8]
```

The **offset** differs by direction:

| Direction | XOR Offset | Notes |
|-----------|-----------|-------|
| C->S | 0 | Key starts at byte 0 |
| S->C (normal) | 6 | Applied to payload after flag byte |
| S->C (compressed) | 6 | Applied to decompressed LZ4 output |

Note: the S->C offset is equivalently described as "offset 5 on the full body including the flag byte" since `body[1]` at XOR position `(1+5)%8 = 6` is the same as `payload[0]` at offset 6.

---

## 4. Plaintext Packet Layout

After decryption, the plaintext structure differs by direction:

### Client -> Server (C->S)

```
[0x9A magic][CRC32 u32LE][u16 LE opcode][payload...]
```

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | Magic byte `0x9A` |
| 1 | 4 | CRC32 checksum (u32 LE) of `plaintext[5:]` (opcode + payload) |
| 5 | 2 | Opcode (little-endian u16) |
| 7 | var | Packet payload |

The CRC32 is computed over the opcode and payload bytes (everything after the 5-byte header).
Verified against all 50 C->S packets in the capture — 50/50 match using Erlang `:erlang.crc32/1`.

### Server -> Client (S->C)

```
[3B header][u16 LE opcode][payload...]
```

| Offset | Size | Field |
|--------|------|-------|
| 0 | 3 | Header (structure not fully reversed — see notes below) |
| 3 | 2 | Opcode (little-endian u16) |
| 5 | var | Packet payload |

S->C packets do **not** have the `0x9A` magic byte and have a 3-byte header instead of 5.

The S->C header is **not** CRC32. Observed patterns:
- Byte 0 is always `0x00` in plaintext (appears as `0xC9` = `key[6]` before decryption)
- Bytes 1-2 vary per packet but are consistent for repeated opcodes (e.g. PktPingResult always has `[00 xx xx]` with the same values)
- The header may encode a sequence number or session-specific field; further analysis needed

---

## 5. Compression: LZ4 Block

When the flag byte is `0x80`, the remaining body bytes are LZ4 block-compressed data.

### Decode Procedure

1. Strip flag byte: `lz4_data = body[1:]`
2. LZ4 block decompress `lz4_data` (size must be discovered, see below)
3. XOR decrypt the decompressed output with offset 6
4. Parse opcode at byte 3 of decrypted output (same S->C layout)

### Compression Details

- **Algorithm**: LZ4 block format (not LZ4 frame — no magic header `04 22 4D 18`)
- **Direction**: S->C only. No compressed C->S packets observed.
- **Threshold**: Small S->C packets (< ~50 bytes) are sent uncompressed; larger ones tend to be compressed
- **Decompressed size**: Not included in the wire format. The LZ4 block format is self-terminating; the receiver must provide a sufficiently large output buffer. Typical compression ratios observed: 1.1x to 2.7x

### Observed Compressed Opcodes

Compression is used for data-heavy response packets:

| Opcode | Name | Typical Size |
|--------|------|-------------|
| 4 | PktLoginResult | 152B |
| 206 | PktWorldMoveFinishResult | 2.5KB |
| 360 | PktFieldBossSpawnInfoReadResult | 30KB |
| 602 | PktSkillListReadResult | 1.2KB |
| 1827 | PktQuestActListReadResult | 556B |
| 3202 | PktConquestDataReadResult | 3.4KB |
| 7802 | PktShortcutKeyListReadResult | 4.4KB |
| 8301 | PktBroadCastNotify | 145-168B |

---

## 6. Full Decode Pipeline

### C->S Packet

```
wire:  [u16 LE len][body...]
body:  [0x00 flag][ciphertext...]
plain: XOR(ciphertext, key, offset=0)
       → [0x9A][CRC32 u32LE][opcode u16LE][payload...]
```

### S->C Packet (normal)

```
wire:  [u16 LE len][body...]
body:  [0x00 flag][ciphertext...]
plain: XOR(ciphertext, key, offset=6)
       → [hdr 3B][opcode u16LE][payload...]
```

### S->C Packet (compressed)

```
wire:  [u16 LE len][body...]
body:  [0x80 flag][lz4_block_data...]
decomp: LZ4_block_decompress(lz4_block_data)
plain:  XOR(decomp, key, offset=6)
        → [hdr 3B][opcode u16LE][payload...]
```

---

## 7. Session Startup Sequence

Observed packet sequence for a fresh game server connection:

```
C->S  PktVersion (1)           142B
S->C  PktPingResult (17)        20B
S->C  PktLoginResult (4)       121B  [LZ4]
S->C  PktClientIdleCheckTimeNotify (8)  16B
S->C  PktWaitingEndNotify (27)  16B
C->S  PktLogin (3)            1138B
C->S  PktPing (16)              27B
S->C  PktSkillListReadResult (602)    648B  [LZ4]
S->C  PktContentsChanceChangeNotify (120)  46B
S->C  PktNetmarbleSDeliveryRequest (29016) 354B [LZ4]
S->C  PktShortcutKeyListReadResult (7802) 2171B [LZ4]
C->S  PktCharacterSelect (109)  23B
S->C  PktWorldMoveReserveResult (202)  78B
...   (game world data, periodic pings)
```

Note: No `PktKeyChangeNotify` (11) / `PktKeyChanged` (12) / `PktKeyChangedResult` (13) was
observed in the capture. The XOR key remained static throughout the entire session. The AES
key exchange documented in `crypto.md` may apply to a different connection stage (lobby) or
may have been disabled/changed in this version.

---

## 8. Notes

- The XOR cipher is the same key for all observed game server connections
- The `0x9A` magic byte in C->S matches `key[0]`, causing `raw[0]` to always be `0x00` after XOR with offset 0 — this is why the flag byte appears as `0x00` on the wire for both directions
- The 4-byte C->S header is **CRC32** (u32 LE) of the opcode + payload bytes (`plaintext[5:]`), confirmed for all 50 packets
- The 3-byte S->C header is **not** CRC32; byte 0 is always `0x00` in plaintext, bytes 1-2 vary but are deterministic per opcode
- Opcodes are consistent with the 1195-entry map in `packet_opcodes.json`

---

## 9. Payload Serialization

After the header and opcode, the remaining bytes are the **payload** — serialized packet fields.

### Field Serialization Order

Fields are serialized sequentially in the order defined by the packet class's `Serialize()` function, which matches the field order in `packet_field_types_v2.json`. Fields are **not** padded or aligned — they are packed tightly.

### Base Class Prefix

Some packet classes inherit from a base class that serializes its own fields **before** the derived class fields. This produces a prefix on the wire that is not present in the field definitions JSON (which only lists the derived class's fields).

Known pattern: a **uint32** (4 bytes LE) is serialized at the start of the payload before the first defined field. The value is typically `0`.

Packets confirmed to have this base class prefix (discovered empirically from captures):

| Opcode | Name | Evidence |
|--------|------|----------|
| 608 | PktSkillStartResult | Without prefix, float positions decode as garbage; with prefix, TargetPosX/Y become valid world coords (~105K, ~134K) |
| 1811 | PktQuestUpdateResult | Without prefix, Result (uint64) reads as `473219496673280`; with prefix, reads as `110180` (valid quest ID) |
| 2046 | PktChatReportAndBanInfoReadResult | Without prefix, BanReason string length is invalid; with prefix, decodes as empty string correctly |

**Detection method**: For packets with known field types, try decoding both with and without a 4-byte skip. If the skipped version produces valid string lengths, reasonable integer ranges, or correct float coordinates, the packet has a base class prefix.

There is no known static indicator in the binary or JSON metadata to predict which packets have this prefix. The `serialize_va` addresses in `packet_definitions.json` differ between base and non-base packets but don't share a common function. This likely reflects a C++ inheritance hierarchy where certain intermediate classes override `Serialize()`.

### Type Corrections

The vtable-based type extraction in `packet_field_types_v2.json` can misidentify field types that share the same byte width:

| JSON Type | Actual Type | How to tell |
|-----------|-------------|-------------|
| `int32` | `float` | Field name contains Pos, Target, Dir, Yaw, Pitch, Roll; value makes sense as coordinate |
| `int32` | `int8` + padding | Alignment shifts subsequent fields; int8 confirmed by obj_offset gaps of 1 byte |

The v2 extraction tool now correctly identifies `float`, `int8`, and `uint16` types via improved FArchive vtable dispatch.
