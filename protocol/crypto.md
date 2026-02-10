# VAMPIR Protocol Cryptography

Analysis of the application-layer encryption used by com.netmarble.thered v1.4.14.

Source binaries:
- `lib/arm64-v8a/libnmsssa.so` (3.8MB) - Netmarble Security SDK, contains crypto primitives
- `lib/arm64-v8a/libUnreal.so` (150MB) - UE5 runtime, references MessageKey and PAK encryption

See also: [`wire_format.md`](wire_format.md) for the full packet framing, flag bytes, and decode pipeline.

---

## 1. Packet Encryption (Observed): XOR Stream Cipher

Live traffic analysis reveals the game server connection uses a **static 8-byte XOR cipher**,
not AES-128-CBC as the binary symbols suggest. AES may apply to a different connection stage
(lobby server) or may have been replaced in this version.

### XOR Key

```
9A A7 84 20 D0 C9 78 B3  (8 bytes)
```

Found in `tools/analyze_packet.py` and confirmed against live packet captures.

### XOR Operation

```
plaintext[i] = ciphertext[i] XOR key[(i + offset) % 8]
```

| Direction | Offset | Opcode Position |
|-----------|--------|-----------------|
| C->S | 0 | Byte 5 of plaintext |
| S->C | 6 (on payload after flag byte) | Byte 3 of plaintext |

### Session Behavior

- The XOR key is **static** for the entire game server session
- No `PktKeyChangeNotify` / `PktKeyChanged` / `PktKeyChangedResult` exchange was observed
- All 1195 mapped opcodes decode correctly with the static key

## 2. Packet Compression: LZ4 Block

The `CNSCryptoCompressor` class uses **LZ4 block compression** (not zlib as initially guessed).

- **Direction**: S->C only. C->S packets are never compressed.
- **Flag**: `body[0] == 0x80` indicates LZ4, `0x00` indicates no compression.
- **Pipeline**: plaintext → XOR encrypt → LZ4 compress → prepend `0x80` flag
- **Decode**: strip `0x80` → LZ4 block decompress → XOR decrypt (offset 6)
- **Format**: LZ4 block (raw), not LZ4 frame (no `04 22 4D 18` magic header)
- **Size**: Decompressed size is not in the wire data; must be discovered by the decompressor

Typical compression ratios: 1.1x–2.7x. Packets under ~50 bytes are sent uncompressed.

## 3. AES-128-CBC (Binary Symbols — Not Observed on Wire)

The `CAesCbc` class and AES key material exist in the binary but were **not observed** in game
server traffic. They may be used for:
- Lobby server connections (separate TCP stream)
- The initial key exchange if it occurs at a different stage
- An older or unused code path

### Key Material (from binary)

| Symbol | Virtual Address | Size | Value (hex) |
|--------|----------------|------|-------------|
| `_InitialKey` | `0x3c0410` | 16 bytes | `e313af529c6655cde45aa73a22e1dff5` |
| `_InitialIV` | `0x3c0420` | 16 bytes | `a4a0ebe78ab88b363d2f68acc1f66e52` |

### Key Exchange Opcodes (defined but not observed)

| Opcode | Name | Fields | Direction |
|--------|------|--------|-----------|
| 11 | PktKeyChangeNotify | Key, NpcId | S -> C |
| 12 | PktKeyChanged | Key, Result | C -> S |
| 13 | PktKeyChangedResult | Result, NpcId | S -> C |

### Crypto Classes (libnmsssa.so)

| Class | RTTI Location | Purpose |
|-------|---------------|---------|
| `CAesCbc` | rodata 0x317389 | AES-128-CBC encrypt/decrypt |
| `CNSCryptoCompressor` | rodata 0x31b5c5 | LZ4 compression + XOR encryption |

---

## 4. PAK File Encryption: AES-256-ECB

The Unreal Engine PAK archive index is encrypted with a separate AES-256 key.

### PAK Encryption Key

Found in `libUnreal.so` `.rodata` section:

```
Key (hex): 4de16fa1dffb68f2b957d49e6beaebcaf7d6b41a0107cd548f0068ecde4d28ed
Algorithm: AES-256-ECB
```

### PAK Archive Details

| Property | Value |
|----------|-------|
| Location | APK -> `assets/main.obb.png` (ZIP) -> `ProjectRED-Android_ASTC.pak` |
| PAK Version | 11 |
| PAK Magic | `0x5A6F12E1` |
| Compression | Oodle |
| Index Offset | 134,799,861 |
| Index Size | 123,360 bytes |
| Encryption Key GUID | `00000000-0000-0000-0000-000000000000` (default) |
| Total Files | 7,834 |
| Uncompressed Files | 4,240 |
| Oodle-Compressed Files | 3,594 |

The null GUID indicates the default (embedded) encryption key is used, which is the 32-byte
key found in the `.rodata` section.

### Encrypted Regions

Both the primary index and the full directory index are encrypted with AES-256-ECB.
Individual file data within the PAK may also be encrypted (per-entry `bEncrypted` flag).

---

## 5. Security Architecture


### Netmarble Security SDK (`libnmsssa.so`)

The security library provides:
- **Packet encryption** via XOR stream cipher (8-byte key, static per session)
- **Packet compression** via LZ4 block format (S->C only, via `CNSCryptoCompressor`)
- **AES-128-CBC** via `CAesCbc` (present in binary, not observed in game server traffic)
- **Security code validation** (referenced in `PktVersionResult.SecurityCodeEnabled`)
- **Anti-tamper checks** (Xigncode integration, opcodes 28901-29162)

### Authentication Tokens

From the `PktLogin` packet fields:
- `Account` - User account identifier
- `Token` - Session authentication token
- `NId` - Netmarble ID
- `NetmarbleSToken` - Netmarble S platform token
- `SecurityCode` - Anti-cheat security code
- `NetmarbleSElements` - Additional Netmarble S elements (from `PktVersion`)

### Token Hierarchy

1. **Netmarble Platform Token** (`NetmarbleSToken`) - Obtained from Netmarble SDK login
2. **Game Session Token** (`Token`) - Issued by lobby server after platform auth
3. **Message Key** (`Key` in `PktKeyChangeNotify`) - Per-session encryption key

---

## 6. Extraction Tools

| Tool | Purpose |
|------|---------|
| `tools/extract_crypto.py` | Extract `_InitialKey` and `_InitialIV` from `libnmsssa.so` |
| `tools/pak_decrypt.py` | Decrypt PAK index, list files, extract uncompressed assets |

### Usage

```bash
# Extract crypto keys
python tools/extract_crypto.py

# Decrypt PAK and list CSV files
python tools/pak_decrypt.py --key 4de16fa1dffb68f2b957d49e6beaebcaf7d6b41a0107cd548f0068ecde4d28ed --list-csv

# Extract specific files from PAK
python tools/pak_decrypt.py --extract "PacketDest"
```
