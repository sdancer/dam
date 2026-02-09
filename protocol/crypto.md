# VAMPIR Protocol Cryptography

Analysis of the application-layer encryption used by com.netmarble.thered v1.4.14.

Source binaries:
- `lib/arm64-v8a/libnmsssa.so` (3.8MB) - Netmarble Security SDK, contains crypto primitives
- `lib/arm64-v8a/libUnreal.so` (150MB) - UE5 runtime, references MessageKey and PAK encryption

---

## 1. Packet Encryption: AES-128-CBC

Packet payload encryption uses AES-128-CBC, implemented by the `CAesCbc` class in `libnmsssa.so`.

### Initial Key Material

Extracted from exported symbols in `libnmsssa.so` `.data` section:

| Symbol | Virtual Address | Size | Value (hex) |
|--------|----------------|------|-------------|
| `_InitialKey` | `0x3c0410` | 16 bytes | `e313af529c6655cde45aa73a22e1dff5` |
| `_InitialIV` | `0x3c0420` | 16 bytes | `a4a0ebe78ab88b363d2f68acc1f66e52` |

### Key Exchange Flow

The initial key is used only for the first encrypted exchange. The protocol performs a key rotation:

1. **Initial connection**: Client uses `_InitialKey` / `_InitialIV` for the first encrypted packet
2. **Key change**: Server sends `PktKeyChangeNotify` (opcode 11) with a new key
3. **Client confirms**: Client sends `PktKeyChanged` (opcode 12) with the new key
4. **Server acks**: Server responds with `PktKeyChangedResult` (opcode 13)
5. **Session key**: All subsequent packets use the negotiated `MessageKey`

### Relevant Packet Opcodes

| Opcode | Name | Fields | Direction |
|--------|------|--------|-----------|
| 11 | PktKeyChangeNotify | Key, NpcId | S -> C |
| 12 | PktKeyChanged | Key, Result | C -> S |
| 13 | PktKeyChangedResult | Result, NpcId | S -> C |

### Crypto Classes (libnmsssa.so)

| Class | RTTI Location | Purpose |
|-------|---------------|---------|
| `CAesCbc` | rodata 0x317389 | AES-128-CBC encrypt/decrypt |
| `CNSCryptoCompressor` | rodata 0x31b5c5 | Combined compression + encryption |

The `CNSCryptoCompressor` wraps compression (likely zlib/LZ4) with `CAesCbc` encryption,
suggesting packets may be compressed before encryption.

---

## 2. PAK File Encryption: AES-256-ECB

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

## 3. Security Architecture

### Netmarble Security SDK (`libnmsssa.so`)

The security library provides:
- **Packet encryption** via `CAesCbc` (AES-128-CBC)
- **Crypto compression** via `CNSCryptoCompressor`
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

## 4. Extraction Tools

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
