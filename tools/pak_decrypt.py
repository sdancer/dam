#!/usr/bin/env python3
"""
PAK file decryption and extraction tool for VAMPIR (com.netmarble.thered).

This script:
1. Finds the AES-256 encryption key in libUnreal.so
2. Extracts and decrypts the PAK file index from the APK
3. Parses the PAK v11 directory structure
4. Lists all files and optionally extracts them

The PAK file is located at:
  APK -> assets/main.obb.png (ZIP) -> ProjectRED/Content/Paks/ProjectRED-Android_ASTC.pak

PAK details:
  - Version: 11 (UE PAK v11)
  - Compression: Oodle
  - bEncryptedIndex: 1
  - EncryptionKeyGuid: 00000000-0000-0000-0000-000000000000 (null/default)
  - Index at offset 134799861, size 123360 bytes
  - 7834 files

Usage:
    python tools/pak_decrypt.py [--list] [--extract PATTERN] [--output-dir DIR]
"""

import argparse
import io
import json
import struct
import sys
import zipfile
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError:
    print("Error: pycryptodome is required. Install with: pip install pycryptodome",
          file=sys.stderr)
    sys.exit(1)


BASE_DIR = Path(__file__).resolve().parent.parent
APK_PATH = BASE_DIR / "com.netmarble.thered.apk"
LIBUNREAL_PATH = BASE_DIR / "lib" / "arm64-v8a" / "libUnreal.so"
PAK_INNER_PATH = "ProjectRED/Content/Paks/ProjectRED-Android_ASTC.pak"
OBB_PATH = "assets/main.obb.png"

# PAK v11 footer size: EncryptionKeyGuid(16) + bEncryptedIndex(1) + Magic(4) +
#   Version(4) + IndexOffset(8) + IndexSize(8) + IndexHash(20) +
#   CompressionMethods(5*32=160) = 221 bytes
PAK_INFO_SIZE_V11 = 221
PAK_MAGIC = 0x5A6F12E1

# Inline PAK entry header: Offset(8) + CompSize(8) + UncompSize(8) + Method(4) +
#   SHA1(20) + NumBlocks(4) + Flags(1) = 53 bytes (for uncompressed entries)
INLINE_HEADER_SIZE = 53


def find_aes_key_in_binary(libunreal_path, encrypted_first_block):
    """
    Find the AES-256 PAK encryption key by brute-force testing 32-byte
    sequences from libUnreal.so sections against the encrypted PAK index.

    The decrypted index should start with an FString mount point, typically
    "../../../\\0" (length=10), so the first 4 bytes of plaintext = 0x0000000A.

    Returns the 32-byte key or None.
    """
    try:
        import lief
    except ImportError:
        print("Warning: lief not available, cannot search binary for key",
              file=sys.stderr)
        return None

    print(f"Parsing {libunreal_path} to search for AES-256 key...")
    binary = lief.parse(str(libunreal_path))
    if binary is None:
        print(f"Error: Failed to parse {libunreal_path}", file=sys.stderr)
        return None

    for section in binary.sections:
        if section.name not in ('.rodata', '.data', '.data.rel.ro'):
            continue
        content = bytes(section.content)
        section_va = section.virtual_address
        print(f"  Searching {section.name} ({len(content)} bytes, "
              f"VA 0x{section_va:x})...")

        for i in range(0, len(content) - 31, 4):
            candidate = content[i:i + 32]
            # Quick filter: skip if too many zero bytes
            if candidate.count(0) > 8:
                continue

            cipher = AES.new(candidate, AES.MODE_ECB)
            decrypted = cipher.decrypt(encrypted_first_block)

            # Check if first 4 bytes = reasonable FString length (1-200)
            strlen = struct.unpack('<i', decrypted[:4])[0]
            if not (1 <= strlen <= 200):
                continue

            # Check if remaining bytes look like ASCII path chars
            rest = decrypted[4:16]
            ascii_count = sum(1 for b in rest if 32 <= b <= 126 or b == 0)
            if ascii_count < 10:
                continue

            va = section_va + i
            mount = decrypted[4:4 + min(strlen, 12)]
            try:
                mount_str = mount.decode('ascii', errors='replace')
            except Exception:
                mount_str = '???'

            print(f"  FOUND key at {section.name} VA=0x{va:x}")
            print(f"  Decrypted mount point starts with: \"{mount_str}\"")
            return candidate

    return None


def parse_pak_footer(pak_data):
    """Parse the FPakInfo footer at the end of the PAK file."""
    info_start = len(pak_data) - PAK_INFO_SIZE_V11
    info = pak_data[info_start:]

    # Parse structure
    encryption_guid = info[0:16]
    b_encrypted_index = info[16]
    magic = struct.unpack_from('<I', info, 17)[0]
    version = struct.unpack_from('<i', info, 21)[0]
    index_offset = struct.unpack_from('<q', info, 25)[0]
    index_size = struct.unpack_from('<q', info, 33)[0]
    index_hash = info[41:61]

    # Compression methods (5 * 32-byte null-terminated strings)
    comp_methods = []
    for i in range(5):
        method_bytes = info[61 + i * 32:61 + (i + 1) * 32]
        name = method_bytes.split(b'\x00')[0].decode('ascii', errors='replace')
        if name:
            comp_methods.append(name)

    if magic != PAK_MAGIC:
        print(f"Warning: PAK magic mismatch: 0x{magic:08X} != 0x{PAK_MAGIC:08X}",
              file=sys.stderr)

    return {
        'magic': magic,
        'version': version,
        'index_offset': index_offset,
        'index_size': index_size,
        'index_hash': index_hash,
        'encrypted_index': bool(b_encrypted_index),
        'encryption_guid': encryption_guid,
        'compression_methods': comp_methods,
    }


def decrypt_index(pak_data, pak_info, aes_key):
    """Decrypt the PAK index using AES-256-ECB."""
    offset = pak_info['index_offset']
    size = pak_info['index_size']
    encrypted = pak_data[offset:offset + size]

    if size % 16 != 0:
        print(f"Warning: Index size {size} not aligned to 16 bytes", file=sys.stderr)

    cipher = AES.new(aes_key, AES.MODE_ECB)
    return cipher.decrypt(encrypted)


def parse_index(decrypted_index):
    """
    Parse the decrypted PAK v11 index.

    Returns (mount_point, num_entries, path_hash_index_info,
             full_dir_index_info, encoded_entries_data).
    """
    pos = 0

    # FString MountPoint
    mount_len = struct.unpack_from('<i', decrypted_index, pos)[0]
    pos += 4
    mount_point = decrypted_index[pos:pos + mount_len].decode(
        'utf-8', errors='replace').rstrip('\x00')
    pos += mount_len

    # int32 NumEntries
    num_entries = struct.unpack_from('<i', decrypted_index, pos)[0]
    pos += 4

    # uint64 PathHashSeed
    path_hash_seed = struct.unpack_from('<Q', decrypted_index, pos)[0]
    pos += 8

    # bHasPathHashIndex
    has_path_hash = struct.unpack_from('<i', decrypted_index, pos)[0]
    pos += 4
    phi_info = None
    if has_path_hash:
        phi_offset = struct.unpack_from('<q', decrypted_index, pos)[0]
        pos += 8
        phi_size = struct.unpack_from('<q', decrypted_index, pos)[0]
        pos += 8
        phi_hash = decrypted_index[pos:pos + 20]
        pos += 20
        phi_info = {'offset': phi_offset, 'size': phi_size, 'hash': phi_hash}

    # bHasFullDirectoryIndex
    has_full_dir = struct.unpack_from('<i', decrypted_index, pos)[0]
    pos += 4
    fdi_info = None
    if has_full_dir:
        fdi_offset = struct.unpack_from('<q', decrypted_index, pos)[0]
        pos += 8
        fdi_size = struct.unpack_from('<q', decrypted_index, pos)[0]
        pos += 8
        fdi_hash = decrypted_index[pos:pos + 20]
        pos += 20
        fdi_info = {'offset': fdi_offset, 'size': fdi_size, 'hash': fdi_hash}

    # EncodedPakEntries
    encoded_size = struct.unpack_from('<i', decrypted_index, pos)[0]
    pos += 4
    encoded_entries = decrypted_index[pos:pos + encoded_size]

    return {
        'mount_point': mount_point,
        'num_entries': num_entries,
        'path_hash_seed': path_hash_seed,
        'path_hash_index': phi_info,
        'full_directory_index': fdi_info,
        'encoded_entries': encoded_entries,
    }


def parse_full_directory_index(pak_data, fdi_info, aes_key):
    """
    Parse the full directory index from the PAK file.

    The FDI is stored separately in the PAK (also encrypted) and contains
    a map of directory -> [(filename, entry_byte_offset), ...].

    Returns dict of {full_path: entry_byte_offset}.
    """
    fdi_data = pak_data[fdi_info['offset']:fdi_info['offset'] + fdi_info['size']]

    # Decrypt if encrypted (size is 16-byte aligned)
    if fdi_info['size'] % 16 == 0:
        cipher = AES.new(aes_key, AES.MODE_ECB)
        fdi_data = cipher.decrypt(fdi_data)

    pos = 0
    num_dirs = struct.unpack_from('<i', fdi_data, pos)[0]
    pos += 4

    all_files = {}

    for _ in range(num_dirs):
        dir_len = struct.unpack_from('<i', fdi_data, pos)[0]
        pos += 4
        dir_name = fdi_data[pos:pos + dir_len].decode(
            'utf-8', errors='replace').rstrip('\x00')
        pos += dir_len

        num_files = struct.unpack_from('<i', fdi_data, pos)[0]
        pos += 4

        for _ in range(num_files):
            fn_len = struct.unpack_from('<i', fdi_data, pos)[0]
            pos += 4
            fn = fdi_data[pos:pos + fn_len].decode(
                'utf-8', errors='replace').rstrip('\x00')
            pos += fn_len
            entry_idx = struct.unpack_from('<i', fdi_data, pos)[0]
            pos += 4

            all_files[dir_name + fn] = entry_idx

    return all_files


def decode_pak_entry(encoded_data, byte_offset):
    """
    Decode a single PAK entry from the encoded entries array.

    PAK v11 encoded entry format (bitfield in first uint32):
      bit 31: bIsOffset32BitSafe
      bit 30: bIsUncompressedSize32BitSafe
      bit 29: bIsSize32BitSafe (compressed size)
      bits 28-23: CompressionMethodIndex (6 bits)
      bit 22: bEncrypted
      bits 21-6: CompressionBlockCount (16 bits)
      bits 5-0: CompressionBlockSize / 2048 (6 bits)

    Followed by variable-length offset and size fields.
    """
    pos = byte_offset
    flags = struct.unpack_from('<I', encoded_data, pos)[0]
    pos += 4

    off_32 = (flags >> 31) & 1
    uncomp_32 = (flags >> 30) & 1
    size_32 = (flags >> 29) & 1
    comp_method = (flags >> 23) & 0x3f
    encrypted = (flags >> 22) & 1
    comp_block_count = (flags >> 6) & 0xffff
    comp_block_size_idx = flags & 0x3f

    # Read offset
    if off_32:
        offset_val = struct.unpack_from('<I', encoded_data, pos)[0]
        pos += 4
    else:
        offset_val = struct.unpack_from('<q', encoded_data, pos)[0]
        pos += 8

    # Read uncompressed size
    if uncomp_32:
        uncomp_size = struct.unpack_from('<I', encoded_data, pos)[0]
        pos += 4
    else:
        uncomp_size = struct.unpack_from('<q', encoded_data, pos)[0]
        pos += 8

    # Read compressed size (only if compressed)
    if comp_method > 0:
        if size_32:
            comp_size = struct.unpack_from('<I', encoded_data, pos)[0]
            pos += 4
        else:
            comp_size = struct.unpack_from('<q', encoded_data, pos)[0]
            pos += 8
    else:
        comp_size = uncomp_size

    return {
        'flags': flags,
        'compression_method': comp_method,
        'encrypted': bool(encrypted),
        'offset': offset_val,
        'uncompressed_size': uncomp_size,
        'compressed_size': comp_size,
        'block_count': comp_block_count,
        'block_size': comp_block_size_idx * 2048 if comp_block_size_idx else 0,
        'entry_byte_size': pos - byte_offset,
    }


def extract_file_data(pak_data, entry, aes_key=None):
    """
    Extract raw file data from the PAK file.

    For uncompressed files (method=0), returns the raw data directly.
    For compressed files (method>0, e.g., Oodle), returns the compressed data.
    If the entry is encrypted, decrypts it first.
    """
    # The offset points to the inline FPakEntry header in the PAK
    # Header: Offset(8) + CompSize(8) + UncompSize(8) + Method(4) + SHA1(20) +
    #         NumBlocks(4) + Flags(1) = 53 bytes minimum
    # For compressed files with blocks, there are additional block descriptors

    offset = entry['offset']

    # Read inline header to verify and get data position
    h_offset = struct.unpack_from('<q', pak_data, offset)[0]
    h_comp_size = struct.unpack_from('<q', pak_data, offset + 8)[0]
    h_uncomp_size = struct.unpack_from('<q', pak_data, offset + 16)[0]
    h_method = struct.unpack_from('<I', pak_data, offset + 24)[0]
    h_sha1 = pak_data[offset + 28:offset + 48]
    h_num_blocks = struct.unpack_from('<I', pak_data, offset + 48)[0]

    # Calculate data start position
    header_size = 53  # base header size
    if h_num_blocks > 0:
        # Each compression block: StartOffset(8) + EndOffset(8) = 16 bytes
        header_size += h_num_blocks * 16
        # Plus compression block size field (4 bytes) after blocks
        header_size += 4

    data_start = offset + header_size
    data_size = h_comp_size

    raw_data = pak_data[data_start:data_start + data_size]

    # Handle encryption
    if entry['encrypted'] and aes_key:
        # Align to 16 bytes for AES
        aligned_size = ((len(raw_data) + 15) // 16) * 16
        if len(raw_data) < aligned_size:
            raw_data = raw_data + b'\x00' * (aligned_size - len(raw_data))
        cipher = AES.new(aes_key, AES.MODE_ECB)
        raw_data = cipher.decrypt(raw_data)
        raw_data = raw_data[:data_size]

    return raw_data, h_uncomp_size, h_method


def main():
    parser = argparse.ArgumentParser(
        description="Decrypt and extract files from VAMPIR PAK archive")
    parser.add_argument('--apk', type=Path, default=APK_PATH,
                        help=f"Path to APK file (default: {APK_PATH})")
    parser.add_argument('--libunreal', type=Path, default=LIBUNREAL_PATH,
                        help=f"Path to libUnreal.so (default: {LIBUNREAL_PATH})")
    parser.add_argument('--key', type=str, default=None,
                        help="AES-256 key as hex string (64 chars). "
                             "If not provided, searches libUnreal.so")
    parser.add_argument('--list', action='store_true',
                        help="List all files in the PAK")
    parser.add_argument('--list-csv', action='store_true',
                        help="List only CSV files")
    parser.add_argument('--extract', type=str, default=None,
                        help="Extract files matching this pattern (substring match)")
    parser.add_argument('--output-dir', type=Path,
                        default=BASE_DIR / "pak_extracted",
                        help="Output directory for extracted files")
    parser.add_argument('--save-index', action='store_true',
                        help="Save file listing to pak_file_list.json")
    parser.add_argument('--info', action='store_true',
                        help="Show PAK header info only")
    args = parser.parse_args()

    # --- Load PAK data ---
    print(f"Opening APK: {args.apk}")
    if not args.apk.exists():
        print(f"Error: APK not found at {args.apk}", file=sys.stderr)
        sys.exit(1)

    apk = zipfile.ZipFile(str(args.apk), 'r')
    print(f"Reading {OBB_PATH} from APK...")
    obb_data = apk.read(OBB_PATH)

    print(f"Opening OBB as ZIP ({len(obb_data)} bytes)...")
    obb_zip = zipfile.ZipFile(io.BytesIO(obb_data), 'r')

    print(f"Reading {PAK_INNER_PATH}...")
    pak_data = obb_zip.read(PAK_INNER_PATH)
    print(f"PAK file size: {len(pak_data)} bytes ({len(pak_data) / 1048576:.1f} MB)")

    # --- Parse PAK footer ---
    print("\n=== PAK Footer ===")
    pak_info = parse_pak_footer(pak_data)
    print(f"Magic: 0x{pak_info['magic']:08X}")
    print(f"Version: {pak_info['version']}")
    print(f"Index offset: {pak_info['index_offset']}")
    print(f"Index size: {pak_info['index_size']}")
    print(f"Index hash (SHA1): {pak_info['index_hash'].hex()}")
    print(f"Encrypted index: {pak_info['encrypted_index']}")
    guid = pak_info['encryption_guid']
    guid_parts = struct.unpack_from('<IIII', guid)
    guid_str = f"{guid_parts[0]:08x}-{guid_parts[1]:04x}-{guid_parts[1] >> 16:04x}-" \
               f"{guid_parts[2]:04x}-{guid_parts[2] >> 16:04x}{guid_parts[3]:08x}"
    print(f"Encryption key GUID: {guid.hex()} "
          f"({'null/default' if guid == b'\\x00' * 16 else guid_str})")
    print(f"Compression methods: {pak_info['compression_methods']}")

    if args.info:
        return

    # --- Find or use AES key ---
    if args.key:
        aes_key = bytes.fromhex(args.key)
        if len(aes_key) != 32:
            print(f"Error: Key must be 32 bytes (64 hex chars), got {len(aes_key)}",
                  file=sys.stderr)
            sys.exit(1)
        print(f"\nUsing provided AES-256 key: {aes_key.hex()}")
    else:
        # Extract first encrypted block for key validation
        idx_offset = pak_info['index_offset']
        first_block = pak_data[idx_offset:idx_offset + 16]

        print(f"\n=== Searching for AES-256 key in {args.libunreal} ===")
        aes_key = find_aes_key_in_binary(args.libunreal, first_block)
        if aes_key is None:
            print("Error: Could not find AES key in binary", file=sys.stderr)
            sys.exit(1)
        print(f"AES-256 key: {aes_key.hex()}")

    # --- Decrypt index ---
    print("\n=== Decrypting PAK Index ===")
    decrypted_index = decrypt_index(pak_data, pak_info, aes_key)
    print(f"Decrypted {len(decrypted_index)} bytes")

    # --- Parse index ---
    index_info = parse_index(decrypted_index)
    print(f"Mount point: \"{index_info['mount_point']}\"")
    print(f"Number of entries: {index_info['num_entries']}")
    print(f"Path hash seed: 0x{index_info['path_hash_seed']:016x}")

    if index_info['path_hash_index']:
        phi = index_info['path_hash_index']
        print(f"Path hash index: offset={phi['offset']} size={phi['size']}")
    if index_info['full_directory_index']:
        fdi = index_info['full_directory_index']
        print(f"Full directory index: offset={fdi['offset']} size={fdi['size']}")

    print(f"Encoded entries size: {len(index_info['encoded_entries'])} bytes")

    # --- Parse full directory index ---
    if not index_info['full_directory_index']:
        print("Error: No full directory index available", file=sys.stderr)
        sys.exit(1)

    print("\n=== Parsing Full Directory Index ===")
    all_files = parse_full_directory_index(
        pak_data, index_info['full_directory_index'], aes_key)
    print(f"Total files: {len(all_files)}")

    # Decode all entries
    encoded_data = index_info['encoded_entries']
    file_entries = {}
    comp_stats = {'None': 0, 'Oodle': 0, 'Other': 0}

    for path, byte_offset in all_files.items():
        try:
            entry = decode_pak_entry(encoded_data, byte_offset)
            file_entries[path] = entry
            method = entry['compression_method']
            if method == 0:
                comp_stats['None'] += 1
            elif method == 1:
                comp_stats['Oodle'] += 1
            else:
                comp_stats['Other'] += 1
        except Exception as e:
            print(f"  Warning: Failed to decode entry for {path}: {e}",
                  file=sys.stderr)

    print(f"Decoded {len(file_entries)} file entries")
    print(f"Compression stats: {comp_stats}")

    # Count file types
    ext_counts = {}
    for path in file_entries:
        ext = Path(path).suffix.lower()
        ext_counts[ext] = ext_counts.get(ext, 0) + 1

    print("\nFile types:")
    for ext, count in sorted(ext_counts.items(), key=lambda x: -x[1]):
        print(f"  {ext or '(none)':12s}: {count}")

    # --- Save file listing ---
    if args.save_index:
        listing = []
        for path in sorted(file_entries.keys()):
            entry = file_entries[path]
            listing.append({
                'path': path,
                'offset': entry['offset'],
                'uncompressed_size': entry['uncompressed_size'],
                'compressed_size': entry['compressed_size'],
                'compression': 'Oodle' if entry['compression_method'] == 1
                               else 'None' if entry['compression_method'] == 0
                               else f'Method{entry["compression_method"]}',
                'encrypted': entry['encrypted'],
            })

        output_path = BASE_DIR / "pak_file_list.json"
        with open(output_path, 'w') as f:
            json.dump(listing, f, indent=2)
        print(f"\nFile listing saved to: {output_path}")

    # --- List files ---
    if args.list or args.list_csv:
        print("\n=== File Listing ===")
        for path in sorted(file_entries.keys()):
            if args.list_csv and not path.endswith('.csv'):
                continue
            entry = file_entries[path]
            method_name = ('None' if entry['compression_method'] == 0
                           else 'Oodle' if entry['compression_method'] == 1
                           else f'M{entry["compression_method"]}')
            enc = 'E' if entry['encrypted'] else ' '
            print(f"  {entry['uncompressed_size']:>10d}  {method_name:5s} {enc} {path}")

    # --- Extract files ---
    if args.extract:
        pattern = args.extract
        matching = {p: e for p, e in file_entries.items() if pattern in p}

        if not matching:
            print(f"\nNo files matching '{pattern}'")
            return

        print(f"\n=== Extracting {len(matching)} files matching '{pattern}' ===")
        args.output_dir.mkdir(parents=True, exist_ok=True)

        extracted_count = 0
        skipped_count = 0

        for path in sorted(matching.keys()):
            entry = matching[path]
            method = entry['compression_method']

            # For now, we can only extract uncompressed files
            # Oodle decompression requires the Oodle SDK which is proprietary
            if method != 0:
                print(f"  SKIP (Oodle compressed): {path}")
                skipped_count += 1
                continue

            try:
                raw_data, h_uncomp_size, h_method = extract_file_data(
                    pak_data, entry, aes_key)
                data = raw_data[:h_uncomp_size]

                # Create output path
                out_path = args.output_dir / path
                out_path.parent.mkdir(parents=True, exist_ok=True)

                with open(out_path, 'wb') as f:
                    f.write(data)

                extracted_count += 1
                print(f"  OK ({len(data):>8d} bytes): {path}")

            except Exception as e:
                print(f"  ERROR: {path}: {e}", file=sys.stderr)
                skipped_count += 1

        print(f"\nExtracted: {extracted_count}, Skipped: {skipped_count}")
        if skipped_count > 0:
            print("Note: Oodle-compressed files cannot be decompressed without "
                  "the proprietary Oodle SDK. Use UnrealPak or quickbms with "
                  "oodle plugin for those files.")


if __name__ == '__main__':
    main()
