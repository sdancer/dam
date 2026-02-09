#!/usr/bin/env python3
"""
Repack config.arm64_v8a.apk with Frida gadget injected into libUnreal.so.

Uses LIEF to add libgadget.so as a NEEDED dependency to libUnreal.so,
then rebuilds and re-signs the APK.
"""

import os
import sys
import shutil
import subprocess
import tempfile
import zipfile
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ORIG_APK = os.path.join(BASE_DIR, "config.arm64_v8a.apk")
GADGET_SO = os.path.join(BASE_DIR, "frida-gadget-android-arm64.so")
OUTPUT_APK = os.path.join(BASE_DIR, "config.arm64_v8a-frida.apk")

GADGET_NAME = "libgadget.so"
# Patch a smaller .so instead of 150MB libUnreal.so (LIEF corrupts large files)
# libCrashSight.so is loaded by libUnreal.so, so gadget loads early enough
TARGET_LIB = "libCrashSight.so"
LIB_DIR = "lib/arm64-v8a"


def patch_so(src_path, dst_path, gadget_name):
    """Use LIEF to add gadget as NEEDED dependency."""
    import lief

    binary = lief.parse(src_path)
    libs = [str(l) for l in binary.libraries]
    if gadget_name in libs:
        print(f"  [*] {gadget_name} already in NEEDED, skipping patch")
        shutil.copy2(src_path, dst_path)
        return

    binary.add_library(gadget_name)
    print(f"  [+] Added {gadget_name} to NEEDED entries")
    binary.write(dst_path)

    # Verify
    patched = lief.parse(dst_path)
    new_libs = [str(l) for l in patched.libraries]
    assert gadget_name in new_libs, f"Patch failed: {gadget_name} not in {new_libs}"
    print(f"  [+] Verified: NEEDED entries now include {gadget_name}")


def write_gadget_config(dst_dir):
    """Write Frida gadget config for listen mode."""
    config = {
        "interaction": {
            "type": "listen",
            "address": "0.0.0.0",
            "port": 27042,
            "on_port_conflict": "pick-next",
            "on_load": "wait"
        }
    }
    config_path = os.path.join(dst_dir, "libgadget.config.so")
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    print(f"  [+] Wrote gadget config: {config_path}")
    return config_path


def repack(work_dir):
    """Repack APK contents from work_dir."""
    unsigned_apk = OUTPUT_APK + ".unsigned"
    aligned_apk = OUTPUT_APK + ".aligned"

    # Build new APK with zip (no compression for .so files for page-alignment)
    print("[*] Building APK...")
    if os.path.exists(unsigned_apk):
        os.remove(unsigned_apk)

    with zipfile.ZipFile(unsigned_apk, "w") as zf:
        for root, dirs, files in os.walk(work_dir):
            for fname in sorted(files):
                fpath = os.path.join(root, fname)
                arcname = os.path.relpath(fpath, work_dir)
                if fname.endswith(".so"):
                    # Store .so files uncompressed (required for android:extractNativeLibs=false)
                    zf.write(fpath, arcname, compress_type=zipfile.ZIP_STORED)
                else:
                    zf.write(fpath, arcname, compress_type=zipfile.ZIP_DEFLATED)

    print(f"  [+] Unsigned APK: {os.path.getsize(unsigned_apk) / 1e6:.1f} MB")

    # zipalign (4-byte alignment, -p for page-align .so)
    print("[*] Zipaligning...")
    if os.path.exists(aligned_apk):
        os.remove(aligned_apk)
    subprocess.run(
        ["zipalign", "-p", "4", unsigned_apk, aligned_apk],
        check=True
    )
    os.remove(unsigned_apk)

    # Sign with apksigner using a debug keystore
    print("[*] Signing APK...")
    keystore = os.path.join(BASE_DIR, "debug.keystore")
    if not os.path.exists(keystore):
        print("  [*] Generating debug keystore...")
        subprocess.run([
            "keytool", "-genkey", "-v",
            "-keystore", keystore,
            "-alias", "debug",
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-validity", "10000",
            "-storepass", "android",
            "-keypass", "android",
            "-dname", "CN=Debug,O=Debug,C=US"
        ], check=True, capture_output=True)

    if os.path.exists(OUTPUT_APK):
        os.remove(OUTPUT_APK)

    subprocess.run([
        "apksigner", "sign",
        "--ks", keystore,
        "--ks-key-alias", "debug",
        "--ks-pass", "pass:android",
        "--key-pass", "pass:android",
        "--out", OUTPUT_APK,
        aligned_apk
    ], check=True)
    os.remove(aligned_apk)

    print(f"  [+] Signed APK: {OUTPUT_APK} ({os.path.getsize(OUTPUT_APK) / 1e6:.1f} MB)")


def main():
    print(f"=== Repacking {os.path.basename(ORIG_APK)} with Frida gadget ===\n")

    if not os.path.exists(GADGET_SO):
        print(f"[-] Frida gadget not found: {GADGET_SO}")
        sys.exit(1)

    # Create temp work directory
    work_dir = tempfile.mkdtemp(prefix="apk_repack_")
    print(f"[*] Work dir: {work_dir}")

    try:
        # Extract original APK
        print("[*] Extracting APK...")
        with zipfile.ZipFile(ORIG_APK) as zf:
            zf.extractall(work_dir)

        # Remove original signature
        meta_inf = os.path.join(work_dir, "META-INF")
        if os.path.exists(meta_inf):
            shutil.rmtree(meta_inf)
            print("  [+] Removed META-INF/")

        # Patch libUnreal.so to load frida gadget
        lib_dir = os.path.join(work_dir, LIB_DIR)
        target_so = os.path.join(lib_dir, TARGET_LIB)
        patched_so = target_so + ".patched"

        print(f"[*] Patching {TARGET_LIB}...")
        patch_so(target_so, patched_so, GADGET_NAME)
        os.replace(patched_so, target_so)

        # Copy frida gadget into lib dir
        gadget_dst = os.path.join(lib_dir, GADGET_NAME)
        shutil.copy2(GADGET_SO, gadget_dst)
        print(f"  [+] Copied gadget as {GADGET_NAME} ({os.path.getsize(gadget_dst) / 1e6:.1f} MB)")

        # Write gadget config (listen mode)
        write_gadget_config(lib_dir)

        # Repack, align, sign
        repack(work_dir)

        print(f"\n=== Done! ===")
        print(f"Install with: adb install-multiple com.netmarble.thered.apk config.en.apk config.xxhdpi.apk {os.path.basename(OUTPUT_APK)}")

    finally:
        shutil.rmtree(work_dir)


if __name__ == "__main__":
    main()
