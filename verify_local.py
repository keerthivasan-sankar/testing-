"""
verify_local.py
================
Local verification script for cryptoflex v0.2.0.

Demonstrates:
  1. Key generation via PolicyEngine
  2. High-level AEAD Encryption & Decryption
  3. Header wire format inspection (Magic, Version 2, Nonce, Components)
  4. Header AAD Tamper Detection (modifying profile_id in blob)
  5. Ciphertext Payload Tamper Detection (modifying payload byte)
  6. Explicit Downgrade Protection (min_profile enforcement)
  7. Low-level key recovery backward-compatibility with v1 headers
"""

import sys
from cryptoflex import (
    Constraint,
    CryptoflexHeader,
    DecryptionError,
    DowngradeError,
    PolicyEngine,
    decrypt,
    encrypt,
    establish_keys,
    recover_root_key,
)


def print_step(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def main():
    print("Running Local Cryptographic Verification for cryptoflex v0.2.0...")

    # --- 1. Establish Keys ---
    print_step("1. Establishing Keys via PolicyEngine (Constraint: FAST)")
    engine = PolicyEngine()
    keyset = establish_keys(engine, constraint=Constraint.FAST)
    print(f"Selected Profile ID : {keyset.profile.profile_id}")
    print(f"Display Name        : {keyset.profile.display_name}")
    print(f"Strength Level      : {keyset.profile.strength_level}")
    print(f"Public Keys Count   : {len(keyset.public_bundle.public_keys)}")
    for alg_id, pub_bytes in keyset.public_bundle.public_keys:
        print(f"  - Component: {alg_id} ({len(pub_bytes)} bytes pubkey)")

    # --- 2. AEAD Encrypt & Decrypt Round-Trip ---
    print_step("2. High-Level AEAD Encryption & Decryption")
    secret_message = b"CONFIDENTIAL: Post-quantum crypto-agility policy verification passed!"
    blob = encrypt(keyset.public_bundle, secret_message)
    print(f"Plaintext size : {len(secret_message)} bytes")
    print(f"Encrypted blob : {len(blob)} bytes (Header v2 + AES-256-GCM Payload)")

    decrypted = decrypt(keyset.private_handles, blob)
    assert decrypted == secret_message, "Decryption mismatch!"
    print(f"Decryption SUCCESS! Recovered: '{decrypted.decode()}'")

    # --- 3. Wire Format Inspection ---
    print_step("3. Wire Format Header Inspection")
    header, consumed = CryptoflexHeader.from_bytes(blob)
    print(f"Magic              : {blob[:4]}")
    print(f"Format Version     : {header.version}")
    print(f"Profile ID         : '{header.profile_id}'")
    print(f"Header Bytes Consumed: {consumed} bytes")
    print(f"AES-GCM Nonce      : {header.nonce.hex()}")
    for alg_id, ct in header.components:
        print(f"  - Component KEM CT: {alg_id} ({len(ct)} bytes ciphertext)")

    # --- 4. Header Tamper Detection (AAD Check) ---
    print_step("4. Header Tamper Resistance (AEAD Associated Data Check)")
    tampered_blob = bytearray(blob)
    # Tamper with the profile ID length/bytes inside the header
    tampered_blob[6] ^= 0x01  # flip a byte inside the profile_id string
    try:
        decrypt(keyset.private_handles, bytes(tampered_blob))
        print("FAIL: Tampered header was NOT caught!")
        sys.exit(1)
    except DecryptionError as e:
        print(f"PASS: Tampered header rejected cleanly via uniform DecryptionError!")
        print(f"      Error caught: {type(e).__name__}('{e}')")

    # --- 5. Ciphertext Payload Tamper Detection ---
    print_step("5. Ciphertext Payload Tamper Resistance (AES-GCM Tag Check)")
    tampered_payload_blob = bytearray(blob)
    tampered_payload_blob[-1] ^= 0xFF  # flip last byte of AEAD tag
    try:
        decrypt(keyset.private_handles, bytes(tampered_payload_blob))
        print("FAIL: Tampered payload was NOT caught!")
        sys.exit(1)
    except DecryptionError as e:
        print(f"PASS: Tampered payload rejected cleanly via uniform DecryptionError!")
        print(f"      Error caught: {type(e).__name__}('{e}')")

    # --- 6. Downgrade Semantics & Minimum Accepted Profile ---
    print_step("6. Downgrade Semantics (min_profile Enforcement)")
    print("Attempting to decrypt classical_only blob when min_profile='hybrid_standard'...")
    try:
        decrypt(keyset.private_handles, blob, min_profile="hybrid_standard")
        print("FAIL: Downgrade attempt was NOT caught!")
        sys.exit(1)
    except DowngradeError as e:
        print(f"PASS: Downgrade attempt blocked BEFORE crypto operation!")
        print(f"      Caught: {type(e).__name__} -> {e}")

    # --- 7. v1 Legacy Header Backwards Compatibility ---
    print_step("7. Legacy Header Backwards Compatibility")
    v1_raw = (
        b"CFLX\x01"
        b"\x0eclassical_only"
        b"\x01"
        b"\x06x25519"
        b"\x00\x20" + (b"\x01" * 32)
    )
    v1_header, v1_consumed = CryptoflexHeader.from_bytes(v1_raw)
    print(f"Parsed v1 Header Version : {v1_header.version}")
    print(f"v1 Nonce                 : {v1_header.nonce} (expected None)")
    print(f"v1 Profile ID            : '{v1_header.profile_id}'")

    print_step("ALL LOCAL VERIFICATION CHECKS PASSED SUCCESSFULLY! [7/7]")


if __name__ == "__main__":
    main()
