# test_encryption_stages.py
import struct
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mop_protocol import (
    HEADER_FORMAT, HEADER_SIZE, MAGIC_BYTE, 
    MSG_FETCH, SOURCE_ORIGIN, pack_status
)

def demonstrate_encryption_pipeline():
    print("=" * 70)
    print("      MOP PROTOCOL: ENCRYPTION & DECRYPTION STAGE INSPECTION")
    print("=" * 70)
    
    # 1. Setup Key and Plaintext Data
    psk = b'0123456789abcdef0123456789abcdef' # 32 bytes (256 bits) for AES-256
    plaintext = b"Hello, secure MOP world! Confidential object data."
    
    print(f"\n[STEP 1] Plaintext Input:")
    print(f"  - String: {plaintext.decode('utf-8')}")
    print(f"  - Bytes:  {plaintext}")
    print(f"  - Length: {len(plaintext)} bytes")

    # 2. Nonce Generation & Encryption (AES-256-GCM)
    aesgcm = AESGCM(psk)
    nonce = os.urandom(12)  # 96-bit (12 bytes) random nonce required for GCM
    
    # Encrypts the plaintext and produces ciphertext combined with an authentication tag
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, None)
    
    # In MOP protocol, we prepend the 12-byte nonce to the ciphertext so the receiver can extract it
    encrypted_payload = nonce + ciphertext_and_tag

    print(f"\n[STEP 2] AES-256-GCM Encryption Stage:")
    print(f"  - Generated Random Nonce (12 bytes): {nonce.hex()}")
    print(f"  - Ciphertext + Auth Tag:             {ciphertext_and_tag.hex()}")
    print(f"  - Final Encrypted Payload (Nonce+CT): {encrypted_payload.hex()}")
    print(f"  - Payload Length:                    {len(encrypted_payload)} bytes")

    # 3. 10-Byte Header Packaging
    msg_type = MSG_FETCH
    outcome = 0
    source = SOURCE_ORIGIN
    status_val = pack_status(outcome, source)
    payload_len = len(encrypted_payload)
    flags = 0

    header = struct.pack(HEADER_FORMAT, MAGIC_BYTE, msg_type, status_val, payload_len, flags)
    
    print(f"\n[STEP 3] 10-Byte MOP Header Packaging Stage:")
    print(f"  - Magic Byte (1B):   0x{MAGIC_BYTE:02X} ('M')")
    print(f"  - Message Type (1B): 0x{msg_type:02X} (MSG_FETCH)")
    print(f"  - Status Value (2B): 0x{status_val:04X} (Outcome={outcome}, Source={source})")
    print(f"  - Payload Length (4B): {payload_len} bytes")
    print(f"  - Flags/Reserved (2B): 0x{flags:04X}")
    print(f"  - Packed Header Hex: {header.hex()} (Strictly 10 bytes)")

    # 4. Complete Wire Packet (Header + Encrypted Payload)
    wire_packet = header + encrypted_payload
    print(f"\n[STEP 4] Complete Wire Packet Transmitted over TCP:")
    print(f"  - Total Wire Size: {len(wire_packet)} bytes (10-byte header + {payload_len}-byte payload)")
    print(f"  - Full Hex Stream: {wire_packet.hex()}")

    print("\n" + "-" * 70)
    print("                  SIMULATING RECEIVER-SIDE DECRYPTION")
    print("-" * 70)

    # 5. Receiving & Unpacking the Header
    received_header = wire_packet[:HEADER_SIZE]
    r_magic, r_type, r_status, r_len, r_flags = struct.unpack(HEADER_FORMAT, received_header)
    
    print(f"\n[STEP 5] Parsing the 10-Byte Header at Receiver:")
    print(f"  - Unpacked Magic Byte: 0x{r_magic:02X} -> Valid Magic? {r_magic == MAGIC_BYTE}")
    print(f"  - Unpacked Msg Type:   0x{r_type:02X}")
    print(f"  - Expected Payload Len:{r_len} bytes")

    # 6. Slicing the Encrypted Payload & Extracting the Nonce
    received_encrypted_payload = wire_packet[HEADER_SIZE : HEADER_SIZE + r_len]
    
    # Extract the first 12 bytes as the nonce
    extracted_nonce = received_encrypted_payload[:12]
    # Extract the remaining bytes as the ciphertext + authentication tag
    extracted_ciphertext = received_encrypted_payload[12:]

    print(f"\n[STEP 6] Nonce Extraction Stage:")
    print(f"  - Sliced Nonce (First 12 bytes): {extracted_nonce.hex()}")
    print(f"  - Sliced Ciphertext + Tag:       {extracted_ciphertext.hex()}")

    # 7. Decryption & Integrity Verification
    decrypted_plaintext = aesgcm.decrypt(extracted_nonce, extracted_ciphertext, None)

    print(f"\n[STEP 7] AES-256-GCM Decryption & Integrity Check:")
    print(f"  - Decrypted Bytes:  {decrypted_plaintext}")
    print(f"  - Decrypted String: {decrypted_plaintext.decode('utf-8')}")
    print("\n[+] SUCCESS: Encryption and decryption pipeline verified cleanly!")
    print("=" * 70)

if __name__ == "__main__":
    demonstrate_encryption_pipeline()