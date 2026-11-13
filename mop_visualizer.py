# mop_visualizer.py
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mop_protocol import HEADER_FORMAT, HEADER_SIZE, MAGIC_BYTE, unpack_status

def get_msg_type_name(msg_type: int) -> str:
    mapping = {
        0x01: "MSG_LIST",
        0x02: "MSG_FETCH",
        0x03: "MSG_OBJECT",
        0x04: "MSG_UNCHANGED",
        0x05: "MSG_FAIL"
    }
    return mapping.get(msg_type, "UNKNOWN_TYPE")

def visualize_packet():
    print("=" * 65)
    print("            MOP PROTOCOL PACKET VISUALIZER & INSPECTOR")
    print("=" * 65)
    
    # Prompt user for hex input from CLI
    hex_input = input("\n[?] Paste MOP packet in HEX format (or press Enter to exit): ").strip()
    if not hex_input:
        print("Exiting visualizer.")
        return
    
    try:
        # Convert hex string into raw binary bytes
        packet_bytes = bytes.fromhex(hex_input)
    except ValueError as e:
        print(f"[!] Error: Invalid hex string provided ({e})")
        return
    
    total_len = len(packet_bytes)
    print(f"\n[+] Total Transmitted Packet Size: {total_len} bytes")
    
    if total_len < HEADER_SIZE:
        print(f"[!] Error: Packet is too short ({total_len} bytes). MOP header requires at least {HEADER_SIZE} bytes.")
        return

    # --- SEGMENT 1: PARSE THE 10-BYTE HEADER ---
    header_data = packet_bytes[:HEADER_SIZE]
    magic, msg_type, status_val, payload_len, flags = struct.unpack(HEADER_FORMAT, header_data)
    outcome, source = unpack_status(status_val)
    
    print("\n" + "-" * 65)
    print(" SEGMENT 1: THE 10-BYTE MOP HEADER")
    print("-" * 65)
    print(f"  Raw Header Hex:       {header_data.hex()}")
    print(f"  [1B] Magic Byte:      0x{magic:02X} ('M' -> Valid? {'YES' if magic == MAGIC_BYTE else 'NO - INVALID MAGIC'})")
    print(f"  [1B] Message Type:    0x{msg_type:02X} ({get_msg_type_name(msg_type)})")
    print(f"  [2B] Status Value:    0x{status_val:04X}")
    print(f"         -> Outcome Code: {outcome}")
    print(f"         -> Source ID:    {source}")
    print(f"  [4B] Payload Length:  {payload_len} bytes")
    print(f"  [2B] Flags / Reserved: 0x{flags:04X}")

    # --- SEGMENT 2: PARSE THE PAYLOAD SECTION ---
    payload_data = packet_bytes[HEADER_SIZE:]
    
    print("\n" + "-" * 65)
    print(f" SEGMENT 2: PAYLOAD SECTION ({len(payload_data)} bytes)")
    print("-" * 65)
    
    if len(payload_data) != payload_len:
        print(f"  [!] WARNING: Actual payload size ({len(payload_data)} bytes) does not match header length ({payload_len} bytes)!")
    
    if payload_len == 0:
        print("  Payload is empty (0 bytes).")
        return

    print(f"  Full Payload Hex: {payload_data.hex()}")

    # --- SEGMENT 3: SUBNET / ENCRYPTION STRUCTURE ANALYSIS ---
    # Assuming encrypted payload containing a 12-byte nonce followed by ciphertext
    if payload_len >= 12:
        nonce = payload_data[:12]
        ciphertext_tag = payload_data[12:]
        
        print(f"\n  --- AES-256-GCM Cryptographic Sub-Segments ---")
        print(f"    [12B] Nonce (Initialization Vector): {nonce.hex()}")
        print(f"    [{len(ciphertext_tag)}B] Ciphertext + Auth Tag:       {ciphertext_tag.hex()}")
        
        # Optional decryption prompt
        decrypt_prompt = input("\n[?] Attempt to decrypt this payload using a PSK? (y/n): ").strip().lower()
        if decrypt_prompt == 'y':
            key_input = input("[?] Enter 32-byte hex key (or press Enter to use default test key): ").strip()
            if not key_input:
                psk = b'0123456789abcdef0123456789abcdef' # Default test key used earlier
            else:
                try:
                    psk = bytes.fromhex(key_input)
                except ValueError:
                    print("[!] Invalid hex key format.")
                    return
            
            try:
                aesgcm = AESGCM(psk)
                decrypted = aesgcm.decrypt(nonce, ciphertext_tag, None)
                print(f"\n[+] DECRYPTION SUCCESSFUL!")
                print(f"    - Decrypted Bytes: {decrypted}")
                try:
                    print(f"    - Decrypted Text:  {decrypted.decode('utf-8')}")
                except UnicodeDecodeError:
                    print("    - (Payload contains binary/non-text data)")
            except Exception as e:
                print(f"[!] Decryption failed: {e}")
    else:
        print("  [i] Payload is under 12 bytes (Unencrypted / Raw data payload).")
        try:
            print(f"  - Plaintext: {payload_data.decode('utf-8')}")
        except UnicodeDecodeError:
            pass
            
    print("=" * 65)

if __name__ == "__main__":
    visualize_packet()