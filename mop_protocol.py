# mop_protocol.py
import struct
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- MOP Protocol Constants ---
MAGIC_BYTE = 0x4D  

HEADER_FORMAT = "!B B H I H"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

# --- Message Type Definitions ---
MSG_LIST = 0x01
MSG_FETCH = 0x02
MSG_OBJECT = 0x03
MSG_UNCHANGED = 0x04
MSG_FAIL = 0x05
MSG_PUT = 0x06  # NEW: Upload an object to the server

# --- Outcome Status Codes ---
STATUS_OK = 200
STATUS_CREATED = 201
STATUS_NOT_MODIFIED = 304
STATUS_BAD_REQUEST = 400
STATUS_FORBIDDEN = 403
STATUS_NOT_FOUND = 404
STATUS_SERVER_ERROR = 500
STATUS_BAD_GATEWAY = 502

SOURCE_ORIGIN = 0x01
SOURCE_PROXY = 0x02

def pack_status(outcome: int, source: int) -> int:
    return ((outcome & 0x0FFF) << 4) | (source & 0x0F)

def unpack_status(status_val: int):
    outcome = (status_val >> 4) & 0x0FFF
    source = status_val & 0x0F
    return outcome, source

def encrypt_payload(plaintext_bytes: bytes, psk: bytes) -> bytes:
    if psk is None: return plaintext_bytes 
    if len(psk) not in (16, 24, 32): raise ValueError(f"Invalid PSK length: {len(psk)}")
    aesgcm = AESGCM(psk)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, plaintext_bytes, None)

def decrypt_payload(encrypted_data: bytes, psk: bytes) -> bytes:
    if psk is None: return encrypted_data
    if len(psk) not in (16, 24, 32): raise ValueError(f"Invalid PSK length: {len(psk)}")
    aesgcm = AESGCM(psk)
    nonce = encrypted_data[:12]
    return aesgcm.decrypt(nonce, encrypted_data[12:], None)

def recv_exact(sock, num_bytes: int) -> bytes:
    data = bytearray()
    while len(data) < num_bytes:
        packet = sock.recv(num_bytes - len(data))
        if not packet: raise ConnectionError("Connection closed prematurely.")
        data.extend(packet)
    return bytes(data)

def send_mop_message(sock, msg_type: int, outcome: int, source: int, payload: bytes = b"", flags: int = 0, psk: bytes = None):
    encrypted_payload = encrypt_payload(payload, psk)
    header = struct.pack(HEADER_FORMAT, MAGIC_BYTE, msg_type, pack_status(outcome, source), len(encrypted_payload), flags)
    sock.sendall(header + encrypted_payload)

def receive_mop_message(sock, psk: bytes = None):
    header_data = recv_exact(sock, HEADER_SIZE)
    magic, msg_type, status_val, payload_len, flags = struct.unpack(HEADER_FORMAT, header_data)
    if magic != MAGIC_BYTE: raise ValueError(f"Invalid MOP magic byte: 0x{magic:02X}.")
    outcome, source = unpack_status(status_val)
    encrypted_payload = recv_exact(sock, payload_len) if payload_len > 0 else b""
    return {
        "msg_type": msg_type, "outcome": outcome, "source": source,
        "flags": flags, "payload": decrypt_payload(encrypted_payload, psk)
    }