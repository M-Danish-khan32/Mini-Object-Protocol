# server folder/server.py
import socket
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from mop_protocol import (
    send_mop_message, receive_mop_message,
    MSG_LIST, MSG_FETCH, MSG_PUT, MSG_UNCHANGED, MSG_FAIL, MSG_OBJECT,
    SOURCE_ORIGIN, STATUS_OK, STATUS_CREATED, STATUS_NOT_MODIFIED, 
    STATUS_NOT_FOUND, STATUS_BAD_REQUEST
)

HOST = "0.0.0.0" 
PORT = 9090
PSK = b'0123456789abcdef0123456789abcdef'

SERVER_ROOT = os.path.dirname(os.path.abspath(__file__))

def run_server():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(1)
    
    print(f"[*] Origin Server running in: {SERVER_ROOT}")
    print(f"[*] Listening on {HOST}:{PORT}...")

    while True:
        conn, addr = server_sock.accept()
        print(f"\n[+] Connection from {addr}")
        try:
            while True:
                request = receive_mop_message(conn, psk=PSK)
                msg_type = request["msg_type"]
                payload = request["payload"]

                if msg_type == MSG_LIST:
                    files = [f for f in os.listdir(SERVER_ROOT) if os.path.isfile(os.path.join(SERVER_ROOT, f)) and f != 'server.py']
                    resp = ", ".join(files).encode('utf-8')
                    send_mop_message(conn, MSG_OBJECT, outcome=STATUS_OK, source=SOURCE_ORIGIN, payload=resp, psk=PSK)

                elif msg_type == MSG_FETCH:
                    filename = payload.decode('utf-8')
                    filepath = os.path.join(SERVER_ROOT, filename)
                    
                    if os.path.exists(filepath):
                        with open(filepath, 'rb') as f:
                            file_data = f.read()
                        print(f" -> Serving file: {filename}")
                        send_mop_message(conn, MSG_OBJECT, outcome=STATUS_OK, source=SOURCE_ORIGIN, payload=file_data, psk=PSK)
                    else:
                        print(f" -> 404 Not Found: {filename}")
                        send_mop_message(conn, MSG_FAIL, outcome=STATUS_NOT_FOUND, source=SOURCE_ORIGIN, payload=b"File Not Found", psk=PSK)

                elif msg_type == MSG_PUT:
                    name_len = payload[0]
                    filename = payload[1:1+name_len].decode('utf-8')
                    file_data = payload[1+name_len:]
                    
                    filepath = os.path.join(SERVER_ROOT, filename)
                    with open(filepath, 'wb') as f:
                        f.write(file_data)
                        
                    print(f" -> Successfully saved uploaded file: {filename}")
                    send_mop_message(conn, MSG_OBJECT, outcome=STATUS_CREATED, source=SOURCE_ORIGIN, payload=b"Upload Successful", psk=PSK)

                elif msg_type == MSG_UNCHANGED:
                    # Payload format: filename|proxy_mtime
                    parts = payload.split(b"|")
                    filename = parts[0].decode('utf-8')
                    proxy_mtime = float(parts[1].decode('utf-8')) if len(parts) > 1 else 0.0
                    
                    filepath = os.path.join(SERVER_ROOT, filename)
                    if os.path.exists(filepath):
                        server_mtime = os.path.getmtime(filepath)
                        
                        # If server file is newer than proxy file, it HAS been modified!
                        if server_mtime > proxy_mtime:
                            print(f" -> [Revalidation] '{filename}' was modified on server! Sending new payload.")
                            with open(filepath, 'rb') as f:
                                file_data = f.read()
                            # Respond with STATUS_OK (200) and the new file data
                            send_mop_message(conn, MSG_OBJECT, outcome=STATUS_OK, source=SOURCE_ORIGIN, payload=file_data, psk=PSK)
                        else:
                            print(f" -> [Revalidation] '{filename}' is unchanged. Sending 304.")
                            send_mop_message(conn, MSG_UNCHANGED, outcome=STATUS_NOT_MODIFIED, source=SOURCE_ORIGIN, payload=b"", psk=PSK)
                    else:
                        send_mop_message(conn, MSG_FAIL, outcome=STATUS_NOT_FOUND, source=SOURCE_ORIGIN, payload=b"File Not Found", psk=PSK)

                elif msg_type == MSG_FAIL:
                    print(f" -> Received manual FAIL request: {payload.decode('utf-8', errors='ignore')}")
                    send_mop_message(conn, MSG_FAIL, outcome=STATUS_BAD_REQUEST, source=SOURCE_ORIGIN, payload=b"Server acknowledged error request", psk=PSK)

                else:
                    print(f" -> Unknown message type: {msg_type}")
                    break

        except ConnectionError:
            print(f"[-] Client disconnected.")
        finally:
            conn.close()

if __name__ == "__main__":
    run_server()