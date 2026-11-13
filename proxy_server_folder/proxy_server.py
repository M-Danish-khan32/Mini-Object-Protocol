# proxy server folder/proxy_server.py
import socket
import sys
import os
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from mop_protocol import (
    send_mop_message, receive_mop_message,
    MSG_FETCH, MSG_OBJECT, MSG_UNCHANGED, MSG_FAIL,
    SOURCE_PROXY, STATUS_OK, STATUS_NOT_MODIFIED, STATUS_BAD_GATEWAY
)

PROXY_HOST = "0.0.0.0"
PROXY_PORT = 9091       
ORIGIN_HOST = "100.122.19.68"
ORIGIN_PORT = 9090      
PSK = b'0123456789abcdef0123456789abcdef'

# Proxy root directory for checking and saving cached files
PROXY_ROOT = os.path.dirname(os.path.abspath(__file__))

# Cache TTL window in seconds
CACHE_TTL = 60.0

def run_proxy():
    proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_sock.bind((PROXY_HOST, PROXY_PORT))
    proxy_sock.listen(1)
    
    print(f"[*] End-to-End Persistent Proxy running in: {PROXY_ROOT}")
    print(f"[*] Listening on {PROXY_HOST}:{PROXY_PORT}...")

    while True:
        client_conn, addr = proxy_sock.accept()
        print(f"\n[+] Client connected from {addr}")
        
        # Establish a persistent upstream connection to the Origin Server for this client session
        origin_sock = None
        try:
            origin_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            origin_sock.connect((ORIGIN_HOST, ORIGIN_PORT))
            print(f"[*] Persistent upstream connection established with Origin Server.")
        except Exception as e:
            print(f"[!] Failed to connect to Origin Server at startup: {e}")
            client_conn.close()
            continue

        try:
            while True:
                request = receive_mop_message(client_conn, psk=PSK)
                msg_type = request["msg_type"]
                payload = request["payload"]
                
                if msg_type == MSG_FETCH:
                    filename = payload.decode('utf-8')
                    filepath = os.path.join(PROXY_ROOT, filename)
                    
                    # Check if file exists locally on disk
                    if os.path.isfile(filepath):
                        file_age = time.time() - os.path.getmtime(filepath)
                        
                        # 1. FRESH CACHE HIT (Within TTL window -> Zero server contact!)
                        if file_age < CACHE_TTL:
                            print(f" -> [Cache HIT] '{filename}' is fresh (age: {file_age:.1f}s). Serving locally.")
                            with open(filepath, 'rb') as f:
                                cached_data = f.read()
                            
                            send_mop_message(client_conn, MSG_OBJECT, outcome=STATUS_OK, source=SOURCE_PROXY, payload=cached_data, psk=PSK)
                            continue
                        
                        # 2. STALE CACHE (TTL Expired -> Revalidate using file timestamp over persistent origin socket)
                        else:
                            print(f" -> [Cache STALE] '{filename}' TTL expired. Revalidating with Origin...")
                            
                            local_mtime = os.path.getmtime(filepath)
                            revalidation_payload = filename.encode('utf-8') + b"|" + str(local_mtime).encode('utf-8')
                            
                            # Send revalidation request over the persistent origin socket
                            send_mop_message(origin_sock, MSG_UNCHANGED, outcome=0, source=SOURCE_PROXY, payload=revalidation_payload, psk=PSK)
                            origin_response = receive_mop_message(origin_sock, psk=PSK)
                            
                            # Case A: Server confirms file hasn't changed (304 Not Modified)
                            if origin_response and origin_response["outcome"] == STATUS_NOT_MODIFIED:
                                print(f"    [Cache REVALIDATED] Origin confirmed 304 Not Modified.")
                                os.utime(filepath, None)
                                
                                with open(filepath, 'rb') as f:
                                    cached_data = f.read()
                                
                                send_mop_message(client_conn, MSG_OBJECT, outcome=STATUS_OK, source=SOURCE_PROXY, payload=cached_data, psk=PSK)
                                continue
                            
                            # Case B: Server sends back new file because it was edited (200 OK)
                            elif origin_response and origin_response["outcome"] == STATUS_OK:
                                print(f"    [Cache UPDATED] Server sent new file version. Overwriting cache.")
                                with open(filepath, 'wb') as f:
                                    f.write(origin_response["payload"])
                                    
                                send_mop_message(
                                    client_conn,
                                    MSG_OBJECT,
                                    outcome=STATUS_OK,
                                    source=origin_response["source"],
                                    payload=origin_response["payload"],
                                    psk=PSK
                                )
                                continue
                    
                    # 3. CACHE MISS (File doesn't exist on proxy yet)
                    print(f" -> [Cache MISS] Fetching '{filename}' from Origin via persistent connection...")
                    send_mop_message(origin_sock, MSG_FETCH, outcome=0, source=SOURCE_PROXY, payload=payload, psk=PSK)
                    origin_response = receive_mop_message(origin_sock, psk=PSK)
                    
                    if origin_response and origin_response["outcome"] == STATUS_OK:
                        print(f"    [Cache STORE] Saving '{filename}' to Proxy folder.")
                        with open(filepath, 'wb') as f:
                            f.write(origin_response["payload"])
                            
                        send_mop_message(
                            client_conn, 
                            MSG_OBJECT, 
                            outcome=STATUS_OK, 
                            source=origin_response["source"], 
                            payload=origin_response["payload"], 
                            psk=PSK
                        )
                    else:
                        fail_payload = origin_response["payload"] if origin_response else b"Origin Unreachable"
                        fail_outcome = origin_response["outcome"] if origin_response else STATUS_BAD_GATEWAY
                        send_mop_message(client_conn, MSG_FAIL, outcome=fail_outcome, source=SOURCE_PROXY, payload=fail_payload, psk=PSK)
                
                else:
                    # Transparent pass-through for LIST, PUT, UNCHANGED, FAIL over the persistent origin socket
                    send_mop_message(origin_sock, msg_type, outcome=0, source=SOURCE_PROXY, payload=payload, psk=PSK)
                    origin_response = receive_mop_message(origin_sock, psk=PSK)
                    
                    if origin_response:
                        send_mop_message(client_conn, origin_response["msg_type"], outcome=origin_response["outcome"], source=origin_response["source"], payload=origin_response["payload"], psk=PSK)
                    else:
                        send_mop_message(client_conn, MSG_FAIL, outcome=STATUS_BAD_GATEWAY, source=SOURCE_PROXY, payload=b"Bad Gateway", psk=PSK)
                        
        except ConnectionError:
            print(f"[-] Client {addr} connection closed/interrupted.")
        except Exception as e:
            print(f"[-] Error in proxy session: {e}")
        finally:
            client_conn.close()
            if origin_sock:
                origin_sock.close()
            print(f"[*] Cleaned up connections for client {addr}.")

if __name__ == "__main__":
    run_proxy()