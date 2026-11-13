# client folder/client.py
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import socket
import sys
import os

# Allow importing from the parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from mop_protocol import (
    send_mop_message, receive_mop_message,
    MSG_LIST, MSG_FETCH, MSG_PUT, MSG_UNCHANGED, MSG_FAIL,
    SOURCE_ORIGIN, STATUS_OK
)

HOST = "100.73.126.86" # Tailscale IP of Proxy (or 127.0.0.1 for local testing)
PORT = 9091 
PSK = b'0123456789abcdef0123456789abcdef'

CLIENT_ROOT = os.path.dirname(os.path.abspath(__file__))

class MOPClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("MOP Protocol Client (Persistent & Non-Persistent)")
        self.root.geometry("650x580")
        
        self.persistent_sock = None # Tracks active persistent socket

        # Message Type Selection
        tk.Label(root, text="Message Type:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.msg_type_var = tk.StringVar(value="FETCH")
        self.type_dropdown = ttk.Combobox(root, textvariable=self.msg_type_var, state="readonly", 
                                          values=["LIST", "FETCH", "PUT", "UNCHANGED", "FAIL"])
        self.type_dropdown.grid(row=0, column=1, padx=10, pady=10, sticky="w")
        self.type_dropdown.bind("<<ComboboxSelected>>", self.toggle_inputs)

        # Filename Input (For FETCH/UNCHANGED)
        tk.Label(root, text="Filename (Fetch/Check):").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.filename_entry = tk.Entry(root, width=30)
        self.filename_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")
        self.filename_entry.insert(0, "b.txt")

        # File Picker (For PUT)
        tk.Label(root, text="File to Upload (PUT):").grid(row=2, column=0, padx=10, pady=10, sticky="w")
        self.filepath_var = tk.StringVar()
        self.filepath_entry = tk.Entry(root, textvariable=self.filepath_var, width=30, state="disabled")
        self.filepath_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")
        self.browse_btn = tk.Button(root, text="Browse", command=self.browse_file, state="disabled")
        self.browse_btn.grid(row=2, column=2, padx=10, pady=10)

        # --- PERSISTENT SESSION CONTROLS ---
        self.persistent_var = tk.BooleanVar(value=False)
        self.persistent_chk = tk.Checkbutton(root, text="Enable Persistent Connection Mode", variable=self.persistent_var, command=self.toggle_persistent_mode)
        self.persistent_chk.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky="w")

        self.disconnect_btn = tk.Button(root, text="Close Persistent Socket", bg="orange", state="disabled", command=self.close_persistent_socket)
        self.disconnect_btn.grid(row=3, column=2, padx=5, pady=5)

        # Send Button
        self.send_btn = tk.Button(root, text="Send Request", bg="lightblue", command=self.send_request)
        self.send_btn.grid(row=4, column=0, columnspan=3, pady=10)

        # Console Output
        self.console = scrolledtext.ScrolledText(root, width=75, height=14, state="disabled")
        self.console.grid(row=5, column=0, columnspan=3, padx=10, pady=10)

    def log(self, text):
        self.console.config(state="normal")
        self.console.insert(tk.END, text + "\n")
        self.console.see(tk.END)
        self.console.config(state="disabled")

    def toggle_inputs(self, event=None):
        selection = self.msg_type_var.get()
        if selection == "PUT":
            self.filename_entry.config(state="disabled")
            self.browse_btn.config(state="normal")
        elif selection in ["FETCH", "UNCHANGED"]:
            self.filename_entry.config(state="normal")
            self.browse_btn.config(state="disabled")
        else:
            self.filename_entry.config(state="disabled")
            self.browse_btn.config(state="disabled")

    def browse_file(self):
        filepath = filedialog.askopenfilename(title="Select File to Upload")
        if filepath: self.filepath_var.set(filepath)

    def toggle_persistent_mode(self):
        if not self.persistent_var.get() and self.persistent_sock:
            self.close_persistent_socket()

    def close_persistent_socket(self):
        if self.persistent_sock:
            try:
                self.persistent_sock.close()
            except:
                pass
            self.persistent_sock = None
            self.log("[*] Persistent TCP connection closed manually.")
        self.disconnect_btn.config(state="disabled")

    def send_request(self):
        msg_str = self.msg_type_var.get()
        payload = b""
        
        msg_mapping = {"LIST": MSG_LIST, "FETCH": MSG_FETCH, "PUT": MSG_PUT, "UNCHANGED": MSG_UNCHANGED, "FAIL": MSG_FAIL}
        msg_type = msg_mapping[msg_str]

        target_filename = ""
        if msg_str in ["FETCH", "UNCHANGED"]:
            target_filename = self.filename_entry.get().strip()
            if not target_filename: return messagebox.showerror("Error", "Filename cannot be empty.")
            payload = target_filename.encode('utf-8')
        elif msg_str == "PUT":
            filepath = self.filepath_var.get()
            if not os.path.exists(filepath): return messagebox.showerror("Error", "Invalid file selected.")
            filename = os.path.basename(filepath).encode('utf-8')
            with open(filepath, 'rb') as f:
                file_data = f.read()
            payload = bytes([len(filename)]) + filename + file_data
        elif msg_str == "FAIL":
            payload = b"Manual Client Error Test"

        is_persistent = self.persistent_var.get()
        mode_str = "PERSISTENT" if is_persistent else "NON-PERSISTENT"
        self.log(f"--- Sending {msg_str} [{mode_str}] to Proxy ---")

        try:
            # Determine socket to use
            if is_persistent:
                if self.persistent_sock is None:
                    self.log("[*] Opening new persistent TCP connection handshake...")
                    self.persistent_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.persistent_sock.connect((HOST, PORT))
                    self.disconnect_btn.config(state="normal")
                sock = self.persistent_sock
            else:
                # Non-persistent: Fresh socket per request
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((HOST, PORT))

            # Send message and receive response
            send_mop_message(sock, msg_type, outcome=0, source=SOURCE_ORIGIN, payload=payload, psk=PSK)
            response = receive_mop_message(sock, psk=PSK)
            
            self.log(f"[Response] Type: {response['msg_type']}, Outcome: {response['outcome']}, Source: {response['source']}")
            
            resp_payload = response['payload']
            
            if msg_str == "FETCH" and response['outcome'] == STATUS_OK:
                save_path = os.path.join(CLIENT_ROOT, target_filename)
                with open(save_path, 'wb') as f:
                    f.write(resp_payload)
                self.log(f"[+] Saved fetched file '{target_filename}' into client folder!")

            if len(resp_payload) > 500:
                self.log(f"[Payload] {len(resp_payload)} bytes of binary data received.")
            else:
                try:
                    self.log(f"[Payload Text] {resp_payload.decode('utf-8')}")
                except:
                    self.log(f"[Payload Hex] {resp_payload.hex()}")

            # Close socket ONLY if non-persistent
            if not is_persistent:
                sock.close()
                self.log("[*] Non-persistent socket closed automatically.")
            else:
                self.log("[*] Persistent socket remains OPEN for next request.")

        except Exception as e:
            self.log(f"[!] Network Error: {e}")
            if is_persistent:
                self.close_persistent_socket()

if __name__ == "__main__":
    root = tk.Tk()
    app = MOPClientGUI(root)
    root.mainloop()