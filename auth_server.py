import socket
import threading
import requests
import logging
import time
import json

# Initialize Audit Logger
logging.basicConfig(filename='auth_audit.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

RYU_GRANT = 'http://10.0.0.254:8080/auth/grant'
RYU_REVOKE = 'http://10.0.0.254:8080/auth/revoke'
TARGET_IP = '10.0.0.3'
SESSION_TIMEOUT = 60

# Load users (Assumes users.json exists in your directory)
with open('users.json', 'r') as f:
    USER_DB = json.load(f)

def session_timer(client_ip):
    logging.info(f"Session active for {client_ip}. Revoking in {SESSION_TIMEOUT}s.")
    time.sleep(SESSION_TIMEOUT)
    try:
        requests.post(RYU_REVOKE, json={'src_ip': client_ip, 'dst_ip': TARGET_IP}, timeout=5)
        logging.info(f"Session EXPIRED: Rule revoked for {client_ip}.")
    except Exception as e:
        logging.error(f"Revocation API failed for {client_ip}: {e}")

def handle_client(conn, addr):
    client_ip = addr[0]
    try:
        # Receive the single payload burst from client.py
        raw_data = conn.recv(1024).decode('utf-8').strip()
        
        # Dynamically parse based on standard client serialization formats
        if raw_data.startswith('{'):
            payload = json.loads(raw_data)
            username, password = payload.get('username', ''), payload.get('password', '')
        elif ',' in raw_data:
            username, password = raw_data.split(',', 1)
        elif ':' in raw_data:
            username, password = raw_data.split(':', 1)
        else:
            parts = raw_data.split()
            username = parts[0] if len(parts) > 0 else ""
            password = parts[1] if len(parts) > 1 else ""

        username = username.strip()
        password = password.strip()
        
        if USER_DB.get(username) == password:
            logging.info(f"AUTH SUCCESS: User '{username}' via IP {client_ip}")
            resp = requests.post(RYU_GRANT, json={'src_ip': client_ip, 'dst_ip': TARGET_IP}, timeout=5)
            
            if resp.status_code == 200:
                conn.send(f"[+] SUCCESS: Network access granted to {TARGET_IP}.\n".encode('utf-8'))
                threading.Thread(target=session_timer, args=(client_ip,), daemon=True).start()
            else:
                conn.send(b"[-] ERROR: Controller refused rule injection.\n")
        else:
            logging.warning(f"AUTH FAILED: Invalid credentials from {client_ip}")
            conn.send(b"[-] DENIED: Invalid credentials.\n")
    except Exception as e:
        logging.error(f"Socket fault with {client_ip}: {e}")
    finally:
        conn.close()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('0.0.0.0', 9999))
server.listen(10)
print("[*] Multithreaded Auth Server listening on port 9999...")

while True:
    conn, addr = server.accept()
    threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
