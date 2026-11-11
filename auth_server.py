import socket
import threading
import requests
import logging
import time
import json
import os

# ---------------------------------------------------------------------------
# Session settings (short demo values; use longer ones in real use)
# ---------------------------------------------------------------------------
HEARTBEAT_INTERVAL = 5   # seconds between the client's heartbeats (the client is told at login)
IDLE_TIMEOUT = 15        # no heartbeat for this long -> the session ends and access is revoked
ABSOLUTE_LIMIT = 120     # a session ends this long after login, however many heartbeats arrive
REAPER_INTERVAL = 1      # how often the reaper thread looks for expired sessions

# Initialize Audit Logger
logging.basicConfig(filename='auth_audit.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

RYU_GRANT = 'http://10.0.0.254:8080/auth/grant'
RYU_REVOKE = 'http://10.0.0.254:8080/auth/revoke'
TARGET_IP = '10.0.0.3'

# Secret shared with the controller; sent in the X-Auth-Token header on every API call.
# Read from the untracked api_token file next to this script. Never log it.
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'api_token')) as f:
    API_HEADERS = {'X-Auth-Token': f.read().strip()}

# Load users (Assumes users.json exists in your directory)
with open('users.json', 'r') as f:
    USER_DB = json.load(f)

# ---------------------------------------------------------------------------
# Session table
# One entry per logged-in user and client IP: (username, ip) -> details.
#   login_time / last_seen : time.monotonic() values (a clock that never jumps backwards)
#   state                  : 'ACTIVE' while access is granted. When the session ends it is
#                            overwritten with the reason ('LOGGED_OUT', 'TIMEOUT', ...), so the
#                            table also shows how each session ended.
# SESSIONS_LOCK is the one lock for the table. Controller calls are made while holding it, so the
# table and the switch rules always change in the same order (a revoke can never overtake a
# newer grant). The cost: if the controller hangs, other session updates wait up to 5 seconds.
# Note: the switch rules are per client IP, so two users logged in from the same IP share them.
# ---------------------------------------------------------------------------
SESSIONS = {}
SESSIONS_LOCK = threading.Lock()

def controller_call(url, client_ip):
    """Ask the controller to grant or revoke client_ip -> TARGET_IP. True if it answered 200."""
    try:
        resp = requests.post(url, json={'src_ip': client_ip, 'dst_ip': TARGET_IP}, headers=API_HEADERS, timeout=5)
        return resp.status_code == 200
    except Exception as e:
        logging.error(f"Controller call {url} failed for {client_ip}: {e}")
        return False

def open_session(username, client_ip):
    """Grant access on the switch, then record the session. Returns True on success."""
    with SESSIONS_LOCK:
        if not controller_call(RYU_GRANT, client_ip):
            return False
        now = time.monotonic()
        SESSIONS[(username, client_ip)] = {'login_time': now, 'last_seen': now, 'state': 'ACTIVE'}
    return True

def touch_session(username, client_ip):
    """Record a heartbeat. Returns False if the session is not ACTIVE (it ended, or never existed)."""
    with SESSIONS_LOCK:
        session = SESSIONS.get((username, client_ip))
        if session is None or session['state'] != 'ACTIVE':
            return False
        session['last_seen'] = time.monotonic()
        return True

def end_session_locked(username, client_ip, reason):
    """End an ACTIVE session: revoke access and record why. The caller must hold SESSIONS_LOCK.
    Returns False if the session was not active."""
    session = SESSIONS.get((username, client_ip))
    if session is None or session['state'] != 'ACTIVE':
        return False
    session['state'] = reason
    # If the revoke fails, the switch rules still disappear on their own timeout.
    revoked = controller_call(RYU_REVOKE, client_ip)
    lasted = time.monotonic() - session['login_time']
    logging.info(f"Session ended: user '{username}' ip {client_ip} reason={reason} "
                 f"after {lasted:.0f}s revoke={'ok' if revoked else 'FAILED'}")
    return True

def close_session(username, client_ip, reason):
    with SESSIONS_LOCK:
        return end_session_locked(username, client_ip, reason)

def reap_expired_sessions():
    """Background thread: every REAPER_INTERVAL seconds end sessions that are idle for too long
    (no heartbeat for IDLE_TIMEOUT) or that have lived longer than ABSOLUTE_LIMIT.
    The check and the ending happen under one lock hold, so a heartbeat that arrives just in time
    cannot be thrown away by a decision made a moment earlier."""
    while True:
        time.sleep(REAPER_INTERVAL)
        now = time.monotonic()
        with SESSIONS_LOCK:
            for (username, client_ip), session in SESSIONS.items():
                if session['state'] != 'ACTIVE':
                    continue
                if now - session['last_seen'] > IDLE_TIMEOUT:
                    end_session_locked(username, client_ip, 'IDLE_TIMEOUT')
                elif now - session['login_time'] > ABSOLUTE_LIMIT:
                    end_session_locked(username, client_ip, 'ABSOLUTE_LIMIT')

def session_loop(conn, username, client_ip):
    """After login, read one-line commands until the client logs out or disconnects.
    HEARTBEAT -> reply OK (or EXPIRED if the session has already ended, then we hang up)
    LOGOUT    -> end the session right now, reply BYE, hang up"""
    conn.settimeout(IDLE_TIMEOUT * 2)  # a client that vanishes must not hold this thread forever
    while True:
        data = conn.recv(1024)
        if not data:
            return  # client closed the connection without LOGOUT: the session simply times out later
        for line in data.decode('utf-8', errors='replace').splitlines():
            command = line.strip().upper()
            if command == 'HEARTBEAT':
                if touch_session(username, client_ip):
                    conn.send(b"OK\n")
                else:
                    conn.send(b"EXPIRED\n")
                    return
            elif command == 'LOGOUT':
                close_session(username, client_ip, 'LOGGED_OUT')
                conn.send(b"BYE\n")
                return
            elif command:
                conn.send(b"ERR unknown command\n")

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
            if open_session(username, client_ip):
                conn.send(f"[+] SUCCESS: Network access granted to {TARGET_IP}. "
                          f"HEARTBEAT_INTERVAL={HEARTBEAT_INTERVAL}\n".encode('utf-8'))
                session_loop(conn, username, client_ip)
            else:
                conn.send(b"[-] ERROR: Controller refused rule injection.\n")
        else:
            logging.warning(f"AUTH FAILED: Invalid credentials from {client_ip}")
            conn.send(b"[-] DENIED: Invalid credentials.\n")
    except socket.timeout:
        logging.info(f"Connection from {client_ip} timed out and was closed.")
    except Exception as e:
        logging.error(f"Socket fault with {client_ip}: {e}")
    finally:
        conn.close()

def serve(listener):
    """Accept connections forever, one thread per client."""
    while True:
        conn, addr = listener.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == '__main__':
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 9999))
    server.listen(10)
    print("[*] Multithreaded Auth Server listening on port 9999...")
    threading.Thread(target=reap_expired_sessions, daemon=True).start()
    serve(server)
