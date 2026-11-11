import select
import socket
import json
import re
import sys
import time

AUTH_SERVER_IP = '10.0.0.2'
AUTH_SERVER_PORT = 9999
TARGET_IP = '10.0.0.3'
DEFAULT_HEARTBEAT_INTERVAL = 5  # only used if the server's reply does not say otherwise

def logout(s):
    """Tell the server we are leaving; it removes our network access straight away."""
    s.send(b"LOGOUT\n")
    reply = b''
    try:
        while b'BYE' not in reply:  # earlier OK replies may still be waiting in front of BYE
            chunk = s.recv(1024)
            if not chunk:
                break
            reply += chunk
    except socket.timeout:
        pass
    if b'BYE' in reply:
        print("\n[+] Logged out. Network access removed.")
    else:
        print("\n[-] Logout was not confirmed by the server.")

def keep_alive(s, interval):
    """Stay connected and send HEARTBEAT every `interval` seconds so the session is not timed out.
    Ends when the user types 'logout' (or presses Ctrl-C), or when the server ends the session.
    If stdin is closed (input came from a pipe) we simply keep sending heartbeats."""
    print(f"[*] Session active. Heartbeat every {interval}s. Type 'logout' + Enter (or press Ctrl-C) to log out.")
    stdin_open = True
    next_beat = time.time() + interval
    try:
        while True:
            watch = [s] + ([sys.stdin] if stdin_open else [])
            readable, _, _ = select.select(watch, [], [], max(0, next_beat - time.time()))

            if s in readable:  # the server said something
                data = s.recv(1024)
                if not data:
                    print("\n[-] The server closed the connection.")
                    return
                if b'EXPIRED' in data:
                    print("\n[-] Session ended by the server (timed out). Log in again to get access back.")
                    return
                # plain OK replies to our heartbeats need no action

            if sys.stdin in readable:  # the user typed something
                line = sys.stdin.readline()
                if line == '':
                    stdin_open = False
                elif line.strip().lower() == 'logout':
                    logout(s)
                    return

            if time.time() >= next_beat:
                s.send(b"HEARTBEAT\n")
                next_beat += interval
    except KeyboardInterrupt:
        logout(s)
    except OSError as e:
        print(f"\n[-] Lost the connection to the server: {e}")

def run_client():
    print("=== Network Access Authentication ===")
    username = input("Username: ").strip()
    password = input("Password: ").strip()

    req = {
        "username": username,
        "password": password,
        "target_ip": TARGET_IP
    }

    print(f"[*] Contacting Auth Server at {AUTH_SERVER_IP}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((AUTH_SERVER_IP, AUTH_SERVER_PORT))
        s.send(json.dumps(req).encode('utf-8'))
        response = s.recv(1024).decode('utf-8').strip()

        # The server replies with a whole line such as "[+] SUCCESS: Network access granted ...",
        # so look for the keyword instead of comparing the entire string.
        if "SUCCESS" in response:
            print(f"\n[+] SUCCESS: Network access granted to {TARGET_IP}.")
            match = re.search(r'HEARTBEAT_INTERVAL=(\d+)', response)
            interval = int(match.group(1)) if match else DEFAULT_HEARTBEAT_INTERVAL
            keep_alive(s, interval)
        elif "DENIED" in response:
            print("\n[-] DENIED: Invalid credentials.")
        else:
            print(f"\n[-] ERROR: {response}")
        s.close()
    except Exception as e:
        print(f"\n[-] Connection failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    run_client()
