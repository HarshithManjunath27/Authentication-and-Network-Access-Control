import socket
import json
import sys

AUTH_SERVER_IP = '10.0.0.2'
AUTH_SERVER_PORT = 9999
TARGET_IP = '10.0.0.3'

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
        response = s.recv(1024).decode('utf-8')
        
        if response == "SUCCESS":
            print(f"\n[+] SUCCESS: Network access granted to {TARGET_IP}.")
        elif response == "FAIL":
            print("\n[-] DENIED: Invalid credentials.")
        else:
            print(f"\n[-] ERROR: {response}")
        s.close()
    except Exception as e:
        print(f"\n[-] Connection failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    run_client()
