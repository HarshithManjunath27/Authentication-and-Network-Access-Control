import socket
import time
import subprocess
import sys

AUTH_SERVER = '10.0.0.2'
TARGET_IP = '10.0.0.3'
PORT = 9999
USERNAME = 'alice'
PASSWORD = 'password123'

print("=== SDN Performance Benchmark ===")

# Phase 1: Authentication Latency
print("[*] Testing Authentication Latency...")
t0 = time.time()
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3.0)
    s.connect((AUTH_SERVER, PORT))
    # Send credentials matching your server's new parsing logic
    s.send(f"{USERNAME},{PASSWORD}\n".encode('utf-8'))
    response = s.recv(1024).decode('utf-8')
    t1 = time.time()
    
    if "SUCCESS" in response:
        auth_latency = (t1 - t0) * 1000
        print(f"[+] Auth Latency: {auth_latency:.2f} ms")
    else:
        print(f"[-] Auth failed. Server replied: {response.strip()}")
        sys.exit(1)
    s.close()
except Exception as e:
    print(f"[-] Socket error: {e}")
    sys.exit(1)

# Phase 2: Rule Installation Delay
print("[*] Testing Rule Installation Delay...")
t2 = time.time()
while True:
    # Fire single fast pings with a 0.5s timeout
    res = subprocess.run(['ping', '-c', '1', '-W', '1', TARGET_IP], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if res.returncode == 0:
        t3 = time.time()
        rule_delay = (t3 - t2) * 1000
        print(f"[+] Rule Installation Delay: {rule_delay:.2f} ms")
        break
    
    # Absolute timeout if the switch never gets the rule
    if time.time() - t2 > 5:
        print("[-] Rule installation timed out. Switch is still blocking traffic.")
        sys.exit(1)

# Phase 3: System Throughput
print("[*] Running iperf throughput stress test (5 seconds)...")
try:
    # Runs iperf client and formats output as CSV to parse the bandwidth value
    iperf_res = subprocess.run(['iperf', '-c', TARGET_IP, '-t', '5', '-y', 'c'], capture_output=True, text=True)
    if iperf_res.returncode == 0:
        # CSV format: date,ip,port,ip,port,id,interval,transferred,bandwidth_bps
        bw_bps = int(iperf_res.stdout.strip().split(',')[-1])
        bw_mbps = bw_bps / 1_000_000
        print(f"[+] System Throughput: {bw_mbps:.2f} Mbits/sec")
    else:
        print("[-] Throughput test failed. Is 'iperf -s' running on the target?")
except FileNotFoundError:
    print("[-] iperf is not installed on this system.")

print("=== Benchmark Complete ===")
