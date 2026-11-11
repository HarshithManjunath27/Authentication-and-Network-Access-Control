#!/bin/bash

echo "[*] Cleaning up old network state and zombie processes..."
sudo mn -c > /dev/null 2>&1
sudo pkill -9 -f ryu-manager
sudo pkill -9 -f auth_server.py

# Create the API secret once (random 64 hex chars, readable only by the owner). It is gitignored.
if [ ! -s api_token ]; then
    echo "[*] Creating api_token..."
    (umask 077; python3 -c 'import secrets; print(secrets.token_hex(32))' > api_token)
fi

echo "[*] Starting Ryu Controller in the background..."
PYTHONPATH=. ./.venv/bin/ryu-manager sdn_controller.py > controller.log 2>&1 &
RYU_PID=$!

echo "[*] Waiting 5 seconds for Ryu to bind to ports 6653 and 8080..."
sleep 5

echo "[*] Launching Mininet..."
sudo python3 topology.py

echo "[*] Mininet exited. Shutting down Ryu Controller..."
sudo kill -9 $RYU_PID
