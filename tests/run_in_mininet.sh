#!/bin/bash
# Usage: tests/run_in_mininet.sh tests/<test>.py
# Same order as start.sh: clean up, create the API token if needed, start Ryu as the normal
# user, then run the test as root (Mininet needs root). Ryu is stopped afterwards.
cd "$(dirname "$0")/.."

if [ ! -s api_token ]; then
    (umask 077; python3 -c 'import secrets; print(secrets.token_hex(32))' > api_token)
fi

sudo mn -c > /dev/null 2>&1
PYTHONPATH=. ./.venv/bin/ryu-manager sdn_controller.py > controller.log 2>&1 &
RYU_PID=$!
sleep 5

sudo python3 "$@"
STATUS=$?

kill $RYU_PID 2>/dev/null
exit $STATUS
