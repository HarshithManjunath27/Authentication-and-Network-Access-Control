"""Benchmark: a plain learning switch versus the access-controlled setup.

Run it through run_benchmark.sh (it starts the right Ryu app for each mode). One call measures one
scenario and appends rows to a CSV:

    sudo python3 benchmark.py --mode plain|controlled --clients 1|2 --run 1 --csv results/benchmark.csv

  plain       the switch runs ryu.app.simple_switch_13, a normal learning switch: no login, no rules.
  controlled  the switch runs sdn_controller.py and h2 runs auth_server.py: a client must log in first.
  clients     1 = only h4 measures; 2 = h4 and h5 measure at the same time.
  run         which repeat this is (run_benchmark.sh repeats every scenario; the chart uses the median).

Every client measures, from inside its own Mininet host:
  reach_before_login  can it ping h3 before logging in? (yes/no)
  login_ms            time from sending the login to the server's SUCCESS reply (controlled mode only)
  first_ping_ms       time until the first ping to h3 gets through. Controlled: counted from the SUCCESS
                      reply, so it includes the time the switch needs to have the rule. Plain: counted
                      from the start, so it includes the switch learning the hosts. A ping is sent every
                      10 ms, so a lost first packet costs 10 ms and not a whole ping time-out.
  avg_ping_ms         average round trip of PINGS pings
  iperf_mbps          TCP throughput to h3 over IPERF_SECONDS seconds (with 2 clients both run together)

The script has two roles: the orchestrator (default) builds the network and starts one worker inside
each client host; a worker (--worker) does the measuring and prints one line of JSON.
"""
import argparse
import csv
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
AUTH_SERVER = ('10.0.0.2', 9999)
TARGET = '10.0.0.3'
CLIENTS = [('h4', 'alice', 'password123'), ('h5', 'bob', 'securepass')]   # demo accounts from users.json
PINGS = 10
IPERF_SECONDS = 5
IPERF_DELAY = 10         # all clients start iperf at the same moment, this many seconds after launch
HEARTBEAT_EVERY = 3      # seconds between heartbeats, so a logged-in client is never timed out
CSV_COLUMNS = ['mode', 'clients', 'run', 'client', 'reach_before_login', 'login_ms', 'first_ping_ms',
               'avg_ping_ms', 'iperf_mbps']


# ---------------------------------------------------------------- parsing helpers (tested locally)
def parse_ping_avg(text):
    """Average round trip in ms from ping's 'rtt min/avg/max/mdev = a/b/c/d ms' line, or None."""
    m = re.search(r'= [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms', text)
    return float(m.group(1)) if m else None


def parse_iperf_mbps(text):
    """Throughput in Mbit/s from 'iperf -y c' output (CSV; the last field of the last line is bits/s)."""
    lines = [l for l in text.strip().splitlines() if l.count(',') >= 8]
    return int(lines[-1].split(',')[-1]) / 1e6 if lines else None


def first_reply_ms(ping_output, start):
    """Milliseconds from `start` (an epoch time) to the first reply in `ping -D` output, whose reply lines
    look like '[1699999999.123456] 64 bytes from 10.0.0.3: icmp_seq=1 ...'. None if nothing was answered."""
    for line in ping_output.splitlines():
        m = re.match(r'\[(\d+\.\d+)\] \d+ bytes from', line)
        if m:
            return (float(m.group(1)) - start) * 1000
    return None


# ---------------------------------------------------------------- worker: runs inside a client host
def ping_once():
    return subprocess.run(['ping', '-c', '1', '-W', '1', TARGET], capture_output=True).returncode == 0


def wait_first_ping():
    """Milliseconds until the first ping to h3 gets through. Sends one ping every 10 ms for 1.5 s and reads
    the time of the first reply from ping's own timestamps (-D), so the answer is accurate to about 10 ms."""
    start = time.time()
    out = subprocess.run(['ping', '-c', '150', '-i', '0.01', '-D', '-W', '1', TARGET], capture_output=True, text=True).stdout
    return first_reply_ms(out, start)


def login(auth_server, user, password):
    """Log in the way client.py does. Returns (socket, login_ms). Raises if the login is refused."""
    start = time.time()
    s = socket.create_connection(auth_server, timeout=5)
    s.send(json.dumps({'username': user, 'password': password}).encode())
    reply = s.recv(1024).decode()
    login_ms = (time.time() - start) * 1000
    if 'SUCCESS' not in reply:
        s.close()
        raise RuntimeError('login refused: ' + reply.strip())
    return s, login_ms


def keep_alive(sock, stop):
    """Send a heartbeat every HEARTBEAT_EVERY seconds until `stop` is set."""
    while not stop.wait(HEARTBEAT_EVERY):
        try:
            sock.send(b'HEARTBEAT\n')
        except OSError:
            return


def worker(args):
    result = {'reach_before_login': None, 'login_ms': None, 'first_ping_ms': None,
              'avg_ping_ms': None, 'iperf_mbps': None, 'error': ''}
    sock, stop = None, threading.Event()
    try:
        if args.mode == 'plain':
            # No login in this mode, so the very first ping is both the "can I reach h3" check and the
            # "time to first ping" measurement (it includes the switch learning the hosts).
            result['first_ping_ms'] = wait_first_ping()
            result['reach_before_login'] = 'yes' if result['first_ping_ms'] is not None else 'no'
        else:
            result['reach_before_login'] = 'yes' if ping_once() else 'no'
            sock, result['login_ms'] = login(AUTH_SERVER, args.user, args.password)
            threading.Thread(target=keep_alive, args=(sock, stop), daemon=True).start()
            result['first_ping_ms'] = wait_first_ping()
        ping = subprocess.run(['ping', '-c', str(PINGS), '-i', '0.2', '-q', TARGET], capture_output=True, text=True)
        result['avg_ping_ms'] = parse_ping_avg(ping.stdout)
        time.sleep(max(0, args.iperf_at - time.time()))      # clients start iperf together
        iperf = subprocess.run(['iperf', '-c', TARGET, '-t', str(IPERF_SECONDS), '-y', 'c'], capture_output=True, text=True)
        result['iperf_mbps'] = parse_iperf_mbps(iperf.stdout)
    except Exception as e:
        result['error'] = str(e)
    finally:
        stop.set()
        if sock:
            try:
                sock.send(b'LOGOUT\n')
                sock.close()
            except OSError:
                pass
    print(json.dumps(result))


# ---------------------------------------------------------------- orchestrator: builds the network
def start_in_host(host, command):
    """Start a background command in a Mininet host (cd is separate so $! is the command's PID)."""
    return int(host.cmd('cd %s; %s > /dev/null 2>&1 & echo $!' % (ROOT, command)).strip().split()[-1])


def orchestrate(args):
    sys.path.insert(0, ROOT)
    from topology import create_net          # the same network the real system and the tests use
    net = create_net()
    time.sleep(3)                            # let the switch connect to Ryu
    h2, h3 = net.get('h2'), net.get('h3')
    pids = []
    rows = []
    try:
        if args.mode == 'controlled':
            pids.append((h2, start_in_host(h2, 'python3 auth_server.py')))
            time.sleep(2)
        pids.append((h3, start_in_host(h3, 'iperf -s')))
        time.sleep(1)
        iperf_at = time.time() + IPERF_DELAY
        workers = []
        for name, user, password in CLIENTS[:args.clients]:
            cmd = [sys.executable, os.path.abspath(__file__), '--worker', '--mode', args.mode,
                   '--user', user, '--password', password, '--iperf-at', str(iperf_at)]
            workers.append((name, net.get(name).popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=ROOT)))
        for name, proc in workers:
            out, err = proc.communicate(timeout=90)
            try:
                r = json.loads(out.strip().splitlines()[-1])
            except (IndexError, ValueError):
                r = {'error': 'no result from worker: ' + err.strip()[-200:]}
            if r.get('error'):
                print('!! %s: %s' % (name, r['error']))
            rows.append({'mode': args.mode, 'clients': args.clients, 'run': args.run, 'client': name,
                         'reach_before_login': r.get('reach_before_login') or '',
                         'login_ms': fmt(r.get('login_ms')), 'first_ping_ms': fmt(r.get('first_ping_ms')),
                         'avg_ping_ms': fmt(r.get('avg_ping_ms'), 3), 'iperf_mbps': fmt(r.get('iperf_mbps'), 0)})
    finally:
        for host, pid in pids:
            host.cmd('kill %d 2>/dev/null' % pid)
        net.stop()
    write_rows(args.csv, rows)
    print()
    print(''.join(c.ljust(20) for c in CSV_COLUMNS))
    for r in rows:
        print(''.join(str(r[c]).ljust(20) for c in CSV_COLUMNS))
    if any(r['iperf_mbps'] == '' or r['first_ping_ms'] == '' for r in rows):
        sys.exit(1)                          # a measurement is missing: say so loudly


def fmt(value, digits=2):
    return '' if value is None else ('%.*f' % (digits, value))


def write_rows(path, rows):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    new_file = not os.path.exists(path) or os.path.getsize(path) == 0
    with open(path, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        if new_file:
            writer.writeheader()
        writer.writerows(rows)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--mode', choices=['plain', 'controlled'], required=True)
    parser.add_argument('--clients', type=int, choices=[1, 2], default=1)
    parser.add_argument('--run', type=int, default=1, help='repeat number, recorded in the CSV')
    parser.add_argument('--csv', default=os.path.join(ROOT, 'results', 'benchmark.csv'))
    parser.add_argument('--worker', action='store_true', help='internal: measure from inside one host')
    parser.add_argument('--user')
    parser.add_argument('--password')
    parser.add_argument('--iperf-at', type=float, default=0.0, dest='iperf_at')
    arguments = parser.parse_args()
    worker(arguments) if arguments.worker else orchestrate(arguments)
