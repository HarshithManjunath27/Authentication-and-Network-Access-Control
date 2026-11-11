"""Task 2 test: heartbeats keep a session alive; when they stop, access is removed after the idle timeout.

Run it with:  tests/run_in_mininet.sh tests/test_session_idle.py        (takes about 70 seconds)

It starts the real auth_server.py on h2 and the real client.py on h4 (demo account alice), then:
  Scenario A  login -> heartbeats keep access past the idle timeout -> freeze the client so heartbeats
              stop -> access must disappear after about IDLE_TIMEOUT -> wake the client: it must learn
              that the server ended the session.
  Scenario B  login -> type 'logout' -> access must disappear at once.
It also checks that the switch rules carry the hard_timeout safety net (and no idle_timeout).
Timeouts are read from auth_server.py / sdn_controller.py, so changing the config needs no test edit.
Prints PASS/FAIL per check; exits with status 1 if anything failed.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from topology import create_net  # noqa: E402

failures = 0


def check(name, passed, detail=''):
    global failures
    if not passed:
        failures += 1
    print('%s  %s %s' % ('PASS' if passed else 'FAIL', name, ('(' + detail + ')') if detail else ''))


def setting(filename, name):
    """Read a number like IDLE_TIMEOUT = 15 from a source file."""
    text = open(os.path.join(ROOT, filename)).read()
    return int(re.search(r'^%s\s*=\s*(\d+)' % name, text, re.M).group(1))


HEARTBEAT = setting('auth_server.py', 'HEARTBEAT_INTERVAL')
IDLE = setting('auth_server.py', 'IDLE_TIMEOUT')
ABSOLUTE = setting('auth_server.py', 'ABSOLUTE_LIMIT')
HARD = setting('sdn_controller.py', 'HARD_TIMEOUT')
AUDIT_LOG = os.path.join(ROOT, 'auth_audit.log')


def flows():
    return subprocess.run(['ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', 's1'], capture_output=True, text=True).stdout


def grant_rules(ip):
    return [l for l in flows().splitlines() if 'priority=100' in l and ip in l]


def can_ping(src, dst):
    return '1 received' in src.cmd('ping -c 1 -W 1 %s' % dst.IP())


def wait_until(condition, timeout, step=0.3):
    """Poll `condition` until it is true; returns the seconds waited, or None on timeout."""
    start = time.time()
    while time.time() - start < timeout:
        if condition():
            return time.time() - start
        time.sleep(step)
    return None


def read(path):
    return open(path).read() if os.path.exists(path) else ''


def new_audit_lines(offset):
    with open(AUDIT_LOG) as f:
        f.seek(offset)
        return f.read()


def start_client(host, out_file, extra_input=''):
    """Run client.py on `host` with demo credentials on stdin. stdin stays open (sleep) so the client
    keeps running; extra_input is typed after 4 s. Returns the client's PID.
    (cd is its own statement on purpose: with 'cd && pipeline &' the shell's $! is a wrapper shell, not the client.)"""
    typed = "; sleep 4; echo %s" % extra_input if extra_input else "; sleep 301"
    cmd = "cd %s; ( printf 'alice\\npassword123\\n'%s ) | python3 -u client.py > %s 2>&1 & echo $!" % (ROOT, typed, out_file)
    return int(host.cmd(cmd).strip().split()[-1])


def alive(host, pid):
    return host.cmd('kill -0 %d 2>/dev/null && echo yes || echo no' % pid).strip() == 'yes'


def main():
    tmp = tempfile.mkdtemp()
    net = create_net()
    time.sleep(3)  # let the switch connect to Ryu
    h2, h3, h4 = net.get('h2'), net.get('h3'), net.get('h4')
    offset = os.path.getsize(AUDIT_LOG) if os.path.exists(AUDIT_LOG) else 0
    server_pid = int(h2.cmd('cd %s; python3 auth_server.py > %s/server.out 2>&1 & echo $!' % (ROOT, tmp)).strip().split()[-1])
    time.sleep(2)
    print('Settings: heartbeat %ds, idle timeout %ds, absolute limit %ds, hard timeout %ds' % (HEARTBEAT, IDLE, ABSOLUTE, HARD))
    try:
        # ---------------- Scenario A: idle expiry ----------------
        print('\n--- Scenario A: heartbeats keep the session alive, silence ends it ---')
        check('before login: h4 cannot ping h3', not can_ping(h4, h3))
        out_a = os.path.join(tmp, 'client_a.out')
        pid = start_client(h4, out_a)
        t_login = time.time()
        check('login: client prints SUCCESS and the heartbeat interval',
              wait_until(lambda: 'SUCCESS' in read(out_a), 6) is not None and 'Heartbeat every %ds' % HEARTBEAT in read(out_a))
        check('after login: h4 can ping h3', can_ping(h4, h3))
        rules = grant_rules('10.0.0.4')
        check('switch has 2 grant rules for h4, each with hard_timeout=%d and no idle_timeout' % HARD,
              len(rules) == 2 and all('hard_timeout=%d' % HARD in r and 'idle_timeout' not in r for r in rules), '%d rules' % len(rules))
        check('hard_timeout (%d) is longer than the absolute limit (%d)' % (HARD, ABSOLUTE), HARD > ABSOLUTE)

        time.sleep(max(0, t_login + IDLE + 5 - time.time()))
        check('%ds after login (idle timeout is %ds) heartbeats have kept the session alive' % (IDLE + 5, IDLE),
              alive(h4, pid) and can_ping(h4, h3))

        h4.cmd('kill -STOP %d' % pid)  # freeze the client: it stops sending heartbeats but stays "connected"
        t_stop = time.time()
        waited = wait_until(lambda: not can_ping(h4, h3), IDLE + 10, step=0.2)
        elapsed = time.time() - t_stop
        # The last heartbeat was between 0 and HEARTBEAT seconds before the freeze, and the reaper checks
        # every second, so access should vanish between IDLE-HEARTBEAT and IDLE+1 seconds after the freeze.
        low, high = IDLE - HEARTBEAT - 2, IDLE + 4
        check('after the heartbeats stop, access is removed after about the idle timeout',
              waited is not None and low <= elapsed <= high, '%.1fs, expected %d-%ds' % (elapsed, low, high))
        check('no grant rules for h4 are left on the switch', not grant_rules('10.0.0.4'))
        log = new_audit_lines(offset)
        check("audit log says: session ended, user 'alice', reason=IDLE_TIMEOUT",
              re.search(r"Session ended: user 'alice' ip 10\.0\.0\.4 reason=IDLE_TIMEOUT", log) is not None)

        h4.cmd('kill -CONT %d' % pid)  # wake the client; its next heartbeat should get EXPIRED
        check('woken client learns the session was ended by the server and exits',
              wait_until(lambda: 'ended by the server' in read(out_a) and not alive(h4, pid), HEARTBEAT + 5) is not None)

        # ---------------- Scenario B: logout ----------------
        print('\n--- Scenario B: logout removes access at once ---')
        out_b = os.path.join(tmp, 'client_b.out')
        start_client(h4, out_b, extra_input='logout')   # logs in, waits 4 s, then types logout
        check('login works again (new session replaces the ended one)',
              wait_until(lambda: 'SUCCESS' in read(out_b), 6) is not None and can_ping(h4, h3))
        check('client confirms the logout',
              wait_until(lambda: 'Logged out' in read(out_b), 10) is not None)
        check('right after logout: h4 cannot ping h3', not can_ping(h4, h3))
        check('no grant rules for h4 are left on the switch', not grant_rules('10.0.0.4'))
        check("audit log says: session ended, user 'alice', reason=LOGGED_OUT",
              re.search(r"Session ended: user 'alice' ip 10\.0\.0\.4 reason=LOGGED_OUT", new_audit_lines(offset)) is not None)
    finally:
        h2.cmd('kill %d 2>/dev/null' % server_pid)
        h4.cmd("pkill -f 'sleep 301' 2>/dev/null; pkill -f 'python3 -u client.py' 2>/dev/null")
        net.stop()
        shutil.rmtree(tmp, ignore_errors=True)
    print('\nRESULT: %s' % ('PASS' if failures == 0 else 'FAIL (%d check(s) failed)' % failures))
    sys.exit(1 if failures else 0)


if __name__ == '__main__':
    main()
