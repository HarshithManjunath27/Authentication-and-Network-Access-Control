"""Task 3 test: rules appear on login and disappear on every kind of revoke - exactly those rules, no others.

Run it with:  tests/run_in_mininet.sh tests/test_rule_lifecycle.py        (takes about 2 minutes)

How it checks "exactly those rules": before anything happens it records the switch's flow table
(`ovs-ofctl -O OpenFlow13 dump-flows s1`) as a BASELINE. After every step it dumps the table again and
requires that
  * the priority-100 (access) rules are exactly the expected pairs, as a list, so a duplicate would show, and
  * every other rule is identical to the baseline (the lockdown and default rules were not touched).
Counters and ages are ignored. It uses the real auth_server.py on h2 and the real client.py on h4/h5
(demo accounts alice and bob). To keep the run short, the auth server is started here with an absolute
session limit of ABSOLUTE_TEST seconds instead of the configured one; the mechanism is the same.

  1  login by h4 installs rules for h4 only; LOGOUT removes exactly them
  2  two users at once: one logs out, the other keeps access; the idle timeout then removes exactly one
  3  the same user logging in twice: no duplicate rules
  4  the absolute limit removes exactly one session's rules while another stays
  5  a revoke for a session that is already gone is not an error; a hostile revoke cannot touch other rules
Also checks the controller log (one line per rule with client, target and reason) and that the token
never appears in it. Prints PASS/FAIL per check; exits with status 1 if anything failed.
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

TARGET = '10.0.0.3'
ABSOLUTE_TEST = 20                       # shortened absolute limit used only in this test
CONTROLLER_LOG = os.path.join(ROOT, 'controller.log')   # written by tests/run_in_mininet.sh
failures = 0
BASE = {}                                # filled in main(): the flow table before any login
LOG_OFFSET = [0]


def check(name, passed, detail=''):
    global failures
    if not passed:
        failures += 1
    print('%s  %s %s' % ('PASS' if passed else 'FAIL', name, ('(' + detail + ')') if detail else ''))


def setting(filename, name):
    text = open(os.path.join(ROOT, filename)).read()
    return int(re.search(r'^%s\s*=\s*(\d+)' % name, text, re.M).group(1))


HEARTBEAT = setting('auth_server.py', 'HEARTBEAT_INTERVAL')
IDLE = setting('auth_server.py', 'IDLE_TIMEOUT')
HARD = setting('sdn_controller.py', 'HARD_TIMEOUT')


def read(path):
    return open(path).read() if os.path.exists(path) else ''


# ---------------------------------------------------------------- flow table helpers
def table():
    """Dump the switch and return (access_pairs, other_rules).
    access_pairs: sorted list of (src, dst) for every priority-100 rule (a list, so duplicates show).
    other_rules: set of all other rules, with counters and ages removed so they can be compared."""
    out = subprocess.run(['ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', 's1'], capture_output=True, text=True).stdout
    grants, others = [], set()
    for line in out.splitlines():
        if 'cookie=' not in line:
            continue
        rule = re.sub(r'(?:cookie|duration|n_packets|n_bytes|idle_age|hard_age)=[^,\s]+,?\s*', '', line).strip()
        if 'priority=100' in rule:
            grants.append(re.search(r'nw_src=([\d.]+),nw_dst=([\d.]+)', rule).groups())
        else:
            others.add(rule)
    return sorted(grants), others


def pairs_for(clients):
    """The access rules a set of logged-in client IPs should have: one pair per client."""
    return sorted([(c, TARGET) for c in clients] + [(TARGET, c) for c in clients])


def table_is(clients):
    grants, others = table()
    return grants == pairs_for(clients) and others == BASE['others']


def check_table(name, clients):
    grants, others = table()
    ok = grants == pairs_for(clients) and others == BASE['others']
    detail = '%d access rules' % len(grants)
    if grants != pairs_for(clients):
        detail += '; expected %s, found %s' % (pairs_for(clients), grants)
    if others != BASE['others']:
        detail += '; OTHER RULES CHANGED: missing %s, new %s' % (sorted(BASE['others'] - others), sorted(others - BASE['others']))
    check(name, ok, detail)


def wait_until(condition, timeout, step=0.3):
    start = time.time()
    while time.time() - start < timeout:
        if condition():
            return time.time() - start
        time.sleep(step)
    return None


def can_ping(src, dst):
    return '1 received' in src.cmd('ping -c 1 -W 1 %s' % dst.IP())


# ---------------------------------------------------------------- controller log helpers
def log_text():
    return read(CONTROLLER_LOG)[LOG_OFFSET[0]:]


def logged(event, client, reason):
    """Both rules (one per direction) were logged for this client, with this reason."""
    text = log_text()
    return all(re.search(r'RULE %s client=%s target=%s direction=%s reason=%s' % (
        event, re.escape(client), re.escape(TARGET), re.escape(d), reason), text)
        for d in ('client->target', 'target->client'))


# ---------------------------------------------------------------- clients
class Client:
    """One client.py process on a Mininet host. Its stdin comes from a FIFO, so the test can type
    'logout' later. type() works once: after that the FIFO's reader has gone."""
    def __init__(self, host, user, password, tmp, name):
        self.host = host
        self.out = os.path.join(tmp, name + '.out')
        self.fifo = os.path.join(tmp, name + '.fifo')
        os.mkfifo(self.fifo)
        # cd is its own statement on purpose: with 'cd && pipeline &' the shell's $! is a wrapper, not the client.
        cmd = "cd %s; ( printf '%s\\n%s\\n'; cat %s ) | python3 -u client.py > %s 2>&1 & echo $!" % (
            ROOT, user, password, self.fifo, self.out)
        self.pid = int(host.cmd(cmd).strip().split()[-1])

    def output(self):
        return read(self.out)

    def logged_in(self):
        return wait_until(lambda: 'SUCCESS' in self.output(), 6) is not None

    def type(self, text):
        try:
            fd = os.open(self.fifo, os.O_WRONLY | os.O_NONBLOCK)
        except OSError:
            return False
        os.write(fd, (text + '\n').encode())
        os.close(fd)
        return True

    def alive(self):
        return self.host.cmd('kill -0 %d 2>/dev/null && echo yes || echo no' % self.pid).strip() == 'yes'

    def freeze(self):
        self.host.cmd('kill -STOP %d' % self.pid)

    def kill(self):
        self.host.cmd('kill -CONT %d 2>/dev/null; kill %d 2>/dev/null' % (self.pid, self.pid))


def curl_post(host, path, body, header_file):
    cmd = ('curl -s -m 3 -o /dev/null -w "%%{http_code}" -X POST -H "Content-Type: application/json" '
           '-H @%s -d \'%s\' http://10.0.0.254:8080%s' % (header_file, body, path))
    return host.cmd(cmd).strip()


# ---------------------------------------------------------------- the scenarios
def scenario_1(net, tmp):
    print('\n--- 1. login installs rules for that client only; LOGOUT removes exactly them ---')
    h3, h4, h5 = net.get('h3'), net.get('h4'), net.get('h5')
    check_table('before login: only the baseline rules, no access rules', [])
    a = Client(h4, 'alice', 'password123', tmp, 's1a')
    check('alice logs in from h4', a.logged_in())
    check_table('after login: exactly h4<->h3 access rules, every other rule unchanged', ['10.0.0.4'])
    check('h4 can reach h3', can_ping(h4, h3))
    check('h5 (not logged in) still cannot reach h3', not can_ping(h5, h3))
    check('controller logged both new rules: client 10.0.0.4, target 10.0.0.3, reason LOGIN', logged('INSTALLED', '10.0.0.4', 'LOGIN'))
    a.type('logout')
    check('LOGOUT: the table returns to the baseline',
          wait_until(lambda: table_is([]), 6) is not None)
    check_table('after LOGOUT: nothing left over', [])
    check('controller logged both removals with reason LOGGED_OUT', logged('REMOVED', '10.0.0.4', 'LOGGED_OUT'))
    a.kill()


def scenario_2(net, tmp):
    print('\n--- 2. two users at once: one leaves, the other keeps access; idle timeout removes exactly one ---')
    h3, h4, h5 = net.get('h3'), net.get('h4'), net.get('h5')
    a = Client(h4, 'alice', 'password123', tmp, 's2a')
    b = Client(h5, 'bob', 'securepass', tmp, 's2b')
    check('alice (h4) and bob (h5) are both logged in', a.logged_in() and b.logged_in())
    check_table('both users: access rules for h4 and h5 only', ['10.0.0.4', '10.0.0.5'])
    check('both can reach h3', can_ping(h4, h3) and can_ping(h5, h3))
    a.type('logout')
    wait_until(lambda: table_is(['10.0.0.5']), 6)
    check_table("alice logs out: only h4's rules go, bob's stay", ['10.0.0.5'])
    check('bob keeps access, alice has lost it', can_ping(h5, h3) and not can_ping(h4, h3))

    a2 = Client(h4, 'alice', 'password123', tmp, 's2a2')
    check('alice logs in again', a2.logged_in())
    check_table('alice and bob again: four access rules', ['10.0.0.4', '10.0.0.5'])
    a2.freeze()   # alice's heartbeats stop; bob's keep going
    t_stop = time.time()
    waited = wait_until(lambda: table_is(['10.0.0.5']), IDLE + 10, step=0.2)
    elapsed = time.time() - t_stop
    low, high = IDLE - HEARTBEAT - 2, IDLE + 4
    check("idle timeout removes alice's rules after about %ds, bob's stay and every other rule is unchanged" % IDLE,
          waited is not None and low <= elapsed <= high, '%.1fs, expected %d-%ds' % (elapsed, low, high))
    check('bob still has access, alice does not', b.alive() and can_ping(h5, h3) and not can_ping(h4, h3))
    check('controller logged both removals with reason IDLE_TIMEOUT', logged('REMOVED', '10.0.0.4', 'IDLE_TIMEOUT'))
    b.type('logout')
    check('bob logs out: back to the baseline', wait_until(lambda: table_is([]), 6) is not None)
    a2.kill()


def scenario_3(net, tmp):
    print('\n--- 3. the same user logging in twice: no duplicate rules ---')
    h3, h4 = net.get('h3'), net.get('h4')
    c1 = Client(h4, 'alice', 'password123', tmp, 's3a')
    check('first login', c1.logged_in())
    c2 = Client(h4, 'alice', 'password123', tmp, 's3b')
    check('second login (same user, same host, first still connected)', c2.logged_in())
    check_table('still exactly one pair of access rules (2 rules, no duplicates)', ['10.0.0.4'])
    check('h4 has access', can_ping(h4, h3))
    c2.type('logout')
    check('one LOGOUT ends the session and removes the rules', wait_until(lambda: table_is([]), 6) is not None)
    check('the first client learns its session is gone and exits',
          wait_until(lambda: 'ended by the server' in c1.output() and not c1.alive(), HEARTBEAT + 5) is not None)
    c1.kill()


def scenario_4(net, tmp):
    print('\n--- 4. the absolute limit (%ds in this test) removes exactly one session while another stays ---' % ABSOLUTE_TEST)
    h3, h4, h5 = net.get('h3'), net.get('h4'), net.get('h5')
    a = Client(h4, 'alice', 'password123', tmp, 's4a')
    check('alice logs in', a.logged_in())
    t_a = time.time()
    time.sleep(8)
    b = Client(h5, 'bob', 'securepass', tmp, 's4b')
    check('bob logs in 8 s later', b.logged_in())
    check_table('both logged in', ['10.0.0.4', '10.0.0.5'])
    waited = wait_until(lambda: table_is(['10.0.0.5']), ABSOLUTE_TEST + 8, step=0.2)
    elapsed = time.time() - t_a
    check("alice's rules go about %ds after her login while her heartbeats are still arriving; bob's stay" % ABSOLUTE_TEST,
          waited is not None and ABSOLUTE_TEST - 2 <= elapsed <= ABSOLUTE_TEST + 4 and a.alive(),
          '%.1fs after login, client alive=%s' % (elapsed, a.alive()))
    check('bob still has access, alice does not', can_ping(net.get('h5'), h3) and not can_ping(h4, h3))
    check('controller logged both removals with reason ABSOLUTE_LIMIT', logged('REMOVED', '10.0.0.4', 'ABSOLUTE_LIMIT'))
    check("bob's own absolute limit then returns the table to the baseline",
          wait_until(lambda: table_is([]), ABSOLUTE_TEST + 4) is not None)
    check('controller logged bob\'s removal with reason ABSOLUTE_LIMIT', logged('REMOVED', '10.0.0.5', 'ABSOLUTE_LIMIT'))
    a.kill()
    b.kill()


def scenario_5(net, tmp):
    print('\n--- 5. revoking something that is already gone is fine; a hostile revoke cannot touch other rules ---')
    h2 = net.get('h2')
    header = os.path.join(tmp, 'token.hdr')
    with open(header, 'w') as f:
        f.write('X-Auth-Token: %s\n' % open(os.path.join(ROOT, 'api_token')).read().strip())
    gone = '{"src_ip":"10.0.0.4","dst_ip":"%s","reason":"TEST"}' % TARGET
    check('revoke for a client with no session -> 200', curl_post(h2, '/auth/revoke', gone, header) == '200')
    check('...and again (already gone twice) -> 200', curl_post(h2, '/auth/revoke', gone, header) == '200')
    check_table('...and the table is unchanged', [])
    lockdown = '{"src_ip":"10.0.0.2","dst_ip":"10.0.0.254","reason":"TEST"}'
    check('revoke aimed at the API lockdown addresses -> 200', curl_post(h2, '/auth/revoke', lockdown, header) == '200')
    check_table('...but every lockdown and default rule is still there', [])
    check('malformed revoke (not an IP) -> 400', curl_post(h2, '/auth/revoke', '{"src_ip":"nope","dst_ip":"x"}', header) == '400')
    check_table('...and the table is unchanged', [])
    check('controller logged the harmless revoke with reason TEST', logged('REMOVED', '10.0.0.4', 'TEST'))


def main():
    tmp = tempfile.mkdtemp()
    net = create_net()
    time.sleep(3)  # let the switch connect to Ryu and receive its rules
    h2 = net.get('h2')
    LOG_OFFSET[0] = len(read(CONTROLLER_LOG))
    check('controller log is readable (run this test through tests/run_in_mininet.sh)', os.path.exists(CONTROLLER_LOG))
    BASE['grants'], BASE['others'] = table()
    assert ABSOLUTE_TEST < HARD
    server_pid = int(h2.cmd("cd %s; python3 -c 'import auth_server as A; A.ABSOLUTE_LIMIT = %d; A.main()' > %s/server.out 2>&1 & echo $!"
                            % (ROOT, ABSOLUTE_TEST, tmp)).strip().split()[-1])
    time.sleep(2)
    print('Settings: heartbeat %ds, idle timeout %ds, absolute limit %ds (test), hard timeout %ds' % (HEARTBEAT, IDLE, ABSOLUTE_TEST, HARD))
    print('Baseline flow table: %d rules, none at priority 100' % len(BASE['others']))
    check('baseline has no access rules', BASE['grants'] == [])
    try:
        scenario_1(net, tmp)
        scenario_2(net, tmp)
        scenario_3(net, tmp)
        scenario_4(net, tmp)
        scenario_5(net, tmp)
        print('\n--- controller log ---')
        text = log_text()
        token = open(os.path.join(ROOT, 'api_token')).read().strip()
        check('the API token never appears in the controller log', token not in text)
        check('no Python errors in the controller log', 'Traceback' not in text)
    finally:
        h2.cmd('kill %d 2>/dev/null' % server_pid)
        subprocess.run(['pkill', '-f', tmp], capture_output=True)   # any client left waiting on a FIFO
        net.stop()
        shutil.rmtree(tmp, ignore_errors=True)
    print('\nRESULT: %s' % ('PASS' if failures == 0 else 'FAIL (%d check(s) failed)' % failures))
    sys.exit(1 if failures else 0)


if __name__ == '__main__':
    main()
