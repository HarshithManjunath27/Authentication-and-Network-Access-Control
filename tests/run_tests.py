"""The six checks for the rubric. Run with:  tests/run_in_mininet.sh tests/run_tests.py   (about 2 minutes)

It starts the real auth_server.py on h2, then uses the real client.py on h4 and h5 (demo accounts alice and
bob) and looks at the real flow table of the switch (`ovs-ofctl -O OpenFlow13 dump-flows s1`).

  1  no login means no access          h4 can not reach h3 before it logs in
  2  valid login gives access          after alice logs in, h4 reaches h3 and the switch has rules for h4
  3  logout removes access             after logout, h4 can not reach h3 and the rules are gone
  4  wrong password is refused         the client is told DENIED, and h4 still has no access
  5  3 wrong passwords block the host  h5's third wrong password creates a priority-200 drop rule with a
                                       60 s hard_timeout, h5 is cut off, h4 is not, and 60 s later the
                                       switch has lifted the block by itself
  6  ordinary host can not use the API h4 (and h3) can not even connect to the REST API on 10.0.0.254:8080
                                       (run while check 5 waits for the block to expire)

Prints PASS or FAIL for each check and exits with status 1 if any failed.
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

BLOCK_SECONDS = int(re.search(r'^BLOCK_SECONDS\s*=\s*(\d+)', open(os.path.join(ROOT, 'auth_server.py')).read(), re.M).group(1))
results = {}     # check number -> (passed, name)


def report(number, name, passed, detail=''):
    results[number] = (passed, name)
    print('%s  %d. %s %s' % ('PASS' if passed else 'FAIL', number, name, ('(' + detail + ')') if detail else ''))


def flows():
    return subprocess.run(['ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', 's1'], capture_output=True, text=True).stdout


def access_rules(ip):
    """The priority-100 access rules that mention this host."""
    return [l for l in flows().splitlines() if 'priority=100' in l and ip in l]


def block_rules(ip):
    """Drop rules at priority 200 for this host, as the controller installs them."""
    return [l for l in flows().splitlines() if 'priority=200' in l and 'nw_src=%s' % ip in l and 'actions=drop' in l]


def can_ping(host, ip, count_wait=1):
    return '1 received' in host.cmd('ping -c 1 -W %d %s' % (count_wait, ip))


def wait_until(condition, timeout, step=0.5):
    start = time.time()
    while time.time() - start < timeout:
        if condition():
            return time.time() - start
        time.sleep(step)
    return None


def read(path):
    return open(path).read() if os.path.exists(path) else ''


def try_login(host, user, password):
    """Run client.py once with these credentials on `host` and return everything it printed.
    A refused login exits at once; a blocked host's connection times out after 5 s."""
    return host.cmd("cd %s; printf '%s\\n%s\\n' | python3 client.py" % (ROOT, user, password))


class Client:
    """A client.py that stays logged in. Its stdin comes from a FIFO, so the test can type 'logout' later."""
    def __init__(self, host, user, password, tmp):
        self.out = os.path.join(tmp, 'client.out')
        self.fifo = os.path.join(tmp, 'client.fifo')
        os.mkfifo(self.fifo)
        # cd is its own statement on purpose: with 'cd && pipeline &' the shell's $! is a wrapper, not the client.
        cmd = "cd %s; ( printf '%s\\n%s\\n'; cat %s ) | python3 -u client.py > %s 2>&1 & echo $!" % (
            ROOT, user, password, self.fifo, self.out)
        self.pid = int(host.cmd(cmd).strip().split()[-1])

    def logged_in(self):
        return wait_until(lambda: 'SUCCESS' in read(self.out), 6) is not None

    def logout(self):
        fd = os.open(self.fifo, os.O_WRONLY | os.O_NONBLOCK)
        os.write(fd, b'logout\n')
        os.close(fd)


def main():
    tmp = tempfile.mkdtemp()
    net = create_net()
    time.sleep(3)  # let the switch connect to Ryu
    h2, h3, h4, h5 = net.get('h2'), net.get('h3'), net.get('h4'), net.get('h5')
    server_pid = int(h2.cmd('cd %s; python3 auth_server.py > %s/server.out 2>&1 & echo $!' % (ROOT, tmp)).strip().split()[-1])
    time.sleep(2)
    try:
        # 1. no login, no access
        report(1, 'no login means no access',
               not can_ping(h4, '10.0.0.3') and not access_rules('10.0.0.4'),
               'h4 can not ping h3 and the switch has no rule for h4')

        # 2. valid login gives access
        client = Client(h4, 'alice', 'password123', tmp)
        ok = client.logged_in() and can_ping(h4, '10.0.0.3') and len(access_rules('10.0.0.4')) == 2
        report(2, 'valid login gives access', ok, 'alice logs in from h4: h4 pings h3 and the switch holds 2 rules for h4')

        # 3. logout removes access
        client.logout()
        gone = wait_until(lambda: not access_rules('10.0.0.4'), 6)
        report(3, 'logout removes access', gone is not None and not can_ping(h4, '10.0.0.3'),
               'after logout the rules are gone and h4 can not ping h3')

        # 4. wrong password is refused
        out = try_login(h4, 'alice', 'not-the-password')
        report(4, 'wrong password is refused',
               'DENIED' in out and not can_ping(h4, '10.0.0.3') and not access_rules('10.0.0.4'),
               'the client prints: ' + (out.strip().splitlines()[-1] if out.strip() else 'nothing'))

        # 5a. three wrong passwords from h5 create the drop rule
        outs = [try_login(h5, 'bob', 'wrong%d' % i) for i in (1, 2, 3)]
        blocked_at = time.time()
        time.sleep(1)
        rules = block_rules('10.0.0.5')
        first_two = all('DENIED' in o for o in outs[:2])
        third = 'BLOCKED' in outs[2]
        rule_ok = len(rules) == 1 and 'hard_timeout=%d' % BLOCK_SECONDS in rules[0]
        cut_off = not can_ping(h5, '10.0.0.2') and not can_ping(h5, '10.0.0.3')
        retry = try_login(h5, 'bob', 'securepass')     # even the right password gets no answer now
        silent = 'SUCCESS' not in retry and 'Connection failed' in retry
        others_ok = can_ping(h4, '10.0.0.2')           # the block is for h5 only
        detail = 'replies DENIED, DENIED, BLOCKED; rule: %s; h5 cut off: %s; h5 login now unanswered: %s; h4 unaffected: %s' % (
            'priority 200, hard_timeout=%d, drop' % BLOCK_SECONDS if rule_ok else (rules[0].strip() if rules else 'MISSING'),
            cut_off, silent, others_ok)
        part_a = first_two and third and rule_ok and cut_off and silent and others_ok

        # 6. (runs while the block counts down) an ordinary host can not use the REST API
        api = []
        for host in (h4, h3):
            code = host.cmd('curl -s -m 3 -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" '
                            '-d \'{"src_ip":"%s","dst_ip":"10.0.0.3"}\' http://10.0.0.254:8080/auth/grant' % host.IP()).strip()
            api.append(code == '000')
        report(6, 'an ordinary host can not reach the REST API',
               all(api) and not access_rules('10.0.0.4') and not access_rules('10.0.0.3'),
               'h4 and h3 get no answer from 10.0.0.254:8080 and their self-grant created no rule')

        # 5b. the switch lifts the block by itself
        remaining = BLOCK_SECONDS + 10 - (time.time() - blocked_at)
        lifted = wait_until(lambda: not block_rules('10.0.0.5'), max(remaining, 1), step=1)
        back = lifted is not None and can_ping(h5, '10.0.0.2')
        report(5, '3 wrong passwords create the %d s drop rule and cut the host off' % BLOCK_SECONDS,
               part_a and back,
               detail + '; lifted by the switch after about %.0f s: %s' % (time.time() - blocked_at, back))
    finally:
        h2.cmd('kill %d 2>/dev/null' % server_pid)
        subprocess.run(['pkill', '-f', tmp], capture_output=True)   # a client left waiting on its FIFO
        net.stop()
        shutil.rmtree(tmp, ignore_errors=True)
    print('\n--- summary ---')
    for number in range(1, 7):
        passed, name = results.get(number, (False, 'did not run'))
        print('%s  %d. %s' % ('PASS' if passed else 'FAIL', number, name))
    passed_count = sum(1 for p, _ in results.values() if p)
    print('\nRESULT: %d of 6 checks passed' % passed_count)
    sys.exit(0 if passed_count == 6 else 1)


if __name__ == '__main__':
    main()
