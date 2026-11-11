"""Step 1e: prove that ordinary hosts cannot reach or abuse the controller's REST API.

Run it with:  tests/run_in_mininet.sh tests/test_api_isolation.py
(the runner cleans Mininet, starts Ryu, then runs this file as root).

Attackers: h3 (the protected target) and h4 (an ordinary client that has not logged in).
Each attacker tries to reach the API and to grant itself access to a victim host.
Then h2 (the auth server) proves the API still works for the one host that is allowed.
Prints PASS/FAIL per check; exits with status 1 if anything failed.
"""
import os
import re
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from topology import create_net  # noqa: E402  (the same network the real system uses)

API = 'http://10.0.0.254:8080'
failures = 0


def check(name, passed, detail=''):
    """Print one PASS/FAIL line and remember failures."""
    global failures
    if not passed:
        failures += 1
    print('%s  %s %s' % ('PASS' if passed else 'FAIL', name, ('(' + detail + ')') if detail else ''))


def curl_post(host, path, body, header_file=None):
    """POST JSON from a Mininet host; returns the HTTP status code, or '000' if no reply."""
    hdr = '-H @%s ' % header_file if header_file else ''
    cmd = ('curl -s -m 3 -o /dev/null -w "%%{http_code}" -X POST -H "Content-Type: application/json" '
           '%s-d \'%s\' %s%s' % (hdr, body, API, path))
    return host.cmd(cmd).strip()


def flows():
    """Current flow table of s1 as text (ovs-ofctl is the supported way to dump flows)."""
    return subprocess.run(['ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', 's1'],
                          capture_output=True, text=True).stdout


def header_file(text):
    """Write one HTTP header line to a temp file so curl can read it with -H @file."""
    f = tempfile.NamedTemporaryFile('w', delete=False)
    f.write(text + '\n')
    f.close()
    return f.name


def attacker_tests(net, name):
    attacker = net.get(name)
    ip = attacker.IP()
    # A victim the attacker would like to reach: the target h3, or h1 if the attacker IS h3.
    victim = net.get('h1' if name == 'h3' else 'h3')
    print('\n--- attacker %s (%s), victim %s (%s) ---' % (name, ip, victim.name, victim.IP()))

    # 1. A TCP connection to the API must hang until it times out (dropped, not refused).
    t0 = time.time()
    out = attacker.cmd("timeout 3 bash -c 'echo > /dev/tcp/10.0.0.254/8080' 2>/dev/null"
                       " && echo CONNECTED || echo BLOCKED").strip()
    elapsed = time.time() - t0
    check('%s: TCP connect to 10.0.0.254:8080 times out' % name,
          out == 'BLOCKED' and elapsed >= 2.5, '%s after %.1fs' % (out, elapsed))

    # 2. Granting itself access fails (no answer at all), and the victim stays unreachable.
    body = '{"src_ip":"%s","dst_ip":"%s"}' % (ip, victim.IP())
    code = curl_post(attacker, '/auth/grant', body)
    check('%s: own grant request gets no answer' % name, code == '000', 'HTTP %s' % code)
    wrong = header_file('X-Auth-Token: guess')
    code = curl_post(attacker, '/auth/grant', body, wrong)
    os.unlink(wrong)
    check('%s: grant with a guessed token gets no answer' % name, code == '000', 'HTTP %s' % code)
    ping = attacker.cmd('ping -c 2 -W 1 %s' % victim.IP())
    loss = re.search(r'(\d+)% packet loss', ping)
    check('%s: ping to %s still fails' % (name, victim.name), bool(loss) and loss.group(1) == '100',
          '%s%% loss' % (loss.group(1) if loss else '?'))

    # 3. The switch must not have a priority-100 (grant) rule for the attacker.
    grant_rules = [l for l in flows().splitlines() if 'priority=100' in l and ip in l]
    check('%s: no priority-100 rule for %s' % (name, ip), not grant_rules, '%d found' % len(grant_rules))


def h2_tests(net):
    print('\n--- h2 (the auth server, allowed) ---')
    h2 = net.get('h2')
    token = open(os.path.join(ROOT, 'api_token')).read().strip()
    good = header_file('X-Auth-Token: %s' % token)
    # Revoking a pair that was never granted is harmless, so it is a safe request to send.
    body = '{"src_ip":"10.0.0.9","dst_ip":"10.0.0.3"}'
    code = curl_post(h2, '/auth/revoke', body)
    check('h2: request without token is rejected', code == '401', 'HTTP %s' % code)
    code = curl_post(h2, '/auth/revoke', body, good)
    check('h2: request with the right token is accepted', code == '200', 'HTTP %s' % code)
    os.unlink(good)
    # ofctl_rest used to expose unauthenticated flow-add endpoints on the same port.
    code = h2.cmd('curl -s -m 3 -o /dev/null -w "%{http_code}" ' + API + '/stats/switches').strip()
    check('h2: ofctl_rest endpoints are gone (/stats/switches)', code == '404', 'HTTP %s' % code)


def counters_tests():
    print('\n--- switch counters ---')
    drop = [l for l in flows().splitlines() if 'priority=25' in l and 'actions=drop' in l]
    packets = int(re.search(r'n_packets=(\d+)', drop[0]).group(1)) if drop else -1
    check('priority-25 drop rule counted the attackers\' packets', packets > 0, 'n_packets=%d' % packets)
    check('no priority-100 rules exist at all', 'priority=100' not in flows())


if __name__ == '__main__':
    net = create_net()
    time.sleep(3)  # let the switch connect to Ryu and receive its rules
    try:
        for attacker_name in ['h3', 'h4']:
            attacker_tests(net, attacker_name)
        h2_tests(net)
        counters_tests()
    finally:
        net.stop()
    print('\nRESULT: %s' % ('PASS' if failures == 0 else 'FAIL (%d check(s) failed)' % failures))
    sys.exit(1 if failures else 0)
