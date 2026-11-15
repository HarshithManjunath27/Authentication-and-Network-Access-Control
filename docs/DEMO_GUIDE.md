# Demo and Viva Guide

This guide is for the two people presenting the project. It explains every file, every feature, how to
demo each one, what the examiner is likely to ask, and how the two presenters split the explanation.

Everything here describes the code on the `bm` branch (the complete version: sessions, brute-force
lockout, tests, benchmark and README). `main` stops at commit `e5c08d6` and does not have the lockout,
`run_tests.py`, the benchmark rewrite or the README.

Contents

1. [The project in one minute](#1-the-project-in-one-minute)
2. [Architecture](#2-architecture)
3. [Key numbers to remember](#3-key-numbers-to-remember)
4. [File-by-file walkthrough](#4-file-by-file-walkthrough)
5. [Feature-by-feature demo steps](#5-feature-by-feature-demo-steps)
6. [Rubric to feature map](#6-rubric-to-feature-map)
7. [Timed demo script](#7-timed-demo-script)
8. [Presenter split: Part A and Part B](#8-presenter-split-part-a-and-part-b)
9. [Cross-knowledge: answering questions on the other half](#9-cross-knowledge-answering-questions-on-the-other-half)
10. [Known limitations (say them before the examiner does)](#10-known-limitations-say-them-before-the-examiner-does)
11. [General viva questions](#11-general-viva-questions)
12. [Pre-demo checklist and troubleshooting](#12-pre-demo-checklist-and-troubleshooting)

---

## 1. The project in one minute

**Problem.** An ordinary switch forwards traffic for anyone plugged into it. We want a network that
denies everything by default and opens a path to a protected service only for a user who has logged in,
and only while they are still using it.

**Solution.** Two programs cooperate:

* A **TCP login server** (`auth_server.py`, on host h2, port 9999) written with low-level Python
  sockets. It checks usernames and passwords, keeps a table of sessions, counts wrong passwords, and
  tells the controller what to do.
* An **SDN controller** (`sdn_controller.py`, a Ryu app speaking OpenFlow 1.3) that turns those
  decisions into switch rules: grant access on login, revoke it on logout or timeout, and block a host
  that guesses passwords.

The login server talks to the controller over a small **REST API** (`/auth/grant`, `/auth/revoke`,
`/auth/block`) that only h2 can reach and that requires a secret token.

**What the demo proves.** Before login, h4 cannot ping the target h3. After login it can. After logout,
idle timeout or the absolute session limit it cannot again. Three wrong passwords drop all traffic from
that host for 60 seconds. No ordinary host can call the controller API to grant itself access. A
benchmark compares the cost of all this against a plain learning switch.

One sentence version for the opening: *"We built a captive-portal style network: hosts must log in over a
TCP socket before the SDN controller installs flow rules that let them reach the protected server, and
those rules are removed automatically when the session ends."*

---

## 2. Architecture

### 2.1 Topology

```
                 +--------------------------------+
                 |  Ryu controller (host OS)      |
                 |  sdn_controller.py             |
                 |   - OpenFlow 1.3 application   |
                 |   - REST API  10.0.0.254:8080  |
                 +--------+------------------+----+
                  OpenFlow 1.3            LOCAL port of s1
                  (tcp 6653)              (address 10.0.0.254)
                          |                  |
                 +--------+------------------+----+
                 |        Open vSwitch  s1        |   default rule: drop everything
                 +--+-------+-------+-------+--+--+
                    |       |       |       |  |
                   h1      h2      h3      h4  h5
                  spare   auth   target  client client
```

| Host | IP | MAC | Switch port | Role |
|---|---|---|---|---|
| h1 | 10.0.0.1 | 00:00:00:00:00:01 | 1 | spare host (used as a "victim" in one API test) |
| h2 | 10.0.0.2 | 00:00:00:00:00:02 | 2 | auth server (TCP 9999) |
| h3 | 10.0.0.3 | 00:00:00:00:00:03 | 3 | protected target |
| h4 | 10.0.0.4 | 00:00:00:00:00:04 | 4 | client A (alice in tests) |
| h5 | 10.0.0.5 | 00:00:00:00:00:05 | 5 | client B (bob in tests) |
| s1 itself | 10.0.0.254 | - | LOCAL | gateway to the host OS, where the Ryu REST API listens |

### 2.2 Two planes, one network ("in-band")

* **Control channel:** Open vSwitch connects to Ryu on `127.0.0.1:6653` (OpenFlow 1.3). This is how
  rules get onto the switch.
* **Application channel:** h2 reaches the controller's REST API through the *data* network, by sending
  HTTP to 10.0.0.254, which is the switch's own LOCAL interface on the host OS. This is why the API has
  to be locked down with flow rules: it sits on the same network as the clients.

### 2.3 Flow table by priority (memorise this table)

| Priority | Match | Action | Why |
|---|---|---|---|
| 200 | IP from one blocked host | drop, `hard_timeout=60` | brute-force block |
| 100 | IP client -> target, and target -> client | ALL + LOCAL, `hard_timeout=150`, `SEND_FLOW_REM` | access earned by login |
| 30 | in_port 2, MAC h2, IP 10.0.0.2 -> 10.0.0.254 TCP 8080 | LOCAL only | the one path to the API |
| 30 | from LOCAL, 10.0.0.254 TCP 8080 -> 10.0.0.2 | out port 2 only | API replies go only to h2 |
| 25 | any IP to 10.0.0.254 | drop | nobody else reaches the API |
| 10 | ARP | ALL + LOCAL | hosts must resolve addresses |
| 10 | IP to 10.0.0.2 / IP from 10.0.0.2 | ALL + LOCAL | everyone can reach the login server |
| 0 | everything | drop | default deny |

Higher priority wins. When a packet matches several rules, the switch applies the one with the highest
priority. That is how a priority-200 drop overrides a priority-100 allow for a blocked host, and how
priority 30 lets h2 through while priority 25 drops everyone else.

### 2.4 Message flow for a login

```
 client (h4)                 auth server (h2)                     controller             switch s1
     |-- 1. JSON {user,pass} -->|                                    |                      |
     |                          |-- check users.json                 |                      |
     |                          |-- 2. POST /auth/grant + token ---->|-- 3. two FlowMods -->| priority 100
     |<-- 4. SUCCESS + HEARTBEAT_INTERVAL=5 <-- 200 OK --------------|                      |
     |-- 5. HEARTBEAT every 5 s ->|  (reply OK)                      |                      |
     |   ... h4 can now reach h3 ...                                                        |
     |-- 6. LOGOUT ------------->|-- 7. POST /auth/revoke + token -->|-- 8. DELETE_STRICT ->|
     |<-- BYE -------------------|                                    |                      |
```

### 2.5 The application protocol (over TCP 9999)

| Direction | Message | Meaning |
|---|---|---|
| client -> server | `{"username": "...", "password": "...", "target_ip": "10.0.0.3"}` | login (also accepts `u,p`, `u:p`, `u p`) |
| server -> client | `[+] SUCCESS: Network access granted to 10.0.0.3. HEARTBEAT_INTERVAL=5` | login worked, keep the socket open |
| server -> client | `[-] DENIED: Invalid credentials.` | wrong password (1st or 2nd in a row) |
| server -> client | `[-] BLOCKED: Too many wrong passwords. This host is blocked for 60 seconds.` | 3rd wrong password in a row |
| server -> client | `[-] ERROR: Controller refused rule injection.` | controller did not answer 200 |
| client -> server | `HEARTBEAT\n` | still here |
| server -> client | `OK\n` / `EXPIRED\n` | session alive / session already ended (server then hangs up) |
| client -> server | `LOGOUT\n` | end the session now |
| server -> client | `BYE\n` | logout done, access removed |
| server -> client | `ERR unknown command\n` | anything else after login |

---

## 3. Key numbers to remember

| Setting | Value | Where | Meaning |
|---|---|---|---|
| Login port | 9999 | `auth_server.py` | TCP listen port on h2 |
| `HEARTBEAT_INTERVAL` | 5 s | `auth_server.py` | told to the client in the SUCCESS reply |
| `IDLE_TIMEOUT` | 15 s | `auth_server.py` | no heartbeat this long ends the session |
| `ABSOLUTE_LIMIT` | 120 s | `auth_server.py` | session ends this long after login regardless |
| `REAPER_INTERVAL` | 1 s | `auth_server.py` | how often expired sessions are checked |
| `LOGIN_TIMEOUT` | 10 s | `auth_server.py` | wait for the login message, else close |
| `MAX_FAILED_LOGINS` | 3 | `auth_server.py` | wrong passwords in a row before blocking |
| `BLOCK_SECONDS` / `BLOCK_TIMEOUT` | 60 s | both files (keep equal) | length of the drop rule |
| `HARD_TIMEOUT` | 150 s | `sdn_controller.py` | safety net on every access rule (> 120) |
| `BLOCK_PRIORITY` | 200 | `sdn_controller.py` | above every other rule |
| REST API | 10.0.0.254:8080 | both | `/auth/grant`, `/auth/revoke`, `/auth/block` |
| OpenFlow | 127.0.0.1:6653, v1.3 | `topology.py` | switch to controller |

Benchmark medians (from `results/benchmark_table.md`):

| Setup | Clients | Reached h3 before login | Login (ms) | First ping (ms) | Avg ping (ms) | Throughput (Mbit/s) |
|---|---|---|---|---|---|---|
| Plain learning switch | 1 | 3 of 3 | - | 1.8 | 0.047 | 128858 |
| Plain learning switch | 2 | 6 of 6 | - | 2.2 | 0.042 | 124763 |
| With access control | 1 | 0 of 3 | 7.5 | 1.0 | 0.065 | 111281 |
| With access control | 2 | 0 of 6 | 7.8 | 1.3 | 0.057 | 107494 |

Headlines: access control blocks 9 of 9 pre-login attempts (plain switch: 0 of 9 blocked), login costs
about 8 ms, ping after login is essentially the same, throughput is about 14% lower (likely because the
access rules flood to ALL + LOCAL).

---

## 4. File-by-file walkthrough

Each file has: purpose, how it connects, a walk through the code, what to say, and likely questions
with answers.

### 4.1 `topology.py` (50 lines)

**Purpose.** Builds the Mininet network: one Open vSwitch `s1` speaking OpenFlow 1.3, five hosts, and a
remote controller at 127.0.0.1:6653.

**Connects to.** `start.sh` runs it. `tests/*.py` and `benchmark.py` import `create_net()` so every
test uses exactly the same network as the demo. `sdn_controller.py` relies on its fixed MACs and port
numbers (h2 on port 2).

**Code walk.**

* `create_net()`:
  * `Mininet(controller=RemoteController, switch=OVSSwitch)`: the controller is not run by Mininet, it is
    our separate Ryu process.
  * `addController('c0', ..., ip='127.0.0.1', port=6653)`: where the switch finds Ryu.
  * `addSwitch('s1', protocols='OpenFlow13')`: forces OpenFlow 1.3, matching the Ryu app's
    `OFP_VERSIONS`.
  * Hosts h1..h5 with fixed IPs `10.0.0.N/24` and fixed MACs `00:00:00:00:00:0N`. Fixed MACs let the
    controller match h2 by MAC in the API rule.
  * Links added in order h1..h5, so hN lands on switch port N. The controller hard-codes `H2_PORT = 2`.
  * `net.build()`, `c0.start()`, `s1.start([c0])`: build and connect.
  * `ip addr add 10.0.0.254/24 dev s1` and `ip link set s1 up`: give the switch's own interface on the
    host OS an address on the data network, and bring it up. This is how h2 reaches the REST API. The
    `link set up` line fixed an earlier "No route to host" bug (an address alone does not bring the
    interface up).
* `build_topology()`: calls `create_net()`, opens the Mininet CLI, stops the network on exit.

**What to say.** "A single-switch star. Fixed addresses and MACs so the controller can write precise
rules. The switch's LOCAL interface gets 10.0.0.254 so the auth server can reach the controller's REST
API over the same network: an in-band design like a real captive portal."

**Likely questions.**

* *Why a single switch?* It is enough to show every mechanism the project needs (default deny,
  per-user rules, blocking). Multi-switch would need path computation, listed as future work.
* *Why RemoteController?* Our logic lives in a Ryu app, a separate process. Mininet's default
  controller is a basic learning switch and would ignore our rules.
* *What is 10.0.0.254?* The switch bridge interface on the host machine. Packets the switch sends to
  `OFPP_LOCAL` arrive there, which is where Ryu's web server listens on port 8080.
* *Why fixed MACs?* Mininet otherwise gives random MACs; the API lockdown rule matches h2's MAC so a host
  that copies h2's IP on another port still does not get through.
* *How do you know h2 is on port 2?* Links are added in order h1..h5, and OVS numbers ports in the order
  they are added. You can confirm with `sh ovs-ofctl -O OpenFlow13 show s1`.

### 4.2 `sdn_controller.py` (211 lines)

**Purpose.** The Ryu application. Installs the default rules when the switch connects, exposes the REST
API, turns API calls into OpenFlow FlowMods, and logs every rule change.

**Connects to.** Receives OpenFlow events from s1. Receives HTTP calls from `auth_server.py` on h2.
Reads the shared secret from `api_token` (created by `start.sh`). Writes its log to `controller.log`
(redirected by `start.sh` / `run_in_mininet.sh`).

**Constants (top of file).** `H2_PORT/H2_MAC/H2_IP` identify the only allowed API caller.
`API_IP/API_PORT` = 10.0.0.254:8080. `TOKEN_FILE` = `api_token`. `HARD_TIMEOUT = 150` (longer than the
120 s absolute session limit so normal endings always happen first). `BLOCK_PRIORITY = 200`,
`BLOCK_TIMEOUT = 60`.

**Class `AuthController(app_manager.RyuApp)`.**

* `OFP_VERSIONS = [OFP_VERSION 1.3]`, `_CONTEXTS = {'wsgi': WSGIApplication}`: OpenFlow 1.3 and Ryu's
  built-in web server.
* `__init__`: reads `api_token`. If it is missing or empty it raises `RuntimeError` and refuses to start
  (fail closed: better no controller than an unprotected one). Registers the REST class with the WSGI
  server.
* `switch_features_handler` (event `EventOFPSwitchFeatures`, `CONFIG_DISPATCHER`): runs once when the
  switch connects. Saves the datapath, then installs the base table: priority 0 drop-all, priority 10
  ARP, priority 10 IP to/from h2, priority 25 drop to 10.0.0.254, and the two priority 30 API rules
  (request from h2 to LOCAL only; reply from LOCAL to port 2 only). An empty action list means drop.
* `add_flow(...)`: helper that wraps actions in an `OFPInstructionActions(APPLY_ACTIONS)` and sends an
  `OFPFlowMod` with priority, match, idle/hard timeouts and flags.
* `log_rule(...)`: one log line per rule: `RULE INSTALLED/REMOVED client=... target=... direction=...
  reason=...`. Never logs the token.
* `grant_access(src_ip, dst_ip, reason)`: installs two priority-100 rules (client->target and
  target->client), action ALL + LOCAL, `hard_timeout=HARD_TIMEOUT`, flag `OFPFF_SEND_FLOW_REM` so the
  switch reports timeouts. Installing an identical rule overwrites it, so logging in twice never makes
  duplicates.
* `revoke_access(src_ip, dst_ip, reason)`: deletes exactly those two rules using `OFPFC_DELETE_STRICT`
  with priority 100. Plain `DELETE` ignores priority and would also delete more specific rules (it could
  wipe the API lockdown); `DELETE_STRICT` only removes a rule with exactly this match and priority.
  Deleting an absent rule is not an error in OpenFlow.
* `block_host(client_ip, reason)`: one priority-200 rule matching `ipv4_src=client_ip`, empty actions
  (drop), `hard_timeout=BLOCK_TIMEOUT`. The switch removes it on its own after 60 s.
* `flow_removed_handler` (event `EventOFPFlowRemoved`): when the switch removes a priority-100 rule by
  timeout, logs `RULE REMOVED ... reason=HARD_TIMEOUT_BY_SWITCH packets=... bytes=...`. Removals we
  ordered are already logged by `revoke_access`.

**Class `AuthRestAPI(ControllerBase)`.**

* `check_caller(req)`: two checks. (1) `req.remote_addr` must be 10.0.0.2, else 403. (2) The
  `X-Auth-Token` header must match the secret, compared with `hmac.compare_digest` (constant time, so
  the response time does not leak how many characters matched), else 401.
* `read_request(req)`: parses the JSON body, validates `src_ip` and `dst_ip` with
  `ipaddress.IPv4Address`, and cleans `reason` down to letters, digits and `_` (max 32 chars) so nobody
  can inject newlines into the log. Returns `None` on bad input, which becomes HTTP 400.
* `grant_handler` / `revoke_handler`: `POST /auth/grant` and `POST /auth/revoke`. Check caller, parse,
  call the app, reply 200, 400, or 503 if the switch is not connected yet.
* `read_block_request` + `block_handler`: `POST /auth/block`. Same token check. Refuses to block h2 or
  10.0.0.254, because blocking those would break logins or the API.

**What to say.** "The controller is proactive: it installs a default-deny table as soon as the switch
connects, so no packet ever needs to go to the controller. Access is added and removed only through
three REST calls, which only the auth server can make, from the right port, MAC and IP, with a secret
token. Every rule has a timeout as a safety net, and every change is logged."

**Likely questions.**

* *Proactive or reactive?* Proactive. There is no `PacketIn` handler. Rules are pushed when the switch
  connects and when the auth server calls the API. This keeps the controller off the data path.
* *Why ALL + LOCAL on the access rules?* Simplicity: the switch floods the packet so it reaches the
  destination without a MAC table. It is a known weakness (other hosts can see the traffic, and it
  costs throughput). The fix, output to the destination port, is in future work.
* *Why both hard_timeout and the auth server's timers?* Defence in depth. If the auth server crashes,
  nobody sends a revoke; the switch still removes the rule after 150 s.
* *Why no idle_timeout on the access rule?* Idleness is judged by heartbeats at the application level,
  which is more meaningful than packet activity. A user reading a page sends no packets but is still
  logged in.
* *What is `DELETE_STRICT`?* Deletes only the flow whose match and priority are exactly as given.
  `DELETE` matches loosely and would also remove more specific flows.
* *How do you stop another host calling the API?* Three layers: priority-25 drop for any IP to
  10.0.0.254, priority-30 allow only for port 2 + h2's MAC + h2's IP + TCP 8080, and in the handler a
  source-IP check plus a constant-time token check.
* *Why constant-time compare?* A normal `==` stops at the first wrong character, so an attacker could
  guess the token one character at a time by timing responses.
* *What happens if the switch is not connected?* `self.datapath` is `None`, the methods return False,
  and the API replies 503.
* *Why did you remove `ofctl_rest`?* It exposes unauthenticated endpoints to add any flow on the same
  port, a full bypass. `test_api_isolation.py` checks `/stats/switches` now returns 404.
* *What does `SEND_FLOW_REM` do?* Asks the switch to send a FlowRemoved message when the rule is
  removed, so the controller can log timeouts with packet and byte counts.

### 4.3 `auth_server.py` (250 lines)

**Purpose.** The TCP login server on h2. Low-level sockets, one thread per client, session table with
heartbeats and timeouts, brute-force counter, and the bridge to the controller.

**Connects to.** Clients (`client.py`, `benchmark.py`, tests) connect on TCP 9999. Calls the controller
at `http://10.0.0.254:8080/auth/{grant,revoke,block}` with `requests` and the `X-Auth-Token` header.
Reads `users.json` and `api_token`. Writes `auth_audit.log`.

**Code walk, top to bottom.**

* Settings block: timing constants (section 3). `AUTH_SERVER_IP = '10.0.0.2'` so it never blocks itself.
* `logging.basicConfig(filename='auth_audit.log', ...)`: audit log of logins, failures, blocks and
  session endings. Passwords and the token are never logged.
* Loads `api_token` into `API_HEADERS` and `users.json` into `USER_DB`.
* **Session table.** `SESSIONS = {(username, ip): {'login_time', 'last_seen', 'state'}}`, protected by
  one `SESSIONS_LOCK`. `time.monotonic()` is used because it never jumps backwards (wall clock can). When
  a session ends, `state` is overwritten with the reason (`LOGGED_OUT`, `IDLE_TIMEOUT`,
  `ABSOLUTE_LIMIT`), so the table also records how it ended.
* `controller_call(url, client_ip, reason)`: POSTs `{src_ip, dst_ip=10.0.0.3, reason}` with a 5 s
  timeout. Returns True only on HTTP 200. Any exception is logged and returns False.
* `open_session`: under the lock, call grant first; only if it succeeds, record the session. So the
  table never says "active" for a user who has no rule.
* `touch_session`: heartbeat. Updates `last_seen` if the session is ACTIVE, else returns False.
* `end_session_locked`: marks the session ended, then revokes, **unless** another ACTIVE session exists
  from the same IP (rules are per IP, so they must stay for that other user). Logs how long it lasted and
  whether the revoke worked. Caller must hold the lock.
* `close_session`: takes the lock and calls the above (used for LOGOUT).
* `reap_expired_sessions`: background daemon thread. Every second, under the lock, ends sessions idle
  for more than 15 s (`IDLE_TIMEOUT`) or older than 120 s (`ABSOLUTE_LIMIT`). Checking and ending under
  one lock hold means a heartbeat that just arrived cannot be lost.
* `session_loop(conn, username, ip)`: after login, reads newline-separated commands. Sets a socket
  timeout of 30 s so a vanished client does not hold the thread forever. `HEARTBEAT` -> `OK` (or
  `EXPIRED` then hang up). `LOGOUT` -> end session, `BYE`, hang up. Empty read = client closed the
  socket: the session will be reaped by the idle timeout.
* **Brute force.** `FAILED_LOGINS = {ip: count}` with `FAILED_LOCK`.
  * `register_failure(ip)`: never counts 10.0.0.2. Increments; on the 3rd returns True and resets the
    count to 0 (so after the block ends the host starts fresh).
  * `reset_failures(ip)`: a correct login clears the count ("in a row").
  * `block_host(ip)`: POST `/auth/block` with reason `BRUTE_FORCE`.
* `handle_client(conn, addr)`: per-connection thread.
  1. `conn.settimeout(LOGIN_TIMEOUT)`: 10 s to send the login, else `socket.timeout` is caught and the
     connection is closed (stops a client from tying up a thread silently).
  2. `recv(1024)`, decode, strip. Accepts JSON, `u,p`, `u:p` or `u p`.
  3. Correct password: log success, reset failures, `open_session`. On success reply SUCCESS with
     `HEARTBEAT_INTERVAL=5` and enter `session_loop`. If the controller refused, reply ERROR.
  4. Wrong password: log failure. If it is the 3rd in a row, reply BLOCKED **first** (once the drop rule
     is in, the reply could not get out), then call `block_host`. Otherwise reply DENIED.
  5. Any other exception (for example malformed JSON) is logged as "Socket fault"; `finally` always
     closes the socket.
* `serve(listener)`: `accept()` forever, one daemon thread per connection.
* `main()`: `socket(AF_INET, SOCK_STREAM)`, `SO_REUSEADDR` (restart without "address already in use"),
  `bind(('0.0.0.0', 9999))`, `listen(10)`, start the reaper, serve.

**What to say.** "This is the socket part of the rubric. A classic TCP server: socket, bind, listen,
accept, one thread per client. A small line-based protocol on top: login, then HEARTBEAT and LOGOUT. It
keeps a thread-safe session table and a reaper thread for timeouts, and every decision is pushed to the
controller over the REST API."

**Likely questions.**

* *Why TCP and not UDP?* Login needs reliable, ordered delivery and a connection that represents the
  session. The open connection carries heartbeats and logout.
* *How is concurrency handled?* Thread per connection, plus a reaper thread. Shared state (sessions and
  failure counts) is protected by locks.
* *Why make the controller call while holding the lock?* So the table and the switch change in the same
  order: a revoke can never overtake a newer grant. The cost is that a hung controller delays other
  session updates by up to the 5 s HTTP timeout.
* *Why `time.monotonic()`?* System time can jump (NTP, manual change); a monotonic clock cannot, so
  timeouts stay correct.
* *What is `SO_REUSEADDR`?* Lets the server rebind to port 9999 immediately after a restart, while old
  connections sit in TIME_WAIT.
* *What does `listen(10)` mean?* Backlog: up to 10 connections can wait to be accepted.
* *What if the client sends nothing?* After 10 s the `recv` raises `socket.timeout`; it is logged and
  the connection closed.
* *What if the client vanishes after login?* `recv` returns empty (clean close) or times out after 30 s;
  the reaper ends the session after 15 s without heartbeats either way.
* *Why reply BLOCKED before installing the block?* Once the drop rule is in, the reply would be dropped
  too, and the user would never learn why.
* *Why count per IP and not per username?* We block a host on the network, which is identified by IP.
  Counting per username would let an attacker try three passwords on every account.
* *Can the auth server block itself?* No: `register_failure` ignores 10.0.0.2, and the controller also
  refuses to block 10.0.0.2 or 10.0.0.254.
* *Are passwords secure?* No, they are plain text in `users.json` and on the wire. This is a known
  limitation; future work is salted hashes and challenge-response.
* *Why `requests` here when the rubric says low-level sockets?* The graded part, client-server login, is
  raw sockets. The controller call is plain HTTP to Ryu's web API; using `requests` keeps it short and
  readable.

### 4.4 `client.py` (104 lines)

**Purpose.** The user's program. Asks for username and password, logs in over TCP, stays connected and
sends heartbeats, logs out on `logout` or Ctrl-C. Shows the server's exact denial message.

**Code walk.**

* `run_client()`: `input()` for username and password; builds JSON `{username, password, target_ip}`;
  `socket(AF_INET, SOCK_STREAM)`, `settimeout(5)`, `connect(('10.0.0.2', 9999))`, `send`, `recv(1024)`.
  * If the reply contains `SUCCESS`: print success, read `HEARTBEAT_INTERVAL=N` with a regex (default 5),
    call `keep_alive`.
  * Otherwise print the server's message as is (DENIED, BLOCKED or ERROR).
  * Any exception (refused, timed out because the host is blocked) prints `Connection failed` and exits 1.
* `keep_alive(s, interval)`: a `select.select` loop over the socket and stdin, with a timeout until the
  next heartbeat. Socket readable: empty means server closed; `EXPIRED` means session ended. Stdin
  readable: `logout` calls `logout(s)`; end of input (piped stdin) just stops watching stdin and keeps
  heartbeating. When the timer is due: send `HEARTBEAT\n`. Ctrl-C triggers a logout.
* `logout(s)`: sends `LOGOUT\n`, reads until `BYE` (earlier `OK`s may be queued in front), prints
  whether the server confirmed it.

**What to say.** "A single-threaded client that multiplexes the keyboard and the socket with `select`,
so it can send heartbeats on a timer and still react to the user typing logout or the server ending the
session."

**Likely questions.**

* *Why `select` instead of threads?* One thread, no locking, and it waits on several inputs at once
  with a timeout: the natural tool for "wait for input or a timer".
* *What was the original client bug?* It compared the reply with the exact string `SUCCESS`, but the
  server sends `[+] SUCCESS: ...`, so success printed as an error. Fixed by checking `"SUCCESS" in
  response` (commit `a0de2cd`).
* *Why does a blocked host see "Connection failed" instead of BLOCKED on the 4th try?* The drop rule
  drops the TCP SYN, so `connect` times out after 5 s. Only the 3rd attempt sees the BLOCKED message.
* *Is the password hidden when typed?* No, it uses `input()`. `getpass` would hide it; small future fix.

### 4.5 `users.json` (4 lines)

Demo accounts: `alice` / `password123`, `bob` / `securepass`. Loaded once at server start (restart the
server after editing). Plain text on purpose for the demo; the honest answer is "in production we would
store salted hashes (PBKDF2/bcrypt)".

### 4.6 `start.sh` (25 lines)

**Purpose.** One command to bring the system up.

1. `sudo mn -c`: clean leftover Mininet state; kill old `ryu-manager` and `auth_server.py`.
2. If `api_token` is missing or empty, create it with `secrets.token_hex(32)` under `umask 077`
   (readable only by the owner). It is in `.gitignore`.
3. Start Ryu from the venv as the normal user: `PYTHONPATH=. ./.venv/bin/ryu-manager sdn_controller.py
   > controller.log 2>&1 &`.
4. Wait 5 s for Ryu to bind 6653 and 8080.
5. `sudo python3 topology.py` (Mininet needs root) opens the `mininet>` prompt.
6. On exit, kill Ryu.

It does **not** start the auth server: you start it on h2 at the Mininet prompt.

**Likely questions.** *Why is Ryu not run as root?* Least privilege: only Mininet and OVS need root.
*Why a venv?* Ryu 4.34 needs Python 3.10 and an old setuptools; Mininet is installed for the system
Python, so they are kept apart.

### 4.7 `.gitignore`

Ignores `.venv/`, `__pycache__/`, `*.log` and `api_token`. The important one is `api_token`: the secret
must never be committed.

### 4.8 `tests/run_in_mininet.sh` (20 lines)

Same steps as `start.sh` but runs a test script instead of the CLI: create token if needed, `mn -c`,
start Ryu with output to `controller.log`, wait 5 s, `sudo python3 <test>`, stop Ryu, return the test's
exit status. Usage: `tests/run_in_mininet.sh tests/run_tests.py`.

### 4.9 `tests/run_tests.py` (178 lines): the six rubric checks

Starts the real `auth_server.py` on h2, drives the real `client.py` on h4/h5, and inspects the real flow
table with `ovs-ofctl -O OpenFlow13 dump-flows s1`. About 2 minutes.

| # | Check | How it is verified |
|---|---|---|
| 1 | no login means no access | h4 cannot ping h3 and there is no priority-100 rule mentioning 10.0.0.4 |
| 2 | valid login gives access | alice logs in from h4 (client kept alive on a FIFO), output has SUCCESS, h4 pings h3, exactly 2 rules for h4 |
| 3 | logout removes access | writes `logout` into the FIFO; within 6 s the rules are gone and the ping fails |
| 4 | wrong password is refused | client prints DENIED, no access, no rules |
| 5 | 3 wrong passwords block the host | h5 gets DENIED, DENIED, BLOCKED; one priority-200 drop rule with `hard_timeout=60`; h5 cannot ping h2 or h3; h5's correct login now gets "Connection failed"; h4 unaffected; then waits until the switch removes the rule by itself and h5 can ping h2 again |
| 6 | ordinary host cannot reach the REST API | h4 and h3 curl `/auth/grant`: HTTP code `000` (no answer at all), and no rule was created (runs while check 5 waits for the block to expire) |

Helpers: `flows()`, `access_rules(ip)`, `block_rules(ip)`, `can_ping()`, `wait_until()`, `try_login()`
(one-shot client with piped input), `Client` class (long-running client fed from a FIFO so the test can
type `logout` later). `BLOCK_SECONDS` is read from `auth_server.py` so the test follows the config.

**Questions.** *Why test from inside Mininet hosts?* That is the real data path through the switch;
testing on the host OS would bypass the flow rules. *Why check the flow table and not only ping?* Ping
proves behaviour; the flow table proves the controller installed or removed exactly what it should.
*Why is check 6 inside check 5?* To save 60 s: it runs while waiting for the block to expire.

### 4.10 `tests/test_api_isolation.py` (125 lines)

Attack tests on the REST API, run from h3 (the target) and h4 (an ordinary client):

* TCP connect to 10.0.0.254:8080 hangs until timeout (dropped, not refused).
* Self-grant with no token and with a guessed token: no answer (`000`).
* Ping to the victim still 100% loss; no priority-100 rule for the attacker.
* From h2: without token -> 401; with token -> 200; `/stats/switches` (old `ofctl_rest`) -> 404.
* The priority-25 drop rule's packet counter is above 0 (it really caught the attack packets).

### 4.11 `tests/test_session_idle.py` (162 lines)

Scenario A: login, heartbeats keep access past 15 s, freeze the client with `kill -STOP` so heartbeats
stop, access disappears after about 15 s, audit log says `reason=IDLE_TIMEOUT`, woken client learns the
session ended. Scenario B: login, `logout`, access gone at once, audit log says `LOGGED_OUT`. Also checks
the rules have `hard_timeout=150` and no idle timeout, and that 150 > 120. Timeouts are read from the
source files.

### 4.12 `tests/test_rule_lifecycle.py` (316 lines)

Proves rules appear and disappear **exactly**. Records the flow table as a baseline, and after every
step requires the priority-100 rules to be exactly the expected pairs (so a duplicate would show) and
every other rule identical to the baseline. Scenarios: (1) login and logout for h4 only; (2) two users,
one logs out, the other keeps access, then idle timeout removes only one; (3) same user logs in twice:
no duplicates; (4) absolute limit (shortened to 20 s in this test) removes one session's rules while
another stays; (5) revoke of an absent session returns 200, a revoke aimed at the lockdown addresses
does not touch them, malformed revoke returns 400. Also checks the controller log has a line per rule,
never contains the token, and has no tracebacks.

### 4.13 `benchmark.py` (216 lines)

**Purpose.** Measures the cost of access control against a baseline: Ryu's stock learning switch
`ryu.app.simple_switch_13`.

**Two roles in one file.**

* **Orchestrator** (default): builds the network with `create_net()`, starts `auth_server.py` on h2
  (controlled mode only) and `iperf -s` on h3, then launches one worker per client (h4, or h4 and h5)
  with `host.popen`, collects their JSON, appends CSV rows, prints a table, exits 1 if a value is
  missing.
* **Worker** (`--worker`): runs inside a client host and measures:
  * `reach_before_login`: one ping to h3 before login (should be `no` in controlled mode).
  * `login_ms`: connect, send JSON, wait for SUCCESS.
  * `first_ping_ms`: pings every 10 ms (`ping -i 0.01 -D`) and reads the timestamp of the first reply.
    Controlled: counted from SUCCESS. Plain: from the start (includes the switch learning MACs).
  * `avg_ping_ms`: average of 10 pings.
  * `iperf_mbps`: 5 s TCP iperf; all clients start at the same moment (`--iperf-at`) to measure
    contention.
  * A heartbeat thread keeps the session alive; LOGOUT at the end.
* Parsers `parse_ping_avg`, `parse_iperf_mbps`, `first_reply_ms` read the tool outputs with regexes.

**Questions.** *Why simple_switch_13 as baseline?* It is the static, no-security learning switch the
rubric calls a "baseline/static approach", running on the same topology and controller framework, so
the only difference is our access control. *Why repeat 3 times and use the median?* Mininet timing is
noisy; the median ignores one odd run. *Why is throughput so high (over 100 Gbit/s)?* Virtual links in
one machine with no rate limit; only the relative difference is meaningful.

### 4.14 `run_benchmark.sh` (37 lines)

Creates the token if needed, then for each mode (`plain` with `ryu.app.simple_switch_13`, `controlled`
with `sdn_controller.py`): `mn -c`, start that Ryu app, run `benchmark.py` for 1 and 2 clients, 3 runs
each, stop Ryu. Finally runs `plot_results.py`. About 5 minutes.

### 4.15 `plot_results.py` (103 lines)

Reads `results/benchmark.csv`, takes the median per (mode, clients) over all clients and runs, draws a
2x2 bar chart (login time, first ping, average ping, throughput) to `results/benchmark.png` using the
non-GUI `Agg` backend, and writes `results/benchmark_table.md`. (The function named `mean` actually
returns the median; the docstring says so.)

### 4.16 `results/` (CSV, PNG, table)

`benchmark.csv`: 18 raw rows (2 modes x 3 runs x (1+2) clients). `benchmark.png`: the chart.
`benchmark_table.md`: the medians. Interpretation is in section 5.10.

### 4.17 `README.md`

The submission documentation: problem, architecture diagram, components table, flow-table priorities,
message flow, install, run, demo, tests, benchmark, results with chart, future work. Point the examiner
to it at the start and end.

### 4.18 Files that are not in the repo but appear at runtime

| File | Created by | Content |
|---|---|---|
| `api_token` | `start.sh` / `run_in_mininet.sh` / `run_benchmark.sh` | 64 hex chars shared secret, mode 600, gitignored |
| `controller.log` | `start.sh` redirect | Ryu output: `RULE INSTALLED/REMOVED`, `HOST BLOCKED` lines |
| `auth_audit.log` | `auth_server.py` | `AUTH SUCCESS/FAILED`, `HOST BLOCKED`, `Session ended ... reason=...` |
| `results/ryu_*.log` | `run_benchmark.sh` | Ryu output during the benchmark |

---

## 5. Feature-by-feature demo steps

Before starting: open three terminals in the repo folder. Terminal 1 runs `./start.sh`. Terminal 2 runs
`tail -f controller.log`. Terminal 3 is for `tail -f auth_audit.log` (it appears after the server
starts) and `sudo ovs-ofctl` commands.

### 5.0 Start everything

```bash
./start.sh                     # terminal 1, asks for sudo, ends at mininet>
```

```
mininet> h2 python3 auth_server.py > /tmp/auth_server.out 2>&1 &
mininet> nodes                 # h1 h2 h3 h4 h5 s1 c0
mininet> net                   # each hN-eth0 on s1-ethN
```

Show the base flow table (terminal 3):

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

Expected: priority 0 drop, priority 10 ARP and h2 rules, priority 25 drop to 10.0.0.254, two priority 30
API rules. No priority 100 or 200 rules. Say: "default deny, only the login server and ARP are open".

### 5.1 Default deny (no login, no access)

```
mininet> h4 ping -c 2 -W 1 h3        # 100% packet loss
mininet> h4 ping -c 2 h2             # works: the login server is always reachable
```

Point at the priority-0 rule's `n_packets` going up in the dump.

### 5.2 Login grants access (socket -> REST -> OpenFlow)

Interactive version (best for the examiner to see typing):

```
mininet> xterm h4                    # if X is available; in the xterm:
# python3 client.py   then type alice / password123
```

Scriptable version at the Mininet prompt:

```
mininet> h4 mkfifo /tmp/h4.in
mininet> h4 (printf 'alice\npassword123\n'; cat /tmp/h4.in) | python3 -u client.py > /tmp/h4.out 2>&1 &
mininet> h4 cat /tmp/h4.out
```

Expected client output:

```
=== Network Access Authentication ===
Username: Password: [*] Contacting Auth Server at 10.0.0.2...

[+] SUCCESS: Network access granted to 10.0.0.3.
[*] Session active. Heartbeat every 5s. Type 'logout' + Enter (or press Ctrl-C) to log out.
```

Then:

```
mininet> h4 ping -c 3 h3             # replies now
mininet> h5 ping -c 2 -W 1 h3        # still blocked: access is per host
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=100
```

Expected: two rules similar to
`hard_timeout=150, priority=100,ip,nw_src=10.0.0.4,nw_dst=10.0.0.3 actions=ALL,LOCAL` and the reverse.
`controller.log` shows two `RULE INSTALLED client=10.0.0.4 target=10.0.0.3 ... reason=LOGIN priority=100
hard_timeout=150` lines; `auth_audit.log` shows `AUTH SUCCESS: User 'alice' via IP 10.0.0.4`.

### 5.3 Heartbeats keep the session alive

Wait 20 seconds (longer than the 15 s idle timeout), ping again: still works. Explain that the client
sends `HEARTBEAT` every 5 s and the server answers `OK`. Optional proof:
`mininet> h4 tcpdump -i h4-eth0 -A port 9999 -c 4` shows `HEARTBEAT` / `OK`.

### 5.4 Logout revokes access immediately

```
mininet> h4 echo logout > /tmp/h4.in
mininet> h4 cat /tmp/h4.out                    # "[+] Logged out. Network access removed."
mininet> h4 ping -c 2 -W 1 h3                  # 100% loss
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=100     # nothing
```

`controller.log`: two `RULE REMOVED ... reason=LOGGED_OUT`. `auth_audit.log`: `Session ended: user
'alice' ip 10.0.0.4 reason=LOGGED_OUT after Ns revoke=ok`.

### 5.5 Idle timeout (client disappears without logging out)

```
mininet> h4 rm -f /tmp/h4.in; h4 mkfifo /tmp/h4.in
mininet> h4 (printf 'alice\npassword123\n'; cat /tmp/h4.in) | python3 -u client.py > /tmp/h4.out 2>&1 &
mininet> h4 ping -c 1 h3                       # works
mininet> h4 pkill -STOP -f client.py           # freeze the client: heartbeats stop
# wait about 16-17 seconds
mininet> h4 ping -c 2 -W 1 h3                  # 100% loss
mininet> h4 pkill -CONT -f client.py           # wake it
mininet> h4 cat /tmp/h4.out                    # "Session ended by the server (timed out)..."
```

`controller.log`: `RULE REMOVED ... reason=IDLE_TIMEOUT`. (If the client stays frozen longer than 30 s
the server hangs up first and the client prints "The server closed the connection" instead.)

### 5.6 Absolute session limit

A session ends 120 s after login even with heartbeats. To demo live, either wait two minutes with a
client logged in, or show `test_rule_lifecycle.py` scenario 4, which uses a 20 s limit. Log line:
`reason=ABSOLUTE_LIMIT`.

### 5.7 Hard-timeout safety net

Explain rather than wait: every access rule has `hard_timeout=150`, so even if the auth server crashes
after a grant, the switch removes the rule by itself. Show `hard_timeout=150` in the dump. To demo: kill
the auth server while logged in (`h2 pkill -f auth_server.py`); within 150 s of the login the rules
vanish and `controller.log` shows `RULE REMOVED ... reason=HARD_TIMEOUT_BY_SWITCH packets=... bytes=...`.

### 5.8 Wrong password and brute-force lockout (challenging scenario)

```
mininet> h5 printf 'bob\nwrong\n' | python3 client.py     # [-] DENIED: Invalid credentials.
mininet> h5 printf 'bob\nwrong\n' | python3 client.py     # [-] DENIED: Invalid credentials.
mininet> h5 printf 'bob\nwrong\n' | python3 client.py     # [-] BLOCKED: ... blocked for 60 seconds.
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=200
#   hard_timeout=60, priority=200,ip,nw_src=10.0.0.5 actions=drop
mininet> h5 ping -c 2 -W 1 h2                             # 100% loss: even the login server
mininet> h5 printf 'bob\nsecurepass\n' | python3 client.py # Connection failed: timed out
mininet> h4 ping -c 1 h2                                  # h4 unaffected
# after 60 s
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=200   # gone
mininet> h5 printf 'bob\nsecurepass\n' | python3 client.py # SUCCESS
```

Logs: `auth_audit.log` has three `AUTH FAILED` and `HOST BLOCKED: 10.0.0.5 after 3 wrong passwords in a
row, drop rule installed`; `controller.log` has `HOST BLOCKED client=10.0.0.5 priority=200
hard_timeout=60 reason=BRUTE_FORCE`. Also mention: a correct login between failures resets the count.

### 5.9 The controller API is protected (unauthorized access scenario)

```
mininet> h4 curl -m 3 -X POST -H "Content-Type: application/json" -d '{"src_ip":"10.0.0.4","dst_ip":"10.0.0.3"}' http://10.0.0.254:8080/auth/grant
#   curl: (28) Connection timed out  -> dropped by the priority-25 rule
mininet> h4 ping -c 1 -W 1 h3                              # still no access
mininet> h2 curl -s -X POST -H "Content-Type: application/json" -d '{"src_ip":"10.0.0.9","dst_ip":"10.0.0.3"}' http://10.0.0.254:8080/auth/revoke
#   {"error": "unauthorized"}   -> h2 can reach it but has no token here (HTTP 401)
```

Never paste the real token on screen. The token test is automated in `test_api_isolation.py`.

### 5.10 Two clients at once

Log in alice on h4 and bob on h5 (two FIFOs, same command pattern). Both reach h3. Log out alice: h5
keeps access, h4 loses it. This shows multiple concurrent clients and per-host rules.

### 5.11 Automated tests

```bash
tests/run_in_mininet.sh tests/run_tests.py           # ~2 min, six PASS lines, "RESULT: 6 of 6 checks passed"
tests/run_in_mininet.sh tests/test_api_isolation.py  # attacker tests from h3 and h4
tests/run_in_mininet.sh tests/test_session_idle.py   # ~70 s
tests/run_in_mininet.sh tests/test_rule_lifecycle.py # ~2 min
```

Exit Mininet from `start.sh` first; the test scripts start their own network and controller.

### 5.12 Benchmark and results

```bash
./run_benchmark.sh        # ~5 min; results/benchmark.csv, benchmark.png, benchmark_table.md
```

For the demo, show the existing `results/benchmark.png` and table rather than re-running. Talking points:

1. **Security works:** 0 of 9 controlled measurements reached h3 before login; 9 of 9 plain did.
2. **Login cost:** about 8 ms median (4.8 to 11.3 ms). Two simultaneous logins were not slower.
3. **Latency after login:** 0.057 to 0.065 ms vs 0.042 to 0.047 ms. The gap is smaller than the run
   to run spread, so no real difference.
4. **Throughput:** about 14% lower with access control (111 vs 129 Gbit/s, one client), every run. We
   did not prove the cause; the likely one is that access rules flood to ALL + LOCAL.
5. **First ping after login:** usually about 1 ms (faster than plain's 2 ms, which includes MAC
   learning). One two-client run took 18 to 20 ms: the controller answers once it has *sent* the rules,
   not once the switch confirmed them, so there can be a small gap. A barrier request would fix it.

---

## 6. Rubric to feature map

| Rubric item (marks) | What satisfies it | Where to point | Demo step |
|---|---|---|---|
| D1 Problem understanding & architecture (2) | captive-portal problem, two-plane design, flow table, message flow | README sections 1-3, this guide section 2 | opening slide / whiteboard |
| D1 TCP socket implementation (4) | raw `socket` server with bind/listen/accept, thread per client, timeouts, line protocol, error handling; `select`-based client | `auth_server.py`, `client.py` | 5.2, 5.3, 5.4 |
| D1 Mininet + SDN implementation (4) | 5-host topology, OpenFlow 1.3 Ryu app, prioritised proactive rules | `topology.py`, `sdn_controller.py` | 5.0, 5.1 |
| D1 Socket-SDN integration (3) | login event -> REST call -> FlowMod; logout/timeout -> DELETE_STRICT | `open_session`, `end_session_locked`, `grant_access`, `revoke_access` | 5.2, 5.4 |
| D1 Initial testing & demo (2) | end-to-end ping before/after login, flow dumps | `run_tests.py` checks 1-3 | 5.1, 5.2, 5.11 |
| D2 Complete application functionality (4) | login, heartbeat, logout, idle and absolute limits, multiple clients, denial messages | `auth_server.py`, `client.py` | 5.2 to 5.6, 5.10 |
| D2 Dynamic SDN functionality (6) | rules added and removed at runtime by app events (filtering, blocking, recovery via hard_timeout, logging/monitoring via FlowRemoved) | `sdn_controller.py` | 5.2, 5.4, 5.5, 5.7, 5.8 |
| D2 Challenging scenario / robustness (4) | brute-force lockout; unauthorized API access; client crash (idle); server crash (hard timeout); malformed input (400 / socket fault) | `register_failure`, `block_host`, API lockdown, `test_api_isolation.py` | 5.5, 5.7, 5.8, 5.9 |
| D2 Performance evaluation & comparison (5) | baseline simple_switch_13 vs controlled, 1 and 2 clients, 3 runs, 4 metrics, chart and table | `benchmark.py`, `run_benchmark.sh`, `plot_results.py`, `results/` | 5.12 |
| D2 Documentation, final demo & viva (6) | README, this guide, reproducible scripts, both presenters explain in depth | `README.md`, `docs/DEMO_GUIDE.md` | whole demo |

---

## 7. Timed demo script

Total about 15 minutes plus questions. Have the network already started and the auth server running
before you are called, so no time is lost on start-up (but be ready to show `start.sh`).

| Time | Who | What | Commands / screen |
|---|---|---|---|
| 0:00-1:30 | A | Problem and goal; architecture diagram; flow table priorities | README diagram |
| 1:30-3:00 | A | `topology.py` and `start.sh`; why 10.0.0.254; show `net` and base flow dump | 5.0 |
| 3:00-4:30 | A | Default deny live; `sdn_controller.py` base rules and REST API | 5.1 |
| 4:30-5:00 | A -> B | Handover (script in 8.3) | |
| 5:00-7:00 | B | `auth_server.py` socket structure and protocol; `client.py` with `select` | code on screen |
| 7:00-8:30 | B | Live login, ping works, flow dump, logs | 5.2 |
| 8:30-9:30 | B | Heartbeat, logout, idle timeout | 5.3, 5.4, 5.5 |
| 9:30-10:00 | B -> A | Handover back | |
| 10:00-11:30 | A | Brute force: DENIED, DENIED, BLOCKED, priority-200 rule, h5 cut off | 5.8 |
| 11:30-12:30 | A | API attack from h4 fails; three layers of protection | 5.9 |
| 12:30-14:00 | B | Tests (show a saved PASS run) and benchmark chart with the five talking points | 5.11, 5.12 |
| 14:00-15:00 | B | Limitations and future work; close | section 10 |

If time is short, drop 5.5 (idle timeout) and show the test output for it instead.

---

## 8. Presenter split: Part A and Part B

### 8.1 Contributions and a note on the git history

Both team members worked on this project. All commits were made from one account (Harshith's), so
`git log` shows a single author even where the teammate wrote or co-wrote the work. The history has not
been rewritten. If an examiner asks why the log shows one name, the true answer is: *"We worked together
and committed from one machine and one account."*

The table below records who worked on what. **Every row is to be confirmed by Harshith** before it is
shown to anyone: edit the "Worked on by" column so it matches what really happened.

| Area | Files | Worked on by (to be confirmed by Harshith) |
|---|---|---|
| Problem statement, architecture, README sections 1-3 | `README.md` | Harshith + [Teammate] (confirm) |
| Network topology | `topology.py` | (confirm) |
| Start-up script and token | `start.sh`, `.gitignore`, `tests/run_in_mininet.sh` | (confirm) |
| SDN controller, flow rules, REST API and its protection | `sdn_controller.py` | (confirm) |
| Brute-force block rule and hard-timeout recovery | `sdn_controller.py` | (confirm) |
| TCP login server, protocol, sessions, reaper | `auth_server.py` | (confirm) |
| Client, heartbeats, logout | `client.py`, `users.json` | (confirm) |
| Brute-force counting in the server | `auth_server.py` | (confirm) |
| Tests | `tests/run_tests.py`, `tests/test_session_idle.py`, `tests/test_api_isolation.py`, `tests/test_rule_lifecycle.py` | (confirm) |
| Benchmark, chart and results | `benchmark.py`, `run_benchmark.sh`, `plot_results.py`, `results/` | (confirm) |
| Results write-up, limitations, future work | `README.md` sections 8-10 | (confirm) |

Each presenter should present the parts they worked on where possible, and still study the rest of their
half with this guide until they can answer every question in it without notes. The rubric's last item
("students demonstrate individual understanding through viva") is marked on that depth.

Replace `[Presenter A]`, `[Presenter B]` and `[Teammate]` below with your names. Suggested split: the
presenter who did more of the network/controller work takes Part A, the other takes Part B.

### 8.2 The split

The halves are balanced by rubric weight: Part A covers the network side (Mininet + SDN 4, dynamic SDN
6, most of robustness); Part B covers the application side (sockets 4, complete functionality 4,
performance 5). Integration (3) and architecture (2) are shared.

**Part A: [Presenter A], network and SDN control**

| Owns | Files |
|---|---|
| Problem statement and architecture | `README.md` sections 1-3 |
| Network topology | `topology.py` |
| Start-up and token | `start.sh`, `.gitignore`, `tests/run_in_mininet.sh` |
| SDN controller, flow table, REST API, API security | `sdn_controller.py` |
| Brute-force block on the switch, hard-timeout recovery | `sdn_controller.py` (`block_host`, `flow_removed_handler`) |
| Security tests | `tests/test_api_isolation.py`, `tests/test_rule_lifecycle.py` |

Must be able to explain without notes: OpenFlow priorities and matches; proactive vs reactive;
`DELETE` vs `DELETE_STRICT`; `hard_timeout` vs `idle_timeout`; `SEND_FLOW_REM`; why 10.0.0.254 and
`OFPP_LOCAL`; the three layers of API protection; constant-time compare; fail-closed token loading; why
ALL + LOCAL and its cost.

**Part B: [Presenter B], socket application, testing and evaluation**

| Owns | Files |
|---|---|
| TCP login server, protocol, threads, sessions, reaper | `auth_server.py` |
| Client, heartbeats, logout, `select` loop | `client.py` |
| Accounts | `users.json` |
| Brute-force counting on the server side | `auth_server.py` (`register_failure`, `reset_failures`, `block_host` call) |
| Main tests | `tests/run_tests.py`, `tests/test_session_idle.py` |
| Performance evaluation | `benchmark.py`, `run_benchmark.sh`, `plot_results.py`, `results/` |
| Results, limitations, future work | `README.md` sections 8-10 |

Must be able to explain without notes: socket/bind/listen/accept/recv/send; `SO_REUSEADDR`; backlog;
thread per client and locks; `settimeout` uses (10 s login, 30 s session); the protocol messages; the
session table states; idle vs absolute limit; why BLOCKED is sent before the block; `select` in the
client; the benchmark method, the baseline choice, median of 3, and every number in the results table.

**Shared (both must know):** the end-to-end login flow in section 2.4 (A explains the right half from
`/auth/grant` onwards, B the left half up to it), and the flow-table summary in section 2.3.

### 8.3 Handover scripts

A to B (after showing default deny):

> "So the switch now drops everything except ARP and traffic to the login server. The only way a host
> gets more is through the three API calls I showed: grant, revoke and block. [B] will now show the
> application that decides when to make those calls: the TCP login server and the client."

B to A (after logout and idle timeout):

> "So far a well-behaved user. Now the hostile cases: someone guessing passwords, and someone trying
> to skip the login and talk to the controller directly. The server only counts the failures; [A] will
> show what the switch does about them."

A to B (after the API attack):

> "That covers how the network defends itself. [B] will show how we tested all of this automatically
> and what it costs in performance compared with a plain switch."

### 8.4 Practice plan

1. Each presenter reads their files line by line with section 4 open, then explains each function aloud
   to the other.
2. Each runs their own demo steps from section 5 at least twice from a fresh `./start.sh`.
3. Swap: each asks the other ten questions from section 9 about the *other* half.
4. One full timed rehearsal using section 7.

---

## 9. Cross-knowledge: answering questions on the other half

Examiners often ask the "other" person on purpose. Each presenter should be able to give these short
answers about the half they do not own, and then say "[name] can go deeper on that".

### 9.1 Part A questions that Presenter B should be able to answer

| Question | Short answer |
|---|---|
| What happens on the switch when a user logs in? | Two priority-100 rules, client->target and back, hard_timeout 150. |
| What is the default rule? | Priority 0, empty action list, so drop everything. |
| How is the auth server protected from being blocked? | The controller refuses to block 10.0.0.2 or 10.0.0.254, and the server never counts its own IP. |
| What is 10.0.0.254? | The switch's LOCAL interface on the host OS, where Ryu's REST API listens on 8080. |
| Why can't h4 call the API? | Priority-25 drop on anything to 10.0.0.254; only h2's port, MAC and IP are allowed on 8080; and the API checks IP and token. |
| What OpenFlow version? | 1.3, set in both `topology.py` and the Ryu app. |
| What if the auth server crashes? | Rules still expire after 150 s (hard timeout). |
| How long does a block last and who removes it? | 60 s; the switch removes it by itself via hard_timeout. |
| Proactive or reactive controller? | Proactive, no PacketIn handler. |

### 9.2 Part B questions that Presenter A should be able to answer

| Question | Short answer |
|---|---|
| TCP or UDP, and why? | TCP: reliable login and a live connection for heartbeats and logout. |
| How does the server handle many clients? | One thread per accepted connection, locks around shared tables. |
| What does the client send? | JSON with username, password, target; then `HEARTBEAT` lines; `LOGOUT`. |
| What are the session timeouts? | Heartbeat 5 s, idle 15 s, absolute 120 s, reaper checks every 1 s. |
| When does a host get blocked? | Third wrong password in a row from the same IP; a correct login resets it. |
| What if a client connects and says nothing? | 10 s login timeout, then the server closes the connection. |
| What did the benchmark compare? | `simple_switch_13` vs our controller, 1 and 2 clients, 3 runs, median. |
| Main results? | 0/9 reach before login, ~8 ms login, same ping, ~14% lower throughput. |
| How many automated checks? | Six in `run_tests.py`, plus three longer test files. |

---

## 10. Known limitations (say them before the examiner does)

Naming these yourselves shows understanding. Each has a one-line fix.

| Limitation | Why it matters | Fix |
|---|---|---|
| Passwords in plain text in `users.json` and on the wire | sniffing or file access reveals them | salted PBKDF2 hashes + challenge-response (HMAC with a nonce) or TLS |
| Access rules match IP only | a host could spoof another logged-in host's IP | also match `eth_src` and `in_port` (MACs are already fixed) |
| Rules flood to ALL + LOCAL (also the priority-10 h2 rules) | other hosts can see the traffic; ~14% throughput cost | output to the destination port only |
| One fixed target 10.0.0.3 for everyone | no per-user policy | `policy.json` with roles and allowed services |
| Rules are per IP; two users on one IP share them | handled in code (revoke skipped while another session is active) but coarse | per-session cookies on flows |
| Login reads one `recv(1024)` | a login split across TCP segments would fail | read until newline / length-prefixed messages |
| Block rule drops IP only; ARP still passes | harmless, but not a full cut-off | add an ARP drop for that MAC |
| Grant returns before the switch confirms | rare 18-20 ms first-ping delay seen in the benchmark | send an OpenFlow barrier request before replying 200 |
| Ryu's web server listens on all interfaces of the host OS | reachable from the host itself (not from Mininet hosts) | bind it to 10.0.0.254 (`--wsapi-host`) |
| REST API is plain HTTP | token visible to anyone on h2's path | TLS for the API |
| Password typed visibly in `client.py` | shoulder surfing | `getpass.getpass()` |
| Single switch | no path computation | multi-switch topology with routing |

---

## 11. General viva questions

* **What is SDN?** Separating the control plane (decisions, in the controller) from the data plane
  (forwarding, in the switch). The controller programs switches through a protocol such as OpenFlow.
* **What is OpenFlow?** The protocol between controller and switch. The controller sends FlowMods
  (add/modify/delete rules); the switch sends events such as PacketIn, FlowRemoved, FeaturesReply.
* **What is a flow rule made of?** Match fields, priority, instructions/actions, timeouts, counters,
  cookie, flags.
* **What is Mininet?** An emulator that creates virtual hosts (network namespaces), switches (Open
  vSwitch) and links on one machine, running real Linux networking code.
* **What is Ryu?** A Python SDN controller framework. Apps subscribe to OpenFlow events with
  `@set_ev_cls` and send messages through the datapath object.
* **What are `CONFIG_DISPATCHER` and `MAIN_DISPATCHER`?** Phases of the switch connection: during
  configuration (features exchange) and normal operation.
* **What is a datapath?** Ryu's object for one connected switch; you send FlowMods through it.
* **Why default deny?** Safer to open specific paths than to try to close every bad one.
* **How is this like a real captive portal / 802.1X?** Same idea: authenticate first, then the network
  grants access. 802.1X does it at the port with EAP and RADIUS; we do it with a TCP login and SDN rules.
* **How would you scale to many switches?** Keep the session logic, but install rules along the path
  computed from the topology (Ryu's topology discovery), and use cookies to remove them per session.
* **What happens if the controller dies?** Existing rules stay on the switch (and expire by timeout);
  no new logins can be granted. OVS's fail mode decides behaviour for unmatched traffic.
* **How did you verify correctness?** Automated tests that ping from inside the hosts and compare the
  real flow table against what is expected, plus logs on both sides.

---

## 12. Pre-demo checklist and troubleshooting

**Checklist (do 30 minutes before):**

* [ ] `git checkout bm` (or the branch you submit) and `git pull`.
* [ ] `.venv/bin/ryu-manager --version` works; `sudo mn --version` works; `iperf -v` is version 2.
* [ ] `sudo mn -c` once.
* [ ] Full run of `tests/run_in_mininet.sh tests/run_tests.py`; save the output in a text file to show
      if live time is short.
* [ ] `results/benchmark.png` opens.
* [ ] Terminals sized large, font big enough for the examiner.
* [ ] `./start.sh`, then start the auth server on h2, then rehearse 5.1 and 5.2 once and log out.
* [ ] Wait 60 s after any brute-force rehearsal so h5 is unblocked.

**Troubleshooting:**

| Symptom | Cause | Fix |
|---|---|---|
| Client says `ERROR: Controller refused rule injection` | auth server cannot reach 10.0.0.254:8080 | check Ryu is running (`controller.log`), check `s1` is up (`sh ip addr show s1`), restart with `./start.sh` |
| Ryu exits at start with `api_token file missing` | no token | run `./start.sh` (it creates it) |
| `Address already in use` on 8080 or 6653 | old Ryu still running | `sudo pkill -f ryu-manager; sudo mn -c` |
| `Connection failed` from h5 | host still blocked | wait 60 s or check `dump-flows ... priority=200` |
| Nothing pings at all, even h2 | switch not connected to controller | `sh ovs-vsctl show` should say `is_connected: true`; restart |
| Auth server exits immediately | started from the wrong folder (cannot find `users.json`) | start it from the repo folder; Mininet hosts share the folder `start.sh` ran in |
| Benchmark row missing values | iperf not installed in hosts or a timeout | `sudo apt install iperf`, re-run `./run_benchmark.sh` |
