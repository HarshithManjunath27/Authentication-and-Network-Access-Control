import hmac
import ipaddress
import json
import os
import re
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import ControllerBase, WSGIApplication, route, Response
from ryu.lib.packet import ether_types

app_instance_name = 'sdn_auth_api_app'

# The only host allowed to talk to the REST API: h2 (the auth server).
# These match topology.py (hN has MAC 00:00:00:00:00:0N and sits on switch port N).
H2_PORT = 2
H2_MAC = '00:00:00:00:00:02'
H2_IP = '10.0.0.2'
# The REST API runs on the host OS, reached through the switch's local port.
API_IP = '10.0.0.254'
API_PORT = 8080
# The shared secret is read from this untracked file (start.sh creates it). It is never logged.
TOKEN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'api_token')
# Safety net: every access rule disappears by itself this many seconds after it was installed, even if
# the auth server crashes and never sends a revoke. Keep it a bit longer than ABSOLUTE_LIMIT (120 s)
# in auth_server.py, so normal session endings always happen first.
HARD_TIMEOUT = 150
# Brute-force block: a drop rule for one host, placed above every other rule (the highest other priority
# is 100, the access rules). The switch removes it by itself after BLOCK_TIMEOUT seconds (hard_timeout).
# Keep BLOCK_TIMEOUT equal to BLOCK_SECONDS in auth_server.py, which is what the user is told.
BLOCK_PRIORITY = 200
BLOCK_TIMEOUT = 60

class AuthController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(AuthController, self).__init__(*args, **kwargs)
        self.datapath = None
        # Load the API secret once at start-up; refuse to start without one (fail closed).
        try:
            with open(TOKEN_FILE) as f:
                self.api_token = f.read().strip()
        except OSError:
            self.api_token = ''
        if not self.api_token:
            raise RuntimeError('api_token file missing or empty: run start.sh to create it')
        wsgi = kwargs['wsgi']
        wsgi.register(AuthRestAPI, {app_instance_name: self})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.datapath = ev.msg.datapath
        ofproto, parser = self.datapath.ofproto, self.datapath.ofproto_parser
        forward_actions = [parser.OFPActionOutput(ofproto.OFPP_ALL), parser.OFPActionOutput(ofproto.OFPP_LOCAL)]

        self.add_flow(self.datapath, 0, parser.OFPMatch(), []) # Baseline Drop
        self.add_flow(self.datapath, 10, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP), forward_actions)
        self.add_flow(self.datapath, 10, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst='10.0.0.2'), forward_actions)
        self.add_flow(self.datapath, 10, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src='10.0.0.2'), forward_actions)

        # --- Lock down the REST API (10.0.0.254:8080) ---
        # Priority 25: every other IP packet addressed to the API is dropped (empty action list).
        self.add_flow(self.datapath, 25, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=API_IP), [])
        # Priority 30: requests from h2 only (right switch port AND MAC AND IP) to TCP 8080
        # go to the host OS (OFPP_LOCAL) and nowhere else.
        self.add_flow(self.datapath, 30, parser.OFPMatch(
            in_port=H2_PORT, eth_src=H2_MAC, eth_type=ether_types.ETH_TYPE_IP, ipv4_src=H2_IP,
            ipv4_dst=API_IP, ip_proto=6, tcp_dst=API_PORT), [parser.OFPActionOutput(ofproto.OFPP_LOCAL)])
        # Priority 30: replies from the API (coming in on the local port) go out h2's port only,
        # not flooded, so other hosts cannot see them.
        self.add_flow(self.datapath, 30, parser.OFPMatch(
            in_port=ofproto.OFPP_LOCAL, eth_type=ether_types.ETH_TYPE_IP, ipv4_src=API_IP,
            ipv4_dst=H2_IP, ip_proto=6, tcp_src=API_PORT), [parser.OFPActionOutput(H2_PORT)])

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0, flags=0):
        inst = [datapath.ofproto_parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout, flags=flags)
        datapath.send_msg(mod)

    def log_rule(self, event, client, target, direction, reason, extra=''):
        """One log line per rule: what happened, for which client and target, and why. Never log the token."""
        self.logger.info(f"RULE {event} client={client} target={target} direction={direction} reason={reason}{extra}")

    def grant_access(self, src_ip, dst_ip, reason='LOGIN'):
        """Install the two priority-100 rules that let src_ip (the client) and dst_ip (the target) talk."""
        if not self.datapath: return False
        ofproto, parser = self.datapath.ofproto, self.datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_ALL), parser.OFPActionOutput(ofproto.OFPP_LOCAL)]
        # SEND_FLOW_REM makes the switch tell us when it removes a rule by itself (a timeout).
        flags = ofproto.OFPFF_SEND_FLOW_REM
        # Installing the same rule twice just overwrites it, so logging in again never creates duplicates.
        for a, b, direction in ((src_ip, dst_ip, 'client->target'), (dst_ip, src_ip, 'target->client')):
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=a, ipv4_dst=b)
            self.add_flow(self.datapath, 100, match, actions, hard_timeout=HARD_TIMEOUT, flags=flags)
            self.log_rule('INSTALLED', src_ip, dst_ip, direction, reason, f' priority=100 hard_timeout={HARD_TIMEOUT}')
        return True

    def revoke_access(self, src_ip, dst_ip, reason='UNSPECIFIED'):
        """Remove exactly the two priority-100 rules for this client and target, and nothing else."""
        if not self.datapath: return False
        ofproto, parser = self.datapath.ofproto, self.datapath.ofproto_parser
        for a, b, direction in ((src_ip, dst_ip, 'client->target'), (dst_ip, src_ip, 'target->client')):
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=a, ipv4_dst=b)
            # DELETE_STRICT only removes a rule with exactly this match AND priority 100. The plain DELETE
            # command ignores the priority and also removes every more specific rule (e.g. the API lockdown).
            mod = parser.OFPFlowMod(datapath=self.datapath, command=ofproto.OFPFC_DELETE_STRICT,
                                    out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY, priority=100, match=match)
            self.datapath.send_msg(mod)
            # Deleting a rule that is already gone is not an error in OpenFlow: the switch just ignores it.
            self.log_rule('REMOVED', src_ip, dst_ip, direction, reason)
        return True

    def block_host(self, client_ip, reason):
        """Drop every IP packet coming from client_ip. An empty action list means drop. Because the
        rule has a hard_timeout, the switch lifts the block by itself even if nobody ever asks it to."""
        if not self.datapath: return False
        match = self.datapath.ofproto_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=client_ip)
        self.add_flow(self.datapath, BLOCK_PRIORITY, match, [], hard_timeout=BLOCK_TIMEOUT)
        self.logger.info(f"HOST BLOCKED client={client_ip} priority={BLOCK_PRIORITY} "
                         f"hard_timeout={BLOCK_TIMEOUT} reason={reason}")
        return True

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        """The switch reports a rule it removed on its own. Removals we ordered are already logged by
        revoke_access, so only timeouts are logged here."""
        msg = ev.msg
        ofproto = msg.datapath.ofproto
        reasons = {ofproto.OFPRR_IDLE_TIMEOUT: 'IDLE_TIMEOUT_BY_SWITCH', ofproto.OFPRR_HARD_TIMEOUT: 'HARD_TIMEOUT_BY_SWITCH'}
        if msg.priority != 100 or msg.reason not in reasons:
            return
        self.logger.info(f"RULE REMOVED src={msg.match['ipv4_src']} dst={msg.match['ipv4_dst']} "
                         f"reason={reasons[msg.reason]} packets={msg.packet_count} bytes={msg.byte_count}")

class AuthRestAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(AuthRestAPI, self).__init__(req, link, data, **config)
        self.app = data[app_instance_name]

    def check_caller(self, req):
        """Return an error Response if the caller is not allowed, or None if it is."""
        # Defence in depth: the switch already blocks other hosts, but check the source IP too.
        if req.remote_addr != H2_IP:
            return Response(status=403, content_type='application/json', body=json.dumps({'error': 'forbidden'}))
        # Compare the token in constant time so response timing does not leak how much matched.
        supplied = req.headers.get('X-Auth-Token', '')
        if not hmac.compare_digest(supplied.encode(), self.app.api_token.encode()):
            return Response(status=401, content_type='application/json', body=json.dumps({'error': 'unauthorized'}))
        return None

    def json_reply(self, status, data):
        return Response(status=status, content_type='application/json', body=json.dumps(data))

    def read_request(self, req):
        """Return (src_ip, dst_ip, reason) from the JSON body, or None if it is missing or malformed."""
        try:
            body = req.json if req.body else {}
            src = str(ipaddress.IPv4Address(body.get('src_ip')))
            dst = str(ipaddress.IPv4Address(body.get('dst_ip')))
            # The reason only goes into the log, so keep it to harmless characters (no newlines).
            reason = re.sub(r'[^A-Za-z0-9_]', '', str(body.get('reason', '')))[:32] or 'UNSPECIFIED'
        except (ValueError, AttributeError, TypeError):
            return None
        return src, dst, reason

    @route('auth', '/auth/grant', methods=['POST'])
    def grant_handler(self, req, **kwargs):
        denied = self.check_caller(req)
        if denied: return denied
        parsed = self.read_request(req)
        if parsed is None:
            return self.json_reply(400, {'error': 'src_ip and dst_ip must be valid IPv4 addresses'})
        if self.app.grant_access(*parsed): return self.json_reply(200, {'status': 'success'})
        return self.json_reply(503, {'error': 'Switch not connected'})

    @route('auth', '/auth/revoke', methods=['POST'])
    def revoke_handler(self, req, **kwargs):
        denied = self.check_caller(req)
        if denied: return denied
        parsed = self.read_request(req)
        if parsed is None:
            return self.json_reply(400, {'error': 'src_ip and dst_ip must be valid IPv4 addresses'})
        # Revoking a session that is already gone is fine: the answer is still success.
        if self.app.revoke_access(*parsed): return self.json_reply(200, {'status': 'success'})
        return self.json_reply(503, {'error': 'Switch not connected'})

    def read_block_request(self, req):
        """Return (client_ip, reason) from the JSON body, or None if it is malformed or must not be blocked.
        The auth server (h2) and the API address can never be blocked: that would break logins or the API."""
        try:
            body = req.json if req.body else {}
            client_ip = str(ipaddress.IPv4Address(body.get('src_ip')))
            reason = re.sub(r'[^A-Za-z0-9_]', '', str(body.get('reason', '')))[:32] or 'UNSPECIFIED'
        except (ValueError, AttributeError, TypeError):
            return None
        if client_ip in (H2_IP, API_IP):
            return None
        return client_ip, reason

    @route('auth', '/auth/block', methods=['POST'])
    def block_handler(self, req, **kwargs):
        denied = self.check_caller(req)
        if denied: return denied
        parsed = self.read_block_request(req)
        if parsed is None:
            return self.json_reply(400, {'error': 'src_ip must be an IPv4 address other than the auth server or the API'})
        if self.app.block_host(*parsed): return self.json_reply(200, {'status': 'success'})
        return self.json_reply(503, {'error': 'Switch not connected'})
