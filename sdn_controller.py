import hmac
import json
import os
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, set_ev_cls
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

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        inst = [datapath.ofproto_parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def grant_access(self, src_ip, dst_ip):
        if not self.datapath: return False
        ofproto, parser = self.datapath.ofproto, self.datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_ALL), parser.OFPActionOutput(ofproto.OFPP_LOCAL)]
        
        self.add_flow(self.datapath, 100, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip), actions, hard_timeout=HARD_TIMEOUT)
        self.add_flow(self.datapath, 100, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=dst_ip, ipv4_dst=src_ip), actions, hard_timeout=HARD_TIMEOUT)
        self.logger.info(f"[+] GRANTED: Access for {src_ip} to {dst_ip}")
        return True

    def revoke_access(self, src_ip, dst_ip):
        if not self.datapath: return False
        ofproto, parser = self.datapath.ofproto, self.datapath.ofproto_parser
        
        match_fwd = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip)
        mod_fwd = parser.OFPFlowMod(datapath=self.datapath, command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY, priority=100, match=match_fwd)
        self.datapath.send_msg(mod_fwd)
        
        match_rev = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=dst_ip, ipv4_dst=src_ip)
        mod_rev = parser.OFPFlowMod(datapath=self.datapath, command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY, priority=100, match=match_rev)
        self.datapath.send_msg(mod_rev)
        
        self.logger.info(f"[-] REVOKED: Access removed for {src_ip}")
        return True

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

    @route('auth', '/auth/grant', methods=['POST'])
    def grant_handler(self, req, **kwargs):
        denied = self.check_caller(req)
        if denied: return denied
        body = req.json if req.body else {}
        if self.app.grant_access(body.get('src_ip'), body.get('dst_ip')): return json.dumps({'status': 'success'})
        return json.dumps({'error': 'Switch not connected'})

    @route('auth', '/auth/revoke', methods=['POST'])
    def revoke_handler(self, req, **kwargs):
        denied = self.check_caller(req)
        if denied: return denied
        body = req.json if req.body else {}
        if self.app.revoke_access(body.get('src_ip'), body.get('dst_ip')): return json.dumps({'status': 'success'})
        return json.dumps({'error': 'Switch not connected'})
