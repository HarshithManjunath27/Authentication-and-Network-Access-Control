import json
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib.packet import ether_types

app_instance_name = 'sdn_auth_api_app'

class AuthController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(AuthController, self).__init__(*args, **kwargs)
        self.datapath = None
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
        self.add_flow(self.datapath, 20, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst='10.0.0.254'), forward_actions)
        self.add_flow(self.datapath, 20, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src='10.0.0.254'), forward_actions)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        inst = [datapath.ofproto_parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    def grant_access(self, src_ip, dst_ip):
        if not self.datapath: return False
        ofproto, parser = self.datapath.ofproto, self.datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_ALL), parser.OFPActionOutput(ofproto.OFPP_LOCAL)]
        
        self.add_flow(self.datapath, 100, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip), actions, idle_timeout=60)
        self.add_flow(self.datapath, 100, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=dst_ip, ipv4_dst=src_ip), actions, idle_timeout=60)
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

    @route('auth', '/auth/grant', methods=['POST'])
    def grant_handler(self, req, **kwargs):
        body = req.json if req.body else {}
        if self.app.grant_access(body.get('src_ip'), body.get('dst_ip')): return json.dumps({'status': 'success'})
        return json.dumps({'error': 'Switch not connected'})

    @route('auth', '/auth/revoke', methods=['POST'])
    def revoke_handler(self, req, **kwargs):
        body = req.json if req.body else {}
        if self.app.revoke_access(body.get('src_ip'), body.get('dst_ip')): return json.dumps({'status': 'success'})
        return json.dumps({'error': 'Switch not connected'})
