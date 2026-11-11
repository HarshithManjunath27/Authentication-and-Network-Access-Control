from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel

def create_net():
    """Build and start the network, then return it (no CLI). Tests import this too."""
    setLogLevel('info')
    net = Mininet(controller=RemoteController, switch=OVSSwitch)

    print("*** Adding controller")
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    print("*** Adding switch")
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    # Fixed MACs (00:00:00:00:00:0N for hN) so the controller can match on MAC as well as IP.
    # Links are added in order h1..h5, so hN is on switch port N (h2 is on port 2).
    print("*** Adding hosts")
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02') # Auth Server
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03') # Target
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04') # New Client A
    h5 = net.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:00:05') # New Client B
    print("*** Creating links")
    for h in [h1, h2, h3, h4, h5]:
      net.addLink(h, s1)
   
    print("*** Starting network")
    net.build()
    c0.start()
    s1.start([c0])

    # Bridge the switch to the host OS so h2 can reach the Ryu REST API
    s1.cmd('ip addr add 10.0.0.254/24 dev s1')
    # An address alone does not turn the interface on: without this the link stays DOWN and the
    # host OS never receives packets sent to 10.0.0.254 (the cause of "No route to host").
    s1.cmd('ip link set s1 up')
    return net

def build_topology():
    net = create_net()
    print("*** Dropping into Mininet CLI")
    CLI(net)

    print("*** Stopping network")
    net.stop()

if __name__ == '__main__':
    build_topology()
