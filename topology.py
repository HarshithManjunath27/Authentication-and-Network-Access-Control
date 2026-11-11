from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel

def build_topology():
    setLogLevel('info')
    net = Mininet(controller=RemoteController, switch=OVSSwitch)

    print("*** Adding controller")
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    print("*** Adding switch")
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    print("*** Adding hosts")
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24') # Auth Server
    h3 = net.addHost('h3', ip='10.0.0.3/24') # Target
    h4 = net.addHost('h4', ip='10.0.0.4/24') # New Client A
    h5 = net.addHost('h5', ip='10.0.0.5/24') # New Client B
    print("*** Creating links")
    for h in [h1, h2, h3, h4, h5]:
      net.addLink(h, s1)
   
    print("*** Starting network")
    net.build()
    c0.start()
    s1.start([c0])

    # Bridge the switch to the host OS so h2 can reach the Ryu REST API
    s1.cmd('ip addr add 10.0.0.254/24 dev s1')
    
    print("*** Dropping into Mininet CLI")
    CLI(net)

    print("*** Stopping network")
    net.stop()

if __name__ == '__main__':
    build_topology()
