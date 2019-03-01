Switch Configuration Examples for Microsoft SDN
=======
### Switch model: Cisco Nexus 3132
### Firmware version: iOS 6.0(2)U6(1)
### Topology: Two top-of-rack (TOR) switches with a L3 topology connected to a Spine using BGP

       +--------+ +--------+
       | Spine1 | | Spine2 |   BGP ASN: 64807
       +--------+ +--------+
            |  \   /  |
            |   \ /   |
            |    X    |
            |   / \   |
    .Rack1..|  /   \  |...............................
    .  +--------+ +--------+                         .
    .  |  TOR1  |=|  TOR2  |   BGP ASN TOR1: 64651   .  ... TORs in additional racks 
    .  +--------+ +--------+   BGP ASN TOR2: 64652   .       can be added to the 
    .       |         |                              .        same Spine pair.
    .       |         |                              .
    .       |         |                              .
    .       |         |                              .
    .       |         |                              .
    .  +-------------------+                         .
    .  |   Hyper-V Hosts   |-+    BGP ASNs:          .
    .  +-------------------+ |-+   MUX=64653         .
    .    +-------------------+ |   GW =64653         .
    .      +-------------------+                     .
    ..................................................       

These sample configuration files use the following subnets:
<table>
 <tr>
  <td>**Subnet name**</td>
  <td>**VLAN ID**</td>
  <td>**Subnet**</td>
  <td>**Assignments**</td>
 </tr>
 <tr>
  <td>TOR1 Loopback</td>
  <td>NA</td>
  <td>10.0.1.73/32</td>
  <td>10.0.1.73 - TOR1</td>
 </tr> 
 <tr>
  <td>TOR2 Loopback</td>
  <td>NA</td>
  <td>10.0.1.74/32</td>
  <td>10.0.1.74 - TOR2</td>
 </tr> 
 <tr>
  <td>Uplink TOR1 to Spine1</td>
  <td>NA</td>
  <td>NA</td>
  <td>BGP unnumbered</td>
 </tr>
  <tr>
  <td>Uplink TOR1 to Spine2</td>
  <td>NA</td>
  <td>NA</td>
  <td>BGP unnumbered</td>
 </tr>
 <tr>
  <td>Uplink TOR2 to Spine1</td>
  <td>NA</td>
  <td>NA</td>
  <td>BGP unnumbered</td>
 </tr>
 <tr>
  <td>Uplink TOR2 to Spine2</td>
  <td>NA</td>
  <td>NA</td>
  <td>BGP unnumbered</td>
 </tr>
 <tr>
  <td>Management</td>
  <td>7</td>
  <td>10.0.3.0/26</td>
  <td>10.0.3.1 - Gateway<br />10.0.3.2 - TOR1<br />10.0.3.3 - TOR2</td>
 </tr>
 <tr>
  <td>Storage 1</td>
  <td>8</td>
  <td>10.0.10.0/26</td>
  <td>10.0.10.1 - Gateway<br />10.0.10.2 - TOR1<br />10.0.10.3 - TOR2</td>
 </tr>
 <tr>
  <td>Storage 2</td>
  <td>9</td>
  <td>10.0.10.64/26</td>
  <td>10.0.10.65 - Gateway<br />10.0.10.66 - TOR1<br />10.0.10.67 - TOR2</td>
 </tr> 
  <tr>
  <td>Transit</td>
  <td>10</td>
  <td>10.0.10.128/26</td>
  <td>10.0.0.129 - Gateway<br />10.0.0.130 - TOR1<br />10.0.0.131 - TOR2</td>
 </tr> 
  <tr>
  <td>HNV PA</td>
  <td>11</td>
  <td>10.0.11.0/25</td>
  <td>10.0.11.1 - Gateway<br />10.0.11.2 - TOR1<br />10.0.11.3 - TOR2</td>
 </tr> 
  <tr>
  <td>Deploy</td>
  <td>Untagged</td>
  <td>10.0.10.192/26</td>
  <td>10.0.10.193 - Gateway<br />10.0.0.194 - TOR1<br />10.0.0.195 - TOR2</td>
 </tr> 
</table>

In addition, each switch device has a connection to an additional switch (not shown here) which gives management access to the device.  So in addition, a management IP address is also assigned to the device on this externally configured switch management subnet:

<table>
<tr><td>Device</td><td>IP Address</td><td>Gateway</td></tr>
<tr><td>TOR1</td><td>10.0.0.149/28</td><td>10.0.0.145</td></tr>
<tr><td>TOR2</td><td>10.0.0.150/28</td><td>10.0.0.145</td></tr>
</table>
 
When modifying the configuration files you will need to modify them to use the subnets you've allocoated from yoru  

## Top of rack switch (TOR) configuration file details

This section will walk through details on the parts of the configuraiton file you will need to change or be aware of:

Update the host name to match your organization's naming convention:

      net add hostname TOR1



### Physical port configuration

Each physical port must be configured to act as a switchport and have the mode set to trunk to allow multiple VLANs to be sent to the host.  For RDMA Priority-flow-control must be on and the service-policy must point to the input queue that you will define below.

Since this is a 40 Gbit switch and we are connecting to hosts with 10 Gbit adapters, we are splitting the 40 Gbit port into four 10 Gbit connections.

Update each Ethernet port to match the above wherever there is a Hyper-V host connected.

    interface Ethernet1/3/1
     speed 10000
     priority-flow-control mode on
     switchport mode trunk
     switchport trunk native vlan 12
     switchport trunk allowed vlan 7-12
     spanning-tree port type edge trunk
     service-policy type queuing input INPUT_QUEUING
     no shutdown

The management port (eth0) has an ip address assigned directly on it.  This address is allocated from your switch management subnet.

    net add interface eth0 ip address 10.0.0.149/28
    net add interface eth0 ip gateway 10.0.0.145
    net add interface eth0 vrf mgmt


All switches require a loopback interface with a /32 subnet assigned to it. Update the loopback sections to match your assigned loopback addresses.
The loopback address will also be used as BGP router ID and will be advertised into BGP so it will shown within a traceroute log.

    net add loopback lo ip address 10.0.1.73/32

BGP is utilized extensively by the Microsoft SDN infrastructure.  While it is only required for peering between the Muxes/Gateways and the top-of-rack switches, it is also useful for peering to Spineregate switches and into the rest of the datacenter as it provides dyanmic route updates and keepalives for the detection of dead links.<br />

Each layer of a network that provides access to the same set of subnets is assigned a uniqe ASN.  Since all Spine switches that are working together for a common set of racks can be equally used for routing, they all share the same ASN.  In this example this Spineregate layer is assigned 64807.

Each device that is to act as a peer needs to be added to the BGP router to allow the dynamic exchange of routes.  Each link to a Spine switch is added here.

    net add bgp autonomous-system 64651
    net add bgp router-id 10.0.1.73/32
    net add bgp bestpath as-path multipath-relax
    net add bgp neighbor ISL peer-group
    net add bgp neighbor ISL remote-as external
    net add bgp neighbor MSSDN peer-group
    net add bgp neighbor MSSDN remote-as 64652
    net add bgp neighbor swp31 interface peer-group ISL
    net add bgp neighbor swp32 interface peer-group ISL
    net add bgp listen range 10.0.10.128/26 peer-group MSSDN
    net add bgp ipv4 unicast network 10.0.1.73/32 
    net add bgp ipv4 unicast redistribute connected route-map ACCEPT_DC_LOCAL
    net add bgp ipv6 unicast neighbor ISL activate
 
For the SDN gateways (Software Load Balancer (SLB) MUX and Multi-tenant gateways) since these will be scaled out it is not practical to add each one individually here, so instead we create a peer group which tells the switch that any member of this subnet can peer. 
 
    

NTP servers are required to give the switch an accurate clock.  Update this section with a set of NTP servers provided by your organization.  If you don't have a dedicated NTP server, an Active Directory server can be used as an NTP server.  Add or remove rows here to match the number of servers you have.

    net add time ntp server 10.0.2.7 vrf mgmt
    
Set the timezone to match your local timezone.

    net add time zone Europe/Zurich


### TOR Redundancy

In order for the two TOR switches to provide the same L2 network to the Hyper-V hosts, they must have dedicated physical link directly connecting each other together.  Since inbound traffic can arrive on either TOR, but must be sent on the physical link to the host where the MAC address was learned, about 50% of the inbound traffic for the hyper-v hosts will traverse the direct connection between the hosts.


    net add bond peerlink bond slaves swp17,swp18
    net add interface peerlink.4094 clag peer-ip 169.254.1.2
    net add interface peerlink.4094 clag sys-mac 44:38:39:ff:00:01
    net add interface peerlink.4094 ip address 169.254.1.1/30

The virtual-address defined in the HSRP section must be used as the gateway for the subnet in the hosts and VMs since the permanent address for each device that is defined in the parent VLAN will become unavailable if the switch where it is assigned goes down.   

Again, the priority must be defined so that one switch has a lower value and will become the primary.  You can leave the default as-is for your environment.



### VLAN Definition

Each VLAN that is available for the host to use is defined as a VLAN interface.

Update the IP address and subnet to match the subnets that you've allocated for your deployment.  Make sure that the IP address specified is different for each TOR.  In this example TOR1 uses the second address in the subnet and TOR2 uses the third address.  The first address will be used for the redundant router as explained next.

    net add vlan 7 ip address 10.0.3.2/26
    net add vlan 7 ip address-virtual 00:00:5e:00:01:07 10.0.3.1/26






### Quality of Service for RDMA

For RDMA based storage to function properly, traffic classes must be defined to separate the RDMA based storage traffic from the rest of the host and VM traffic.  

    class-map type qos match-all RDMA
      match cos 3
    class-map type queuing RDMA
      match qos-group 3
    policy-map type qos QOS_MARKING
    class RDMA
        set qos-group 3
    class class-default
    policy-map type queuing QOS_QUEUEING
    class type queuing RDMA
        bandwidth percent 50
    class type queuing class-default
        bandwidth percent 50
    policy-map type queuing INPUT_QUEUING
      class type queuing RDMA
        pause buffer-size 101920 pause-threshold 46800 resume-threshold 34320
      class type queuing class-default
    class-map type network-qos RDMA
      match qos-group 3
    class-map type network-qos Scavenger-1
      match qos-group 1
    policy-map type network-qos QOS_NETWORK
      class type network-qos RDMA
        mtu 2240
        pause no-drop
      class type network-qos class-default
        mtu 9216
    policy-map type network-qos jumbo-queuing
      class type network-qos class-default
        mtu 9216
    system qos
      service-policy type qos input QOS_MARKING
      service-policy type queuing output QOS_QUEUEING
      service-policy type network-qos QOS_NETWORK
    class-map type control-plane match-any copp-icmp
      match access-group name copp-system-acl-icmp
    class-map type control-plane match-any copp-ntp
      match access-group name copp-system-acl-ntp
    class-map type control-plane match-any copp-s-arp
    class-map type control-plane match-any copp-s-bfd
    class-map type control-plane match-any copp-s-bpdu
    class-map type control-plane match-any copp-s-dai
    class-map type control-plane match-any copp-s-default
    class-map type control-plane match-any copp-s-dhcpreq
    class-map type control-plane match-any copp-s-dhcpresp
      match access-group name copp-system-dhcp-relay
    class-map type control-plane match-any copp-s-dpss
    class-map type control-plane match-any copp-s-eigrp
      match access-group name copp-system-acl-eigrp
      match access-group name copp-system-acl-eigrp6
    class-map type control-plane match-any copp-s-glean
    class-map type control-plane match-any copp-s-igmp
      match access-group name copp-system-acl-igmp
    class-map type control-plane match-any copp-s-ipmcmiss
    class-map type control-plane match-any copp-s-l2switched
    class-map type control-plane match-any copp-s-l3destmiss
    class-map type control-plane match-any copp-s-l3mtufail
    class-map type control-plane match-any copp-s-l3slowpath
    class-map type control-plane match-any copp-s-mpls
    class-map type control-plane match-any copp-s-pimautorp
    class-map type control-plane match-any copp-s-pimreg
      match access-group name copp-system-acl-pimreg
    class-map type control-plane match-any copp-s-ping
      match access-group name copp-system-acl-ping
    class-map type control-plane match-any copp-s-ptp
    class-map type control-plane match-any copp-s-routingProto1
      match access-group name copp-system-acl-routingproto1
    class-map type control-plane match-any copp-s-routingProto2
      match access-group name copp-system-acl-routingproto2
    class-map type control-plane match-any copp-s-selfIp
    class-map type control-plane match-any copp-s-ttl1
    class-map type control-plane match-any copp-s-vxlan
    class-map type control-plane match-any copp-snmp
      match access-group name copp-system-acl-snmp
    class-map type control-plane match-any copp-ssh
      match access-group name copp-system-acl-ssh
    class-map type control-plane match-any copp-stftp
      match access-group name copp-system-acl-stftp
    class-map type control-plane match-any copp-tacacsradius
      match access-group name copp-system-acl-tacacsradius
    class-map type control-plane match-any copp-telnet
      match access-group name copp-system-acl-telnet
    policy-map type control-plane copp-system-policy 
        class copp-s-selfIp
            police pps 500 
        class copp-s-default
            police pps 400 
        class copp-s-l2switched
            police pps 200 
        class copp-s-ping
            police pps 100 
        class copp-s-l3destmiss
            police pps 100 
        class copp-s-glean
            police pps 500 
        class copp-s-l3mtufail
            police pps 100 
        class copp-s-ttl1
            police pps 100 
        class copp-s-ipmcmiss
            police pps 400 
        class copp-s-l3slowpath
            police pps 100 
        class copp-s-dhcpreq
            police pps 300 
        class copp-s-dhcpresp
            police pps 300 
        class copp-s-dai
            police pps 300 
        class copp-s-igmp
            police pps 400 
        class copp-s-routingProto2
            police pps 4000 
        class copp-s-eigrp
            police pps 200 
        class copp-s-pimreg
            police pps 200 
        class copp-s-pimautorp
            police pps 200 
        class copp-s-routingProto1
            police pps 4000 
        class copp-s-arp
            police pps 400 
        class copp-s-ptp
            police pps 1000 
        class copp-s-vxlan
            police pps 1000 
        class copp-s-bfd
            police pps 350 
        class copp-s-bpdu
            police pps 6000 
        class copp-s-dpss
            police pps 1000 
        class copp-s-mpls
            police pps 100 
        class copp-icmp
            police pps 200 
        class copp-telnet
            police pps 500 
        class copp-ssh
            police pps 500 
        class copp-snmp
            police pps 500 
        class copp-ntp
            police pps 100 
        class copp-tacacsradius
            police pps 400 
        class copp-stftp
            police pps 400 
    control-plane
    service-policy input copp-system-policy 

The above enables DCB and defines the necessary traffic classes to allow RDMA to function.  50% of the bandwidth on each host port will be reserved for storage and 50% for host/VM traffic.  Adjust the "bandwidth percent" here based on the requirements of your workload.  


___
**IMPORTANT**

The bandwidth percentages allocated here must match the DCB QOS settings you apply on the Hyper-V host physical adapters or RDMA will not function properly.
___

In addition a VLAN must be defined for each physical adapter in the host in order for the RDMA to be tagged:

    interface Vlan8
        description Storage1
        no shutdown
        no ip redirects
        ip address 10.0.10.2/26
        hsrp version 2
        hsrp 1 
            priority 140 forwarding-threshold lower 1 upper 140
            ip 10.0.10.1 

    interface Vlan9
        description Storage2
        no shutdown
        no ip redirects
        ip address 10.0.10.66/26
        hsrp version 2
        hsrp 1 
            priority 140 forwarding-threshold lower 1 upper 140
            ip 10.0.10.65 
___    
**IMPORTANT**

RDMA traffic must be on tagged VLANs.  RDMA will not function properly if sent on an untagged interface.
___
