Switch Configuration Examples for Microsoft SDN
=======
### Switch model: Dell Force10 S4810
### Firmware version: FTOS 9.9 (0.0)
### Topology: Two aggregate and two top-of-rack (TOR) switches with a L3 topology connected to the border of datacenter core using point-to-point port-channels and BGP

       +--------+ +--------+
       | Border | | Border |   BGP ASN: 4232570300
       +--------+ +--------+
            |  \   /  |
            |   \ /   |
            |    X    |
            |   / \   |
            |  /   \  |
       +--------+ +--------+
       |  Agg1  | |  Agg2  |   BGP ASN: 64807
       +--------+ +--------+
            |  \   /  |
            |   \ /   |
            |    X    |
            |   / \   |
    .Rack1..|  /   \  |.........................
    .  +--------+ +--------+                   .
    .  |  TOR1  |=|  TOR2  |   BGP ASN: 64651  .  ... TORs in additional racks 
    .  +--------+ +--------+                   .       can be added to the 
    .       |         |                        .        same Agg pair.
    .       |         |                        .
    .       |         |                        .
    .       |         |                        .
    .       |         |                        .
    .  +-------------------+                   .
    .  |   Hyper-V Hosts   |-+    BGP ASNs:    .
    .  +-------------------+ |-+   MUX=64652   .
    .    +-------------------+ |   GW =64653   .
    .      +-------------------+               .
    ............................................       

These sample configuration files use the following subnets:
<table>
 <tr>
  <td>Subnet name</td>
  <td>VLAN ID</td>
  <td>Subnet</td>
  <td>Assignments</td>
 </tr>
 <tr>
  <td>Agg1 Loopback</td>
  <td>NA</td>
  <td>10.0.1.69/32</td>
  <td>10.0.1.69 - AGG1</td>
 </tr>
 <tr>
  <td>Agg2 Loopback</td>
  <td>NA</td>
  <td>10.0.1.75/32</td>
  <td>10.0.1.75 - AGG1</td>
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
  <td>Port-Channel Border1 to Agg1</td>
  <td>NA</td>
  <td>10.0.1.57/31</td>
  <td>10.0.1.56 - Border1<br />10.0.1.57 - AGG1</td>
 </tr>
 <tr>
  <td>Port-Channel Border2 to Agg1</td>
  <td>NA</td>
  <td>10.0.1.61/31</td>
  <td>10.0.1.60 - Border2<br />10.0.1.61 - AGG1</td>
 </tr>
 <tr>
  <td>Port-Channel Border1 to Agg2</td>
  <td>NA</td>
  <td>10.0.1.59/31</td>
  <td>10.0.1.58 - Border1<br />10.0.1.58 - AGG2</td>
 </tr>
 <tr>
  <td>Port-Channel Border2 to Agg2</td>
  <td>NA</td>
  <td>10.0.1.62/31</td>
  <td>10.0.1.61 - Border2<br />10.0.1.62 - AGG2</td>
 </tr>          
 <tr>
  <td>Port-Channel Agg1 to TOR1</td>
  <td>NA</td>
  <td>10.0.0.24/31</td>
  <td>10.0.0.24 - Agg1<br />10.0.0.25 - TOR1</td>
 </tr>
 <tr>
  <td>Port-Channel Agg1 to TOR2</td>
  <td>NA</td>
  <td>10.0.0.26/31</td>
  <td>10.0.0.26 - Agg1<br />10.0.0.27 - TOR2</td>
 </tr>
 <tr>
  <td>Port-Channel Agg2 to TOR1</td>
  <td>NA</td>
  <td>10.0.0.42/31</td>
  <td>10.0.0.42 - Agg2<br />10.0.0.43 - TOR1</td>
 </tr>
 <tr>
  <td>Port-Channel Agg2 to TOR2</td>
  <td>NA</td>
  <td>10.0.0.44/31</td>
  <td>10.0.0.44 - Agg2<br />10.0.0.45 - TOR2</td>
 </tr>
 <tr>
  <td>Unused Ports (Reserved)</td>
  <td>2</td>
  <td>NA</td>
  <td>NA</td>
 </tr>
 <tr>
  <td>Bad Ports (Reserved)</td>
  <td>3</td>
  <td>NA</td>
  <td>NA</td>
 </tr> 
 <tr>
  <td>Reserved Ports (Reserved)</td>
  <td>4</td>
  <td>NA</td>
  <td>NA</td>
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
  <td>10.0.10.129 - Gateway<br />10.0.10.130 - TOR1<br />10.0.10.131 - TOR2</td>
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
<tr><td>AGG1</td><td>10.0.0.135/28</td><td>10.0.0.129</td></tr>
<tr><td>AGG2</td><td>10.0.0.151/28</td><td>10.0.0.145</td></tr>
<tr><td>TOR1</td><td>10.0.0.149/28</td><td>10.0.0.145</td></tr>
<tr><td>TOR2</td><td>10.0.0.150/28</td><td>10.0.0.145</td></tr>
</table>
 
When modifying the configuration files you will need to modify them to use the subnets you've allocoated from yoru  

## Aggregate switch configuration file details

This section will walk through details on the parts of the configuraiton file you will need to change or be aware of:

    hostname AGG1
Update the host name to match your organization's naming convention

    protocol lldp 
     advertise management-tlv system-capabilities system-description system-name 
     advertise interface-port-desc 
    !
Enabling LLDP allows for easy identification of links between devices and verification of the port that a device is connected to.  You can leave this section as-is.
 
     enable password 7 <password>
    !
     username admin password 7 <password> privilege 15
    !

Replace the &lt;password> text with your own top secret password.

    interface TenGigabitEthernet 0/0
     description Uplink to Border1
     no ip address
    !  
     port-channel-protocol LACP 
      port-channel 86 mode active  
     no shutdown
    !
Multiple physical links are used to connect an aggregate switches to each other switch.  These are bundled together using a port-channel with LACP configured on the port channel.  This allows the multiple links to act as a single set of teamed interfaces.  A unique port channel number is assigned to each set of links.  In the above example 86 is the assigned port channel number.  Later on you will create an interface on each port-channel.

    interface TenGigabitEthernet 0/5
     no ip address
     shutdown
    ! 
It is a best practice to disable ports that do not have any physical connection or is unused.  The above section shuts down the port "TenGigabitEthernet 0/5" using the "shutdown" keyword.

    interface ManagementEthernet 0/0
     ip address 10.0.0.135/28
     no shutdown
    ! 
The management port (which is a physical port on the front of the device) has an ip address assigned directly on it.  This address is allocated from your switch management subnet.

    interface Loopback 0
     ip address 10.0.1.69/32
     ip unreachables
     no shutdown
    ! 
All switches require a loopback interface with a /32 subnet assigned to it.  Update the loopback section to match your assigned loopback address.
    interface Port-channel 86
     description Link to Border1
     ip address 10.0.1.57/31
     rate-interval 30
     ip unreachables
     no shutdown
    ! 
As mentioned above, each port channel has an ip interface assigned to it to use as a point-to-point link to allow each device to be used as a next-hop between devices.  These point-to-point links are represented as /31 subnets, with the lower number belonging to the device that is used as the default path for the other.

    interface Vlan 1
    !
The aggregate switches do not have any usable VLANs defined as there are no IP endpoints directly attached to them.  All access, other than the management interface itself, is through routing on the port-channels.  This is in contrast to the top-of-rack switches which have several VLANs that are used by the Hyper-V hosts as directly attached endpoints.

    router bgp 64807
     maximum-paths ebgp 16
     maximum-paths ibgp 16
     redistribute static 
     redistribute connected 
     bgp four-octet-as-support

BGP is utilized extensively by the Microsoft SDN infrastructure.  While it is only required for peering between the Muxes/Gateways and the top-of-rack switches, it is also useful for peering to aggregate switches and into the rest of the datacenter as it provides dyanmic route updates and keepalives for the detection of dead links.<br />
Each layer of a network that provides access to the same set of subnets is assigned a uniqe ASN.  Since all aggregate switches that are working together for a common set of racks can be equally used for routing, they all share the same ASN.  In the above example this aggregate layer is assigned 64807.

    neighbor 10.0.1.56 remote-as 4232570300 
    neighbor 10.0.1.56 description Border1 
    neighbor 10.0.1.56 route-map MEDZERO out
    neighbor 10.0.1.56 remove-private-AS
    neighbor 10.0.1.56 no shutdown 
 
 <p>
 Each device that is to act as a peer needs to be added to the BGP router to allow the dynamic exchange of routes.  For the aggregate switches this includes uplinks to the border, and downlinks to each top of rack switchs.  in this example, the Border devices share a common ASN "4232570300" since they can be used equally.  This four octet ASN and requires that four-octet-as-support is enabled as shown in the previous section.
 </p>
 <p>
 Add remove neighbor sections for each BGP peer that this device is directly connected to.  In this example that consists of Border1, Border2 and TOR1 and TOR2.
 </p>
 
    management route 0.0.0.0/0 10.0.0.129 
    
 The management interface for this switch needs a default gateway and that is specified here.

    snmp-server community Cloud_RO ro 
    snmp-server community Cloud_RW rw 
    snmp-server enable traps bgp
    snmp-server enable traps snmp authentication coldstart linkdown linkup 
    snmp-server enable traps vrrp
    snmp-server enable traps lacp
    snmp-server enable traps entity
    snmp-server enable traps stack
    snmp-server enable traps stp
    snmp-server enable traps ecfm
    snmp-server enable traps vlt
    snmp-server enable traps fips
    snmp-server enable traps ets
    snmp-server enable traps xstp
    snmp-server enable traps isis
    snmp-server enable traps config 
    snmp-server enable traps pfc
    snmp-server enable traps envmon cam-utilization fan supply temperature 
    snmp-server enable traps ecmp
    snmp-server host 10.0.2.254 traps version 2c Cloud_RO udp-port 162

SNMP is used for monitoring of the switch but not required for establishment of the data path through the switch.  Customize this section as needed for your organization's monitoring infrastructure.

    ntp server 10.0.2.7
    ntp server 10.0.2.8
    ntp server 10.0.2.9

NTP servers are required to give the switch an accurate clock.  Update this section with a set of NTP servers provided by your organization.  If you don't have a dedicated NTP server, an Active Directory server can be used as an NTP server.  Add or remove rows here to match the number of servers you have.

    clock timezone PST -8 
    clock summer-time PDT recurring 2 Sun Mar 02:00 1 Sun Nov 02:00 

Set the timezone to match your local timezone and seasonal clock adjustment requirements.

## Top of rack switch (TOR) configuration file details

<p>
The top of rack switch follows the same configuration sections as the aggregate switch.  However There are a few key additional requirements:
 * Hyper-V hosts are connected to TORs and need VLANs for segmenting traffic
 * Hyper-V hosts that use RDMA based storage must have the necessary quality of service (QOS) settings defined in the physical switch.
 * Hyper-V hosts that are connected to multiple TOR switches using a switch embedded team in the virtual switch must have the same L2 network available on each link.  This means the TORs must be configured as a redundant pair with a direct physical link between them for the L2 traffic to traverse.
  
</p>
### Physical port configuration

Each physical port must be configured to act as a switchport and have portmode hybrid to allow tagged VLANs and untagged for deployment.  dcp-map must refer to the dcb-map that you will define later.

    interface TenGigabitEthernet 0/1
     no ip address
     portmode hybrid
     switchport
     dcb-map RDMA-dcb-map-profile
     no shutdown
    ! 

Update each TenGigabitEthernet port to match the above wherever there is a Hyper-V host connected.


### VLAN Definition

Each VLAN that is available for the host to use is defined as a VLAN interface:

    interface Vlan 7
    description Management
    name Management
    ip address 10.0.3.2/26
    tagged TenGigabitEthernet 0/1-36
    ! 

Update the IP address and subnet to match the subnets that you've allocated for this deployment.  Make sure that the ip address specified is different for each TOR.  In this example TOR1 uses the second address in the subnet and TOR2 uses the third address.  The first address will be used for the redundant router as explained below.

Update the "tagged TenGigabitEthernet 0/1-36" line to reference only the ports where you have Hyper-V hosts attached.


### TOR Redundancy

In order for the two TOR switches to provide the same L2 network to the Hyper-V hosts, they must have dedicated physical link directly connecting each other together.  Since inbound traffic can arrive on either TOR, but must be sent on the physical link to the host where the MAC address was learned, about 50% of the inbound traffic for the hyper-v hosts will traverse the direct connection between the hosts.

In this example, physical ports "TenGigabitEthernet 0/45" through "TenGigabitEthernet 0/47" are used for this direct connection:

    interface TenGigabitEthernet 0/45
     description Link to Rack1_TOR2
     no ip address
     no shutdown
    ! 
    interface TenGigabitEthernet 0/46
     description Link to Rack1_TOR2
     no ip address
     no shutdown
    ! 
    interface TenGigabitEthernet 0/47
     description Link to Rack1_TOR2
     no ip address
     no shutdown
    ! 

Update the physical intefaces to match the physical links in your environment.  These three links are combined into a single port channel:

    interface Port-channel 100
     description Link to TOR2
     no ip address
     channel-member TenGigabitEthernet 0/45-47
     rate-interval 30
     no shutdown
    ! 

Update the above section so the channel-member match your physical interfaces.

To define this as a redundant link, the switch must be configured to use VLT.  By enabling VLT and specifying the port channel, the L2 will span across the link and you'll be able to define redundant routers on VLANs.

    vlt domain 100 
     peer-link port-channel 100 
     back-up destination 10.0.0.150 
     primary-priority 1 
     system-mac mac-address de:ad:00:be:ef:01 
     unit-id 0 
    ! 

Update the above back-up destination to be the management IP address of the other TOR in this environment.

Note that one switch will be the primary and the other secondary.  The one that will be the primary should be given a lower primary-priority as shown in these example.  In this example you can leave this setting as-is.

And finally to make the router on each VLAN redundant you must configure VRRP on each VLAN as shown here for the Management VLAN:

     vrrp-group 7 
      no preempt  
      priority 110 
      virtual-address 10.0.3.1 
     ip unreachables
     no shutdown
    ! 

Update the virtual-address in each vrrp-group to be the first address in the subnet. 

The virtual-address defined in the vrrp-group must be used as the gateway for the subnet in the hosts and VMs since the permanent address for each device that is defined in the parent VLAN will become unavailable if the switch where it is assigned goes down.   

Again, the priority must be defined so that one switch has a lower value and will become the primary.  You can leave the default as-is for your environment.


### Quality of Service for RDMA

For RDMA based storage to function properly, traffic classes must be defined to separate the RDMA based storage traffic from the rest of the host and VM traffic.  

    dcb enable
    ! 
    dcb-map RDMA-dcb-map-profile
    priority-group 0 bandwidth 50 pfc on
    priority-group 1 bandwidth 50 pfc off
    priority-pgid 1 1 1 0 1 1 1 1
    !

The above enables DCB and defines the necessary traffic classes to allow RDMA to function.  50% of the bandwidth on each host port will be reserved for storage and 50% for host/VM traffic.  Adjust the percentage here based on the requirements of your workload.  Priority-group 0 is for storage, and priority-group 1 is for all else.

IMPORTANT: the bandwidth percentages allocated here must match the DCB QOS settings you apply on the Hyper-V host physical adapters or RDMA will not function properly.

In addition a VLAN must be defined for each physical adapter in the host in order for the RDMA to be tagged:

    interface Vlan 8
    description Storage1
    name Storage1
    ip address 10.0.10.2/26
    tagged TenGigabitEthernet 0/1-36
    ! 
    vrrp-group 8 
    no preempt  
    priority 110 
    virtual-address 10.0.10.1 
    ip unreachables
    no shutdown
    ! 
    interface Vlan 9
    description Storage2
    name Storage2
    ip address 10.0.10.66/26
    tagged TenGigabitEthernet 0/1-36
    ! 
    vrrp-group 9 
    no preempt  
    priority 110 
    virtual-address 10.0.10.65 
    ip unreachables
    no shutdown
    ! 

IMPORTANT: RDMA traffic must be on tagged VLANs.  RDMA will not function properly if sent on an untagged interface.
 
### Steps for applying this configuration to the switch
 
Once you've customized and determined the appropriate settings for your environment you can apply them to your switch.  You have several options for how to do that including:
1. Issuing these commands one-by-one into the switch command prompt using the serial port or a SSH connection.
2. Using Dell AFM to configure the switch using this file as a template
3. Copying the entire file to the switch's startupconfig using scp, ftp or tftp.  This will requre you to first ensure the correct firmware version is on the switch and that the management IP address, management route and admin password have been enabled manually.

For example from Windows PowerShell using SCP:

    .\pscp -pw <password> ".\Dell S4810-TOR1.cfg" admin@10.0.0.149:startup-config 
    
Then log into the switch and enter a reload command.
