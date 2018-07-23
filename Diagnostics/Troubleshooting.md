# Troubleshooting SDN

Deploying the Microsoft Windows SDN Stack may require some troubleshooting of problems that arise during fabric and tenant deployment. Please reference the [SDN Troubleshooting Topic](https://technet.microsoft.com/en-us/library/mt715794.aspx)  for more details.
 
### Collecting Logs and Traces
If you aren't able to troubleshoot the issue on you're own, the next step will be to collect logs. In order to proceed in an investigation, we need both the Host ID and the Port Profile IDs of any VM NICs for which there is no policy available in the Host Agent’s OVSDB ms_vtep database.


1. Execute this script to get the Host ID
```none
PS > Get-ItemProperty "hklm:\system\currentcontrolset\services\nchostagent\parameters" -Name HostId |fl HostId
```
2. Execute this script (download from GitHub – [Get-AllPortProfiles](https://github.com/Microsoft/SDN/blob/master/Diagnostics/Get-AllPortProfiles.ps1) ) to get the Port Profile IDs for each VM (indicate which VM NIC does not have policies) 
 

### Gateways Troubleshooting

From Network Controller: 
* Get-NetworkControllerLogicalNetwork
* Get-NetworkControllerPublicIPAddress
* Get-NetworkControllerGatewayPool
* Get-NetworkControllerGateway
* Get-NetworkControllerVirtualGateway
* Get-NetworkControllerNetworkInterface
         
From GW VM: 
* Ipconfig /allcompartments /all
* Get-NetRoute –IncludeAllCompartments –AddressFamily
* Get-NetBgpRouter
* Get-NetBgpRouter | Get-BgpPeer
* Get-NetBgpRouter | Get-BgpRouteInformation

From Top of Rack (ToR) Switch: 
* sh ip bgp summary (for 3rd party BGP Routers)
* Windows BGP Router 
* Get-BgpRouter
* Get-BgpPeer
* Get-BgpRouteInformation
         
In addition to these, from the issues we have seen so far (especially on SDNExpress based deployments), the most common reason for Tenant Compartment not getting configured on GW VMs seem to be the fact that the GW Capacity in FabricConfig.psd1 is less compared to what folks try to assign to the Network Connections (S2S Tunnels) in TenantConfig.psd1. This can be checked easily by comparing outputs of the following
 
 ```none
PS > (Get-NetworkControllerGatewayPool –ConnectionUri $uri).properties.Capacity
PS > (Get-NetworkControllerVirtualgatewayNetworkConnection –ConnectionUri $uri -VirtualGatewayId "TenantName").properties.OutboundKiloBitsPerSecond
PS > (Get-NetworkControllerVirtualgatewayNetworkConnection –ConnectionUri $uri -VirtualGatewayId "TenantName").properties.InboundKiloBitsPerSecond
 ```
