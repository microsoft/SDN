# Troubleshooting SDN

Deploying the Microsoft Windows SDN Stack may require some troubleshooting of problems that arise during fabric and tenant deployment. The instructions provided below is for collecting a set of data which will aid in the troubleshooting and triage process. Please look at the [SDN Troubleshooting](https://technet.microsoft.com/en-us/library/mt715794.aspx) TechNet article for more information on individual commands and triage.
 
Make sure you have the most recent diagnostic KBs (download location forthcoming) installed on all of your NC nodes and Hyper-V Hosts. Also, make sure the tools have been installed on the Hyper-V Hosts:
```none
PS> Add-WindowsFeature RSAT-NetworkController –IncludeManagementTools  
PS> Import-Module NetworkControllerDiagnostics  
 ```
### Triage and Data Collection 
1. Validate that Network Controller is up and running correctly (Executed from one of the NC Nodes):
```none
PS> Debug-WinFabNodeStatus
```
Check that ReplicaStatus is Ready and HealthState is Ok (if any nodes are not in Ready/Ok state, note which one is unhealthy in the bug)

```none  
PS> Get-NetworkControllerReplica
```

Check that the Replica Status is Ready for each service (if any service is not in Ready state, note which service is unhealthy and on which node it is running in the bug)
 
2. Validate the NC Host Agents have made connections to the Network Controller (Execute on each Hyper-V host)
```none
C:\> netstat -anp tcp |findstr 6640
```

There should be three ESTABLISHED connections and one LISTENING socket
- Listening on Hyper-V hosts IP on port 6640
- Two established connections to Hyper-V host IP on port 6640 from NC node(s) on ephemeral ports (> 32000) Connection established bet
- One established connection from Hyper-V host IP to REST IP on port 6640
 
3. Check the Network Controller’s configuration state (Executed from any Hyper-V host)
```none
PS> Debug-NetworkControllerConfigurationState -NcIpAddress <Enter FQDN or IP – based on cert subject name configured>
```

Look for any resources which have status Warning or Failure
_Caveat: If you deployed using VMM, please use the VMM variant of the script available on GitHub [Debug-NetworkControllerConfigurationStateVmm](https://github.com/Microsoft/SDN/blob/master/Diagnostics/Debug-NetworkControllerConfigurationVMM.ps1)_
 
4. Check the SLB Configuration State (Executed from an NC node)
```none
PS > Debug-SlbConfigState
```
Output location should be indicated – default is C:\SDNDiagnostics\NetworkControllerState\SlbConfigState.txt
_Caveat: This script does not work for VMM-based deployments_
 
5. Check policies in Host Agent
```none
C:\> ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_vtep
```
The key table in this output is the ucast_macs_remote table which lists the tenant VM NIC IP and MAC address. Check to see if policy is missing for any given tenant VM IP address.
 
6. Look for HNV Provider Addresses (PA IPs) on the host
```none
PS > Get-ProviderAddress
 ```
 
Attach the full output of all of these commands to the bug.

### Collecting Logs and Traces
Next step will probably be log collection. In order to proceed in an investigation, we need both the Host ID and the Port Profile IDs of any VM NICs for which there is no policy available in the Host Agent’s OVSDB ms_vtep database.

1. Collect most recent ETL log files under C:\SDNDiagnostics\Logs directory on all NC nodes and Hyper-V host in question (Zip)
2. Execute this script to get the Host ID
```none
PS > Get-ItemProperty "hklm:\system\currentcontrolset\services\nchostagent\parameters" -Name HostId |fl HostId
```
3. Execute this script (download from GitHub – [Get-AllPortProfiles](https://github.com/Microsoft/SDN/blob/master/Diagnostics/Get-AllPortProfiles.ps1) ) to get the Port Profile IDs for each VM (indicate which VM NIC does not have policies) 
 
Attach this information to the bug as well.
 
Lastly, make a note of what was happening before the degradation of service or error occurred.

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
