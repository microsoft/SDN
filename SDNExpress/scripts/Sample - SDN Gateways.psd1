@{
    ScriptVersion        = '2.0'

    #Location from where the VHD will be copied.  VHDPath can be a local directory where SDN Express is run or an SMB share.
    VHDPath              = 'C:\images'
    #Name of the VHDX as the golden image to use for VM creation.  Use the convert-windowsimage utility to create this from an iso or install.wim.
    VHDFile              = 'RS5_RELEASE_SVC_HCI_17784.1068.200716-1400_serverazurestackhcicor_en-us_HCI.vhdx'

    #This is the location on the Hyper-V host where the VM files will be stored, including the VHD.  A subdirectory will be created for each VM using the VM name.  This location can be a local path on the host, a cluster volume, or an SMB share with appropriate permissions.
    VMLocation           = 'c:\VMs'

    #Specify the name of the active directory domain where you want the SDN infrastructure VMs to be joined.  Domain join takes place offline prior to VM creation.
    JoinDomain           = 'sa18.nttest.microsoft.com'

    #IMPORTANT: if you deploy multiple network controllers onto the same network segments, you must change the SDNMacPool range to prevent overlap.
    SDNMacPoolStart      = "00-11-22-00-01-00"
    SDNMacPoolEnd        = "00-11-22-00-01-FF"

    #ManagmentSubnet, ManagementGateway, and ManagementDNS are not required if DHCP is configured for the management adapters below.
    ManagementSubnet     = '10.127.134.128/25'
    ManagementGateway    = '10.127.134.129'
    ManagementDNS        = @('10.127.130.7', '10.127.130.8')
    #Use 0, or comment out ManagementVLANID to configure the management adapter for untagged traffic 
    ManagementVLANID     = 7

    #Usernames must be in the format Domain\User, Example: Contoso\Greg
    #IMPORTANT: DomainJoinUsername is used for admin operations on the Hyper-V host when creating VMs, it is no longer used for domain joining, instead the current user that is running the script requires domain join permission.
    DomainJoinUsername   = 'sa18\george'
    LocalAdminDomainUser = 'sa18\george'
    NCUsername           = 'sa18\george'

    #RestName must contain the FQDN that will be assigned to the SDN REST floating IP.
    RestName             = 'sa20n28sdn-test.sa18.nttest.microsoft.com'

   NCs = @(
        #Optional parameters for each NC: 
        #  MacAddress - if not specified Mac Address is taken from start of SDNMacPool. SDN Mac Pool start is incremented to not include this mac.
        #  HostName - if not specified, taken round robin from list of hypervhosts
        #  ManagementIP - if not specified, Management adapter will be configured for DHCP on the ManagementVLANID VLAN.  If DHCP is used it is strongly recommended that you configure a reservation for the assigned IP address on the DHCP server.
        @{ComputerName='sa20n28-NC001'; HostName='SA20n28-2'; ManagementIP='10.127.134.201'; MACAddress = '001DD8220000'},
        @{ComputerName='sa20n28-NC002'; HostName='SA20n28-3'; ManagementIP='10.127.134.202'; MACAddress = '001DD8220001'},
        @{ComputerName='sa20n28-NC003'; HostName='SA20n28-3'; ManagementIP='10.127.134.203'; MACAddress = '001DD8220002'}
    )
    Muxes = @( 
        #Optional parameters for each Mux: 
        #  HostName - if not specified, taken round robin from list of hypervhosts
        #  MacAddress - if not specified Management adapter Mac Address is taken from start of SDNMacPool. SDN Mac Pool start is incremented to not include this mac.
        #  PAMacAddress - if not specified PA Adapter Mac Address is taken from start of SDNMacPool. SDN Mac Pool start is incremented to not include this mac.
        #  PAIPAddress - if not specified the PA IP Address is taken from the beginning of the HNV PA Pool.  The start of the pool is incremented to not include this address.
        #  ManagementIP - if not specified, Management adapter will be configured for DHCP on the ManagementVLANID VLAN.  If DHCP is used it is strongly recommended that you configure a reservation for the assigned IP address on the DHCP server.
        #IMPORTANT NOTE: if specified, PAMacAddress must be outside of the SDN Mac Pool range.   PAIPAddress must be outside of the HNV PA IP Pool Start and End range.
        @{ComputerName='sa20n28-Mux01'; HostName='SA20n28-2'; ManagementIP='10.127.134.204'; MACAddress = '001DD8220003'; PAMacAddress = '001DD8220005'; PAIPAddress='10.10.202.62'},
        @{ComputerName='sa20n28-Mux02'; HostName='SA20n28-3'; ManagementIP='10.127.134.205'; MACAddress = '001DD8220004'; PAMacAddress = '001DD8220006'; PAIPAddress='10.10.202.63'}
    )
    Gateways = @(
        #Optional parameters for each Gateway: 
        #  HostName - if not specified, taken round robin from list of hypervhosts
        #  MacAddress - if not specified Management adapter Mac Address is taken from start of SDNMacPool.  SDN Mac Pool start is incremented to not include this mac.
        #  BackEndMac - if not specified Back End Adapter Mac Address is taken from start of SDNMacPool.  This Mac remains within the SDN Mac Pool.
        #  FrontEndMac - if not specified Front End Adapter Mac Address is taken from start of SDNMacPool.  This Mac remains within the SDN Mac Pool.
        #  FrontEndIP - if not specified the FrontEnd IP Address is taken from the beginning of the HNV PA Pool.  
        #  ManagementIP - if not specified, Management adapter will be configured for DHCP on the ManagementVLANID VLAN.  If DHCP is used it is strongly recommended that you configure a reservation for the assigned IP address on the DHCP server.
        #IMPORTANT NOTE: if specified, frontendmac, backendmac must be within the SDN Mac Pool range.   FrontEndIP must be within the HNV PA IP Pool Start and End range.
        @{ComputerName='sa20n28-GW01'; HostName='SA20n28-2'; ManagementIP='10.127.134.206'; MACAddress='001DD8220005'; BackEndMac='0011220001FA'; FrontEndMac='0011220001FB'; FrontEndIP='10.10.202.60'},
        @{ComputerName='sa20n28-GW02'; HostName='SA20n28-3'; ManagementIP='10.127.134.207'; MACAddress='001DD8220006'; BackEndMac='0011220001F9'; FrontEndMac='0011220001F8'; FrontEndIP='10.10.202.61'}
    )

    # Names of the initial Hyper-V hosts to add to the SDN deployment.  If you will be using additional Hyper-V hosts on different HNV PA subnets, you must add those after the initial deployment using the Add-SDNExpressHost function in the SDNExpressModule. 
    HyperVHosts = @(
        'SA20n28-1', 
        'SA20n28-2', 
        'SA20n28-3',
        'SA20n28-4'
    )

    # Intiail HNV PA subnet to add for the network virtualization overlay to use.  You can add additional HNV PA subnets after deployment using the Add-SDNExpressVirtualNetworkPASubnet function in the sdnexpressmodule.
   PASubnet             = '10.10.202.0/25'
   PAVLANID             = '11'
   PAGateway            = '10.10.202.1'
   PAPoolStart          = '10.10.202.49'
   PAPoolEnd            = '10.10.202.61'  

    # Load Balancer and Gateway BGP information
    # SDN ASN to be used for load balancing VIPs, public IPs and GRE gateway advertisements.  Peering will take place from the HNV PA IP addresses assigned above.  It is recommended that your network administrator configure a peer group for the HNV PA subnet. 
    SDNASN               = '64628'
    
    # Router BGP peering endpoint ASN and IP address that is configured for peering by your network administrator.  On some routers it is recommended to peer with the loopback address.
   Routers = @(
      @{ RouterASN='64647'; RouterIPAddress='10.10.202.1'}
   )
    
    # Initial set of VIP subnets to use for load balancing and public IPs
    PublicVIPSubnet = '10.127.134.24/29'
    PrivateVIPSubnet = '12.0.0.0/29'

    # Subnet to use for GRE gateway connection endpoints.  This subnet is only used if you configure GRE gateway connections.
     GRESubnet            = '15.127.134.24/29'
    
    # Gateway VM network capacity, used by SDN controller for capacity management of gateway connections.    
     Capacity             = '10000000'


    # Optional fields.  Uncomment items if you need to override the defaults.

    # Initial gateway pool name, if not specified will use DefaultAll.  Additional pools can be added after the initial deployment using the SDNExpressModule.
    # PoolName             = ''

    # Specify ProductKey if you have a product key to use for newly created VMs.  If this is not specified you may need 
    # to connect to the VM console to proceed with eval mode.
    # ProductKey       = '#####-#####-#####-#####-#####'

    # Switch name is only required if more than one virtual switch exists on the Hyper-V hosts.
    SwitchName = "ConvergedSwitch"

    # Amount of Memory and number of Processors to assign to VMs that are created.
    # If not specified a default of 8 procs and 8GB RAM are used.
    # VMMemory = 4GB
    # VMProcessorCount = 4

    # If Locale and Timezone are not specified the local time zone of the deployment machine is used.
    # Locale           = ''
    # TimeZone         = ''

    # Passwords can be optionally included if stored encrypted as text encoded secure strings.  Passwords will only be used
    # if SDN Express is run on the same machine where they were encrypted, otherwise it will prompt for passwords.
    # DomainJoinSecurePassword  = ''
    # LocalAdminSecurePassword   = ''
    # NCSecurePassword   = ''

}
